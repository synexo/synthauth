'use strict';

/**
 * flow.js — Transport-agnostic authentication flows.
 *
 * Dialogue adapter interface:
 * {
 *   send(text):   void             — output a line of text to the user
 *   prompt(text): Promise<string>  — display prompt, return trimmed user input
 * }
 *
 * Config object:
 * {
 *   pepper:    string,
 *   synthSalt: Buffer,
 *   db:        AuthDB,
 *   wordList:  WordList,
 *   sessions:  SessionStore,
 *   ipAddress: string|null,
 * }
 */

const {
  isValidUsernameInput,
  deriveIdentity,
  decodeRecoveryCode,
  decodeRecoveryCodeToWords,
} = require('./crypto');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Max codeword/recovery-code attempts before a login session is terminated. */
const MAX_LOGIN_ATTEMPTS = 5;

/**
 * After this many failed codeword attempts, remind the user about "recover".
 * Must be < MAX_LOGIN_ATTEMPTS.
 */
const RECOVER_REMINDER_AFTER = 3;

/** Max confirmation attempts during registration / recovery re-entry. */
const MAX_CONFIRM_ATTEMPTS = 3;

/**
 * Regex for a structurally valid recovery code.
 * Exactly 8 alphanumeric chars, optionally with a dash after position 4.
 * Crockford substitutions (I→1, L→1, O→0) are applied during decode so
 * those chars are intentionally accepted here too.
 */
const RECOVERY_CODE_RE = /^[0-9A-Za-z]{4}-?[0-9A-Za-z]{4}$/;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function madLibs(username, words) {
  const [w1, w2, w3] = words.map(w => w.toUpperCase());
  return [
    `  • ${username} writes songs about ${w1}, ${w2}, and ${w3}.`,
    `  • ${username} paints pictures of ${w1}, ${w2}, and ${w3}.`,
    `  • ${username} often contemplates ${w1}, ${w2}, and ${w3}.`,
  ];
}

/** Normalize codeword input — space or dash separated, any case → lowercase tokens. */
function extractCodewords(line) {
  return line.trim().replace(/-/g, ' ').split(/\s+/).filter(Boolean).map(w => w.toLowerCase());
}

/** Normalize a recovery code: strip dash, uppercase. */
function normalizeRecoveryCode(input) {
  return input.trim().replace(/-/g, '').toUpperCase();
}

/**
 * Return true if `input` structurally resembles a recovery code (XXXX-XXXX or XXXXXXXX).
 * Does not guarantee semantic validity.
 */
function looksLikeRecoveryCode(input) {
  return RECOVERY_CODE_RE.test(input.trim());
}

/**
 * Decode a recovery code and verify the derived identity exists in the registry.
 * Returns { recoveredWords, identity } on full success, null on any failure.
 *
 * All failure cases are intentionally collapsed to null — callers must not
 * distinguish between bad format, bad range, or unknown identity.
 *
 * Recovery codes are normalised to uppercase before decode, so lowercase
 * input is accepted transparently.
 *
 * @param {string} rawCode
 * @param {string} rawUsername
 * @param {object} config
 * @returns {Promise<{ recoveredWords: string[], identity: object }|null>}
 */
async function tryDecodeAndVerifyRecovery(rawCode, rawUsername, config) {
  const { wordList, db } = config;

  // 1. Structural format check + Crockford decode + range check
  const decoded = decodeRecoveryCodeToWords(rawCode, wordList);
  if (!decoded) return null;

  const recoveredWords = decoded.words;

  // 2. Derive identity
  let identity;
  try {
    identity = await deriveIdentity(
      rawUsername,
      recoveredWords,
      config.pepper,
      config.synthSalt,
      wordList
    );
  } catch (e) {
    return null;
  }

  // 3. Registry check — must exist before we reveal anything
  if (!db.find(identity.internalId)) return null;

  return { recoveredWords, identity };
}

/**
 * Attempt to decode a recovery code and derive the identity, WITHOUT
 * checking the database. Used for silent BBS auto-registration: if the
 * code is cryptographically valid but no account exists yet, we create one.
 *
 * Returns { words, identity } on successful decode+derive, null if the
 * code itself is bad (bad format, out-of-range indices, Argon2 failure).
 *
 * @param {string} rawCode
 * @param {string} rawUsername
 * @param {object} config
 * @returns {Promise<{ words: string[], identity: object }|null>}
 */
async function tryDecodeRecoveryNoDB(rawCode, rawUsername, config) {
  const { wordList } = config;

  // Structural + range validation (no DB)
  const decoded = decodeRecoveryCodeToWords(rawCode, wordList);
  if (!decoded) return null;

  // Derive identity from the decoded words
  let identity;
  try {
    identity = await deriveIdentity(
      rawUsername,
      decoded.words,
      config.pepper,
      config.synthSalt,
      wordList
    );
  } catch (e) {
    return null;
  }

  return { words: decoded.words, identity };
}

// ---------------------------------------------------------------------------
// Flow: Entry point
// ---------------------------------------------------------------------------

async function entryFlow(dialogue, config) {
  dialogue.send('');
  dialogue.send('Welcome to SynthDoor.');
  dialogue.send('');

  const input = await dialogue.prompt('Enter your username or "new": ');

  if (input.trim().toLowerCase() === 'new') {
    return registrationFlow(dialogue, config);
  }

  return loginFlow(dialogue, config, input.trim());
}

// ---------------------------------------------------------------------------
// Flow: Login
// ---------------------------------------------------------------------------

/**
 * Login flow with a retry loop.
 *
 * - Up to MAX_LOGIN_ATTEMPTS valid-dictionary submissions or recovery code
 *   attempts are allowed per session. Malformed entries (wrong word count,
 *   typo → Levenshtein hint) do not consume an attempt.
 * - A recovery code entered at the codeword prompt works as an alternative
 *   password.
 * - "recover" keyword redirects to recoveryFlow.
 * - After RECOVER_REMINDER_AFTER failures, the prompt and a tip line both
 *   mention the recover option.
 * - If a clean, valid submission (correct EFF words, no duplicates) produces
 *   no InternalID match AND no PublicID collision, the user is offered the
 *   chance to register with those exact words.
 * - If a structurally valid recovery code is entered and decodes successfully
 *   but no account exists, the account is silently created (BBS rlogin path).
 *
 * @param {object}      dialogue
 * @param {object}      config
 * @param {string|null} prefilledUsername
 */
async function loginFlow(dialogue, config, prefilledUsername = null) {
  const { db, wordList, ipAddress, sessions } = config;

  let rawUsername = prefilledUsername;

  if (!rawUsername) {
    rawUsername = await dialogue.prompt('Enter your username: ');
  }

  if (!rawUsername || !isValidUsernameInput(rawUsername.trim())) {
    dialogue.send('Invalid username. Usernames must contain only letters and numbers.');
    return { success: false, reason: 'invalid_username' };
  }

  let failedAttempts = 0;

  while (failedAttempts < MAX_LOGIN_ATTEMPTS) {

    const showRecoverHint = failedAttempts >= RECOVER_REMINDER_AFTER;
    const promptSuffix    = showRecoverHint
      ? ' (or "recover" to use your recovery key)'
      : ' or "recover"';

    const codeInput = await dialogue.prompt(`Enter your code words${promptSuffix}: `);
    const trimmed   = codeInput.trim();

    // ── "recover" keyword ──────────────────────────────────────────────────
    if (trimmed.toLowerCase() === 'recover') {
      return recoveryFlow(dialogue, config, rawUsername.trim());
    }

    // ── Recovery code entered directly (XXXX-XXXX) ─────────────────────────
    if (looksLikeRecoveryCode(trimmed)) {
      if (ipAddress) {
        const rl = db.rateLimit(`login:${ipAddress}`, MAX_LOGIN_ATTEMPTS, 60);
        if (!rl.allowed) {
          dialogue.send('Too many login attempts. Please try again in a minute.');
          return { success: false, reason: 'rate_limited' };
        }
      }

      // Step 1: try full verify (code valid + account exists) → normal login
      const recovered = await tryDecodeAndVerifyRecovery(trimmed, rawUsername.trim(), config);

      if (recovered) {
        // Account exists — log in normally
        const token = sessions.create({
          username:   recovered.identity.displayName,
          publicId:   recovered.identity.publicId,
          internalId: recovered.identity.internalId,
        });
        dialogue.send('');
        dialogue.send(`Welcome back, ${recovered.identity.publicId}!`);
        dialogue.send('');
        return {
          success:  true,
          action:   'login',
          username: recovered.identity.displayName,
          publicId: recovered.identity.publicId,
          token,
        };
      }

      // Step 2: code is structurally/cryptographically valid but no account —
      // attempt silent BBS auto-registration (no words/key shown, no prompts)
      const decoded = await tryDecodeRecoveryNoDB(trimmed, rawUsername.trim(), config);

      if (decoded) {
        // Valid code, no account yet — silently register
        const rl = ipAddress
          ? db.rateLimit(`register:${ipAddress}`, 1, 60)
          : { allowed: true };

        if (!rl.allowed) {
          dialogue.send('Too many registration attempts. Please try again in a minute.');
          return { success: false, reason: 'rate_limited' };
        }

        // TOCTOU guard: check one more time right before write
        if (!db.publicIdExists(decoded.identity.internalId)) {
          db.register(decoded.identity.internalId, ipAddress || null);
        }
        // Whether we just registered or another concurrent request beat us,
        // the account now exists — issue a session
        const token = sessions.create({
          username:   decoded.identity.displayName,
          publicId:   decoded.identity.publicId,
          internalId: decoded.identity.internalId,
        });
        return {
          success:  true,
          action:   'register',
          username: decoded.identity.displayName,
          publicId: decoded.identity.publicId,
          token,
        };
      }

      // Code was bad format/range — treat as a failed attempt
      failedAttempts++;
      dialogue.send('');
      dialogue.send('Invalid identity. Contemplate the songs and pictures for your words and try again.');
      dialogue.send('');
      if (failedAttempts >= RECOVER_REMINDER_AFTER) {
        dialogue.send('  Tip: type "recover" to use your recovery key instead.');
        dialogue.send('');
      }
      continue;
    }

    // ── Three-word entry ───────────────────────────────────────────────────
    const codewords = extractCodewords(trimmed);

    // Wrong count — re-prompt without consuming an attempt
    if (codewords.length !== 3) {
      dialogue.send('Please enter exactly 3 code words separated by spaces.');
      continue;
    }

    // EFF dictionary validation — Levenshtein hints on typos, re-prompt without consuming
    const validation = wordList.validateThree(codewords);
    if (!validation.valid) {
      if (validation.duplicates) {
        dialogue.send('Code words must all be different.');
      } else {
        for (const err of validation.errors) {
          dialogue.send(
            err.suggestion
              ? `"${err.input}" is not a valid code word. Did you mean "${err.suggestion.toUpperCase()}"?`
              : `"${err.input}" is not a valid code word.`
          );
        }
      }
      continue;
    }

    // Consume one rate-limit slot per valid dictionary submission
    if (ipAddress) {
      const rl = db.rateLimit(`login:${ipAddress}`, MAX_LOGIN_ATTEMPTS, 60);
      if (!rl.allowed) {
        dialogue.send('Too many login attempts. Please try again in a minute.');
        return { success: false, reason: 'rate_limited' };
      }
    }

    // Derive identity
    let identity;
    try {
      identity = await deriveIdentity(
        rawUsername.trim(),
        validation.normalized,
        config.pepper,
        config.synthSalt,
        wordList
      );
    } catch (err) {
      dialogue.send('An internal error occurred. Please try again.');
      return { success: false, reason: 'internal_error' };
    }

    // ── Match found — log in ───────────────────────────────────────────────
    if (db.find(identity.internalId)) {
      const token = sessions.create({
        username:   identity.displayName,
        publicId:   identity.publicId,
        internalId: identity.internalId,
      });
      dialogue.send('');
      dialogue.send(`Welcome back, ${identity.publicId}!`);
      dialogue.send('');
      return {
        success:  true,
        action:   'login',
        username: identity.displayName,
        publicId: identity.publicId,
        token,
      };
    }

    // ── No InternalID match ────────────────────────────────────────────────
    // Offer to register when the derived identity is completely unknown:
    // no InternalID match AND no PublicID prefix collision.
    if (!db.publicIdExists(identity.internalId)) {
      dialogue.send('');
      dialogue.send('User not found. Create a new account? (yes or no)');
      const answer = await dialogue.prompt('> ');

      if (answer.trim().toLowerCase() === 'yes') {
        return registrationFlow(dialogue, config, {
          rawUsername:     rawUsername.trim(),
          chosenWords:     validation.normalized,
          derivedIdentity: identity,
        });
      }

      dialogue.send('');
      // Fall through to the normal failure path
    }

    // No match (or user declined registration)
    failedAttempts++;
    dialogue.send('');
    dialogue.send('Invalid identity. Contemplate the songs and pictures for your words and try again.');
    dialogue.send('');
    if (failedAttempts >= RECOVER_REMINDER_AFTER && failedAttempts < MAX_LOGIN_ATTEMPTS) {
      dialogue.send('  Tip: type "recover" to use your recovery key instead.');
      dialogue.send('');
    }
  }

  dialogue.send('Too many failed attempts. Please reconnect to try again.');
  return { success: false, reason: 'max_attempts' };
}

// ---------------------------------------------------------------------------
// Flow: Registration
// ---------------------------------------------------------------------------

/**
 * @param {object}  dialogue
 * @param {object}  config
 * @param {object}  [prefilled]  When called from loginFlow after "User not found":
 *                               { rawUsername, chosenWords, derivedIdentity }
 *                               The identity has already been derived and checked
 *                               for uniqueness; word generation is skipped.
 */
async function registrationFlow(dialogue, config, prefilled = null) {
  const { db, wordList, ipAddress, sessions } = config;

  // Rate-limit only applies to fresh registrations (not the login→register path,
  // which already consumed a login rate-limit slot).
  if (!prefilled && ipAddress) {
    const rl = db.rateLimit(`register:${ipAddress}`, 1, 60);
    if (!rl.allowed) {
      dialogue.send('Too many registration attempts. Please try again in a minute.');
      return { success: false, reason: 'rate_limited' };
    }
  }

  let identity;

  if (prefilled) {
    // Words and identity already chosen and verified by loginFlow —
    // no need to collect username or generate new words.
    identity = prefilled.derivedIdentity;
  } else {
    // Fresh registration path — collect username and generate words.
    const rawUsername = await dialogue.prompt('Enter your desired username: ');

    if (!rawUsername || !isValidUsernameInput(rawUsername.trim())) {
      dialogue.send('Invalid username. Use only letters and numbers (A-Z, a-z, 0-9).');
      return { success: false, reason: 'invalid_username' };
    }

    identity = null;
    for (let i = 0; i < 5; i++) {
      const candidate = await deriveIdentity(
        rawUsername.trim(),
        wordList.pickUnique(3),
        config.pepper,
        config.synthSalt,
        wordList
      );
      if (!db.publicIdExists(candidate.internalId)) { identity = candidate; break; }
    }

    if (!identity) {
      dialogue.send('');
      dialogue.send(`The username "${rawUsername.trim()}" is unavailable. Please try a different username.`);
      dialogue.send('');
      return { success: false, reason: 'username_unavailable' };
    }
  }

  const displayWords = identity.alphabetizedWords.map(w => w.toUpperCase());

  dialogue.send('');
  dialogue.send(`Your identity has been created. Others will see you as: ${identity.publicId}`);
  dialogue.send('It cannot be changed.');
  dialogue.send('');
  dialogue.send(`Your code words are: ${displayWords.join('  ')}`);
  dialogue.send(`Your recovery key is: ${identity.recoveryCode}`);
  dialogue.send('');
  dialogue.send("  - Don't lose your recovery key. It can be used instead of your code words.");
  dialogue.send('  - Remember your words. They can never be changed.');
  dialogue.send('');

  for (const line of madLibs(identity.displayName, identity.alphabetizedWords)) {
    dialogue.send(line);
  }
  dialogue.send('');

  // Muscle-memory confirmation.
  let confirmed    = false;
  let confirmAttempts = 0;

  while (!confirmed && confirmAttempts < MAX_CONFIRM_ATTEMPTS) {
    const confirmInput = await dialogue.prompt('Enter your code words to confirm registration: ');
    const confirmWords = extractCodewords(confirmInput.trim());

    if (confirmWords.length !== 3) {
      dialogue.send('Please enter all 3 code words.');
      confirmAttempts++;
      continue;
    }

    const sortedInput   = [...confirmWords].sort().join(',');
    const sortedCorrect = [...identity.alphabetizedWords].sort().join(',');

    if (sortedInput === sortedCorrect) {
      confirmed = true;
    } else {
      confirmAttempts++;
      dialogue.send('');
      dialogue.send('Those are not the words shown. Please check the words above and try again.');
      dialogue.send(`Your words are: ${displayWords.join('  ')}`);
      dialogue.send('');
    }
  }

  if (!confirmed) {
    dialogue.send('Registration cancelled. Your identity was not saved.');
    return { success: false, reason: 'confirmation_failed' };
  }

  // TOCTOU guard
  if (db.publicIdExists(identity.internalId)) {
    dialogue.send('');
    dialogue.send('Error: This identity was claimed by another session while you were confirming.');
    dialogue.send('Please restart and try a different username.');
    dialogue.send('');
    return { success: false, reason: 'username_unavailable' };
  }

  db.register(identity.internalId, ipAddress || null);

  const token = sessions.create({
    username:   identity.displayName,
    publicId:   identity.publicId,
    internalId: identity.internalId,
  });

  dialogue.send('');
  dialogue.send(`Identity confirmed. Welcome, ${identity.publicId}!`);
  dialogue.send('');

  return {
    success:  true,
    action:   'register',
    username: identity.displayName,
    publicId: identity.publicId,
    token,
  };
}

// ---------------------------------------------------------------------------
// Flow: Recovery
// ---------------------------------------------------------------------------

/**
 * Recovery flow.
 *
 * The code is validated AND identity existence verified BEFORE words are shown.
 * All failure cases return the same "Recovery code invalid." message.
 * Recovery codes are normalised to uppercase, so lowercase input is accepted.
 * Up to MAX_LOGIN_ATTEMPTS attempts are allowed (sharing the login rate-limit
 * bucket) — "Recovery code invalid." does not terminate the session.
 *
 * @param {object} dialogue
 * @param {object} config
 * @param {string} rawUsername
 */
async function recoveryFlow(dialogue, config, rawUsername) {
  const { db, wordList, sessions, ipAddress } = config;

  let attempts = 0;

  while (attempts < MAX_LOGIN_ATTEMPTS) {
    // Consume one rate-limit slot per attempt
    if (ipAddress) {
      const rl = db.rateLimit(`login:${ipAddress}`, MAX_LOGIN_ATTEMPTS, 60);
      if (!rl.allowed) {
        dialogue.send('Too many attempts. Please try again in a minute.');
        return { success: false, reason: 'rate_limited' };
      }
    }

    const codeInput = await dialogue.prompt('Enter your recovery key (XXXX-XXXX): ');

    // Validate format + existence before revealing anything.
    const recovered = await tryDecodeAndVerifyRecovery(
      codeInput.trim(),
      rawUsername,
      config
    );

    if (!recovered) {
      attempts++;
      dialogue.send('Recovery code invalid.');
      if (attempts < MAX_LOGIN_ATTEMPTS) {
        dialogue.send('');
        continue;
      }
      dialogue.send('Too many failed attempts. Please reconnect to try again.');
      return { success: false, reason: 'invalid_recovery_code' };
    }

    // ── Code accepted — show words ─────────────────────────────────────────
    const { recoveredWords, identity } = recovered;
    const displayWords = recoveredWords.map(w => w.toUpperCase());

    dialogue.send('');
    dialogue.send('Recovery accepted. Your code words are:');
    dialogue.send(`  ${displayWords.join('  ')}`);
    dialogue.send('');

    for (const line of madLibs(identity.displayName, identity.alphabetizedWords)) {
      dialogue.send(line);
    }
    dialogue.send('');

    // ── Muscle-memory re-entry ─────────────────────────────────────────────
    let confirmed    = false;
    let reAttempts   = 0;

    while (!confirmed && reAttempts < MAX_CONFIRM_ATTEMPTS) {
      const reInput = await dialogue.prompt('Enter your code words to proceed: ');
      const reWords = extractCodewords(reInput.trim());

      if (reWords.length !== 3) {
        dialogue.send('Please enter all 3 code words.');
        reAttempts++;
        continue;
      }

      const sortedInput   = [...reWords].sort().join(',');
      const sortedCorrect = [...recoveredWords].sort().join(',');

      if (sortedInput === sortedCorrect) {
        confirmed = true;
      } else {
        reAttempts++;
        dialogue.send('');
        dialogue.send('Those are not the words shown. Please check above and try again.');
        dialogue.send(`  ${displayWords.join('  ')}`);
        dialogue.send('');
      }
    }

    if (!confirmed) {
      dialogue.send('Recovery failed. Please reconnect to try again.');
      return { success: false, reason: 'recovery_failed' };
    }

    const token = sessions.create({
      username:   identity.displayName,
      publicId:   identity.publicId,
      internalId: identity.internalId,
    });

    dialogue.send('');
    dialogue.send(`Welcome back, ${identity.publicId}!`);
    dialogue.send('');

    return {
      success:  true,
      action:   'recover',
      username: identity.displayName,
      publicId: identity.publicId,
      token,
    };
  }

  return { success: false, reason: 'max_attempts' };
}

module.exports = { entryFlow, loginFlow, registrationFlow, recoveryFlow, madLibs };
