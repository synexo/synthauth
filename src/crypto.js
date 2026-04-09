'use strict';

const crypto = require('crypto');
const argon2 = require('argon2');

// ---------------------------------------------------------------------------
// Base62 encoding  (0-9 A-Z a-z)
// Used for the identity suffix portion of InternalID / PublicID.
// ---------------------------------------------------------------------------
const BASE62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const BASE62_VALID = /^[0-9A-Za-z]+$/;

/**
 * Encode a Buffer to a Base62 string.
 * Treats the buffer as a big-endian unsigned integer.
 * @param {Buffer} buf
 * @returns {string}
 */
function base62Encode(buf) {
  // Convert buffer to BigInt
  let n = BigInt('0x' + buf.toString('hex'));
  if (n === 0n) return '0';
  let result = '';
  while (n > 0n) {
    result = BASE62_CHARS[Number(n % 62n)] + result;
    n = n / 62n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Crockford's Base32 encoding
// Alphabet: 0-9 A-H J-N P-Z  (excludes I L O U)
// Used for human-friendly recovery codes.
// ---------------------------------------------------------------------------
const CROCKFORD_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * Encode a BigInt to Crockford Base32, zero-padded to `length` characters.
 * @param {bigint} n
 * @param {number} length  total output length (pad with leading zeros)
 * @returns {string}
 */
function crockfordEncode(n, length = 8) {
  if (n < 0n) throw new Error('crockfordEncode: negative value');
  let result = '';
  while (n > 0n) {
    result = CROCKFORD_CHARS[Number(n % 32n)] + result;
    n = n / 32n;
  }
  result = result || '0';
  while (result.length < length) result = '0' + result;
  return result;
}

/**
 * Decode a Crockford Base32 string (with optional dash) to BigInt.
 * Case-insensitive; I→1, L→1, O→0 (Crockford substitutions).
 * @param {string} str
 * @returns {bigint}
 */
function crockfordDecode(str) {
  const clean = str.replace(/-/g, '').toUpperCase()
    .replace(/I/g, '1')
    .replace(/L/g, '1')
    .replace(/O/g, '0');

  let n = 0n;
  for (const ch of clean) {
    const idx = CROCKFORD_CHARS.indexOf(ch);
    if (idx === -1) throw new Error(`crockfordDecode: invalid character '${ch}'`);
    n = n * 32n + BigInt(idx);
  }
  return n;
}

// ---------------------------------------------------------------------------
// Username normalization
// ---------------------------------------------------------------------------

/**
 * Validate that a username candidate contains only Base62 characters.
 * Accepts PublicID format (strips suffix at first hyphen).
 * @param {string} input
 * @returns {boolean}
 */
function isValidUsernameInput(input) {
  // Strip public-ID suffix if present
  const stripped = input.split('-')[0];
  return BASE62_VALID.test(stripped) && stripped.length > 0;
}

/**
 * Normalize a username to its internal 13-char padded form.
 *  - Strip everything from first hyphen onward (handles PublicID input)
 *  - Truncate to 13 Base62 characters
 *  - Right-pad with underscores to exactly 13 characters
 *
 * @param {string} input  raw username or PublicID
 * @returns {string}  exactly 13 characters
 */
function normalizeUsername(input) {
  // Strip public-ID suffix
  let base = input.split('-')[0];
  // Truncate
  base = base.substring(0, 13);
  // Pad
  return base.padEnd(13, '_');
}

/**
 * Return the display form of a normalized username (trim trailing underscores).
 * @param {string} normalized  13-char internal username
 * @returns {string}
 */
function displayUsername(normalized) {
  return normalized.replace(/_+$/, '');
}

// ---------------------------------------------------------------------------
// Core cryptographic identity derivation
// ---------------------------------------------------------------------------

/**
 * Derive the per-user salt deterministically via HMAC-SHA256.
 * UserSalt = HMAC-SHA256(key: SYNTH_SALT, msg: normalizedUsername).slice(0, 16)
 *
 * @param {string} normalizedUsername  13-char padded username
 * @param {Buffer} synthSalt           SYNTH_SALT from env (min 16 bytes)
 * @returns {Buffer}  16 bytes
 */
function deriveUserSalt(normalizedUsername, synthSalt) {
  return crypto
    .createHmac('sha256', synthSalt)
    .update(normalizedUsername, 'utf8')
    .digest()
    .slice(0, 16);
}

/**
 * Derive the Argon2id master key.
 *
 * Input string: normalizedUsername + ":" + sortedLowercaseWords + ":" + PEPPER
 * Salt: UserSalt (16 bytes)
 *
 * @param {string} normalizedUsername
 * @param {string[]} alphabetizedWords  already sorted, lowercase, 3 words
 * @param {string} pepper               PEPPER from env
 * @param {Buffer} userSalt             16-byte salt
 * @returns {Promise<Buffer>}           raw 32-byte master key
 */
async function deriveMasterKey(normalizedUsername, alphabetizedWords, pepper, userSalt) {
  const inputStr = `${normalizedUsername}:${alphabetizedWords.join('-')}:${pepper}`;

  return argon2.hash(inputStr, {
    type:        argon2.argon2id,
    memoryCost:  65536,
    timeCost:    3,
    parallelism: 4,
    salt:        userSalt,
    raw:         true,
    hashLength:  32,
  });
}

/**
 * Build InternalID and PublicID from a normalized username and master key.
 *
 * InternalID: normalizedUsername + "-" + base62(masterKey)
 * PublicID:   displayUsername    + "-" + base62(masterKey).substring(0, 6)
 *
 * @param {string} normalizedUsername
 * @param {Buffer} masterKey  32-byte raw key
 * @returns {{ internalId: string, publicId: string }}
 */
function buildIdentity(normalizedUsername, masterKey) {
  const b62 = base62Encode(masterKey);
  const internalId = `${normalizedUsername}-${b62}`;
  const publicId   = `${displayUsername(normalizedUsername)}-${b62.substring(0, 6)}`;
  return { internalId, publicId };
}

// ---------------------------------------------------------------------------
// Recovery code (Crockford Base32 of word-index integer)
// ---------------------------------------------------------------------------

/**
 * Encode 3 word indices (0–7775 each) into an 8-char Crockford Base32 string,
 * formatted as XXXX-XXXX.
 *
 * Value = (idx0 * 7776²) + (idx1 * 7776) + idx2
 *
 * @param {number[]} indices  [i0, i1, i2] for alphabetized words
 * @returns {string}  e.g. "H8F3-9A2X"
 */
function encodeRecoveryCode(indices) {
  const [i0, i1, i2] = indices;
  const n = BigInt(i0) * 7776n * 7776n + BigInt(i1) * 7776n + BigInt(i2);
  const encoded = crockfordEncode(n, 8);
  return `${encoded.slice(0, 4)}-${encoded.slice(4)}`;
}

/**
 * Decode an 8-char Crockford Base32 recovery code (with or without dash)
 * back into 3 word indices.
 *
 * @param {string} code  e.g. "H8F3-9A2X"
 * @returns {number[]}  [i0, i1, i2]
 */
function decodeRecoveryCode(code) {
  const n = crockfordDecode(code);
  const i2 = Number(n % 7776n);
  const i1 = Number((n / 7776n) % 7776n);
  const i0 = Number(n / (7776n * 7776n));
  return [i0, i1, i2];
}

/**
 * Generate a cryptographically random valid recovery code.
 * Picks 3 unique random word indices (0–7775), packs them, and encodes
 * as Crockford Base32. Every code produced is guaranteed to decode back
 * to a valid word triple.
 *
 * @returns {string}  e.g. "H8F3-9A2X"
 */
function generateRecoveryCode() {
  const indices = [];
  while (indices.length < 3) {
    const idx = crypto.randomInt(0, 7776);
    if (!indices.includes(idx)) indices.push(idx);
  }
  return encodeRecoveryCode(indices);
}

/**
 * Attempt to decode a recovery code string to word indices + words, without
 * any database interaction. Returns null if the code is structurally invalid,
 * fails Crockford decode, or produces out-of-range indices.
 *
 * This is the pre-DB step used to distinguish "bad format/range" from
 * "valid code but no account" — the latter is used for silent BBS
 * auto-registration.
 *
 * @param {string}   rawCode
 * @param {WordList} wordList
 * @returns {{ indices: number[], words: string[] } | null}
 */
function decodeRecoveryCodeToWords(rawCode, wordList) {
  const RECOVERY_CODE_RE = /^[0-9A-Za-z]{4}-?[0-9A-Za-z]{4}$/;
  if (!RECOVERY_CODE_RE.test(rawCode.trim())) return null;

  const normalized = rawCode.trim().replace(/-/g, '').toUpperCase();

  let indices;
  try {
    indices = decodeRecoveryCode(normalized);
  } catch (e) {
    return null;
  }

  if (indices.some(i => i < 0 || i > 7775)) return null;

  const words = indices.map(i => wordList.atIndex(i));
  return { indices, words };
}

// ---------------------------------------------------------------------------
// High-level identity creation helper (called by flow.js)
// ---------------------------------------------------------------------------

/**
 * Given a raw username + 3 raw words, derive all identity components.
 *
 * Words are sorted alphabetically before all operations so order never matters.
 *
 * @param {string}   rawUsername
 * @param {string[]} rawWords        3 validated lowercase EFF words (any order)
 * @param {string}   pepper          PEPPER env var
 * @param {Buffer}   synthSalt       SYNTH_SALT env var (Buffer)
 * @param {WordList} wordList        WordList instance for index lookup
 * @returns {Promise<IdentityResult>}
 */
async function deriveIdentity(rawUsername, rawWords, pepper, synthSalt, wordList) {
  const normalized       = normalizeUsername(rawUsername);
  const alphabetized     = [...rawWords].map(w => w.toLowerCase()).sort();
  const userSalt         = deriveUserSalt(normalized, synthSalt);
  const masterKey        = await deriveMasterKey(normalized, alphabetized, pepper, userSalt);
  const { internalId, publicId } = buildIdentity(normalized, masterKey);

  const indices     = alphabetized.map(w => wordList.indexOf(w));
  const recoveryCode = encodeRecoveryCode(indices);

  return {
    normalizedUsername: normalized,
    displayName:        displayUsername(normalized),
    alphabetizedWords:  alphabetized,
    internalId,
    publicId,
    recoveryCode,
  };
}

module.exports = {
  normalizeUsername,
  displayUsername,
  isValidUsernameInput,
  deriveUserSalt,
  deriveMasterKey,
  buildIdentity,
  base62Encode,
  crockfordEncode,
  crockfordDecode,
  encodeRecoveryCode,
  decodeRecoveryCode,
  decodeRecoveryCodeToWords,
  generateRecoveryCode,
  deriveIdentity,
};
