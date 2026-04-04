'use strict';

const path      = require('path');
const fs        = require('fs');
const SynthAuth = require('../index');

const TEST_DB = path.join(__dirname, 'test-integration.db');
if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

const auth = new SynthAuth({
  pepper:      'integration-test-pepper',
  synthSalt:   Buffer.from('aabbccddeeff00112233445566778899', 'hex'),
  dbPath:      TEST_DB,
  wordlistPath: path.join(__dirname, '..', 'src', 'eff_large_wordlist.txt'),
});

const wordList = auth.wordList;
const USERNAME = 'TestUser42';

let passed = 0;
let failed = 0;

function assert(cond, label) {
  if (cond) { console.log(`  ✓ ${label}`); passed++; }
  else       { console.error(`  ✗ ${label}`); failed++; }
}

function makeDialogue(script) {
  const lines = [];
  let   idx   = 0;
  return {
    dialogue: {
      send(t)   { lines.push(t); },
      prompt(t) {
        lines.push(`[PROMPT] ${t}`);
        const entry = script[idx++];
        if (entry === undefined) throw new Error(`Script exhausted at: "${t}"`);
        return Promise.resolve(typeof entry === 'function' ? entry(lines) : entry);
      },
    },
    lines,
  };
}

const getWordLine     = lines => lines.find(l => l && l.startsWith('Your code words are:'));
const getRecoveryLine = lines => lines.find(l => l && l.startsWith('Your recovery key is:'));
const extractWords    = lines => getWordLine(lines).replace('Your code words are:', '').trim().split(/\s+/).filter(Boolean).map(w => w.toLowerCase());
const extractRecovery = lines => getRecoveryLine(lines).replace('Your recovery key is:', '').trim();

async function run() {
  console.log('=== SynthAuth Integration Tests ===\n');

  let REG_WORDS    = null;
  let REG_PUBLICID = null;
  let REG_RECOVERY = null;

  // ── 1. Registration ───────────────────────────────────────────────────────
  console.log('[ 1 ] Registration');
  {
    const { dialogue, lines } = makeDialogue([
      'new', USERNAME,
      (sent) => extractWords(sent).join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.1');
    REG_WORDS    = extractWords(lines);
    REG_PUBLICID = r.publicId;
    REG_RECOVERY = extractRecovery(lines);

    assert(r.success && r.action === 'register',               'registers');
    assert(r.username === USERNAME,                            'display username correct');
    assert(r.publicId.split('-')[1].length === 6,             'publicId suffix 6 chars');
    assert(typeof r.token === 'string',                       'token issued');
    assert(lines.some(l => l.includes("Don't lose")),         'new recovery key message shown');
    assert(!lines.some(l => l.includes('only way to recover')),'old message absent');
  }

  // ── 2. Login — correct words ──────────────────────────────────────────────
  console.log('\n[ 2 ] Login — correct words');
  {
    const { dialogue } = makeDialogue([USERNAME, REG_WORDS.join(' ')]);
    const r = await auth.loginFlow(dialogue, '127.0.0.1');
    assert(r.success && r.action === 'login', 'login succeeds');
  }

  // ── 3. Login — wrong then correct (retry loop) ────────────────────────────
  console.log('\n[ 3 ] Login — wrong attempt, then correct');
  {
    const wrong = wordList.pickUnique(3);
    const { dialogue } = makeDialogue([USERNAME, wrong.join(' '), 'no', REG_WORDS.join(' ')]);
    const r = await auth.loginFlow(dialogue, '127.0.0.2');
    assert(r.success, 'succeeds after one failure');
  }

  // ── 4. Login — typo hint, no attempt consumed ─────────────────────────────
  console.log('\n[ 4 ] Login — typo hint then correct');
  {
    const typo = REG_WORDS[0] + 'zz';
    const { dialogue, lines } = makeDialogue([
      USERNAME,
      [typo, REG_WORDS[1], REG_WORDS[2]].join(' '),
      REG_WORDS.join(' '),
    ]);
    const r = await auth.loginFlow(dialogue, '127.0.0.3');
    assert(r.success,                                 'succeeds after typo');
    assert(lines.some(l => l.includes('Did you mean')), 'Levenshtein hint shown');
  }

  // ── 5. Login — recover reminder after 3 failures ─────────────────────────
  console.log('\n[ 5 ] Login — recover reminder after 3 failures');
  {
    const wrong = wordList.pickUnique(3);
    const { dialogue, lines } = makeDialogue([
      USERNAME,
      wrong.join(' '), 'no',
      wrong.join(' '), 'no',
      wrong.join(' '), 'no',
      REG_WORDS.join(' '),
    ]);
    const r = await auth.loginFlow(dialogue, '127.0.0.4');
    assert(r.success,                              'succeeds after 3 failures');
    assert(lines.some(l => l.includes('recover')), 'recover reminder shown');
  }

  // ── 6. Login — "recover" keyword redirects ────────────────────────────────
  console.log('\n[ 6 ] Login — "recover" keyword');
  {
    const { dialogue } = makeDialogue([
      USERNAME, 'recover', REG_RECOVERY, REG_WORDS.join(' '),
    ]);
    const r = await auth.loginFlow(dialogue, '127.0.0.5');
    assert(r.success && r.action === 'recover', 'recovery via keyword works');
  }

  // ── 7. Login — recovery code as direct password ───────────────────────────
  console.log('\n[ 7 ] Login — recovery code as direct password');
  {
    const { dialogue } = makeDialogue([USERNAME, REG_RECOVERY]);
    const r = await auth.loginFlow(dialogue, '127.0.0.6');
    assert(r.success && r.action === 'login', 'recovery code accepted as password');
  }

  // ── 8. Login — lowercase recovery code normalised ────────────────────────
  console.log('\n[ 8 ] Login — lowercase recovery code normalised to uppercase');
  {
    const { dialogue } = makeDialogue([USERNAME, REG_RECOVERY.toLowerCase()]);
    const r = await auth.loginFlow(dialogue, '127.0.0.6b');
    assert(r.success, 'lowercase recovery code accepted');
  }

  // ── 9. Login — wrong recovery code, retry, then correct words ────────────
  console.log('\n[ 9 ] Login — wrong recovery code then correct words');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME,
      '0000-0000',          // bad code
      REG_WORDS.join(' '),  // correct on next attempt
    ]);
    const r = await auth.loginFlow(dialogue, '127.0.0.7');
    assert(r.success,                                    'succeeds after bad recovery code');
    assert(lines.some(l => l.includes('Contemplate')),   'failure message shown for bad code');
  }

  // ── 10. Login — word order independence ──────────────────────────────────
  console.log('\n[ 10 ] Login — reversed word order');
  {
    const { dialogue } = makeDialogue([USERNAME, [...REG_WORDS].reverse().join(' ')]);
    const r = await auth.loginFlow(dialogue, '127.0.0.8');
    assert(r.success, 'succeeds with reversed words');
  }

  // ── 11. Login — uppercase words ──────────────────────────────────────────
  console.log('\n[ 11 ] Login — uppercase words');
  {
    const { dialogue } = makeDialogue([USERNAME, REG_WORDS.map(w => w.toUpperCase()).join(' ')]);
    const r = await auth.loginFlow(dialogue, '127.0.0.9');
    assert(r.success, 'succeeds with uppercase words');
  }

  // ── 12. "User not found" → register with chosen words ────────────────────
  console.log('\n[ 12 ] Login — unrecognised clean submission → offer to register');
  {
    const freshWords = wordList.pickUnique(3);
    const { dialogue, lines } = makeDialogue([
      'NewUserXYZ99',
      freshWords.join(' '),   // clean EFF words, no account yet
      'yes',                  // accept registration offer
      (sent) => extractWords(sent).join(' '), // confirm the words shown
    ]);
    const r = await auth.entryFlow(dialogue, '127.1.0.1');

    assert(r.success && r.action === 'register',              'registers via login prompt');
    assert(lines.some(l => l.includes('User not found')),     '"User not found" prompt shown');
    assert(lines.some(l => l.includes('has been created')),   'identity creation message shown');
    assert(lines.some(l => l.includes("Don't lose")),         'recovery key message shown');
  }

  // ── 13. "User not found" → decline ───────────────────────────────────────
  console.log('\n[ 13 ] Login — unrecognised words → decline registration offer');
  {
    const freshWords = wordList.pickUnique(3);
    // After declining, the loop continues. Feed enough wrong attempts to exhaust.
    const { dialogue, lines } = makeDialogue([
      'AnotherUser22',
      freshWords.join(' '), 'no',         // 1st attempt: unknown user, decline offer
      wordList.pickUnique(3).join(' '),    // 2nd: wrong (AnotherUser22 still unknown)
      'no',                               // decline again
      wordList.pickUnique(3).join(' '),    // 3rd
      'no',
      wordList.pickUnique(3).join(' '),    // 4th
      'no',
      wordList.pickUnique(3).join(' '),    // 5th — exhausts MAX_LOGIN_ATTEMPTS
      'no',
    ]);
    const r = await auth.entryFlow(dialogue, '127.1.0.3');
    assert(!r.success,                                          'fails after declining');
    assert(lines.some(l => l.includes('User not found')),       'offer was shown');
    assert(lines.filter(l => l.includes('User not found')).length >= 1, 'offer appeared at least once');
  }

  // ── 14. Recovery — malformed code ("3") rejected, retry allowed ──────────
  console.log('\n[ 14 ] Recovery — malformed code rejected, retry succeeds');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME, 'recover',
      '3',              // malformed — rejected
      REG_RECOVERY,     // correct on second try
      REG_WORDS.join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.10');
    assert(r.success && r.action === 'recover',                'recovery succeeds after bad code');
    assert(lines.some(l => l.includes('Recovery code invalid')), 'invalid message shown');
    // Words must never appear before "Recovery accepted".
    // "Recovery accepted. Your code words are:" is a single line, so we check
    // there is no standalone "Your code words are:" line before the accepted line.
    const acceptedIdx  = lines.findIndex(l => l.includes('Recovery accepted'));
    const earlyWords   = lines.slice(0, Math.max(0, acceptedIdx)).some(l =>
      l.includes('Your code words are') && !l.includes('Recovery accepted')
    );
    assert(acceptedIdx !== -1 && !earlyWords,                   'words not shown before valid code');
  }

  // ── 15. Recovery — valid format, non-existent identity, retry allowed ─────
  console.log('\n[ 15 ] Recovery — unknown identity rejected, retry succeeds');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME, 'recover',
      '0000-0000',       // structurally valid, wrong identity
      REG_RECOVERY,
      REG_WORDS.join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.11');
    assert(r.success,                                          'recovery succeeds after wrong code');
    assert(lines.some(l => l.includes('Recovery code invalid')),'generic error for wrong identity');
  }

  // ── 16. Recovery — lowercase code normalised ─────────────────────────────
  console.log('\n[ 16 ] Recovery — lowercase code accepted');
  {
    const { dialogue } = makeDialogue([
      USERNAME, 'recover',
      REG_RECOVERY.toLowerCase(),
      REG_WORDS.join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.12');
    assert(r.success, 'lowercase recovery code accepted in recoveryFlow');
  }

  // ── 17. Recovery — single EFF word rejected ───────────────────────────────
  console.log('\n[ 17 ] Recovery — single word rejected');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME, 'recover',
      REG_WORDS[0],    // one word — doesn't match XXXX-XXXX
      REG_RECOVERY,
      REG_WORDS.join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.13');
    assert(r.success,                                           'succeeds after single-word bad input');
    assert(lines.some(l => l.includes('Recovery code invalid')), 'generic error shown');
  }

  // ── 18. Recovery — full happy path ───────────────────────────────────────
  console.log('\n[ 18 ] Recovery — full happy path');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME, 'recover', REG_RECOVERY, REG_WORDS.join(' '),
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.14');
    assert(r.success && r.action === 'recover',             'recovery succeeds');
    assert(lines.some(l => l.includes('Recovery accepted')), 'accepted message shown');
    assert(lines.some(l => l.includes('writes songs')),      'Mad-Libs shown');
  }

  // ── 19. Recovery re-entry — no Levenshtein, plain message ────────────────
  console.log('\n[ 19 ] Recovery re-entry — plain mismatch, no Levenshtein');
  {
    const { dialogue, lines } = makeDialogue([
      USERNAME, 'recover', REG_RECOVERY,
      wordList.pickUnique(3).join(' '),  // wrong at re-entry
      REG_WORDS.join(' '),               // correct
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.15');
    assert(r.success,                                        'succeeds after wrong re-entry');
    assert(lines.some(l => l.includes('not the words shown')), 'plain message shown');
    assert(!lines.some(l => l.includes('Did you mean')),     'no Levenshtein at re-entry');
  }

  // ── 20. Registration confirm — no Levenshtein ────────────────────────────
  console.log('\n[ 20 ] Registration confirm — plain mismatch, no Levenshtein');
  {
    const { dialogue, lines } = makeDialogue([
      'new', 'ConfirmTest2',
      (sent) => wordList.pickUnique(3).join(' '),  // wrong first confirm
      (sent) => extractWords(sent).join(' '),       // correct second
    ]);
    const r = await auth.entryFlow(dialogue, '127.0.0.16');
    assert(r.success,                                        'registers after wrong first confirm');
    assert(lines.some(l => l.includes('not the words shown')), 'plain mismatch message');
    assert(!lines.some(l => l.includes('Did you mean')),     'no Levenshtein at confirm');
  }

  // ── 21. Username normalization ────────────────────────────────────────────
  console.log('\n[ 21 ] Username normalization');
  {
    const a = await auth.deriveIdentity('ElizaBethMontgomery', REG_WORDS);
    const b = await auth.deriveIdentity('ElizaBethMont',       REG_WORDS);
    assert(a.internalId === b.internalId, 'truncation produces same identity');
    const c = await auth.deriveIdentity(REG_PUBLICID, REG_WORDS);
    assert(c.internalId === (await auth.deriveIdentity(USERNAME, REG_WORDS)).internalId,
      'PublicID as username strips suffix');
  }

  // ── 22. Recovery code round-trip ─────────────────────────────────────────
  console.log('\n[ 22 ] Recovery code round-trip');
  {
    const d       = await auth.deriveIdentity(USERNAME, REG_WORDS);
    const decoded = auth.crypto.decodeRecoveryCode(d.recoveryCode);
    const back    = decoded.map(i => wordList.atIndex(i));
    assert(back.join(',') === d.alphabetizedWords.join(','), 'decodes back to original words');
    assert(d.recoveryCode === REG_RECOVERY, 'matches code shown at registration');
  }

  // ── 23. DB: publicIdExists — the canonical collision guard ──────────────
  console.log('\n[ 23 ] DB.publicIdExists — collision guard');
  {
    const d    = await auth.deriveIdentity(USERNAME, REG_WORDS);
    const fake = 'AAAAAAAAAAAAA-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ';
    assert(auth.db.publicIdExists(d.internalId),  'publicIdExists true for registered identity');
    assert(!auth.db.publicIdExists(fake),          'publicIdExists false for unknown prefix');

    // Prove that db.exists() alone would MISS a PublicID collision.
    // Synthetic InternalID: same 20-char PublicID prefix, different full suffix.
    // Same PublicID — different InternalID. publicIdExists catches it; exists does not.
    const collisionId = d.internalId.slice(0, 20) + 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    assert(!auth.db.exists(collisionId),           'db.exists() misses PublicID collision (expected blind spot)');
    assert(auth.db.publicIdExists(collisionId),    'db.publicIdExists() catches the same collision');
  }

  // ── 24. Session lifecycle ─────────────────────────────────────────────────
  console.log('\n[ 24 ] Session lifecycle');
  {
    const t = auth.sessions.create({ username: 'x', publicId: 'x-000000', internalId: 'x' });
    assert(auth.sessions.get(t) !== null, 'session retrievable');
    auth.sessions.destroy(t);
    assert(auth.sessions.get(t) === null, 'session destroyed');
  }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log(`\n${'─'.repeat(44)}`);
  console.log(`  Passed: ${passed}  |  Failed: ${failed}`);
  if (failed === 0) console.log('  ✓ All integration tests passed.\n');
  else { console.log('  ✗ Some tests failed.\n'); process.exitCode = 1; }

  auth.db.close();
  if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
}

run().catch(e => { console.error('\nFatal:', e); process.exit(1); });
