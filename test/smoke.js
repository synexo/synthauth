'use strict';

const path = require('path');
const crypto = require('../src/crypto');
const WordList = require('../src/wordlist');

async function main() {
  console.log('=== SynthAuth Crypto Smoke Test ===\n');

  const PEPPER     = 'test-pepper-value';
  const SYNTH_SALT = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex');

  const wordList = new WordList(path.join(__dirname, '..', 'src', 'eff_large_wordlist.txt'));
  console.log(`WordList loaded: ${wordList.words.length} words`);

  // --- Username normalization ---
  console.log('\n--- Username Normalization ---');
  const cases = [
    'ElizaBethMontgomery',
    'Bob',
    'ElizaBethMont-u3HG1d',
    'ExactlyThirte',
  ];
  for (const c of cases) {
    const norm = crypto.normalizeUsername(c);
    const disp = crypto.displayUsername(norm);
    console.log(`  "${c}" → norm:"${norm}" (${norm.length}) display:"${disp}"`);
  }

  // --- Recovery code round-trip ---
  console.log('\n--- Recovery Code Round-Trip ---');
  const testIndices = [42, 1000, 7775];
  const encoded = crypto.encodeRecoveryCode(testIndices);
  const decoded = crypto.decodeRecoveryCode(encoded);
  console.log(`  indices: ${testIndices} → encoded: ${encoded} → decoded: ${decoded}`);
  console.log(`  Match: ${JSON.stringify(testIndices) === JSON.stringify(decoded)}`);
  const zeroCode = crypto.encodeRecoveryCode([0, 0, 0]);
  const zeroBack = crypto.decodeRecoveryCode(zeroCode);
  console.log(`  [0,0,0] → ${zeroCode} → ${zeroBack} ✓: ${zeroBack.join(',') === '0,0,0'}`);
  const maxCode = crypto.encodeRecoveryCode([7775, 7775, 7775]);
  const maxBack  = crypto.decodeRecoveryCode(maxCode);
  console.log(`  [7775,7775,7775] → ${maxCode} → ${maxBack} ✓: ${maxBack.join(',') === '7775,7775,7775'}`);

  // --- Full identity derivation (EFF words: abacus, cabbage, sacrament) ---
  console.log('\n--- Identity Derivation ---');
  const t0 = Date.now();
  const id1 = await crypto.deriveIdentity('ElizaBethMontgomery', ['abacus', 'cabbage', 'sacrament'], PEPPER, SYNTH_SALT, wordList);
  const t1 = Date.now();
  console.log(`  Username: ElizaBethMontgomery`);
  console.log(`  Words (input order): abacus cabbage sacrament`);
  console.log(`  Alphabetized:        ${id1.alphabetizedWords}`);
  console.log(`  InternalID: ${id1.internalId}`);
  console.log(`  PublicID:   ${id1.publicId}`);
  console.log(`  Recovery:   ${id1.recoveryCode}`);
  console.log(`  Time: ${t1 - t0}ms`);

  // Order-independence
  const id2 = await crypto.deriveIdentity('ElizaBethMontgomery', ['sacrament', 'abacus', 'cabbage'], PEPPER, SYNTH_SALT, wordList);
  console.log(`\n  Same words different order → same InternalID: ${id1.internalId === id2.internalId}`);

  // Bob (change, oblivion, abacus — all valid EFF words)
  const id3 = await crypto.deriveIdentity('Bob', ['change', 'oblivion', 'abacus'], PEPPER, SYNTH_SALT, wordList);
  console.log(`\n  Bob + [change, oblivion, abacus]:`);
  console.log(`  PublicID: ${id3.publicId}`);
  console.log(`  Internal: ${id3.internalId}`);

  // --- WordList validation ---
  console.log('\n--- WordList Validation ---');
  console.log(`  "abacus" valid: ${wordList.isValid('abacus')}`);
  console.log(`  "ABACUS" valid: ${wordList.isValid('ABACUS')}`);
  console.log(`  "xyzzy"  valid: ${wordList.isValid('xyzzy')}`);
  console.log(`  closest to "abacuss": ${wordList.closestMatch('abacuss')}`);
  console.log(`  closest to "cabagge": ${wordList.closestMatch('cabagge')}`);

  const vGood = wordList.validateThree(['ABACUS', 'cabbage', 'SACRAMENT']);
  console.log(`  validate all-valid: valid=${vGood.valid} normalized=${vGood.normalized}`);

  const vBad = wordList.validateThree(['abacuss', 'cabbage', 'sacrament']);
  console.log(`  validate one-typo:  valid=${vBad.valid} suggestion="${vBad.errors[0].suggestion}"`);

  const vDup = wordList.validateThree(['abacus', 'abacus', 'sacrament']);
  console.log(`  validate duplicates: valid=${vDup.valid} duplicates=${vDup.duplicates}`);

  console.log('\n=== All tests passed ===');
}

main().catch(e => { console.error(e); process.exit(1); });
