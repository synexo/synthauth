'use strict';

const fs = require('fs');
const path = require('path');
const levenshtein = require('fast-levenshtein');

/**
 * WordList — loads the EFF Large Wordlist, exposes lookup, validation,
 * random selection, and Levenshtein "did you mean?" suggestions.
 *
 * The EFF list has exactly 7,776 entries (6^5), indexed 11111–66666.
 * We store them as a plain array (position 0–7775 = internal index)
 * and a Set for O(1) validation.
 */
class WordList {
  constructor(wordlistPath) {
    const filePath = wordlistPath || path.join(__dirname, 'eff_large_wordlist.txt');
    const raw = fs.readFileSync(filePath, 'utf8').trim().split('\n');

    /** @type {string[]} words[0..7775] */
    this.words = raw.map(line => line.split('\t')[1].trim().toLowerCase());

    /** @type {Set<string>} */
    this._set = new Set(this.words);

    if (this.words.length !== 7776) {
      throw new Error(`WordList: expected 7776 words, got ${this.words.length}`);
    }
  }

  /** Returns true if word is in the EFF list (case-insensitive). */
  isValid(word) {
    return this._set.has(word.toLowerCase());
  }

  /** Returns the 0-based index of word, or -1 if not found. */
  indexOf(word) {
    return this.words.indexOf(word.toLowerCase());
  }

  /** Returns the word at 0-based index. */
  atIndex(index) {
    return this.words[index];
  }

  /**
   * Pick `n` unique random words.
   * @param {number} n
   * @returns {string[]}
   */
  pickUnique(n) {
    const picked = new Set();
    while (picked.size < n) {
      picked.add(this.words[Math.floor(Math.random() * 7776)]);
    }
    return Array.from(picked);
  }

  /**
   * Given a word not in the list, find the closest valid word via
   * Levenshtein distance. Returns the best match (string).
   * Searches the full 7,776-word list; fast enough for interactive use.
   * @param {string} input
   * @returns {string}
   */
  closestMatch(input) {
    const lower = input.toLowerCase();
    let best = null;
    let bestDist = Infinity;

    for (const word of this.words) {
      const dist = levenshtein.get(lower, word);
      if (dist < bestDist) {
        bestDist = dist;
        best = word;
        if (dist === 1) break; // can't do better
      }
    }

    return best;
  }

  /**
   * Validate an array of 3 raw words (any case).
   * Returns { valid: true, normalized: [w1,w2,w3] } on success, or
   * { valid: false, errors: [{ input, suggestion }] }
   *
   * @param {string[]} rawWords  array of exactly 3 words
   */
  validateThree(rawWords) {
    const errors = [];
    const normalized = [];

    for (const raw of rawWords) {
      const lower = raw.toLowerCase();
      if (this.isValid(lower)) {
        normalized.push(lower);
      } else {
        errors.push({ input: raw, suggestion: this.closestMatch(lower) });
      }
    }

    // Also check for duplicates among valid words
    if (errors.length === 0) {
      const unique = new Set(normalized);
      if (unique.size !== 3) {
        return { valid: false, errors: [{ input: rawWords.join(' '), suggestion: null }], duplicates: true };
      }
    }

    if (errors.length > 0) {
      return { valid: false, errors };
    }

    return { valid: true, normalized };
  }
}

module.exports = WordList;
