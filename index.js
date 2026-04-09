'use strict';

/**
 * SynthAuth — Deterministic Identity System (DIS)
 *
 * Usage:
 *
 *   const SynthAuth = require('./packages/synth-auth');
 *   require('dotenv').config();
 *
 *   const auth = new SynthAuth({
 *     pepper:    process.env.PEPPER,
 *     synthSalt: Buffer.from(process.env.SYNTH_SALT, 'hex'),
 *     dbPath:    './data/synth-auth.db',          // optional
 *     wordlistPath: './src/eff_large_wordlist.txt', // optional
 *   });
 *
 *   // In an Express app:
 *   app.use(auth.sessions.expressMiddleware());
 *
 *   // In a telnet handler:
 *   const result = await auth.entryFlow(dialogue, ipAddress);
 *   if (result.success) {
 *     connection.username = result.username;
 *     connection.token    = result.token;
 *   }
 *
 *   // Generate a BBS system code (for rlogin auto-registration):
 *   const bbsCode = auth.generateBBSCode();
 */

const path         = require('path');
const WordList     = require('./src/wordlist');
const AuthDB       = require('./src/db');
const SessionStore = require('./src/session');
const { entryFlow, loginFlow, registrationFlow, recoveryFlow } = require('./src/flow');
const crypto       = require('./src/crypto');

class SynthAuth {
  /**
   * @param {object} opts
   * @param {string}  opts.pepper          PEPPER secret (required)
   * @param {Buffer}  opts.synthSalt       SYNTH_SALT secret as Buffer (required, min 16 bytes)
   * @param {string}  [opts.dbPath]        Path to SQLite file
   * @param {string}  [opts.wordlistPath]  Path to EFF wordlist
   * @param {number}  [opts.sessionTtl]    Session TTL in seconds (default 3600)
   */
  constructor(opts = {}) {
    if (!opts.pepper)    throw new Error('SynthAuth: opts.pepper is required');
    if (!opts.synthSalt) throw new Error('SynthAuth: opts.synthSalt is required');
    if (!Buffer.isBuffer(opts.synthSalt) || opts.synthSalt.length < 16) {
      throw new Error('SynthAuth: opts.synthSalt must be a Buffer of at least 16 bytes');
    }

    this._pepper    = opts.pepper;
    this._synthSalt = opts.synthSalt;

    this.wordList = new WordList(opts.wordlistPath);
    this.db       = new AuthDB(opts.dbPath);
    this.sessions = new SessionStore({ ttlSeconds: opts.sessionTtl || 3600 });

    // Expose lower-level modules for integrators who need direct access
    this.crypto = crypto;
  }

  /**
   * Build the config object passed to all flow functions.
   * @param {string|null} ipAddress
   * @returns {object}
   */
  _config(ipAddress = null) {
    return {
      pepper:    this._pepper,
      synthSalt: this._synthSalt,
      db:        this.db,
      wordList:  this.wordList,
      sessions:  this.sessions,
      ipAddress,
    };
  }

  // ---------------------------------------------------------------------------
  // High-level flow methods
  // ---------------------------------------------------------------------------

  /**
   * Full entry flow: greets user, asks for username or "new", dispatches to
   * login or registration accordingly.
   *
   * @param {object}      dialogue    { send(text), prompt(text): Promise<string> }
   * @param {string|null} ipAddress
   * @returns {Promise<AuthResult>}
   */
  async entryFlow(dialogue, ipAddress = null) {
    return entryFlow(dialogue, this._config(ipAddress));
  }

  /**
   * Login flow only (useful when username is already known, e.g. from DORINFO1).
   *
   * For rlogin BBS integration: pass the BBS username as prefilledUsername and
   * have the transport layer supply the BBS system code at the code words prompt.
   * If the system code decodes to a valid word triple but no account exists yet,
   * the account is silently created and a session token returned — no prompts
   * or word disclosure.
   *
   * @param {object}      dialogue
   * @param {string|null} ipAddress
   * @param {string}      [prefilledUsername]
   * @returns {Promise<AuthResult>}
   */
  async loginFlow(dialogue, ipAddress = null, prefilledUsername = null) {
    return loginFlow(dialogue, this._config(ipAddress), prefilledUsername);
  }

  /**
   * Registration flow only.
   *
   * @param {object}      dialogue
   * @param {string|null} ipAddress
   * @returns {Promise<AuthResult>}
   */
  async registrationFlow(dialogue, ipAddress = null) {
    return registrationFlow(dialogue, this._config(ipAddress));
  }

  /**
   * Recovery flow only.
   *
   * @param {object}      dialogue
   * @param {string}      rawUsername
   * @param {string|null} ipAddress
   * @returns {Promise<AuthResult>}
   */
  async recoveryFlow(dialogue, rawUsername, ipAddress = null) {
    return recoveryFlow(dialogue, this._config(ipAddress), rawUsername);
  }

  // ---------------------------------------------------------------------------
  // Direct identity derivation (for integrators / admin tools)
  // ---------------------------------------------------------------------------

  /**
   * Derive a full identity from username + codewords without touching the DB.
   * Useful for verification, migration, admin tools.
   *
   * @param {string}   rawUsername
   * @param {string[]} rawWords  3 EFF words (any order, any case)
   * @returns {Promise<object>}
   */
  async deriveIdentity(rawUsername, rawWords) {
    return crypto.deriveIdentity(rawUsername, rawWords, this._pepper, this._synthSalt, this.wordList);
  }

  // ---------------------------------------------------------------------------
  // BBS integration helpers
  // ---------------------------------------------------------------------------

  /**
   * Generate a cryptographically random valid BBS system code.
   *
   * The returned code is a standard Crockford Base32 recovery code (XXXX-XXXX)
   * that maps to a unique word triple. Use it as the static system-id value
   * sent via rlogin. All users connecting from that BBS will share this code;
   * combined with their username it deterministically creates (or looks up)
   * their per-user identity.
   *
   * Generate once per BBS system and store it securely — treat it like a
   * password. A different code produces a completely separate identity space.
   *
   * @returns {string}  e.g. "H8F3-9A2X"
   */
  generateBBSCode() {
    return crypto.generateRecoveryCode();
  }
}

module.exports = SynthAuth;

/**
 * @typedef {object} AuthResult
 * @property {boolean} success
 * @property {string}  [action]    'login' | 'register' | 'recover'
 * @property {string}  [username]  Display username
 * @property {string}  [publicId]  Public-facing ID (e.g. "Bob-JJ3uui")
 * @property {string}  [token]     Session token
 * @property {string}  [reason]    Failure reason if !success
 */
