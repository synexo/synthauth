'use strict';

const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');

/**
 * AuthDB — thin SQLite wrapper for the SynthAuth identity registry.
 *
 * Schema (single table):
 *   identities(internal_id TEXT PRIMARY KEY, created_at INTEGER, ip_address TEXT)
 *
 * PublicID is intentionally NOT stored — it is trivially derivable from InternalID.
 */
class AuthDB {
  /**
   * @param {string} [dbPath]  Path to SQLite file. Defaults to ./data/synth-auth.db
   */
  constructor(dbPath) {
    const resolved = dbPath || path.join(__dirname, '..', 'data', 'synth-auth.db');
    const dir = path.dirname(resolved);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    this.db = new Database(resolved);
    this._migrate();
  }

  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS identities (
        internal_id TEXT PRIMARY KEY,
        created_at  INTEGER NOT NULL,
        ip_address  TEXT
      );

      CREATE TABLE IF NOT EXISTS rate_limits (
        key        TEXT PRIMARY KEY,
        count      INTEGER NOT NULL DEFAULT 0,
        window_start INTEGER NOT NULL
      );
    `);
  }

  // ---------------------------------------------------------------------------
  // Identity registry
  // ---------------------------------------------------------------------------

  /**
   * Check if an exact InternalID already exists in the registry.
   *
   * NOTE: this is NOT used for registration collision safety. Two different
   * word sets can produce InternalIDs that share the same 6-char PublicID
   * suffix (same PublicID, different full keys). Use publicIdExists() for
   * all registration and uniqueness checks. This method is retained for
   * direct lookups and tooling use.
   *
   * @param {string} internalId
   * @returns {boolean}
   */
  exists(internalId) {
    const row = this.db
      .prepare('SELECT 1 FROM identities WHERE internal_id = ?')
      .get(internalId);
    return !!row;
  }

  /**
   * Insert a new identity into the registry.
   * @param {string}      internalId
   * @param {string|null} ipAddress
   * @returns {boolean}  true on success, false if already exists
   */
  register(internalId, ipAddress = null) {
    try {
      this.db
        .prepare('INSERT INTO identities (internal_id, created_at, ip_address) VALUES (?, ?, ?)')
        .run(internalId, Math.floor(Date.now() / 1000), ipAddress || null);
      return true;
    } catch (e) {
      if (e.code === 'SQLITE_CONSTRAINT_PRIMARYKEY') return false;
      throw e;
    }
  }

  /**
   * Look up an identity. Returns the full row or null.
   * @param {string} internalId
   * @returns {{ internal_id: string, created_at: number, ip_address: string|null }|null}
   */
  find(internalId) {
    return this.db
      .prepare('SELECT * FROM identities WHERE internal_id = ?')
      .get(internalId) || null;
  }

  /**
   * THE canonical collision guard for registration.
   *
   * Checks whether the PublicID derived from `internalId` is already claimed
   * by any registered identity. Must be used (not db.exists()) whenever
   * deciding whether a new identity is safe to register.
   *
   * Why this matters: Two distinct username+word combinations can produce
   * InternalIDs whose full Base62 suffixes differ but whose first 6 characters
   * are identical. Those two InternalIDs would be unique in the DB (no exact
   * collision) but would display the same PublicID to users. publicIdExists()
   * catches both cases by checking the 20-char prefix that encodes the full
   * PublicID: 13 username chars + "-" + 6 suffix chars.
   *
   * PublicID = DisplayUsername + "-" + Base62Suffix[0:6]
   * InternalID = NormalizedUsername + "-" + Base62Suffix
   * Shared PublicID ⟺ internalId[0:20] identical
   *
   * @param {string} internalId  candidate InternalID
   * @returns {boolean}
   */
  publicIdExists(internalId) {
    const prefix = internalId.slice(0, 20);
    const row = this.db
      .prepare("SELECT 1 FROM identities WHERE substr(internal_id, 1, 20) = ?")
      .get(prefix);
    return !!row;
  }

  /**
   * Check if any identity is registered under this normalized username.
   * InternalID always starts with NormalizedUsername + "-", so we can
   * check for any row whose internal_id begins with that prefix.
   *
   * Used to decide whether "User not found — register?" is appropriate:
   * we only offer it when the username itself has no account at all.
   *
   * @param {string} normalizedUsername  13-char padded form
   * @returns {boolean}
   */
  usernameExists(normalizedUsername) {
    const prefix = normalizedUsername + '-';
    const row = this.db
      .prepare("SELECT 1 FROM identities WHERE substr(internal_id, 1, ?) = ?")
      .get(prefix.length, prefix);
    return !!row;
  }

  // ---------------------------------------------------------------------------
  // Rate limiting  (sliding window, in-DB counter)
  // ---------------------------------------------------------------------------

  /**
   * Check and increment a rate-limit counter.
   *
   * @param {string} key          e.g. "login:1.2.3.4" or "register:1.2.3.4"
   * @param {number} maxCount     max allowed events in the window
   * @param {number} windowSecs   rolling window length in seconds
   * @returns {{ allowed: boolean, remaining: number }}
   */
  rateLimit(key, maxCount, windowSecs) {
    const now = Math.floor(Date.now() / 1000);

    const row = this.db
      .prepare('SELECT * FROM rate_limits WHERE key = ?')
      .get(key);

    if (!row || (now - row.window_start) >= windowSecs) {
      // New window
      this.db
        .prepare(`
          INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)
          ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start
        `)
        .run(key, now);
      return { allowed: true, remaining: maxCount - 1 };
    }

    if (row.count >= maxCount) {
      return { allowed: false, remaining: 0 };
    }

    this.db
      .prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?')
      .run(key);

    return { allowed: true, remaining: maxCount - row.count - 1 };
  }

  close() {
    this.db.close();
  }
}

module.exports = AuthDB;
