'use strict';

const crypto = require('crypto');

/**
 * SessionStore — lightweight in-memory session store.
 *
 * Issues opaque signed tokens. Designed for use with Express (see
 * SynthAuth.expressMiddleware()), but has no framework dependency.
 *
 * For production use, swap _store for a Redis or DB-backed store.
 * The token format: base64url(random 32 bytes) — no embedded claims.
 * Session data lives server-side only.
 *
 * Also provides a TCP session attachment helper used by the telnet/rlogin
 * path: sessions are keyed by connection handle rather than a cookie token.
 */
class SessionStore {
  /**
   * @param {object} [opts]
   * @param {number}  [opts.ttlSeconds=3600]  Session TTL in seconds (default 1 hour)
   */
  constructor(opts = {}) {
    this.ttlSeconds = opts.ttlSeconds || 3600;
    /** @type {Map<string, { data: object, expiresAt: number }>} */
    this._store = new Map();

    // Prune expired sessions every 5 minutes
    this._pruneInterval = setInterval(() => this._prune(), 5 * 60 * 1000);
    this._pruneInterval.unref(); // don't prevent Node exit
  }

  // ---------------------------------------------------------------------------
  // Token-based sessions (HTTP / Express)
  // ---------------------------------------------------------------------------

  /**
   * Create a new session, returning an opaque token.
   * @param {object} data  Session payload (e.g. { username, internalId, publicId })
   * @returns {string}     Opaque session token
   */
  create(data) {
    const token     = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Math.floor(Date.now() / 1000) + this.ttlSeconds;
    this._store.set(token, { data: { ...data }, expiresAt });
    return token;
  }

  /**
   * Retrieve session data for a token. Returns null if expired or not found.
   * @param {string} token
   * @returns {object|null}
   */
  get(token) {
    const entry = this._store.get(token);
    if (!entry) return null;
    if (Math.floor(Date.now() / 1000) > entry.expiresAt) {
      this._store.delete(token);
      return null;
    }
    return entry.data;
  }

  /**
   * Extend session TTL (call on each authenticated request).
   * @param {string} token
   * @returns {boolean}
   */
  touch(token) {
    const entry = this._store.get(token);
    if (!entry) return false;
    entry.expiresAt = Math.floor(Date.now() / 1000) + this.ttlSeconds;
    return true;
  }

  /**
   * Destroy a session (logout).
   * @param {string} token
   */
  destroy(token) {
    this._store.delete(token);
  }

  // ---------------------------------------------------------------------------
  // Connection-keyed sessions (TCP / telnet / rlogin)
  // The "key" is any unique handle — e.g. socket.remoteAddress + port,
  // or a connection ID assigned by the transport layer.
  // ---------------------------------------------------------------------------

  /**
   * Attach session data to a connection handle.
   * @param {string} connectionKey
   * @param {object} data
   */
  attachToConnection(connectionKey, data) {
    const expiresAt = Math.floor(Date.now() / 1000) + this.ttlSeconds;
    this._store.set(`conn:${connectionKey}`, { data: { ...data }, expiresAt });
  }

  /**
   * Retrieve session data for a connection handle.
   * @param {string} connectionKey
   * @returns {object|null}
   */
  getByConnection(connectionKey) {
    return this.get(`conn:${connectionKey}`);
  }

  /**
   * Remove session for a connection (on disconnect).
   * @param {string} connectionKey
   */
  detachConnection(connectionKey) {
    this._store.delete(`conn:${connectionKey}`);
  }

  // ---------------------------------------------------------------------------
  // Express middleware
  // ---------------------------------------------------------------------------

  /**
   * Returns an Express middleware that:
   *  - Reads a session token from the `X-SynthAuth-Token` header OR
   *    a `synthauth_token` cookie.
   *  - Attaches `req.synthSession` (data object) if valid.
   *  - Attaches `req.synthToken` (token string) for downstream use.
   *
   * Usage:
   *   app.use(synthAuth.sessionMiddleware());
   *   app.get('/profile', (req, res) => {
   *     if (!req.synthSession) return res.status(401).json({ error: 'Not authenticated' });
   *     res.json(req.synthSession);
   *   });
   */
  expressMiddleware() {
    const store = this;
    return function synthAuthSession(req, _res, next) {
      let token = req.headers['x-synthauth-token'];
      if (!token && req.cookies) {
        token = req.cookies['synthauth_token'];
      }

      if (token) {
        const data = store.get(token);
        if (data) {
          store.touch(token);
        
          // 1. Keep the full data for internal server use
          req.synthSession = data; 
        
          // 2. Create a "safe" version for JSON responses
          const { internalId, ...safe } = data;
          req.synthSessionSafe = safe;
        
          req.synthToken = token;
        }
      }
      next();
    };
  }

  _prune() {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, entry] of this._store) {
      if (now > entry.expiresAt) this._store.delete(key);
    }
  }

  destroy_all() {
    clearInterval(this._pruneInterval);
    this._store.clear();
  }
}

module.exports = SessionStore;
