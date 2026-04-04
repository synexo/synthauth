# SynthAuth

**Deterministic Identity System (DIS)**

SynthAuth is a passwordless, zero-knowledge-storage identity module built for [SynthDoor](https://github.com/synthdoor) — a Node.js BBS door game framework — and designed to be used anywhere.

There is no password database. There are no stored hashes. An identity exists only as the cryptographic collision between a username and three words from the [EFF Large Wordlist](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases). If a user knows their words, they can authenticate from any machine, at any time, with no true account recovery infrastructure. If they lose their words, the identity is mathematically unreachable — by anyone.

```
Example account:
- User entered username: Synthdoor
- Generated public ID: Synthdoor-u7gM92
- Generated code words: AIDE BLESS SHERRY
```

## What This Is Good For

✅ **BBS door games, MUDs, ephemeral game sessions**  
Single-session accounts; account loss = reset character. No persistent user database needed. Online rate limiting prevents casual brute-force.

✅ **Video game save codes**  
"Glacier Banana Whiskey" instead of "A5FX9KL2Z". Deterministic, memorable, offline-verifiable. Modern alternative to classic game codes.

✅ **Anonymous forum posts or ephemeral chat**  
Throwaway accounts with no email/password reset infrastructure. Account expires after session or X days. Attacker takeover during window is acceptable (moderation handles spam).

### What This Is NOT Good For

❌ **Sensitive or high-value accounts** — If takeover causes financial loss, data exposure, or regulatory breach, use traditional auth + 2FA.

❌ **Persistent personal data** — Medical records, banking, government. DIS trades revocation for zero storage. Cannot force password changes or recover from compromise.

❌ **Systems requiring account revocation** — No way to invalidate a compromised identity without destroying the account entirely.

❌ **Enterprise or regulated systems** — No audit trails, SAML/OAuth, GDPR compliance, or account recovery infrastructure.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Auth Flows](#auth-flows)
- [UX Design](#ux-design)
- [SynthDoor Integration](#synthdoor-integration)
- [Security Reference](#security-reference)
- [Database Schema](#database-schema)
- [Configuration](#configuration)
- [Contributing](#contributing)
- [License](#license)

---

## How It Works

### Identity Derivation

Every identity is derived deterministically from two inputs the user provides and two secrets the server holds. Nothing else is ever stored.

```
Username input  ──► Normalize to 13 chars (truncate / pad with _)
                           │
                           ├──► HMAC-SHA256(key: SYNTH_SALT)
                           │          └──► UserSalt  (16 bytes, unique per user)
                           │
Three code words ──► Alphabetize ──► lowercase ──► join with "-"
                           │
                           └──► Argon2id(
                                    input:  NormalizedUsername + ":" +
                                            AlphabetizedWords  + ":" + PEPPER,
                                    salt:   UserSalt,
                                    memory: 65536 KiB (64 MB),
                                    time:   3 iterations,
                                    par:    4 lanes,
                                    raw:    true, 32 bytes
                                ) ──► MasterKey
                                           │
                                           ├──► Base62(MasterKey) = suffix
                                           │
                                           ├──► InternalID: NormalizedUsername + "-" + suffix
                                           │    (stored in DB — collision-proof)
                                           │
                                           └──► PublicID:   DisplayUsername + "-" + suffix[0:6]
                                                (never stored — trivially re-derived)
```

The three code words are **always alphabetized before processing**, so entry order never matters. `FLOOD CHANGE ROBOT` and `ROBOT FLOOD CHANGE` produce the same identity.

### Username Normalization

| Input | Normalized (internal) | Display |
|---|---|---|
| `ElizaBethMontgomery` | `ElizaBethMont` (truncated at 13) | `ElizaBethMont` |
| `Bob` | `Bob__________` (padded to 13) | `Bob` |
| `Bob-JJ3uui` | `Bob__________` (suffix stripped) | `Bob` |

Usernames are Base62 (A–Z, a–z, 0–9). Underscores are internal padding only and never shown to users. The system also accepts a full PublicID as login input and strips the suffix automatically — entering `Bob-JJ3uui` at the username prompt works identically to entering `Bob`.

### Recovery Codes

Three word indices (0–7775 each) are packed into a single integer and encoded as 8 characters of [Crockford's Base32](https://www.crockford.com/base32.html) (alphabet excludes I, L, O, U to prevent transcription errors), formatted `XXXX-XXXX`.

```
value = (idx₀ × 7776²) + (idx₁ × 7776) + idx₂
code  = CrockfordBase32(value, padded to 8 chars)
```

The recovery code is a **lossless, deterministic representation** of the three words. It decodes back to the exact triple. It is displayed once at registration and never stored.

---

## Quick Start

### Prerequisites

- Node.js LTS (v18 or later)
- npm

### Installation

```bash
git clone https://github.com/synthdoor/synth-auth.git
cd synth-auth
npm install
```

### Generate secrets and configure

```bash
# Copy the template
cp .env.example .env

# Generate cryptographically random secrets and append to .env
npm run generate-secrets >> .env

# Open .env and remove the placeholder lines,
# keeping only the freshly generated PEPPER and SYNTH_SALT values.
```

> ⚠️ **PEPPER and SYNTH_SALT are irreplaceable master secrets.** If either is lost or rotated, every registered identity becomes permanently inaccessible — there is no recovery path. Store them in a secrets manager and back them up offline before running in production.

### Run the test interface

```bash
npm start
# → http://localhost:3000
```

The web interface provides a retro BBS terminal UI for testing all auth flows — registration, login, and recovery — in a browser.

### Run the test suite

```bash
npm test                    # both suites
npm run test:unit           # crypto smoke tests only
npm run test:integration    # full flow tests (31 assertions)
```

---

## Architecture

```
synth-auth/
├── index.js                  ← SynthAuth class — public API entry point
├── server.js                 ← Express server + SSE dialogue bridge (test/web use)
├── src/
│   ├── crypto.js             ← All deterministic identity math
│   │                           (normalization, HMAC, Argon2id, Base62, Crockford B32)
│   ├── wordlist.js           ← EFF wordlist loader, validator, Levenshtein hints
│   ├── db.js                 ← SQLite identity registry + rate limiting
│   ├── session.js            ← In-memory session store (HTTP tokens + TCP handles)
│   ├── flow.js               ← Transport-agnostic auth flows (login/register/recover)
│   └── eff_large_wordlist.txt
├── web/
│   └── index.html            ← BBS terminal test UI (self-contained HTML/CSS/JS)
├── test/
│   ├── smoke.js              ← Crypto unit tests
│   └── integration.js        ← Full flow integration tests (31 assertions)
├── data/                     ← Auto-created at runtime; SQLite DB lives here
├── .env.example
├── .gitignore
└── package.json
```

### Module responsibilities

**`crypto.js`** — Pure functions with no side effects. Username normalization, HMAC-derived user salts, Argon2id key derivation, Base62 encoding, Crockford Base32 encode/decode, recovery code packing and unpacking. All deterministic; nothing is stored.

**`wordlist.js`** — Loads and indexes the EFF Large Wordlist (7,776 entries). O(1) validation via `Set`, sequential index lookup, `pickUnique` for random selection, and Levenshtein-based `closestMatch` for the "did you mean?" hint system.

**`db.js`** — Thin `better-sqlite3` wrapper. Manages the `identities` table (written once at registration, read-only thereafter) and a `rate_limits` table for per-IP throttling. PublicID is intentionally never written.

**`session.js`** — In-memory session store. Issues opaque 32-byte random tokens for HTTP use; provides Express middleware. Also supports connection-keyed sessions for TCP/telnet transports where a socket handle is the natural session key. Prunes expired sessions automatically.

**`flow.js`** — The three auth flows: `entryFlow`, `loginFlow`, `registrationFlow`, `recoveryFlow`. All I/O is abstracted through a **dialogue adapter** (`send` / `prompt`), making every flow transport-agnostic. The same code runs over telnet, SSE, WebSocket, or a test harness without modification.

**`index.js`** — The `SynthAuth` class. Wires all modules together, exposes the public API, and builds the config object passed to flow functions.

---

## API Reference

### Constructor

```js
const SynthAuth = require('./synth-auth');

const auth = new SynthAuth({
  pepper:       process.env.PEPPER,                         // required
  synthSalt:    Buffer.from(process.env.SYNTH_SALT, 'hex'), // required, ≥16 bytes
  dbPath:       './data/synth-auth.db',                     // optional
  wordlistPath: './src/eff_large_wordlist.txt',             // optional
  sessionTtl:   3600,                                       // optional, seconds
});
```

### Flow methods

All flow methods take a [dialogue adapter](#the-dialogue-adapter) as their first argument and an optional IP address string as their second.

#### `auth.entryFlow(dialogue, ipAddress?)`

Full entry point. Greets the user, asks for a username or `"new"`, and dispatches to login or registration. This is the method to call at the start of any new connection.

```js
const result = await auth.entryFlow(dialogue, socket.remoteAddress);
```

#### `auth.loginFlow(dialogue, ipAddress?, prefilledUsername?)`

Login only. Accepts a pre-known username (e.g. from a DORINFO1 file) to skip the username prompt.

```js
const result = await auth.loginFlow(dialogue, ip, 'KnownUser');
```

#### `auth.registrationFlow(dialogue, ipAddress?)`

Registration only. Generates three unique code words, presents the Mad-Lib mnemonics and recovery code, and requires the user to type the words back before committing to the registry.

#### `auth.recoveryFlow(dialogue, rawUsername, ipAddress?)`

Recovery only. Accepts a Crockford Base32 recovery code, decodes it to the three words, shows the Mad-Libs as a memory reinforcer, and requires physical re-entry before granting a session.

### Return value (all flows)

```js
// Success
{
  success:  true,
  action:   'login' | 'register' | 'recover',
  username: 'Bob',           // display username (no padding)
  publicId: 'Bob-JJ3uui',   // public-facing identity
  token:    '...',           // opaque session token (base64url, 44 chars)
}

// Failure
{
  success: false,
  reason:  'not_found'           |  // valid words, no matching identity
           'invalid_words'       |  // one or more words not in EFF list
           'wrong_word_count'    |  // not exactly 3 words entered
           'invalid_username'    |  // non-Base62 characters in username
           'username_unavailable'|  // 5 consecutive PublicID collisions
           'confirmation_failed' |  // muscle-memory re-entry failed 3 times
           'rate_limited'        |  // too many attempts from this IP
           'internal_error',        // Argon2 or other unexpected failure
}
```

### `auth.deriveIdentity(rawUsername, rawWords)`

Derive a full identity without touching the database. Useful for admin tools, migration scripts, or verification.

```js
const identity = await auth.deriveIdentity('Bob', ['flood', 'robot', 'change']);
// {
//   normalizedUsername: 'Bob__________',
//   displayName:        'Bob',
//   alphabetizedWords:  ['change', 'flood', 'robot'],
//   internalId:         'Bob__________-<base62>',
//   publicId:           'Bob-<6chars>',
//   recoveryCode:       'XXXX-XXXX',
// }
```

### `auth.sessions` — SessionStore

The session store is exposed directly for integrators who need to manage sessions outside the flow methods.

```js
// Create (flows do this automatically on success)
const token = auth.sessions.create({ username, publicId, internalId });

// Read — returns null if expired or not found
const data = auth.sessions.get(token);

// Extend TTL — call on each authenticated request
auth.sessions.touch(token);

// Destroy (logout)
auth.sessions.destroy(token);

// TCP connection-keyed sessions
auth.sessions.attachToConnection(connKey, { username, publicId, internalId });
auth.sessions.getByConnection(connKey);
auth.sessions.detachConnection(connKey);   // always call on disconnect
```

### `auth.sessions.expressMiddleware()`

Returns an Express middleware that attaches `req.synthSession` and `req.synthToken` to authenticated requests. Reads the token from the `X-SynthAuth-Token` header or the `synthauth_token` cookie.

```js
app.use(auth.sessions.expressMiddleware());

app.get('/profile', (req, res) => {
  if (!req.synthSession) return res.status(401).json({ error: 'unauthenticated' });
  res.json(req.synthSession);
  // → { username: 'Bob', publicId: 'Bob-JJ3uui', internalId: 'Bob__________-...' }
});
```

---

## Auth Flows

### The Dialogue Adapter

Every flow function takes a **dialogue adapter** as its first argument. This is a plain object with two methods that abstract all terminal I/O:

```js
const dialogue = {
  // Output a line of text (no response expected)
  send(text) {
    terminal.println(text);
  },

  // Display a prompt and return a Promise resolving to the user's trimmed input
  prompt(text) {
    return terminal.readLine({ echo: true, prompt: text });
  },
};
```

The same flow logic runs unchanged over any transport. You write a thin adapter for your environment — telnet, WebSocket, HTTP/SSE, test harness — and the flows handle the rest.

### Registration

```
Welcome to SynthDoor.

Enter your username or "new":  new
Enter your desired username:   Alice

  Your identity has been created. Others will see you as: Alice-r7Kx2M
  It cannot be changed.

  Your code words are:  CRABBING  ESTRANGED  SUBURB
  Your recovery key is: 2C6P-7VVJ

  - Save your recovery key. It is the only way to recover your words.
  - Remember your words. They can never be changed.

  • Alice writes songs about CRABBING, ESTRANGED, and SUBURB.
  • Alice paints pictures of CRABBING, ESTRANGED, and SUBURB.
  • Alice often contemplates CRABBING, ESTRANGED, and SUBURB.

Enter your code words to confirm registration:  crabbing estranged suburb

  Identity confirmed. Welcome, Alice-r7Kx2M!
```

Words are **generated by the server** — the user never chooses them. Three unique words are drawn from the EFF list, alphabetized, and shown alongside the Mad-Lib mnemonics. The user must type them back before the identity is committed to the registry.

If they fail three times, registration is cancelled and nothing is saved. If a PublicID suffix collision occurs, up to five different word sets are tried automatically. After five consecutive collisions the username is considered unavailable.

### Login

```
Enter your username or "new":           Alice
Enter your code words or "recover":     crabbing estranged suburb

  Welcome back, Alice-r7Kx2M!
```

Word order is ignored — the system alphabetizes before derivation. Entry is fully case-insensitive. If a word is not in the EFF dictionary, a Levenshtein suggestion is offered:

```
  "estrangd" is not a valid code word. Did you mean "estranged"?
```

The system never auto-corrects and never reveals whether any word in the set was correct. On a valid dictionary submission that produces no match, the message is always:

> *Invalid identity. Contemplate the songs and pictures for your words and try again.*

### Recovery

```
Enter your username or "new":          Alice
Enter your code words or "recover":    recover
Enter your 8-character recovery key:   2C6P-7VVJ

  Recovery accepted. Your code words are:
    CRABBING  ESTRANGED  SUBURB

  • Alice writes songs about CRABBING, ESTRANGED, and SUBURB.
  • Alice paints pictures of CRABBING, ESTRANGED, and SUBURB.
  • Alice often contemplates CRABBING, ESTRANGED, and SUBURB.

Enter your code words to proceed:      crabbing estranged suburb

  Welcome back, Alice-r7Kx2M!
```

The recovery code is decoded to the three words, which are displayed with the Mad-Lib phrases. The user must re-type the words — the same muscle-memory confirmation as registration — before a session is granted.

---

## UX Design

SynthAuth's UX is designed around the insight that the costliest moment in a wordlist-based auth system is **the moment the user forgets their words** — not the moment an attacker tries to break in. The cryptography handles the latter. The UX handles the former.

### Mad-Lib Mnemonics

At registration (and during recovery), the three words are embedded in three short narrative phrases tied to the user's own name:

```
• Alice writes songs about CRABBING, ESTRANGED, and SUBURB.
• Alice paints pictures of CRABBING, ESTRANGED, and SUBURB.
• Alice often contemplates CRABBING, ESTRANGED, and SUBURB.
```

The intentional weirdness of the combination — the *bizarreness effect* — makes the words memorable in a way a plain list never could. Users remember absurd mental images far better than abstract word sequences.

### Muscle-Memory Confirmation

During both registration and recovery, users cannot proceed until they physically type all three words. This is not validation theatre. Typing the words encodes them through kinesthetic memory in addition to visual memory. Users who have typed their words are measurably less likely to forget them.

### Blind Spellcheck

If a word is not in the EFF dictionary, the system offers a Levenshtein-distance suggestion without revealing anything about the auth state:

> *"cabagge" is not a valid code word. Did you mean "cabbage"?*

The system never auto-corrects. It helps users with genuine typos, but provides no information about whether any other word in the set was correct.

### Cryptic Error Theming

A valid dictionary submission that fails to match any identity always returns the same response, regardless of how many words were right:

> *Invalid identity. Contemplate the songs and pictures for your words and try again.*

The message refers back to the Mad-Lib mnemonics — encouraging the user to visualize their words rather than guess — without leaking any information about the input.

---

## SynthDoor Integration

SynthAuth ships as a standalone module. It is not yet wired into SynthDoor's core. The intended integration point is `game-router.js` or the transport layer.

### Connection routing

```js
// packages/server/src/game-router.js  (or transport handler)
const SynthAuth = require('../../synth-auth');

const auth = new SynthAuth({
  pepper:    process.env.PEPPER,
  synthSalt: Buffer.from(process.env.SYNTH_SALT, 'hex'),
});

async function handleNewConnection(connection) {
  // DORINFO1 present — trust the external BBS's authentication.
  if (connection.dorinfo) {
    connection.username = connection.dorinfo.username;
    return routeToGame(connection);
  }

  // No DORINFO1 — authenticate with SynthAuth.
  const dialogue = {
    send:   (text) => connection.terminal.println(text),
    prompt: (text) => connection.terminal.readLine({ prompt: text }),
  };

  const result = await auth.entryFlow(dialogue, connection.remoteAddress);

  if (!result.success) {
    connection.terminal.println('Authentication failed. Goodbye.');
    return connection.close();
  }

  connection.username = result.username;
  connection.publicId = result.publicId;

  auth.sessions.attachToConnection(connection.id, {
    username:   result.username,
    publicId:   result.publicId,
    internalId: result.internalId,
  });

  routeToGame(connection);
}

async function handleDisconnect(connection) {
  auth.sessions.detachConnection(connection.id);
}
```

### Future expansion

The dialogue adapter and session store design anticipates a full BBS shell where a user logs in once and moves freely between games and applications. The session token from `entryFlow` can be carried by any component that needs to know who the user is — a chat system, a mail module, a game — without re-authentication.

---

## Security Reference

### ⚠️ Critical Limitations

**Do not use SynthAuth for high-value or sensitive accounts.** This system has intentional cryptographic limits:

- **36-bit entropy**: Three random words from a 7,776-word list provide ~36 bits of entropy. This is **weaker than a 9-character password**. Online brute-force is rate-limited and impractical, but offline brute-force (if PEPPER is compromised) is feasible on GPU clusters.

- **No revocation or password change**: Once issued, codewords cannot be changed. A compromised account cannot be recovered by forcing a password reset. The only mitigation is account destruction and re-registration.

- **PEPPER compromise = total loss**: If the PEPPER secret is leaked, all accounts are instantly compromisable. There is no rotation path without invalidating every account. This is not a bug; it's the irreversible trade-off for storing zero secrets.

**This is acceptable for**:
- Session-based accounts (BBS games, ephemeral chat, throwaway forums)
- Single-use or short-lived identities (game save codes, license keys)
- Peer-to-peer verification where secrets are never stored server-side

**This is not acceptable for**:
- Banking, medical, government, or any regulated sector
- Long-lived accounts with persistent data
- Systems where account compromise causes real financial or personal harm
- Anything requiring GDPR, HIPAA, SOC2, or similar compliance

### Threat model

| Threat | Mitigation |
|---|---|
| Database breach | Only `InternalID` (a derived value) is stored. Words are never stored in any form. A database dump is useless without PEPPER and SYNTH_SALT. |
| Offline brute-force of words (no PEPPER) | Argon2id at 64 MB / 3 iterations: ~200–400 ms per attempt. The EFF list has 7,776³ ≈ 470 billion possible word triples. Exhaustive search would require approximately 5,000 CPU-years per target. |
| Preimage attack on InternalID | InternalID contains a full Base62-encoded 32-byte Argon2id output. No feasible preimage attack exists. |
| Online brute-force / stuffing | 5 failed login attempts per IP per minute. 1 registration per IP per minute. |
| Levenshtein hint leaking state | The hint fires only on *dictionary validation*, before any cryptographic operation. It confirms only that an input word was absent from the EFF list — not that any other word was correct. |
| Recovery code interception | A recovery code encodes the three words. It carries the same sensitivity. Display it once; never store it. |
| Error message oracle | All failed auth attempts return the same message regardless of how many words were correct. |

### Cryptographic parameters

| Parameter | Value | Rationale |
|---|---|---|
| KDF | Argon2id | Resistant to GPU and side-channel attacks. The `id` variant provides both data-dependent and data-independent memory access patterns. |
| Memory cost | 65,536 KiB (64 MB) | Impractical to run in parallel on commodity hardware at scale. |
| Time cost | 3 iterations | Balances security with acceptable interactive latency. |
| Parallelism | 4 lanes | Increases memory bandwidth requirements for parallel attacks. |
| Salt derivation | HMAC-SHA256(SYNTH_SALT, username) | Unique per user without storage. Cannot be precomputed without SYNTH_SALT. |
| Suffix encoding | Base62 (0–9, A–Z, a–z) | Dense, unambiguous printable encoding of the 32-byte master key. |
| Recovery encoding | Crockford Base32 | Human-transcription-safe. Excludes I, L, O, U. Dash-formatted for readability. |

### Core Limitations

| Limit | Impact |
|-------|--------|
| **36-bit entropy** | Three random words from 7,776 options ≈ 36 bits. Weaker than a 9-character password. Online brute-force is rate-limited and impractical; offline brute-force (if PEPPER leaks) is feasible on GPU clusters. |
| **No password changes** | Codewords cannot be changed once issued. A compromised account has no recovery path except deletion. |
| **PEPPER loss = total loss** | If the PEPPER secret is lost or corrupted, every account becomes permanently inaccessible. There is no recovery and no rotation path. |
| **PEPPER compromise = total compromise** | If PEPPER is leaked, all accounts are instantly compromisable. Attacker can impersonate any user without brute-force. There is no safe rotation. |

### Fail States

**Database breach (PEPPER and SYNTH_SALT remain secret)**  
🟢 **Safe.** InternalID is a derived hash. Attacker learns only usernames, timestamps, registration IPs. Cannot impersonate without PEPPER or brute-forcing.

**PEPPER or SYNTH_SALT is lost**  
🔴 **Catastrophic.** Every account becomes permanently inaccessible. No recovery path. No rotation. Total user-base loss.

**PEPPER or SYNTH_SALT is compromised**  
🔴 **Total compromise.** Attacker can instantly derive and impersonate any account. No rotation is safe without invalidating all accounts. Assume all users compromised.

**User's recovery code is leaked**  
🟡 **Medium risk.** Recovery code is password-equivalent (losslessly reversible to codewords). Leaked RC = attacker can impersonate for duration of session. For ephemeral games, acceptable. For persistent accounts, treat as compromise.

**User's codewords are guessed or phished**  
🔴 **Account loss.** Attacker can log in. No audit trail. No forced logout or password change mechanism exists. For ephemeral games (session expires in hours), acceptable risk. For persistent accounts, educate users: treat codewords like passwords.

### Online Attack Resistance (Assuming PEPPER Remains Secret)

| Threat | Assessment |
|--------|-----------|
| Brute-force your account | Low ✅ — Rate limit (5 failures/min/IP) + 64MB Argon2 + 36 bits entropy = ~200ms per attempt. Infeasible at scale. |
| Brute-force across many accounts | Low ✅ — Same per-IP rate limiting applies. Distributed attacks still face Argon2 latency. |
| Database leak | Safe ✅ — Hashes without PEPPER are useless. Usernames/dates only. |
| Intercept codewords on plaintext telnet | Exposed ❌ — Use TLS/SSH, not plaintext telnet. Transport problem, not DIS problem. |


## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by emailing the maintainers directly (see repository contact information). Include as much detail as you can:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations, if you have them

## Cryptographic Design Notes

Reviewers should be aware of the following intentional design decisions:

- **No secrets are stored.** The identity registry contains only `InternalID` values (Argon2id outputs). The three code words and the PEPPER/SYNTH_SALT secrets are never written to disk by this module.
- **PEPPER and SYNTH_SALT are deployment secrets.** Their loss is catastrophic and irreversible by design — this is the trade-off for zero stored secrets.
- **The Levenshtein hint is pre-derivation.** It fires on dictionary validation only, before any cryptographic operation, and cannot be used to probe the identity state.


### Operational notes

- **PEPPER and SYNTH_SALT must never be co-located with the database.** Use a secrets manager or separate infrastructure.
- **Argon2id derivation must stay asynchronous.** Each call blocks the thread for 200–400 ms. In SynthDoor's multi-player telnet environment, synchronous derivation would stall all active connections during auth. All flow functions are `async` for this reason.
- **Sessions are in-memory.** A process restart clears all active sessions. For high-availability deployments, back the session store with Redis or a database.
- **Rate limit counters are per-process.** The SQLite rate limiter is correct for single-process deployments. Clustered deployments should use a shared store.

---

## Database Schema

```sql
-- Identity registry.
-- Written once at registration. Never updated. Read-only thereafter.
CREATE TABLE identities (
  internal_id  TEXT     PRIMARY KEY,  -- NormalizedUsername-Base62(MasterKey)
  created_at   INTEGER  NOT NULL,     -- Unix timestamp (seconds)
  ip_address   TEXT                   -- IP at registration time, or NULL
);

-- Per-IP rate limiting counters (sliding window).
CREATE TABLE rate_limits (
  key           TEXT     PRIMARY KEY,  -- e.g. "login:1.2.3.4"
  count         INTEGER  NOT NULL DEFAULT 0,
  window_start  INTEGER  NOT NULL      -- Unix timestamp of current window start
);
```

PublicID is **never stored**. It is derived on demand from InternalID by trimming trailing underscores from the username portion and taking the first 6 characters of the Base62 suffix.

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for a full annotated template.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PEPPER` | Yes | — | Fixed pepper included in every Argon2 derivation. 32+ random bytes recommended. |
| `SYNTH_SALT` | Yes | — | Hex-encoded HMAC key for user salt derivation. 64 hex chars (32 bytes) recommended. |
| `PORT` | No | `3000` | HTTP port for the test server. |
| `SESSION_TTL` | No | `3600` | Session lifetime in seconds. |
| `DB_PATH` | No | `./data/synth-auth.db` | Path to SQLite database file. |

Generate production-grade values:

```bash
node -e "
  const c = require('crypto');
  console.log('PEPPER='     + c.randomBytes(32).toString('hex'));
  console.log('SYNTH_SALT=' + c.randomBytes(32).toString('hex'));
"
```

Or use the npm shorthand:

```bash
npm run generate-secrets
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for anything beyond small fixes.

### Development setup

```bash
git clone https://github.com/synthdoor/synth-auth.git
cd synth-auth
npm install
cp .env.example .env
npm run generate-secrets >> .env   # edit .env to keep only the new lines
npm test
```

### Before submitting a PR

- All tests must pass: `npm test`
- New behaviour should have coverage in `test/integration.js`
- Do not commit `.env`, `data/`, or `node_modules/`

---

## License

[MIT](LICENSE)
