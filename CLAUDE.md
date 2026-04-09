# CLAUDE.md — SynthAuth Codebase Guide

This file describes the architecture, invariants, and conventions of the SynthAuth codebase for AI assistants working on it. Read this before touching any file.

---

## What This Project Is

SynthAuth is a **Deterministic Identity System (DIS)**. It derives cryptographic identities from a username and three EFF wordlist words using Argon2id. There is no password database and no stored hashes — the identity registry contains only the Argon2id output (InternalID). The same inputs always produce the same identity.

It also supports **BBS rlogin auto-registration**: a BBS can send a static recovery code as the rlogin system-id, which SynthAuth uses to silently create and recognize player identities with no user interaction.

---

## File Map

```
index.js          Public API — SynthAuth class. Wires all modules. Start here.
server.js         Express HTTP server + SSE bridge. Test/demo only.
src/crypto.js     All pure crypto. No side effects, no I/O, no DB.
src/flow.js       Auth flows. Transport-agnostic. Dialogue adapter pattern.
src/db.js         SQLite wrapper. Identity registry + rate limiting.
src/session.js    In-memory session store. HTTP tokens + TCP connection keys.
src/wordlist.js   EFF wordlist loader, O(1) validation, Levenshtein hints.
web/index.html    Self-contained browser UI. Talks to server.js via SSE.
test/smoke.js     Crypto unit tests. No DB, no network.
test/integration.js  Full flow tests. 31 assertions. Creates/destroys a temp DB.
```

---

## Core Invariants — Never Violate These

**1. Nothing sensitive is ever stored.**
The DB contains only `internal_id` (a 32-byte Argon2id output encoded in Base62), `created_at`, and `ip_address`. The three code words, the PEPPER, and the SYNTH_SALT are never written to disk by this codebase. PublicID is never stored either — it is derived from InternalID on demand.

**2. Words are always alphabetized before derivation.**
`deriveIdentity` sorts the input words before passing them to Argon2id. This makes word order irrelevant to the caller. Do not break this — changing sort order would invalidate every registered identity.

**3. Argon2id parameters must not change.**
`memoryCost: 65536`, `timeCost: 3`, `parallelism: 4`, `hashLength: 32`, `raw: true`. Changing any of these invalidates every registered identity. If you need to change them, you need a migration path.

**4. `publicIdExists()` is the canonical collision guard, not `exists()`.**
Two different word sets can produce InternalIDs that share the same 6-char PublicID prefix (same PublicID, different full keys). `db.publicIdExists(internalId)` checks the first 20 characters of InternalID (13 username chars + `-` + 6 suffix chars). Always use this before registration. Never use `db.exists()` for registration decisions.

**5. Error messages must not leak auth state.**
Failed login always returns the same message: `"Invalid identity. Contemplate the songs and pictures for your words and try again."` regardless of whether 0, 1, 2, or all 3 words were correct. The Levenshtein hint fires only on dictionary validation (pre-crypto), never on auth failure.

**6. BBS auto-registration must not disclose words.**
When a valid recovery code produces no existing account (the silent BBS path), the account is created and a session token returned with **zero dialogue output**. The words encoded in the BBS system code must never be shown to the connecting user, logged, or included in any API response. See the BBS section below.

**7. `decodeRecoveryCodeToWords` is pre-DB only.**
This function validates and decodes a recovery code without touching the database. It returns the decoded words and indices, or null. It exists specifically to support the two-stage check in `loginFlow`: first check if the account exists (`tryDecodeAndVerifyRecovery`), then — only if it doesn't — attempt silent registration (`tryDecodeRecoveryNoDB`). Do not skip the two-stage check.

---

## Identity Derivation Pipeline

```
rawUsername
  → normalizeUsername()         strip suffix, truncate to 13, pad with _ to 13
  → deriveUserSalt()            HMAC-SHA256(SYNTH_SALT, normalizedUsername)[0:16]

rawWords[]
  → lowercase + sort            alphabetical, always — order-independence
  → join with "-"

Argon2id(
  input:  normalizedUsername + ":" + sortedWords.join("-") + ":" + PEPPER,
  salt:   userSalt,
  memory: 65536 KiB,
  time:   3,
  par:    4,
  raw:    true, 32 bytes
) → masterKey (Buffer, 32 bytes)

base62Encode(masterKey) → suffix (variable length, typically ~43 chars)

internalId = normalizedUsername + "-" + suffix
publicId   = displayUsername(normalizedUsername) + "-" + suffix.slice(0, 6)
```

`displayUsername` strips trailing underscores from the 13-char normalized form.

---

## Recovery Code Format

```
indices = [i0, i1, i2]  where each i ∈ [0, 7775]  (EFF wordlist positions)
value   = i0 × 7776² + i1 × 7776 + i2
code    = CrockfordBase32(value, padded to 8 chars), formatted XXXX-XXXX
```

Crockford alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U).

An 8-char Crockford string holds 40 bits. The max valid triple value is 470,184,984,575 (~38.8 bits). The remaining ~57.2% of 8-char Crockford values are out-of-range and rejected. `generateRecoveryCode()` always produces in-range codes by drawing indices from `[0, 7776)` directly.

---

## Flow Architecture

Every flow (`entryFlow`, `loginFlow`, `registrationFlow`, `recoveryFlow`) takes:
- A **dialogue adapter**: `{ send(text): void, prompt(text): Promise<string> }`
- A **config object**: `{ pepper, synthSalt, db, wordList, sessions, ipAddress }`

The dialogue adapter is the only I/O interface. Flows never call `process.stdout`, never use Express, never touch sockets. This makes every flow testable with a simple script array (see `test/integration.js` — `makeDialogue`).

### Login flow decision tree

```
codeInput received
├── === "recover"          → recoveryFlow()
├── looksLikeRecoveryCode()
│   ├── consume login rate limit slot
│   ├── tryDecodeAndVerifyRecovery()
│   │   ├── success (account exists)   → issue session, Welcome back
│   │   └── null
│   │       ├── tryDecodeRecoveryNoDB()
│   │       │   ├── success (valid code, no account)
│   │       │   │   ├── consume register rate limit slot
│   │       │   │   ├── publicIdExists() guard
│   │       │   │   ├── db.register()
│   │       │   │   └── issue session, NO output  ← BBS silent path
│   │       │   └── null (bad format/range)
│   │       │       └── failedAttempts++, error message
│   │       └── (already handled above)
└── 3-word entry
    ├── wrong count        → re-prompt (no attempt consumed)
    ├── invalid words      → Levenshtein hint, re-prompt (no attempt consumed)
    ├── consume login rate limit slot
    ├── deriveIdentity()
    ├── db.find() hit      → issue session, Welcome back
    └── db.find() miss
        ├── !publicIdExists() → offer registration
        │   ├── "yes"       → registrationFlow(prefilled)
        │   └── "no"        → failedAttempts++, error message
        └── publicIdExists() (collision) → failedAttempts++, error message
```

### Rate limiting slots

| Event | Key | Limit |
|---|---|---|
| Login attempt (valid dict or recovery code) | `login:{ip}` | 5 per 60s |
| Registration (interactive or BBS silent) | `register:{ip}` | 1 per 60s |
| Recovery flow attempt | `login:{ip}` | 5 per 60s (shared with login) |

---

## BBS rlogin Integration

### What it does

When a structurally valid recovery code is entered at the code words prompt but no matching account exists in the DB, SynthAuth silently registers the account and returns a session token. No output is sent through the dialogue adapter. The caller receives `{ success: true, action: 'register', ... }`.

### Why words are never disclosed

The BBS system code encodes three EFF words. Those words, combined with the player's username, produce a unique identity. If a player knew those words, they could log in directly using them — bypassing the BBS entirely — and could also impersonate any other player of the same BBS whose username they know (since all players share the same system code). The silent path exists precisely to prevent word disclosure.

### The two-stage check

`tryDecodeAndVerifyRecovery` — validates the code AND checks the DB. Used first. Returns `{ recoveredWords, identity }` on full success, `null` on any failure. The recovery flow also uses this exclusively — it must never reveal words before confirming the account exists.

`tryDecodeRecoveryNoDB` — validates the code WITHOUT checking the DB. Used only in `loginFlow` as the second stage when `tryDecodeAndVerifyRecovery` returns null. Returns `{ words, identity }` if the code itself is cryptographically valid, `null` if the code is bad format or out-of-range.

The distinction matters: `tryDecodeAndVerifyRecovery` returning null could mean "bad code" OR "valid code, no account." `tryDecodeRecoveryNoDB` disambiguates: if it also returns null, the code itself is bad. If it returns a result, the code is valid and the account simply doesn't exist yet.

### TOCTOU guard

The silent registration path checks `db.publicIdExists()` immediately before `db.register()`. If a concurrent request races in between `tryDecodeRecoveryNoDB` and the write, `publicIdExists()` will return true and the write is skipped — but a session is still issued against the now-existing account. This is correct: both concurrent requests end up authenticated.

### `generateRecoveryCode()` / `auth.generateBBSCode()`

Generates a random valid BBS system code. Available as:
- `crypto.generateRecoveryCode()` — low-level, in `src/crypto.js`
- `auth.generateBBSCode()` — public API on the SynthAuth class
- `GET /api/generate-bbs-code` — HTTP endpoint in `server.js`
- "REQUEST NEW BBS CODE" button — in `web/index.html`

Each call produces an independent random code. Generate once per BBS; store securely.

---

## Adding Tests

Integration tests live in `test/integration.js`. Each test uses `makeDialogue(script)`:

```js
function makeDialogue(script) {
  const lines = [];
  let   idx   = 0;
  return {
    dialogue: {
      send(t)   { lines.push(t); },
      prompt(t) {
        lines.push(`[PROMPT] ${t}`);
        const entry = script[idx++];
        return Promise.resolve(typeof entry === 'function' ? entry(lines) : entry);
      },
    },
    lines,
  };
}
```

Script entries are strings (returned verbatim) or functions `(lines) => string` (inspect prior output to extract dynamic values like words or recovery codes). A function entry is useful when you need to echo back whatever the server generated.

For the BBS silent path, the dialogue receives no prompts after the code words prompt — the flow returns immediately. A minimal script for a BBS auto-registration test looks like:

```js
const { dialogue, lines } = makeDialogue([
  'BobFromBBS',     // username prompt
  'H8F3-9A2X',     // code words prompt — BBS system code
]);
const r = await auth.loginFlow(dialogue, '10.0.0.1');
assert(r.success && r.action === 'register', 'silent BBS registration');
assert(lines.filter(l => l && !l.startsWith('[PROMPT]')).length === 0,
  'no output lines during silent registration');
```

The second `loginFlow` call with the same username and code should return `action: 'login'`.

---

## Things That Are Easy to Get Wrong

**Do not call `db.exists()` for registration decisions.** Use `db.publicIdExists()`. The former only catches exact InternalID collisions; the latter catches same-PublicID collisions (different full key, same first 6 suffix chars).

**Do not add Levenshtein hints to the auth failure message.** The hint fires on dictionary validation only, before Argon2 is called. Once a word triple passes dictionary validation and Argon2 runs, the result is binary: match or no match. No hint is appropriate.

**Do not change Argon2 parameters.** See invariant #3 above. Even a one-byte change to the input string format (`":"` separator, word join character, PEPPER suffix) invalidates every identity.

**Do not sort words after validation.** `extractCodewords` lowercases and splits. `deriveIdentity` sorts internally. If you sort before passing to `deriveIdentity`, you sort twice, which is fine — but if you sort and then call a raw `deriveMasterKey`, you may produce an incorrect result if the sort order differs from what `deriveIdentity` would produce. Always go through `deriveIdentity`.

**Do not pass the raw recovery code string to `deriveIdentity`.** The code encodes word *indices*, not words directly. Decode it to words first (via `decodeRecoveryCodeToWords` or `decodeRecoveryCode` + `wordList.atIndex`), then pass those words to `deriveIdentity`.

**Async everywhere.** Argon2id takes 200–400ms per call. Any synchronous wrapper will block the Node.js event loop and stall all active connections. All flow functions are `async` for this reason. Do not add synchronous wrappers.

**The BBS silent path produces no dialogue output.** If you add any `dialogue.send()` calls to the silent registration branch in `loginFlow`, you break the rlogin integration. The entire point is zero output.

---

## HTTP API (server.js)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/start` | Begin a new auth flow. Returns `{ sessionId }`. |
| `GET` | `/api/stream/:sessionId` | SSE stream. Emits `line`, `prompt`, `done`, `error` events. |
| `POST` | `/api/respond/:sessionId` | Send user input `{ input }` to pending prompt. |
| `GET` | `/api/session` | Check current HTTP session via cookie/header. |
| `POST` | `/api/logout` | Destroy current session. |
| `GET` | `/api/generate-bbs-code` | Generate a random valid BBS system code. Returns `{ code }`. |

The SSE bridge exists purely to connect the browser UI to the transport-agnostic flow functions. `loginFlow` does not know it is running over HTTP — it only sees the dialogue adapter.

---

## Session Token Format

32 random bytes encoded as base64url (44 characters). No embedded claims. Session data lives entirely in the server-side `SessionStore._store` Map. Tokens are read from the `X-SynthAuth-Token` header or the `synthauth_token` cookie by the Express middleware.

The `internalId` field is present in `req.synthSession` (for internal server use) but stripped from `req.synthSessionSafe` and from `/api/session` responses. Never expose `internalId` to the browser.

---

## Wordlist

The EFF Large Wordlist has exactly 7,776 entries (6⁵). They are stored:
- As `wordList.words` — a plain array, index 0–7775
- As `wordList._set` — a `Set` for O(1) `isValid()` checks

The on-disk format is `DDDDD\tword\n` (5-digit dice roll, tab, word). Only the word portion is stored in memory. The dice rolls are discarded after loading.

---

## Coding Conventions

- `'use strict'` at the top of every file
- `const` everywhere; `let` only for loop counters and reassigned primitives
- Async functions return Promises; no callback-style code
- Error messages shown to users are final — no stack traces, no internal IDs
- All rate limit keys follow the pattern `"action:ipAddress"` (e.g. `"login:127.0.0.1"`)
- The `config` object is built once per flow call in `SynthAuth._config()` and passed down — never reconstructed mid-flow
