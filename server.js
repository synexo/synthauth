'use strict';

require('dotenv').config();

const express    = require('express');
const path       = require('path');
const crypto     = require('crypto');
const SynthAuth  = require('./index');
const { generateRecoveryCode } = require('./src/crypto');

// ---------------------------------------------------------------------------
// Secrets — load from .env, fall back to safe dev defaults with a warning
// ---------------------------------------------------------------------------
let PEPPER     = process.env.PEPPER;
let SYNTH_SALT_HEX = process.env.SYNTH_SALT;

if (!PEPPER || !SYNTH_SALT_HEX) {
  console.warn('\n⚠  WARNING: PEPPER / SYNTH_SALT not set in .env — using insecure dev defaults.');
  console.warn('   Never use this in production. See .env.example\n');
  PEPPER         = 'dev-pepper-CHANGE-ME';
  SYNTH_SALT_HEX = '000102030405060708090a0b0c0d0e0f';
}

const SYNTH_SALT = Buffer.from(SYNTH_SALT_HEX, 'hex');

const auth = new SynthAuth({
  pepper:    PEPPER,
  synthSalt: SYNTH_SALT,
  dbPath:    path.join(__dirname, 'data', 'synth-auth.db'),
  wordlistPath: path.join(__dirname, 'src', 'eff_large_wordlist.txt'),
});

// ---------------------------------------------------------------------------
// Pending dialogue sessions
// ---------------------------------------------------------------------------

/** @type {Map<string, PendingSession>} */
const pendingSessions = new Map();

function createDialogue(sessionId) {
  const session = {
    outputQueue:  [],
    resolveNext:  null,
    promptText:   null,
    sseWrite:     null,
    done:         false,
    result:       null,
  };
  pendingSessions.set(sessionId, session);

  const dialogue = {
    send(text) {
      if (session.sseWrite) {
        session.sseWrite({ type: 'line', text });
      } else {
        session.outputQueue.push({ type: 'line', text });
      }
    },
    prompt(text) {
      return new Promise(resolve => {
        const msg = { type: 'prompt', text };
        if (session.sseWrite) {
          session.sseWrite(msg);
        } else {
          session.outputQueue.push(msg);
        }
        session.promptText  = text;
        session.resolveNext = resolve;
      });
    },
  };

  return dialogue;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'web')));
app.use(auth.sessions.expressMiddleware());

// ---------------------------------------------------------------------------
// POST /api/start
// ---------------------------------------------------------------------------
app.post('/api/start', (req, res) => {
  const sessionId = crypto.randomUUID();
  const ipAddress = req.ip || req.socket.remoteAddress;
  const dialogue  = createDialogue(sessionId);
  const session   = pendingSessions.get(sessionId);

  auth.entryFlow(dialogue, ipAddress)
    .then(result => {
      session.result = result;
      session.done   = true;
      if (session.sseWrite) {
        session.sseWrite({ type: 'done', result });
      }
    })
    .catch(err => {
      console.error('Flow error:', err);
      session.done = true;
      if (session.sseWrite) {
        session.sseWrite({ type: 'error', message: err.message });
      }
    });

  res.json({ sessionId });
});

// ---------------------------------------------------------------------------
// GET /api/stream/:sessionId  (Server-Sent Events)
// ---------------------------------------------------------------------------
app.get('/api/stream/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = pendingSessions.get(sessionId);

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function sseWrite(obj) {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  }

  session.sseWrite = sseWrite;

  for (const item of session.outputQueue) {
    sseWrite(item);
  }
  session.outputQueue = [];

  if (session.done) {
    sseWrite({ type: 'done', result: session.result });
  }

  req.on('close', () => {
    session.sseWrite = null;
  });
});

// ---------------------------------------------------------------------------
// POST /api/respond/:sessionId
// ---------------------------------------------------------------------------
app.post('/api/respond/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = pendingSessions.get(sessionId);

  if (!session) return res.status(404).json({ error: 'Session not found' });
  if (!session.resolveNext) return res.status(409).json({ error: 'No prompt pending' });

  const { input } = req.body;
  const resolve   = session.resolveNext;
  session.resolveNext = null;
  session.promptText  = null;

  resolve(input || '');
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /api/session
// ---------------------------------------------------------------------------
app.get('/api/session', (req, res) => {
  if (req.synthSession) {
    const { internalId, ...safeSession } = req.synthSession;
    return res.json({ authenticated: true, ...safeSession });
  }
  res.json({ authenticated: false });
});

// ---------------------------------------------------------------------------
// POST /api/logout
// ---------------------------------------------------------------------------
app.post('/api/logout', (req, res) => {
  if (req.synthToken) {
    auth.sessions.destroy(req.synthToken);
  }
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /api/generate-bbs-code
// Returns a freshly generated random valid BBS recovery code.
// ---------------------------------------------------------------------------
app.get('/api/generate-bbs-code', (req, res) => {
  const code = generateRecoveryCode();
  res.json({ code });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  SynthAuth test server running at http://localhost:${PORT}`);
  console.log('  Open that URL in your browser to test the auth flow.\n');
});

module.exports = app;
