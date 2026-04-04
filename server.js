'use strict';

require('dotenv').config();

const express    = require('express');
const path       = require('path');
const crypto     = require('crypto');
const SynthAuth  = require('./index');

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
// Each web SSE connection gets a UUID. The flow communicates with the browser
// via a simple promise/resolve queue — the server side "prompts" and waits
// for the client to POST back an answer.
// ---------------------------------------------------------------------------

/** @type {Map<string, PendingSession>} */
const pendingSessions = new Map();

/**
 * @typedef {object} PendingSession
 * @property {string[]}    outputQueue   lines waiting to be sent to client
 * @property {Function|null} resolveNext resolve() for the current prompt
 * @property {string|null}   promptText  current prompt text
 * @property {Function}      sseWrite    write a line to SSE stream
 * @property {boolean}       done        flow has finished
 */

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
// Begins a new auth flow. Returns { sessionId }.
// ---------------------------------------------------------------------------
app.post('/api/start', (req, res) => {
  const sessionId = crypto.randomUUID();
  const ipAddress = req.ip || req.socket.remoteAddress;
  const dialogue  = createDialogue(sessionId);
  const session   = pendingSessions.get(sessionId);

  // Run the flow asynchronously — it will block on dialogue.prompt() calls
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
// Client connects here to receive output lines and prompt events.
// ---------------------------------------------------------------------------
app.get('/api/stream/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = pendingSessions.get(sessionId);

  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }

  // Set up SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function sseWrite(obj) {
    res.write(`data: ${JSON.stringify(obj)}\n\n`);
  }

  session.sseWrite = sseWrite;

  // Flush any buffered output that arrived before SSE connected
  for (const item of session.outputQueue) {
    sseWrite(item);
  }
  session.outputQueue = [];

  // If flow is already done (race condition)
  if (session.done) {
    sseWrite({ type: 'done', result: session.result });
  }

  req.on('close', () => {
    session.sseWrite = null;
  });
});

// ---------------------------------------------------------------------------
// POST /api/respond/:sessionId
// Client sends the user's typed response to the current prompt.
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
// GET /api/session — check current HTTP session (from token cookie/header)
// ---------------------------------------------------------------------------
app.get('/api/session', (req, res) => {
  if (req.synthSession) {
    // Destructure to pull internalId out, then use '...safe' to send the rest
    const { internalId, ...safeSession } = req.synthSession;
    
    return res.json({ 
      authenticated: true, 
      ...safeSession 
    });
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
// Start server
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n  SynthAuth test server running at http://localhost:${PORT}`);
  console.log('  Open that URL in your browser to test the auth flow.\n');
});

module.exports = app;
