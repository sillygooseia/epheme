'use strict';
const crypto = require('crypto');

// 28 unambiguous characters — no I, L, O, U, 0, 1 to avoid misreads
const QC_CODE_ALPHABET = 'BCDFGHJKMNPQRSTVWXYZ23456789';
const QC_CODE_LEN      = 6;
const QC_SESSION_TTL   = 60; // seconds

function _generateCode() {
  const bytes = crypto.randomBytes(QC_CODE_LEN);
  let s = '';
  for (let i = 0; i < QC_CODE_LEN; i++) {
    s += QC_CODE_ALPHABET[bytes[i] % QC_CODE_ALPHABET.length];
  }
  return `${s.slice(0, 3)}-${s.slice(3)}`; // "XXX-XXX" display format
}

function _hashCode(code) {
  // Strip the dash, uppercase, then SHA-256 for safe storage
  const normalized = code.replace(/-/g, '').toUpperCase();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function _isValidJwk(v) {
  return v && typeof v === 'object'
    && v.kty === 'EC'
    && v.crv === 'P-256'
    && typeof v.x === 'string'
    && typeof v.y === 'string';
}

function _isValidBase64url(v, maxLen) {
  return typeof v === 'string'
    && v.length > 0
    && v.length <= maxLen
    && /^[A-Za-z0-9+/=_-]+$/.test(v);
}

/**
 * registerQuickConnectRoutes — mounts all /api/quick-connect/* HTTP endpoints.
 *
 * Privacy model:
 *   - Server only ever sees: hashed code, two ephemeral public keys (not identity keys),
 *     timestamps, encrypted blobs. It can never reconstruct contact data or identity.
 *   - All session state is ephemeral Redis with a 60-second TTL.
 *   - Session is deleted immediately after both sides complete the handshake.
 *   - IP rate limits use hashed IPs via the existing buildIpRateLimiter helper.
 *
 * Socket events emitted:
 *   qc:peer-joined  { sessionId }  → room `qc:{sessionId}` when Device B calls /join
 *   qc:complete     { sessionId }  → room `qc:{sessionId}` when both cards are submitted
 *
 * Socket events consumed (must be registered by the caller in the io.on('connection') block):
 *   qc:subscribe    { sessionId }  — client joins the per-session socket room
 *
 * @param {import('express').Application} app
 * @param {import('socket.io').Server}    io
 * @param {object}   redis             — ioredis client (primary pub client)
 * @param {Function} verifyDeviceJWT   — returns decoded payload or null
 * @param {{ initiateLimiter?: Function, joinLimiter?: Function }} [rateLimiters]
 */
function registerQuickConnectRoutes(app, io, redis, verifyDeviceJWT, rateLimiters = {}) {

  // ─── Auth middleware ───────────────────────────────────────────────────────

  function requireDevice(req, res, next) {
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const payload     = verifyDeviceJWT(bearerToken);
    if (!payload) {
      return res.status(401).json({ error: 'Device JWT required', code: 'DEVICE_JWT_REQUIRED' });
    }
    req.devicePayload = payload;
    req.deviceId      = payload.device_id;
    next();
  }

  // Deferred-init middleware pass-through for limiter not yet built (avoids crash at startup).
  const _rl = (mw) => mw || ((req, res, next) => next());

  // UUID v4 shape — used to validate sessionId path params before hitting Redis.
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  // ─── POST /api/quick-connect/initiate ─────────────────────────────────────
  // Device A starts a pairing session. Generates a short code and stores an
  // ephemeral Redis entry containing the hashed code and Device A's ephemeral
  // public key. Returns the plaintext code to Device A only.
  app.post('/api/quick-connect/initiate', _rl(rateLimiters.initiateLimiter), requireDevice, async (req, res) => {
    const { ephemeralPubKey } = req.body || {};
    if (!_isValidJwk(ephemeralPubKey)) {
      return res.status(400).json({ error: 'ephemeralPubKey must be a P-256 JWK', code: 'INVALID_PUBKEY' });
    }

    // Device-level anti-spam: max 10 initiations per 5-minute window.
    // Key includes a bucketed timestamp so it auto-expires without a separate TTL scan.
    const devRateKey = `qc:devrate:${req.deviceId}:${Math.floor(Date.now() / 1000 / 300)}`;
    const devCount = parseInt(await redis.incr(devRateKey), 10);
    if (devCount === 1) await redis.expire(devRateKey, 300);
    if (devCount > 10) {
      return res.status(429).json({
        error: 'Too many Quick Connect sessions. Try again in a few minutes.',
        code:  'DEVICE_RATE_LIMIT',
      });
    }

    const sessionId  = crypto.randomUUID();
    const rawCode    = _generateCode();
    const hashedCode = _hashCode(rawCode);
    const expiresAt  = Math.floor(Date.now() / 1000) + QC_SESSION_TTL;

    const pipeline = redis.pipeline();
    pipeline.hset(`qc:session:${sessionId}`,
      'hashed_code',    hashedCode,
      'deviceA_id',     req.deviceId,
      'deviceA_pubkey', JSON.stringify(ephemeralPubKey),
      'state',          'waiting',
    );
    pipeline.expire(`qc:session:${sessionId}`, QC_SESSION_TTL);
    // Code → sessionId reverse lookup; same TTL.
    pipeline.set(`qc:code:${hashedCode}`, sessionId, 'EX', QC_SESSION_TTL);
    await pipeline.exec();

    return res.json({ sessionId, code: rawCode, expiresAt });
  });

  // ─── POST /api/quick-connect/join ─────────────────────────────────────────
  // Device B submits the code shown on Device A's screen. Server validates the
  // code, stores Device B's ephemeral public key, transitions state to 'pairing',
  // and returns Device A's ephemeral public key so B can begin the ECDH handshake.
  app.post('/api/quick-connect/join', _rl(rateLimiters.joinLimiter), requireDevice, async (req, res) => {
    const { code, ephemeralPubKey } = req.body || {};
    if (typeof code !== 'string' || code.trim().length === 0) {
      return res.status(400).json({ error: 'code is required', code: 'INVALID_CODE' });
    }
    if (!_isValidJwk(ephemeralPubKey)) {
      return res.status(400).json({ error: 'ephemeralPubKey must be a P-256 JWK', code: 'INVALID_PUBKEY' });
    }

    const hashedCode = _hashCode(code.trim());
    const sessionId  = await redis.get(`qc:code:${hashedCode}`);
    if (!sessionId) {
      return res.status(404).json({ error: 'Code not found or expired', code: 'CODE_NOT_FOUND' });
    }

    const session = await redis.hgetall(`qc:session:${sessionId}`);
    if (!session || !session.state) {
      return res.status(410).json({ error: 'Session expired', code: 'SESSION_EXPIRED' });
    }
    if (session.state !== 'waiting') {
      return res.status(409).json({ error: 'Session already claimed', code: 'SESSION_CLAIMED' });
    }
    if (session.deviceA_id === req.deviceId) {
      return res.status(400).json({ error: 'Cannot join your own session', code: 'SELF_JOIN' });
    }

    const pipeline = redis.pipeline();
    pipeline.hset(`qc:session:${sessionId}`,
      'deviceB_id',     req.deviceId,
      'deviceB_pubkey', JSON.stringify(ephemeralPubKey),
      'state',          'pairing',
    );
    // Reset TTL from join time so both devices get a full window for card exchange.
    pipeline.expire(`qc:session:${sessionId}`, QC_SESSION_TTL);
    pipeline.expire(`qc:code:${hashedCode}`, QC_SESSION_TTL);
    await pipeline.exec();

    // Notify Device A via Socket.IO so it can skip polling.
    io.to(`qc:${sessionId}`).emit('qc:peer-joined', { sessionId });

    return res.json({ sessionId, peerPubKey: JSON.parse(session.deviceA_pubkey) });
  });

  // ─── GET /api/quick-connect/:sessionId/status ─────────────────────────────
  // Polling endpoint for both devices. Device A uses it to get Device B's public
  // key and card. Also acts as the cleanup trigger: once both sides fetch a
  // 'complete' response with a peerCard, the session is deleted immediately.
  app.get('/api/quick-connect/:sessionId/status', requireDevice, async (req, res) => {
    const { sessionId } = req.params;
    if (!UUID_RE.test(sessionId)) {
      return res.status(400).json({ error: 'Invalid sessionId', code: 'INVALID_SESSION_ID' });
    }

    const session = await redis.hgetall(`qc:session:${sessionId}`);
    if (!session || !session.state) {
      return res.status(410).json({ error: 'Session not found or expired', code: 'SESSION_EXPIRED' });
    }

    const isA = session.deviceA_id === req.deviceId;
    const isB = session.deviceB_id === req.deviceId;
    if (!isA && !isB) {
      return res.status(403).json({ error: 'Not a participant in this session', code: 'NOT_PARTICIPANT' });
    }

    const response = { state: session.state };

    if (session.state === 'pairing' || session.state === 'complete') {
      const peerPubkeyRaw = isA ? session.deviceB_pubkey : session.deviceA_pubkey;
      response.peerPubKey = peerPubkeyRaw ? JSON.parse(peerPubkeyRaw) : null;

      const peerIv = isA ? session.cardB_iv : session.cardA_iv;
      const peerCt = isA ? session.cardB_ct : session.cardA_ct;
      if (peerIv && peerCt) response.peerCard = { iv: peerIv, ct: peerCt };
    }

    // Eager cleanup: track which participants have seen the completed session.
    // Delete all session keys once both sides have fetched a complete+peerCard response.
    if (session.state === 'complete' && response.peerCard) {
      const fetchKey      = `qc:fetched:${sessionId}:${req.deviceId}`;
      const alreadyFetched = await redis.get(fetchKey);
      if (!alreadyFetched) {
        await redis.set(fetchKey, '1', 'EX', 120);
      } else {
        const otherDeviceId  = isA ? session.deviceB_id : session.deviceA_id;
        const otherFetchKey  = `qc:fetched:${sessionId}:${otherDeviceId}`;
        await redis.del(`qc:session:${sessionId}`, fetchKey, otherFetchKey);
        if (session.hashed_code) await redis.del(`qc:code:${session.hashed_code}`);
      }
    }

    return res.json(response);
  });

  // ─── POST /api/quick-connect/:sessionId/card ──────────────────────────────
  // Each device submits their AES-GCM encrypted contact card (iv + ct).
  // The server stores only the opaque blobs. When both cards are present the
  // session transitions to 'complete' and qc:complete is emitted to both sockets.
  app.post('/api/quick-connect/:sessionId/card', requireDevice, async (req, res) => {
    const { sessionId } = req.params;
    if (!UUID_RE.test(sessionId)) {
      return res.status(400).json({ error: 'Invalid sessionId', code: 'INVALID_SESSION_ID' });
    }

    const { iv, ct } = req.body || {};
    // iv is 12 bytes → 16 base64url chars; ct is AES-GCM ciphertext (card JSON + 16-byte auth tag).
    // Max ct length: ~600 bytes of plaintext JSON + 16 auth tag → ~828 base64 chars → 1024 limit is generous.
    if (!_isValidBase64url(iv, 32) || !_isValidBase64url(ct, 1024)) {
      return res.status(400).json({
        error: 'iv and ct must be base64url strings within size limits',
        code:  'INVALID_CARD',
      });
    }

    const session = await redis.hgetall(`qc:session:${sessionId}`);
    if (!session || !session.state) {
      return res.status(410).json({ error: 'Session not found or expired', code: 'SESSION_EXPIRED' });
    }
    if (session.state !== 'pairing') {
      return res.status(409).json({
        error:  `Cannot submit card in state: ${session.state}`,
        code:   'WRONG_STATE',
      });
    }

    const isA = session.deviceA_id === req.deviceId;
    const isB = session.deviceB_id === req.deviceId;
    if (!isA && !isB) {
      return res.status(403).json({ error: 'Not a participant in this session', code: 'NOT_PARTICIPANT' });
    }

    const myIvField = isA ? 'cardA_iv' : 'cardB_iv';
    const myCtField = isA ? 'cardA_ct' : 'cardB_ct';
    const peerIv    = isA ? session.cardB_iv : session.cardA_iv;
    const peerCt    = isA ? session.cardB_ct : session.cardA_ct;
    const bothReady = !!(peerIv && peerCt);

    const pipeline = redis.pipeline();
    pipeline.hset(`qc:session:${sessionId}`, myIvField, iv, myCtField, ct);
    if (bothReady) pipeline.hset(`qc:session:${sessionId}`, 'state', 'complete');
    await pipeline.exec();

    const responsePayload = { ok: true };
    if (bothReady) {
      responsePayload.peerCard = { iv: peerIv, ct: peerCt };
      io.to(`qc:${sessionId}`).emit('qc:complete', { sessionId });
    }

    return res.json(responsePayload);
  });
}

module.exports = registerQuickConnectRoutes;
