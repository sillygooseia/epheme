'use strict';
const crypto = require('crypto');

// ─── Admin rate-limiter (module-level; survives across requests) ─────────────
const _adminFailWindows = new Map(); // ip → { count, resetAt }
function _adminCheckRate(ip) {
  const now = Date.now();
  const WINDOW = 15 * 60 * 1000; // 15 minutes
  const MAX_FAILS = 10;
  let w = _adminFailWindows.get(ip);
  if (!w || now > w.resetAt) {
    _adminFailWindows.set(ip, { count: 0, resetAt: now + WINDOW });
    return true; // not rate-limited
  }
  return w.count < MAX_FAILS;
}
function _adminRecordFail(ip) {
  const w = _adminFailWindows.get(ip);
  if (w) w.count++;
}

/**
 * Express middleware: validates X-Device-Admin-Secret against DEVICE_ADMIN_SECRET.
 * Exported so callers (e.g. PAT routes in bafgo) can attach it to their own routes.
 *
 * Security notes:
 *  - Both values are HMAC'd with a derived key before timingSafeEqual comparison,
 *    preventing secret-length enumeration via a length pre-check.
 *  - Sliding-window rate limiter (10 failures / IP / 15 min) prevents brute force.
 */
function requireDeviceAdmin(req, res, next) {
  const secret = process.env.DEVICE_ADMIN_SECRET;
  if (!secret) return res.status(503).json({ error: 'Device admin not configured (DEVICE_ADMIN_SECRET missing)' });
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!_adminCheckRate(ip)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  }
  const provided = req.get('x-device-admin-secret') || '';
  const hmacKey = crypto.createHash('sha256').update('admin-secret-comparison').digest();
  const a = crypto.createHmac('sha256', hmacKey).update(secret).digest();
  const b = crypto.createHmac('sha256', hmacKey).update(provided).digest();
  if (!crypto.timingSafeEqual(a, b)) {
    _adminRecordFail(ip);
    return res.status(403).json({ error: 'Invalid or missing X-Device-Admin-Secret' });
  }
  next();
}

/**
 * registerDeviceRoutes — mounts all /api/devices/* and /api/presence endpoints.
 *
 * @param {import('express').Application} app
 * @param {import('./deviceStore')} deviceStore
 * @param {{
 *   certManager:          import('./certManager'),
 *   issueDeviceJWT:       (device: object) => string,
 *   verifyDeviceJWT:      (token: string) => object|null,
 *   deviceJwtTtl:         number,
 *   emitHubEvent:         (name: string, payload: object) => void,
 *   tenantSlug:           string,
 *   patStore?:            object,
 *   isDeviceAutoApprove:  boolean,
 *   pubClient:            object|Function,
 *   rateLimiters?:        { tokenLimiter?: Function, challengeLimiter?: Function, authLimiter?: Function },
 * }} opts
 */
function registerDeviceRoutes(app, getDeviceStore, {
  certManager,
  issueDeviceJWT,
  verifyDeviceJWT,
  deviceJwtTtl,
  emitHubEvent,
  tenantSlug,
  patStore         = null,
  isDeviceAutoApprove,
  pubClient,
  rateLimiters     = {},
} = {}) {
    function _getPubClient() {
      return (typeof pubClient === 'function') ? pubClient() : pubClient;
    }

  // getDeviceStore is a function returning the current DeviceStore instance (may be null
  // if better-sqlite3 is missing or not yet initialised). All route handlers call it at
  // request time so they pick up the instance once it becomes available.

  /** Deferred-init middleware pass-through (mirrors bafgo's _rl helper). */
  function _rl(getMw) {
    return function (req, res, next) {
      const mw = getMw();
      if (!mw) return next();
      return mw(req, res, next);
    };
  }

  // ─── Challenge store (in-memory, single-use, auto-expiry) ───────────────
  const _deviceChallenges = new Map(); // deviceId → { nonce, expiresAt }
  const CHALLENGE_TTL_MS  = 60_000;   // 60 seconds

  function _createChallenge(deviceId) {
    const nonce     = crypto.randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + CHALLENGE_TTL_MS;
    _deviceChallenges.set(deviceId, { nonce, expiresAt });
    return { nonce, expiresAt };
  }

  function _consumeChallenge(deviceId, nonce) {
    const entry = _deviceChallenges.get(deviceId);
    if (!entry) return false;
    _deviceChallenges.delete(deviceId); // one-time use
    if (Date.now() > entry.expiresAt) return false;
    const a = Buffer.from(entry.nonce);
    const b = Buffer.from(typeof nonce === 'string' ? nonce : '');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }

  // Rate-limit device registrations: max 5 per IP per hour.
  const _deviceRegRateWindows = new Map();
  function _deviceRegCheckRate(ip) {
    const now = Date.now();
    let w = _deviceRegRateWindows.get(ip);
    if (!w || now > w.resetAt) { _deviceRegRateWindows.set(ip, { count: 1, resetAt: now + 3600000 }); return true; }
    if (w.count >= 5) return false;
    w.count++; return true;
  }

  const _DEVICE_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  // ======================== Device registration & management endpoints ========================

  /**
   * POST /api/devices/register
   * Supports two paths:
   *   Cert path (new):    body { displayName, publicKeySPKI }  → { pendingId, certMode: true }
   *   Legacy token path:  body { displayName, clientToken }    → { pendingId, certMode: false }
   */
  app.post('/api/devices/register', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available (better-sqlite3 not installed)' });
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    if (!_deviceRegCheckRate(ip)) return res.status(429).json({ error: 'Too many registration requests. Try again later.' });
    const { displayName, clientToken, publicKeySPKI } = req.body || {};
    if (typeof displayName !== 'string' || !displayName.trim()) return res.status(400).json({ error: 'displayName is required' });
    const safeName = displayName.trim().slice(0, 64);

    // ── Certificate path ─────────────────────────────────────────────────
    if (typeof publicKeySPKI === 'string') {
      if (publicKeySPKI.length < 80 || publicKeySPKI.length > 4096) {
        return res.status(400).json({ error: 'publicKeySPKI must be a valid base64-encoded SPKI key (80–4096 chars)' });
      }
      if (!/^[A-Za-z0-9+/=]+$/.test(publicKeySPKI)) {
        return res.status(400).json({ error: 'publicKeySPKI must be base64-encoded' });
      }
      try {
        const { pendingId } = deviceStore.createPendingCert({ tenant: tenantSlug, displayName: safeName, publicKeySPKI });
        emitHubEvent('device.registered', { pendingId, displayName: safeName, tenant: tenantSlug, mode: 'cert' });
        if (isDeviceAutoApprove) {
          if (certManager.isLoaded()) {
            const { certPem, fingerprint } = certManager.issueCert(pendingId, tenantSlug, 'member', publicKeySPKI);
            const activated = deviceStore.activateWithCert({ pendingId, role: 'member', certPem, certFingerprint: fingerprint });
            if (activated) {
              emitHubEvent('device.activated', { deviceId: activated.deviceId, tenant: tenantSlug, role: 'member' });
              return res.json({ pendingId, deviceId: activated.deviceId, autoApproved: true, certMode: true });
            }
          } else {
            const activated = deviceStore.activate({ pendingId, role: 'member' });
            if (activated) {
              emitHubEvent('device.activated', { deviceId: activated.deviceId, tenant: tenantSlug, role: 'member' });
              return res.json({ pendingId, deviceId: activated.deviceId, autoApproved: true, certMode: true });
            }
          }
        }
        res.json({ pendingId, certMode: true });
      } catch (err) {
        console.error('[device] register (cert) error', err);
        res.status(500).json({ error: 'Failed to create certificate-based registration' });
      }
      return;
    }

    // ── Legacy token path ────────────────────────────────────────────
    if (typeof clientToken !== 'string' || clientToken.length < 32 || clientToken.length > 256) {
      return res.status(400).json({ error: 'clientToken must be 32–256 characters (or provide publicKeySPKI for certificate registration)' });
    }
    try {
      const { pendingId } = deviceStore.createPending({ tenant: tenantSlug, displayName: safeName, rawToken: clientToken });
      emitHubEvent('device.registered', { pendingId, displayName: safeName, tenant: tenantSlug, mode: 'token' });
      if (isDeviceAutoApprove) {
        const activated = deviceStore.activate({ pendingId, role: 'member' });
        if (activated) {
          emitHubEvent('device.activated', { deviceId: activated.deviceId, tenant: tenantSlug, role: 'member' });
          return res.json({ pendingId, deviceId: activated.deviceId, autoApproved: true, certMode: false });
        }
      }
      res.json({ pendingId, certMode: false });
    } catch (err) {
      console.error('[device] register error', err);
      res.status(500).json({ error: 'Failed to create registration' });
    }
  });

  /**
   * GET /api/devices/register/:pendingId/status
   * Client polls until status = 'active'.
   * Returns { status, deviceId?, certificate?, certFingerprint? }
   */
  app.get('/api/devices/register/:pendingId/status', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { pendingId } = req.params;
    if (!_DEVICE_UUID_RE.test(pendingId)) return res.status(400).json({ error: 'invalid pendingId' });
    res.json(deviceStore.getPendingStatusFull(pendingId));
  });

  /**
   * POST /api/devices/:deviceId/token
   * Exchange the raw clientToken for a short-lived device access JWT.
   * Body: { clientToken: '<raw-token>' }
   */
  app.post('/api/devices/:deviceId/token', _rl(() => rateLimiters.tokenLimiter), (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    const { clientToken } = req.body || {};
    if (typeof clientToken !== 'string' || clientToken.length < 32) {
      return res.status(400).json({ error: 'clientToken required (min 32 chars)' });
    }
    const device = deviceStore.verifyDeviceToken(deviceId, clientToken);
    if (!device) return res.status(403).json({ error: 'Invalid device credentials or device revoked', code: 'DEVICE_INVALID' });
    try {
      const token = issueDeviceJWT(device);
      res.json({ token, expiresIn: deviceJwtTtl, deviceId, role: device.role });
    } catch (err) {
      console.error('[device] token issuance error', err);
      res.status(500).json({ error: 'Failed to issue device token' });
    }
  });

  /**
   * GET /api/devices/:deviceId/challenge
   * Issue a single-use nonce for ECDSA challenge-response authentication.
   */
  app.get('/api/devices/:deviceId/challenge', _rl(() => rateLimiters.challengeLimiter), (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    const device = deviceStore.getDevice(deviceId);
    if (!device || device.revoked) return res.status(404).json({ error: 'Device not found or revoked' });
    if (!device.public_key) return res.status(409).json({ error: 'Device not enrolled with a certificate', code: 'NOT_CERT_DEVICE' });
    const { nonce, expiresAt } = _createChallenge(deviceId);
    res.json({ nonce, expiresAt });
  });

  /**
   * POST /api/devices/:deviceId/authenticate
   * Validate a signed challenge, return a fresh device JWT.
   * Body: { nonce: string, signature: string (base64/base64url ECDSA-P256) }
   */
  app.post('/api/devices/:deviceId/authenticate', _rl(() => rateLimiters.authLimiter), async (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    const { nonce, signature } = req.body || {};
    if (typeof nonce !== 'string' || !nonce) return res.status(400).json({ error: 'nonce required' });
    if (typeof signature !== 'string' || !signature) return res.status(400).json({ error: 'signature required' });
    try {
      if (!_consumeChallenge(deviceId, nonce)) {
        return res.status(401).json({ error: 'Challenge expired or invalid', code: 'CHALLENGE_INVALID' });
      }
      const device = deviceStore.verifyDeviceChallenge(deviceId, nonce, signature);
      if (!device) return res.status(403).json({ error: 'Signature verification failed', code: 'SIGNATURE_INVALID' });
      const token = issueDeviceJWT(device);
      emitHubEvent('device.authenticated', { deviceId, tenant: tenantSlug });
      res.json({ token, certificate: device.certificate || null, expiresIn: deviceJwtTtl, role: device.role });
    } catch (err) {
      console.error('[device] authenticate error', err);
      res.status(500).json({ error: 'Authentication failed' });
    }
  });

  // ---- Device self-service endpoints (require a valid device JWT) ----

  /**
   * GET /api/devices/me
   * Returns the calling device's own registration info and PAT/premium status.
   */
  app.get('/api/devices/me', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const devicePayload = verifyDeviceJWT(bearerToken);
    if (!devicePayload) return res.status(401).json({ error: 'Valid device token required', code: 'AUTH_REQUIRED' });
    try {
      const device = deviceStore.getDevice(devicePayload.device_id);
      if (!device || device.revoked) return res.status(404).json({ error: 'Device not found or revoked' });
      const { token_hash, ...safeDevice } = device;
      const pat = patStore
        ? patStore.getStatusByDevice(device.id, { certFingerprint: device.cert_fingerprint || undefined })
        : { premium: false, credits: 0, patId: null };
      res.json({ device: safeDevice, pat });
    } catch (err) {
      console.error('[device] /me error', err);
      res.status(500).json({ error: 'Failed to retrieve device info' });
    }
  });

  /**
   * DELETE /api/devices/me
   * Permanently removes the calling device's registration (self-deregistration).
   */
  app.delete('/api/devices/me', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const devicePayload = verifyDeviceJWT(bearerToken);
    if (!devicePayload) return res.status(401).json({ error: 'Valid device token required', code: 'AUTH_REQUIRED' });
    try {
      const deleted = deviceStore.deleteDevice(devicePayload.device_id);
      if (!deleted) return res.status(404).json({ error: 'Device not found' });
      res.json({ ok: true });
    } catch (err) {
      console.error('[device] /me delete error', err);
      res.status(500).json({ error: 'Failed to delete device registration' });
    }
  });

  // ---- Admin-only device management (require X-Device-Admin-Secret header) ----

  /** GET /api/devices/pending — list pending (unapproved) registrations for the tenant. */
  app.get('/api/devices/pending', requireDeviceAdmin, (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    try {
      res.json({ pending: deviceStore.listPending(tenantSlug) });
    } catch (err) {
      console.error('[device] list pending error', err);
      res.status(500).json({ error: 'Failed to list pending registrations' });
    }
  });

  /**
   * POST /api/devices/pending/:pendingId/activate
   * Admin approves a pending registration. Automatically issues an X.509 cert for
   * cert-based registrations when the CA is loaded.
   * Body: { role?: string, displayName?: string }
   */
  app.post('/api/devices/pending/:pendingId/activate', requireDeviceAdmin, async (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { pendingId } = req.params;
    if (!_DEVICE_UUID_RE.test(pendingId)) return res.status(400).json({ error: 'invalid pendingId' });
    const { role, displayName } = req.body || {};
    const safeRole = typeof role === 'string' ? role.trim().slice(0, 32) : 'member';
    const safeName = typeof displayName === 'string' ? displayName.trim().slice(0, 64) : undefined;
    try {
      const pending = deviceStore.getPendingRecord(pendingId);
      if (pending?.public_key && certManager.isLoaded()) {
        const { certPem, fingerprint } = certManager.issueCert(pendingId, tenantSlug, safeRole, pending.public_key);
        const result = deviceStore.activateWithCert({ pendingId, role: safeRole, displayNameOverride: safeName, certPem, certFingerprint: fingerprint });
        if (!result) return res.status(404).json({ error: 'Pending registration not found or expired' });
        if (patStore) {
          try { patStore.updateCertFingerprint(result.deviceId, fingerprint); } catch { /* no PAT bound — fine */ }
        }
        emitHubEvent('device.activated', { deviceId: result.deviceId, tenant: tenantSlug, role: safeRole });
        return res.json({ deviceId: result.deviceId, ok: true, certIssued: true });
      }
      const result = deviceStore.activate({ pendingId, role: safeRole, displayNameOverride: safeName });
      if (!result) return res.status(404).json({ error: 'Pending registration not found or expired' });
      emitHubEvent('device.activated', { deviceId: result.deviceId, tenant: tenantSlug, role: safeRole });
      res.json({ deviceId: result.deviceId, ok: true, certIssued: false });
    } catch (err) {
      console.error('[device] activate error', err);
      res.status(500).json({ error: 'Failed to activate device' });
    }
  });

  /** GET /api/devices — list all active devices for the tenant (admin only). */
  app.get('/api/devices', requireDeviceAdmin, (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    try {
      res.json({ devices: deviceStore.listDevices(tenantSlug, { showRevoked: req.query.showRevoked === 'true' }) });
    } catch (err) {
      console.error('[device] list devices error', err);
      res.status(500).json({ error: 'Failed to list devices' });
    }
  });

  /** POST /api/devices/:deviceId/revoke — admin revokes a device immediately. */
  app.post('/api/devices/:deviceId/revoke', requireDeviceAdmin, (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    try {
      const revoked = deviceStore.revokeDevice(deviceId);
      if (!revoked) return res.status(404).json({ error: 'Device not found' });
      emitHubEvent('device.revoked', { deviceId, tenant: tenantSlug });
      res.json({ ok: true });
    } catch (err) {
      console.error('[device] revoke error', err);
      res.status(500).json({ error: 'Failed to revoke device' });
    }
  });

  /**
   * PATCH /api/devices/:deviceId/role — admin changes the role of an active device.
   * Body: { role: string }
   */
  app.patch('/api/devices/:deviceId/role', requireDeviceAdmin, (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    const { role } = req.body || {};
    if (typeof role !== 'string' || !role.trim()) return res.status(400).json({ error: 'role is required' });
    const safeRole = role.trim().slice(0, 32);
    try {
      const updated = deviceStore.updateDeviceRole(deviceId, safeRole);
      if (!updated) return res.status(404).json({ error: 'Device not found or already revoked' });
      res.json({ ok: true });
    } catch (err) {
      console.error('[device] update role error', err);
      res.status(500).json({ error: 'Failed to update device role' });
    }
  });

  // ======================== Contact identity endpoints =================

  /**
   * PUT /api/devices/me/identity-pubkey
   * Register (or update) this device's long-lived P-256 ECDH identity public key.
   * Body: { identityPubKey: JsonWebKey }
   */
  app.put('/api/devices/me/identity-pubkey', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const devicePayload = verifyDeviceJWT(bearerToken);
    if (!devicePayload) return res.status(401).json({ error: 'Valid device token required', code: 'AUTH_REQUIRED' });
    const { identityPubKey } = req.body || {};
    if (!identityPubKey || typeof identityPubKey !== 'object') {
      return res.status(400).json({ error: 'identityPubKey (JWK object) is required' });
    }
    if (identityPubKey.kty !== 'EC' || identityPubKey.crv !== 'P-256' ||
        typeof identityPubKey.x !== 'string' || typeof identityPubKey.y !== 'string') {
      return res.status(400).json({ error: 'identityPubKey must be a P-256 EC JWK' });
    }
    const pubOnly = { kty: identityPubKey.kty, crv: identityPubKey.crv, x: identityPubKey.x, y: identityPubKey.y };
    try {
      deviceStore.setIdentityEcdhPubKey(devicePayload.device_id, JSON.stringify(pubOnly));
      res.json({ ok: true });
    } catch (err) {
      console.error('[contacts] setIdentityEcdhPubKey error', err);
      res.status(500).json({ error: 'Failed to store identity public key' });
    }
  });

  /**
   * GET /api/devices/:deviceId/identity-pubkey
   * Fetch a contact's display name and identity ECDH public key.
   * Caller must be an active device on the same tenant.
   */
  app.get('/api/devices/:deviceId/identity-pubkey', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const callerPayload = verifyDeviceJWT(bearerToken);
    if (!callerPayload) return res.status(401).json({ error: 'Valid device token required', code: 'AUTH_REQUIRED' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    try {
      const target = deviceStore.getDevice(deviceId);
      if (!target || target.revoked) return res.status(404).json({ error: 'Device not found' });
      if (target.tenant !== callerPayload.tenant) return res.status(403).json({ error: 'Device not in your tenant' });
      const pubKeyRaw = deviceStore.getIdentityEcdhPubKey(deviceId);
      let identityPubKey = null;
      if (pubKeyRaw) {
        try { identityPubKey = JSON.parse(pubKeyRaw); } catch { /* malformed — return null */ }
      }
      res.json({ deviceId, displayName: target.display_name, identityPubKey });
    } catch (err) {
      console.error('[contacts] getIdentityEcdhPubKey error', err);
      res.status(500).json({ error: 'Failed to fetch device info' });
    }
  });

  /**
   * GET /api/presence?deviceIds[]=<uuid>&...
   * Returns current online status for up to 100 device IDs (own tenant only).
   * Requires a valid device JWT.
   */
  app.get('/api/presence', async (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const callerPayload = verifyDeviceJWT(bearerToken);
    if (!callerPayload) return res.status(401).json({ error: 'Valid device token required', code: 'AUTH_REQUIRED' });

    const raw = req.query.deviceIds;
    const ids = (Array.isArray(raw) ? raw : (raw ? [raw] : []))
      .filter(id => typeof id === 'string' && _DEVICE_UUID_RE.test(id))
      .slice(0, 100);
    if (!ids.length) return res.json({});

    try {
      const redis = _getPubClient();
      if (!redis) return res.status(503).json({ error: 'Presence service unavailable' });
      const keys = ids.map(id => `presence:${callerPayload.tenant}:${id}`);
      const values = await redis.mget(...keys);
      const result = {};
      ids.forEach((id, i) => { result[id] = values[i] === '1'; });
      res.json(result);
    } catch (err) {
      console.error('[presence] /api/presence error:', err?.message);
      res.status(500).json({ error: 'Presence check failed' });
    }
  });

  /**
   * GET /api/devices/:deviceId/card
   * Public endpoint — no auth required.
   * Returns minimal public info for "Add as Contact" deep links: { deviceId, displayName }.
   */
  app.get('/api/devices/:deviceId/card', (req, res) => {
    const deviceStore = getDeviceStore();
    if (!deviceStore) return res.status(503).json({ error: 'Device auth not available' });
    const { deviceId } = req.params;
    if (!_DEVICE_UUID_RE.test(deviceId)) return res.status(400).json({ error: 'invalid deviceId' });
    try {
      const target = deviceStore.getDevice(deviceId);
      if (!target || target.revoked) return res.status(404).json({ error: 'Device not found' });
      if (target.tenant !== tenantSlug) return res.status(404).json({ error: 'Device not found' });
      res.json({ deviceId, displayName: target.display_name });
    } catch (err) {
      console.error('[contacts] card error', err);
      res.status(500).json({ error: 'Failed to fetch device card' });
    }
  });

  // ======================== End contact identity endpoints =============

  /**
   * GET /api/devices/ca-cert
   * Returns the public CA certificate PEM (for clients to pin).
   * Returns 204 when cert auth is not configured.
   */
  app.get('/api/devices/ca-cert', (req, res) => {
    if (!certManager.isLoaded()) return res.status(204).send();
    res.type('text/plain').send(certManager.getCaCertPem());
  });

  console.log('[device] Device routes registered.');
}

module.exports = { registerDeviceRoutes, requireDeviceAdmin };
