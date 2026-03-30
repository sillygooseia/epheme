'use strict';
/**
 * @epheme/core/deviceRegistry
 *
 * Portable device-authentication primitives for any BafGo-compatible server.
 * Wraps the JWT issuance/verification logic from hub/backend/index.js and
 * exposes Express-compatible middleware factories.
 *
 * Usage:
 *   const { createDeviceRegistry } = require('@epheme/core/deviceRegistry');
 *
 *   const registry = createDeviceRegistry({
 *     deviceJwtSecret: process.env.DEVICE_JWT_SECRET,
 *     deviceJwtTtl:    parseInt(process.env.DEVICE_JWT_TTL || '3600', 10),
 *   });
 *
 *   // Issue a JWT when a device authenticates successfully
 *   const token = registry.issueDeviceJWT(deviceRow);
 *
 *   // Verify incoming Bearer token in a route
 *   app.get('/api/me', registry.requireDevice(), (req, res) => {
 *     res.json({ device: req.device });
 *   });
 *
 *   // Admin-only route (X-Device-Admin-Secret header)
 *   app.get('/api/admin/devices', registry.requireAdmin(), (req, res) => { ... });
 */

const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

// ── Rate-limit state for failed admin secret checks ──────────────────────────
const _adminFailMap = new Map(); // ip → { count, resetAt }
const ADMIN_WINDOW_MS    = 60_000; // 1 minute sliding window
const ADMIN_MAX_FAILURES = 10;

function _adminCheckRate(ip) {
  const now = Date.now();
  const w   = _adminFailMap.get(ip);
  if (!w || now > w.resetAt) return true;
  return w.count < ADMIN_MAX_FAILURES;
}

function _adminRecordFail(ip) {
  const now = Date.now();
  const w   = _adminFailMap.get(ip);
  if (!w || now > w.resetAt) {
    _adminFailMap.set(ip, { count: 1, resetAt: now + ADMIN_WINDOW_MS });
  } else {
    w.count++;
  }
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Create a device registry helper bound to the given configuration.
 *
 * @param {object} opts
 * @param {string} opts.deviceJwtSecret   - HS256 secret for device JWTs (required at auth time).
 * @param {number} [opts.deviceJwtTtl=3600] - Lifetime of issued tokens in seconds.
 * @returns {DeviceRegistry}
 */
function createDeviceRegistry({ deviceJwtSecret, deviceJwtTtl = 3600 } = {}) {

  // ── JWT issue / verify ──────────────────────────────────────────────────

  /**
   * Issue a short-lived HS256 device access JWT.
   *
   * @param {object} device - Must contain `id`, `tenant`, `role`.
   *                          Optionally `cert_fingerprint` for cert-enrolled devices.
   * @returns {string} Signed JWT string.
   */
  function issueDeviceJWT(device) {
    if (!deviceJwtSecret) throw new Error('DEVICE_JWT_SECRET not configured');
    const payload = {
      device_id: device.id,
      tenant:    device.tenant,
      role:      device.role,
      type:      'device_access',
    };
    if (device.cert_fingerprint) payload.certFingerprint = device.cert_fingerprint;
    return jwt.sign(payload, deviceJwtSecret, { expiresIn: deviceJwtTtl });
  }

  /**
   * Verify a device access JWT.
   *
   * @param {string} token - Bearer token string.
   * @returns {object|null} Decoded payload, or null if invalid/missing.
   */
  function verifyDeviceJWT(token) {
    if (!deviceJwtSecret || !token) return null;
    try {
      const payload = jwt.verify(token, deviceJwtSecret);
      if (payload.type !== 'device_access') return null;
      return payload;
    } catch {
      return null;
    }
  }

  // ── Express middleware factories ────────────────────────────────────────

  /**
   * Return an Express middleware that validates the Bearer device JWT and
   * attaches the decoded payload as `req.device`.
   *
   * @param {object} [opts]
   * @param {string} [opts.requiredRole] - If set, also enforces this role (e.g. 'admin').
   * @returns {function} Express middleware (req, res, next)
   */
  function requireDevice({ requiredRole } = {}) {
    return function deviceAuthMiddleware(req, res, next) {
      const authHeader = req.get('Authorization') || '';
      const bearer     = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      const payload    = verifyDeviceJWT(bearer);
      if (!payload) {
        return res.status(401).json({ error: 'Device authentication required' });
      }
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: `Role '${requiredRole}' required` });
      }
      req.device = payload;
      next();
    };
  }

  /**
   * Return an Express middleware that enforces the X-Device-Admin-Secret header.
   * Reads the expected secret from the environment key you supply (default:
   * `DEVICE_ADMIN_SECRET`).
   *
   * The comparison is HMAC-based (sha256) so timingSafeEqual always compares
   * fixed-length digests, preventing secret-length leakage via a length pre-check.
   *
   * @param {object} [opts]
   * @param {string} [opts.envKey='DEVICE_ADMIN_SECRET'] - Environment variable name.
   * @returns {function} Express middleware (req, res, next)
   */
  function requireAdmin({ envKey = 'DEVICE_ADMIN_SECRET' } = {}) {
    return function adminAuthMiddleware(req, res, next) {
      const secret = process.env[envKey];
      if (!secret) {
        return res.status(503).json({ error: `Device admin not configured (${envKey} missing)` });
      }
      const ip = req.ip || req.socket?.remoteAddress || 'unknown';
      if (!_adminCheckRate(ip)) {
        return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
      }
      const provided = req.get('x-device-admin-secret') || '';
      const hmacKey  = crypto.createHash('sha256').update('admin-secret-comparison').digest();
      const a = crypto.createHmac('sha256', hmacKey).update(secret).digest();
      const b = crypto.createHmac('sha256', hmacKey).update(provided).digest();
      if (!crypto.timingSafeEqual(a, b)) {
        _adminRecordFail(ip);
        return res.status(403).json({ error: 'Invalid or missing X-Device-Admin-Secret' });
      }
      next();
    };
  }

  return { issueDeviceJWT, verifyDeviceJWT, requireDevice, requireAdmin };
}

module.exports = { createDeviceRegistry };
