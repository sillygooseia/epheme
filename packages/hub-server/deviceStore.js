'use strict';
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

const DB_PATH         = process.env.DEVICE_DB_PATH || path.join(__dirname, 'data', 'devices.db');
const PENDING_TTL     = parseInt(process.env.DEVICE_PENDING_TTL_SECONDS || '86400', 10); // 24 h
const PBKDF2_ITER     = 100_000;
const CONTACT_MSG_TTL = parseInt(process.env.CONTACT_MESSAGE_TTL_SECONDS || '86400', 10); // 24 h

/**
 * DeviceStore — SQLite-backed store for device registrations.
 *
 * Two-table design:
 *   pending_devices — registration requests awaiting admin approval.
 *   devices         — approved, active (or revoked) device records.
 *
 * Tokens are never stored in plaintext; only PBKDF2 hashes are persisted.
 * Public keys (for future WebAuthn support) are stored as-is.
 *
 * Requires 'better-sqlite3': npm install better-sqlite3
 *
 * Production note: mount DEVICE_DB_PATH to a persistent volume — the SQLite
 * file is lost on container restart if stored in the container layer.
 */
class DeviceStore {
  constructor() {
    // Lazy-require so the module loads cleanly even if better-sqlite3 is absent.
    const Database = require('better-sqlite3');
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    this.db = new Database(DB_PATH);
    this.db.pragma('journal_mode = WAL');   // safe for concurrent readers/one writer
    this.db.pragma('foreign_keys = ON');
    this._migrate();
  }

  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS pending_devices (
        id                   TEXT    PRIMARY KEY,
        tenant               TEXT    NOT NULL,
        display_name         TEXT    NOT NULL,
        token_hash           TEXT    NOT NULL,
        created_at           INTEGER NOT NULL,
        expires_at           INTEGER NOT NULL,
        activated_device_id  TEXT    DEFAULT NULL
      );
      CREATE TABLE IF NOT EXISTS devices (
        id           TEXT    PRIMARY KEY,
        tenant       TEXT    NOT NULL,
        display_name TEXT    NOT NULL,
        token_hash   TEXT    NOT NULL,
        role         TEXT    NOT NULL DEFAULT 'member',
        revoked      INTEGER NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL,
        last_seen    INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant);
      CREATE INDEX IF NOT EXISTS idx_pending_tenant ON pending_devices(tenant);
    `);

    // ── Certificate column migrations (idempotent ALTER TABLE) ────────────────
    const pendingCols = this.db.prepare('PRAGMA table_info(pending_devices)').all().map(c => c.name);
    if (!pendingCols.includes('public_key')) {
      this.db.exec('ALTER TABLE pending_devices ADD COLUMN public_key TEXT DEFAULT NULL');
    }
    const deviceCols = this.db.prepare('PRAGMA table_info(devices)').all().map(c => c.name);
    if (!deviceCols.includes('public_key')) {
      this.db.exec('ALTER TABLE devices ADD COLUMN public_key TEXT DEFAULT NULL');
    }
    if (!deviceCols.includes('certificate')) {
      this.db.exec('ALTER TABLE devices ADD COLUMN certificate TEXT DEFAULT NULL');
    }
    if (!deviceCols.includes('cert_fingerprint')) {
      this.db.exec('ALTER TABLE devices ADD COLUMN cert_fingerprint TEXT DEFAULT NULL');
      this.db.exec('CREATE INDEX IF NOT EXISTS idx_devices_cert_fp ON devices(cert_fingerprint)');
    }
    if (!deviceCols.includes('identity_ecdh_pub_key')) {
      this.db.exec('ALTER TABLE devices ADD COLUMN identity_ecdh_pub_key TEXT DEFAULT NULL');
    }

    // ── Contact messages table ─────────────────────────────────────────────
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS contact_messages (
        id                      TEXT    PRIMARY KEY,
        from_device_id          TEXT    NOT NULL,
        to_device_id            TEXT    NOT NULL,
        sender_ephemeral_pub_key TEXT   NOT NULL,
        encrypted_iv            TEXT    NOT NULL,
        encrypted_ct            TEXT    NOT NULL,
        type                    TEXT    NOT NULL DEFAULT 'knock',
        sent_at                 INTEGER NOT NULL,
        expires_at              INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_contact_msg_to   ON contact_messages(to_device_id);
      CREATE INDEX IF NOT EXISTS idx_contact_msg_exp  ON contact_messages(expires_at);
    `);
  }

  // ─── Identity ECDH public key ─────────────────────────────────────────────

  /**
   * setIdentityEcdhPubKey — store the device's long-lived P-256 ECDH public key (JWK).
   * Called by the device on first use of the contacts feature (or on re-registration).
   */
  setIdentityEcdhPubKey(deviceId, jwkString) {
    this.db.prepare(`UPDATE devices SET identity_ecdh_pub_key = ? WHERE id = ? AND revoked = 0`)
      .run(jwkString, deviceId);
  }

  /**
   * getIdentityEcdhPubKey — return the stored JWK string or null.
   */
  getIdentityEcdhPubKey(deviceId) {
    const row = this.db.prepare(`SELECT identity_ecdh_pub_key FROM devices WHERE id = ? AND revoked = 0`)
      .get(deviceId);
    return row?.identity_ecdh_pub_key || null;
  }

  // ─── Contact messages ─────────────────────────────────────────────────────

  /**
   * createContactMessage — store an encrypted knock/message for an offline device.
   */
  createContactMessage({ fromDeviceId, toDeviceId, senderEphemeralPubKey, iv, ct, type = 'knock' }) {
    const id        = crypto.randomUUID();
    const now       = Date.now();
    const expiresAt = now + CONTACT_MSG_TTL * 1000;
    this.db.prepare(`
      INSERT INTO contact_messages
        (id, from_device_id, to_device_id, sender_ephemeral_pub_key, encrypted_iv, encrypted_ct, type, sent_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, fromDeviceId, toDeviceId, senderEphemeralPubKey, iv, ct, type, now, expiresAt);
    return id;
  }

  /**
   * getPendingMessages — return all non-expired messages for a device, oldest first.
   */
  getPendingMessages(toDeviceId) {
    return this.db.prepare(`
      SELECT id, from_device_id, to_device_id, sender_ephemeral_pub_key, encrypted_iv, encrypted_ct, type, sent_at
      FROM contact_messages
      WHERE to_device_id = ? AND expires_at > ?
      ORDER BY sent_at ASC
    `).all(toDeviceId, Date.now());
  }

  /**
   * ackMessage — delete a delivered message once the recipient acknowledges it.
   * The toDeviceId check prevents a different device from deleting another device's messages.
   */
  ackMessage(id, toDeviceId) {
    this.db.prepare(`DELETE FROM contact_messages WHERE id = ? AND to_device_id = ?`)
      .run(id, toDeviceId);
  }

  /**
   * cleanExpiredMessages — purge all messages past their TTL.
   * Call periodically (e.g., every 10 minutes) to keep the table from growing unbounded.
   */
  cleanExpiredMessages() {
    const info = this.db.prepare(`DELETE FROM contact_messages WHERE expires_at <= ?`).run(Date.now());
    return { deleted: info.changes };
  }

  // ─── Internal token hashing (PBKDF2 sync) ────────────────────────────────

  _hashToken(raw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const key  = crypto.pbkdf2Sync(raw, salt, PBKDF2_ITER, 32, 'sha256').toString('hex');
    return `pbkdf2:${salt}:${key}`;
  }

  _verifyToken(raw, stored) {
    const parts = stored.split(':');
    if (parts.length !== 3 || parts[0] !== 'pbkdf2') return false;
    const [, salt, expected] = parts;
    const actual = crypto.pbkdf2Sync(raw, salt, PBKDF2_ITER, 32, 'sha256').toString('hex');
    const a = Buffer.from(actual, 'hex');
    const e = Buffer.from(expected, 'hex');
    return a.length === e.length && crypto.timingSafeEqual(a, e);
  }

  // ─── Pending registrations ────────────────────────────────────────────────

  /**
   * createPending — store a new pending registration request.
   * @param {string} tenant
   * @param {string} displayName
   * @param {string} rawToken — client-generated secret (hashed before storage)
   * @returns {{ pendingId: string }}
   */
  createPending({ tenant, displayName, rawToken }) {
    const id        = crypto.randomUUID();
    const now       = Date.now();
    const expiresAt = now + PENDING_TTL * 1000;
    const tokenHash = this._hashToken(rawToken);
    this.db.prepare(`
      INSERT INTO pending_devices (id, tenant, display_name, token_hash, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(id, tenant, displayName, tokenHash, now, expiresAt);
    return { pendingId: id };
  }

  /**
   * getPendingStatus — used by the client to poll for admin activation.
   * @returns {{ status: 'pending'|'active'|'expired'|'not_found', deviceId?: string }}
   */
  getPendingStatus(pendingId) {
    const row = this.db.prepare(`SELECT * FROM pending_devices WHERE id = ?`).get(pendingId);
    if (!row) return { status: 'not_found' };
    if (row.activated_device_id) return { status: 'active', deviceId: row.activated_device_id };
    if (Date.now() > row.expires_at) return { status: 'expired' };
    return { status: 'pending' };
  }

  /**
   * listPending — admin view of all non-activated, non-expired requests for a tenant.
   */
  listPending(tenant) {
    return this.db.prepare(`
      SELECT id, tenant, display_name, created_at, expires_at
      FROM pending_devices
      WHERE tenant = ? AND activated_device_id IS NULL AND expires_at > ?
    `).all(tenant, Date.now());
  }

  /**
   * activate — admin approves a pending registration; creates a device record.
   * The pending row is retained with activated_device_id set (for client polling).
   * @returns {{ deviceId: string } | null}
   */
  activate({ pendingId, role = 'member', displayNameOverride } = {}) {
    const now = Date.now();
    const pending = this.db.prepare(`
      SELECT * FROM pending_devices
      WHERE id = ? AND activated_device_id IS NULL AND expires_at > ?
    `).get(pendingId, now);
    if (!pending) return null;

    const deviceId    = crypto.randomUUID();
    const displayName = (displayNameOverride && displayNameOverride.trim()) || pending.display_name;

    this.db.prepare(`
      INSERT INTO devices (id, tenant, display_name, token_hash, public_key, role, revoked, created_at, last_seen)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(deviceId, pending.tenant, displayName, pending.token_hash, pending.public_key ?? null, role, now, now);

    // Mark pending row as activated (not deleted — client needs it for status polling).
    this.db.prepare(`
      UPDATE pending_devices SET activated_device_id = ? WHERE id = ?
    `).run(deviceId, pendingId);

    return { deviceId };
  }

  // ─── Active devices ───────────────────────────────────────────────────────

  /**
   * getDevice — return the full device row (includes revoked flag, token_hash).
   * Returns null if not found.
   */
  getDevice(deviceId) {
    return this.db.prepare(`SELECT * FROM devices WHERE id = ?`).get(deviceId) || null;
  }

  /**
   * verifyDeviceToken — verify a raw token against the stored PBKDF2 hash.
   * Updates last_seen on success.
   * Returns the device record (without token_hash) or null.
   */
  verifyDeviceToken(deviceId, rawToken) {
    const device = this.getDevice(deviceId);
    if (!device || device.revoked) return null;
    if (!this._verifyToken(rawToken, device.token_hash)) return null;
    this.db.prepare(`UPDATE devices SET last_seen = ? WHERE id = ?`).run(Date.now(), deviceId);
    const { token_hash, ...rest } = device; // never return the hash
    return rest;
  }

  /**
   * revokeDevice — mark a device as revoked. Returns true if the device was found.
   */
  revokeDevice(deviceId) {
    const info = this.db.prepare(`UPDATE devices SET revoked = 1 WHERE id = ?`).run(deviceId);
    return info.changes > 0;
  }

  /**
   * updateDeviceRole — change the role of an active device.
   * The change takes effect on the device's next token refresh (existing JWTs remain valid
   * until their TTL expires, typically ≤ 1 hour).
   * Returns true if the device was found.
   */
  updateDeviceRole(deviceId, role) {
    const safeRole = String(role || '').trim().slice(0, 32) || 'member';
    const info = this.db.prepare(`UPDATE devices SET role = ? WHERE id = ? AND revoked = 0`).run(safeRole, deviceId);
    return info.changes > 0;
  }

  /**
   * deleteDevice — permanently remove a device record and its originating pending row.
   * Used by the device self-service DELETE /api/devices/me endpoint.
   * Returns true if a record was deleted.
   */
  deleteDevice(deviceId) {
    const info = this.db.prepare(`DELETE FROM devices WHERE id = ?`).run(deviceId);
    // Remove the pending row that activated this device so the slot is fully cleared.
    this.db.prepare(`DELETE FROM pending_devices WHERE activated_device_id = ?`).run(deviceId);
    return info.changes > 0;
  }

  /**
   * listDevices — list all devices for a tenant.
   * @param {string} tenant
   * @param {{ showRevoked?: boolean }} [opts]
   */
  listDevices(tenant, { showRevoked = false } = {}) {
    const sql = showRevoked
      ? `SELECT id, tenant, display_name, role, revoked, created_at, last_seen FROM devices WHERE tenant = ?`
      : `SELECT id, tenant, display_name, role, revoked, created_at, last_seen FROM devices WHERE tenant = ? AND revoked = 0`;
    return this.db.prepare(sql).all(tenant);
  }

  // ─── Certificate-based registration ──────────────────────────────────────

  /**
   * createPendingCert — store a pending cert-based registration.
   * Sets token_hash to the sentinel 'cert-only' (never a valid PBKDF2 hash).
   * @param {string} tenant
   * @param {string} displayName
   * @param {string} publicKeySPKI  base64-encoded SPKI public key from the device
   * @returns {{ pendingId: string }}
   */
  createPendingCert({ tenant, displayName, publicKeySPKI }) {
    const id        = crypto.randomUUID();
    const now       = Date.now();
    const expiresAt = now + PENDING_TTL * 1000;
    this.db.prepare(`
      INSERT INTO pending_devices (id, tenant, display_name, token_hash, public_key, created_at, expires_at)
      VALUES (?, ?, ?, 'cert-only', ?, ?, ?)
    `).run(id, tenant, displayName, publicKeySPKI, now, expiresAt);
    return { pendingId: id };
  }

  /**
   * activateWithCert — admin approves a cert-based pending registration.
   * @param {{ pendingId, role, displayNameOverride, certPem, certFingerprint }}
   * @returns {{ deviceId: string } | null}
   */
  activateWithCert({ pendingId, role = 'member', displayNameOverride, certPem, certFingerprint }) {
    const now = Date.now();
    const pending = this.db.prepare(`
      SELECT * FROM pending_devices
      WHERE id = ? AND activated_device_id IS NULL AND expires_at > ? AND public_key IS NOT NULL
    `).get(pendingId, now);
    if (!pending) return null;

    const deviceId    = crypto.randomUUID();
    const displayName = (displayNameOverride && displayNameOverride.trim()) || pending.display_name;

    this.db.prepare(`
      INSERT INTO devices
        (id, tenant, display_name, token_hash, role, revoked, public_key, certificate, cert_fingerprint, created_at, last_seen)
      VALUES (?, ?, ?, 'cert-only', ?, 0, ?, ?, ?, ?, ?)
    `).run(deviceId, pending.tenant, displayName, role, pending.public_key, certPem, certFingerprint, now, now);

    this.db.prepare(`
      UPDATE pending_devices SET activated_device_id = ? WHERE id = ?
    `).run(deviceId, pendingId);

    return { deviceId };
  }

  /**
   * getPendingRecord — return the raw pending_devices row (used by activate endpoint
   * to inspect public_key presence before deciding cert vs legacy path).
   * Returns null if not found.
   */
  getPendingRecord(pendingId) {
    return this.db.prepare(`SELECT * FROM pending_devices WHERE id = ?`).get(pendingId) || null;
  }

  /**
   * getPendingStatusFull — cert-aware version of getPendingStatus.
   * When active, also returns the stored certificate and fingerprint.
   * @returns {{ status, deviceId?, certificate?, certFingerprint? }}
   */
  getPendingStatusFull(pendingId) {
    const row = this.db.prepare(`SELECT * FROM pending_devices WHERE id = ?`).get(pendingId);
    if (!row) return { status: 'not_found' };
    if (row.activated_device_id) {
      const device = this.getDevice(row.activated_device_id);
      return {
        status: 'active',
        deviceId: row.activated_device_id,
        certificate:     device?.certificate      || null,
        certFingerprint: device?.cert_fingerprint || null,
      };
    }
    if (Date.now() > row.expires_at) return { status: 'expired' };
    return { status: 'pending' };
  }

  /**
   * verifyDeviceChallenge — verify an ECDSA P-256 challenge-response signature.
   * Called AFTER the nonce has been validated by _consumeChallenge() in index.js.
   * Updates last_seen on success.
   *
   * @param {string} deviceId
   * @param {string} nonce         The original challenge nonce string that was signed
   * @param {string} signatureB64  base64/base64url ECDSA-P256 signature (IEEE P1363 r|s format)
   * @returns {object|null}  Device record (without token_hash) on success, null on failure
   */
  verifyDeviceChallenge(deviceId, nonce, signatureB64) {
    const device = this.getDevice(deviceId);
    if (!device || device.revoked || !device.public_key) return null;

    try {
      const publicKey = crypto.createPublicKey({
        key:    Buffer.from(device.public_key, 'base64'),
        format: 'der',
        type:   'spki',
      });
      // Web Crypto produces IEEE P1363 (r|s) format; Node's `dsaEncoding` option handles this
      const valid = crypto.verify(
        'sha256',
        Buffer.from(nonce),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signatureB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
      );
      if (!valid) return null;
    } catch {
      return null;
    }

    this.db.prepare(`UPDATE devices SET last_seen = ? WHERE id = ?`).run(Date.now(), deviceId);
    const { token_hash, ...rest } = device;
    return rest;
  }

  /**
   * getDeviceByCertFingerprint — look up a non-revoked device by its certificate fingerprint.
   * Returns null if not found.
   */
  getDeviceByCertFingerprint(fingerprint) {
    if (!fingerprint) return null;
    const device = this.db.prepare(`
      SELECT * FROM devices WHERE cert_fingerprint = ? AND revoked = 0
    `).get(fingerprint);
    if (!device) return null;
    const { token_hash, ...rest } = device;
    return rest;
  }
}

module.exports = DeviceStore;
