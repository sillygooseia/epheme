'use strict';
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

const DB_PATH             = process.env.SYNC_DB_PATH        || path.join(__dirname, '..', 'data', 'sync.db');
const SYNC_DELTA_TTL_DAYS = parseInt(process.env.SYNC_DELTA_TTL_DAYS || '30', 10);

/**
 * SyncStore — SQLite-backed store for the BafGo Sovereign Sync system.
 *
 * Five-table design:
 *   sync_rooms            — room metadata (id, tenant, creator)
 *   sync_members          — per-room device membership, ECDH pub keys, wrapped room keys
 *   sync_deltas           — encrypted CRDT update blobs; auto-deleted when all active members ACK
 *   sync_history_requests — bootstrapping requests from new devices
 *   sync_snapshots        — full-doc encrypted snapshots for bootstrapping + key rotation
 *
 * Privacy model:
 *   - encrypted_ct is always AES-GCM ciphertext; the server cannot read content.
 *   - No plaintext data, credentials, or identity is stored beyond device IDs.
 *   - ACKs are JSON arrays; stale devices are excluded from ACK accounting after TTL.
 *
 * Requires 'better-sqlite3' (already a dependency for DeviceStore / PATStore).
 *
 * Production note: mount SYNC_DB_PATH to a persistent volume — the SQLite
 * file is lost on container restart if stored in the container layer.
 */
class SyncStore {
  constructor() {
    // Lazy-require so the module gracefully absent if better-sqlite3 not installed.
    const Database = require('better-sqlite3');
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    this.db = new Database(DB_PATH);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this._migrate();
  }

  _migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sync_rooms (
        room_id    TEXT    PRIMARY KEY,
        tenant     TEXT    NOT NULL,
        created_by TEXT    NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sync_members (
        room_id      TEXT    NOT NULL,
        device_id    TEXT    NOT NULL,
        ecdh_pub_key TEXT    NOT NULL,
        wrapped_key  TEXT    DEFAULT NULL,
        joined_at    INTEGER NOT NULL,
        last_ack_at  INTEGER DEFAULT NULL,
        stale        INTEGER NOT NULL DEFAULT 0,
        removed      INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (room_id, device_id)
      );
      CREATE INDEX IF NOT EXISTS idx_sync_members_room   ON sync_members(room_id);
      CREATE INDEX IF NOT EXISTS idx_sync_members_device ON sync_members(device_id);

      CREATE TABLE IF NOT EXISTS sync_deltas (
        id           TEXT    PRIMARY KEY,
        room_id      TEXT    NOT NULL,
        posted_by    TEXT    NOT NULL,
        iv           TEXT    NOT NULL,
        encrypted_ct TEXT    NOT NULL,
        created_at   INTEGER NOT NULL,
        acks         TEXT    NOT NULL DEFAULT '[]'
      );
      CREATE INDEX IF NOT EXISTS idx_sync_deltas_room    ON sync_deltas(room_id);
      CREATE INDEX IF NOT EXISTS idx_sync_deltas_created ON sync_deltas(created_at);

      CREATE TABLE IF NOT EXISTS sync_history_requests (
        id                TEXT    PRIMARY KEY,
        room_id           TEXT    NOT NULL,
        requesting_device TEXT    NOT NULL,
        requested_at      INTEGER NOT NULL,
        fulfilled         INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_sync_history_room ON sync_history_requests(room_id);

      CREATE TABLE IF NOT EXISTS sync_snapshots (
        id           TEXT    PRIMARY KEY,
        room_id      TEXT    NOT NULL,
        for_device   TEXT    NOT NULL,
        iv           TEXT    NOT NULL,
        encrypted_ct TEXT    NOT NULL,
        created_at   INTEGER NOT NULL,
        downloaded   INTEGER NOT NULL DEFAULT 0
      );
      CREATE INDEX IF NOT EXISTS idx_sync_snapshots_room_device ON sync_snapshots(room_id, for_device);
    `);
    // v2: room lock support — idempotent ALTER TABLE
    try { this.db.exec(`ALTER TABLE sync_rooms ADD COLUMN locked INTEGER NOT NULL DEFAULT 0`); } catch { /* column already exists */ }
  }

  // ─── Rooms ────────────────────────────────────────────────────────────────

  createRoom({ roomId, tenant, createdBy }) {
    const id  = roomId || crypto.randomUUID();
    const now = Date.now();
    this.db.prepare(`
      INSERT OR IGNORE INTO sync_rooms (room_id, tenant, created_by, created_at)
      VALUES (?, ?, ?, ?)
    `).run(id, tenant, createdBy, now);
    return id;
  }

  getRoom(roomId) {
    return this.db.prepare(`SELECT * FROM sync_rooms WHERE room_id = ?`).get(roomId) || null;
  }

  lockRoom(roomId) {
    this.db.prepare(`UPDATE sync_rooms SET locked = 1 WHERE room_id = ?`).run(roomId);
  }

  unlockRoom(roomId) {
    this.db.prepare(`UPDATE sync_rooms SET locked = 0 WHERE room_id = ?`).run(roomId);
  }

  // ─── Members ──────────────────────────────────────────────────────────────

  /** Add a new member, or re-activate a previously removed one. */
  addMember({ roomId, deviceId, ecdhPubKey }) {
    const now = Date.now();
    this.db.prepare(`
      INSERT INTO sync_members (room_id, device_id, ecdh_pub_key, joined_at, stale, removed)
      VALUES (?, ?, ?, ?, 0, 0)
      ON CONFLICT(room_id, device_id) DO UPDATE SET
        ecdh_pub_key = excluded.ecdh_pub_key,
        joined_at    = excluded.joined_at,
        stale        = 0,
        removed      = 0,
        wrapped_key  = CASE
                         WHEN excluded.ecdh_pub_key = sync_members.ecdh_pub_key
                         THEN sync_members.wrapped_key
                         ELSE NULL
                       END,
        last_ack_at  = NULL
    `).run(roomId, deviceId, ecdhPubKey, now);
  }

  getMember(roomId, deviceId) {
    return this.db.prepare(
      `SELECT * FROM sync_members WHERE room_id = ? AND device_id = ?`
    ).get(roomId, deviceId) || null;
  }

  /** Returns all active (non-removed) members for a room. */
  getMembers(roomId) {
    return this.db.prepare(
      `SELECT * FROM sync_members WHERE room_id = ? AND removed = 0`
    ).all(roomId);
  }

  /** Returns active non-stale members (used for ACK accounting). */
  _getActiveMembers(roomId) {
    return this.db.prepare(
      `SELECT * FROM sync_members WHERE room_id = ? AND removed = 0 AND stale = 0`
    ).all(roomId);
  }

  setWrappedKey(roomId, deviceId, wrappedKey) {
    this.db.prepare(
      `UPDATE sync_members SET wrapped_key = ? WHERE room_id = ? AND device_id = ?`
    ).run(wrappedKey, roomId, deviceId);
  }

  markStale(roomId, deviceId) {
    this.db.prepare(
      `UPDATE sync_members SET stale = 1 WHERE room_id = ? AND device_id = ?`
    ).run(roomId, deviceId);
  }

  unmarkStale(roomId, deviceId) {
    this.db.prepare(
      `UPDATE sync_members SET stale = 0, last_ack_at = ? WHERE room_id = ? AND device_id = ?`
    ).run(Date.now(), roomId, deviceId);
  }

  /**
   * Remove a device from a room. After removal it is excluded from ACK accounting
   * on all pending deltas; deltas that are now fully-acked by remaining members
   * are deleted immediately.
   */
  removeDevice(roomId, deviceId) {
    this.db.prepare(
      `UPDATE sync_members SET removed = 1 WHERE room_id = ? AND device_id = ?`
    ).run(roomId, deviceId);
    // Re-evaluate all pending deltas — some may now be fully acked.
    const deltas = this.db.prepare(
      `SELECT id FROM sync_deltas WHERE room_id = ?`
    ).all(roomId);
    for (const { id } of deltas) {
      this._maybeDeleteDelta(id, roomId);
    }
  }

  /**
   * Atomically update wrapped keys for multiple members (key rotation).
   * @param {string} roomId
   * @param {{ deviceId: string, wrappedKey: string }[]} newWrappedKeys
   */
  rotateKeys(roomId, newWrappedKeys) {
    const update = this.db.prepare(
      `UPDATE sync_members SET wrapped_key = ? WHERE room_id = ? AND device_id = ?`
    );
    const tx = this.db.transaction((keys) => {
      for (const { deviceId, wrappedKey } of keys) {
        update.run(wrappedKey, roomId, deviceId);
      }
    });
    tx(newWrappedKeys);
  }

  // ─── Deltas ───────────────────────────────────────────────────────────────

  postDelta({ roomId, postedBy, iv, encryptedCt }) {
    const id  = crypto.randomUUID();
    const now = Date.now();
    this.db.prepare(`
      INSERT INTO sync_deltas (id, room_id, posted_by, iv, encrypted_ct, created_at, acks)
      VALUES (?, ?, ?, ?, ?, ?, '[]')
    `).run(id, roomId, postedBy, iv, encryptedCt, now);
    return id;
  }

  /** Returns all deltas for this room that have not yet been ACK'd by deviceId. */
  pullDeltas(roomId, deviceId) {
    const rows = this.db.prepare(
      `SELECT * FROM sync_deltas WHERE room_id = ? ORDER BY created_at ASC`
    ).all(roomId);
    return rows.filter((row) => {
      try {
        const acks = JSON.parse(row.acks);
        return !acks.includes(deviceId);
      } catch {
        return true;
      }
    });
  }

  /**
   * Record that deviceId has acknowledged deltaId.
   * Updates last_ack_at on the member row and deletes the delta if fully ACK'd.
   */
  ackDelta(deltaId, deviceId) {
    const row = this.db.prepare(`SELECT * FROM sync_deltas WHERE id = ?`).get(deltaId);
    if (!row) return;
    let acks;
    try { acks = JSON.parse(row.acks); } catch { acks = []; }
    if (!acks.includes(deviceId)) {
      acks.push(deviceId);
      this.db.prepare(`UPDATE sync_deltas SET acks = ? WHERE id = ?`)
        .run(JSON.stringify(acks), deltaId);
      this.db.prepare(`
        UPDATE sync_members SET last_ack_at = ?, stale = 0
        WHERE room_id = ? AND device_id = ?
      `).run(Date.now(), row.room_id, deviceId);
    }
    this._maybeDeleteDelta(deltaId, row.room_id);
  }

  /** Delete a delta if all active (non-stale, non-removed) members have ACK'd it. */
  _maybeDeleteDelta(deltaId, roomId) {
    const row = this.db.prepare(`SELECT acks FROM sync_deltas WHERE id = ?`).get(deltaId);
    if (!row) return;
    const activeMembers = this._getActiveMembers(roomId);
    if (activeMembers.length === 0) return;
    let acks;
    try { acks = JSON.parse(row.acks); } catch { acks = []; }
    const allAcked = activeMembers.every((m) => acks.includes(m.device_id));
    if (allAcked) {
      this.db.prepare(`DELETE FROM sync_deltas WHERE id = ?`).run(deltaId);
    }
  }

  // ─── History requests ─────────────────────────────────────────────────────

  createHistoryRequest({ roomId, requestingDevice }) {
    const id  = crypto.randomUUID();
    const now = Date.now();
    this.db.prepare(`
      INSERT INTO sync_history_requests (id, room_id, requesting_device, requested_at, fulfilled)
      VALUES (?, ?, ?, ?, 0)
    `).run(id, roomId, requestingDevice, now);
    return id;
  }

  getPendingHistoryRequests(roomId) {
    return this.db.prepare(
      `SELECT * FROM sync_history_requests WHERE room_id = ? AND fulfilled = 0`
    ).all(roomId);
  }

  fulfillHistoryRequest(requestId) {
    this.db.prepare(
      `UPDATE sync_history_requests SET fulfilled = 1 WHERE id = ?`
    ).run(requestId);
  }

  // ─── Snapshots ────────────────────────────────────────────────────────────

  createSnapshot({ roomId, forDevice, iv, encryptedCt }) {
    const id  = crypto.randomUUID();
    const now = Date.now();
    this.db.prepare(`
      INSERT INTO sync_snapshots (id, room_id, for_device, iv, encrypted_ct, created_at, downloaded)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(id, roomId, forDevice, iv, encryptedCt, now);
    return id;
  }

  /** Returns the most recent undownloaded snapshot for a device. */
  getSnapshot(roomId, forDevice) {
    return this.db.prepare(`
      SELECT * FROM sync_snapshots
      WHERE room_id = ? AND (for_device = ? OR for_device = '*') AND downloaded = 0
      ORDER BY created_at DESC
      LIMIT 1
    `).get(roomId, forDevice) || null;
  }

  markSnapshotDownloaded(snapshotId) {
    this.db.prepare(`UPDATE sync_snapshots SET downloaded = 1 WHERE id = ?`).run(snapshotId);
  }

  // ─── Cleanup ──────────────────────────────────────────────────────────────

  /**
   * cleanupExpiredDeltas — intended to run daily.
   *
   * 1. Mark devices stale if last_ack_at (or joined_at if never acked) is older than ttlDays.
   * 2. Delete deltas where all active non-stale members have now acked.
   * 3. Hard-delete any delta older than ttlDays regardless of ACK state.
   * 4. Delete downloaded snapshots older than 24 h.
   *
   * @returns {{ staleMarked: number, deltasDeleted: number }}
   */
  cleanupExpiredDeltas(ttlDays = SYNC_DELTA_TTL_DAYS) {
    const ttlMs     = ttlDays * 24 * 60 * 60 * 1000;
    const cutoff    = Date.now() - ttlMs;
    const oneDayAgo = Date.now() - 86400 * 1000;

    // 1. Mark stale
    const staleInfo = this.db.prepare(`
      UPDATE sync_members SET stale = 1
      WHERE removed = 0 AND (
        (last_ack_at IS NOT NULL AND last_ack_at < ?) OR
        (last_ack_at IS NULL     AND joined_at  < ?)
      )
    `).run(cutoff, cutoff);

    // 2. Re-evaluate deltas (now that some members may be newly stale)
    let deltasDeleted = 0;
    const rooms = this.db.prepare(`SELECT DISTINCT room_id FROM sync_deltas`).all().map(r => r.room_id);
    for (const roomId of rooms) {
      const deltaIds = this.db.prepare(`SELECT id FROM sync_deltas WHERE room_id = ?`).all(roomId);
      for (const { id } of deltaIds) {
        const before = this.db.prepare(`SELECT id FROM sync_deltas WHERE id = ?`).get(id);
        this._maybeDeleteDelta(id, roomId);
        const after = this.db.prepare(`SELECT id FROM sync_deltas WHERE id = ?`).get(id);
        if (before && !after) deltasDeleted++;
      }
    }

    // 3. Hard-delete old deltas past TTL
    const hardInfo = this.db.prepare(`DELETE FROM sync_deltas WHERE created_at < ?`).run(cutoff);
    deltasDeleted += hardInfo.changes;

    // 4. Clean up downloaded snapshots older than 24 h
    this.db.prepare(`DELETE FROM sync_snapshots WHERE downloaded = 1 AND created_at < ?`).run(oneDayAgo);

    return { staleMarked: staleInfo.changes, deltasDeleted };
  }

  /** Delete every row in every sync table. For dev resets only. */
  wipeAll() {
    this.db.exec(`
      DELETE FROM sync_snapshots;
      DELETE FROM sync_history_requests;
      DELETE FROM sync_deltas;
      DELETE FROM sync_members;
      DELETE FROM sync_rooms;
    `);
  }
}

module.exports = SyncStore;
