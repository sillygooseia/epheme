'use strict';
const crypto = require('crypto');

const SYNC_SNAPSHOT_MAX_BYTES = parseInt(process.env.SYNC_SNAPSHOT_MAX_BYTES || String(10 * 1024 * 1024), 10);
const SYNC_DELTA_MAX_BYTES    = parseInt(process.env.SYNC_DELTA_MAX_BYTES    || String(512 * 1024), 10);

/**
 * registerSyncRoutes — registers all Sovereign Sync REST endpoints on `app`.
 *
 * All routes require a valid device JWT (Bearer token).
 * Socket events emitted:
 *   sync:member-join-requested  { roomId, deviceId, ecdhPubKey }  → room members
 *   sync:delta-posted           { roomId, deltaId }               → room members
 *   sync:key-rotation-required  { roomId }                        → room members
 *   sync:history-requested      { roomId, deviceId, requestId }   → room members
 *
 * @param {import('express').Application} app
 * @param {import('socket.io').Server} io
 * @param {import('./SyncStore')} syncStore
 * @param {(token: string) => object|null} verifyDeviceJWT
 */
function registerSyncRoutes(app, io, syncStore, verifyDeviceJWT) {

  // ─── Auth middleware ───────────────────────────────────────────────────────

  function requireDevice(req, res, next) {
    const authHeader  = req.get('authorization') || '';
    const bearerToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const payload     = verifyDeviceJWT(bearerToken);
    if (!payload) return res.status(401).json({ error: 'Device JWT required' });
    req.devicePayload = payload;
    req.deviceId      = payload.device_id;
    next();
  }

  // ─── Input validation helpers ─────────────────────────────────────────────

  /** Verify an object looks like a P-256 ECDH JWK public key. */
  function isValidEcdhPubKey(v) {
    return v && typeof v === 'object'
      && v.kty === 'EC'
      && v.crv === 'P-256'
      && typeof v.x === 'string'
      && typeof v.y === 'string';
  }

  /** Verify a string is valid base64/base64url and within a size limit. */
  function isValidBase64(v, maxLength) {
    return typeof v === 'string'
      && v.length <= maxLength
      && /^[A-Za-z0-9+/=_-]+$/.test(v);
  }

  // ─── POST /api/sync/rooms ─────────────────────────────────────────────────
  // Create a new sync room. Caller becomes its first member.
  // Body: { ecdhPubKey: JsonWebKey }
  app.post('/api/sync/rooms', requireDevice, (req, res) => {
    const { ecdhPubKey } = req.body || {};
    if (!isValidEcdhPubKey(ecdhPubKey)) {
      return res.status(400).json({ error: 'Invalid ecdhPubKey — must be P-256 JWK' });
    }
    const roomId = crypto.randomUUID();
    try {
      syncStore.createRoom({ roomId, tenant: req.devicePayload.tenant || '__default__', createdBy: req.deviceId });
      syncStore.addMember({ roomId, deviceId: req.deviceId, ecdhPubKey: JSON.stringify(ecdhPubKey) });
      return res.json({ roomId });
    } catch (err) {
      console.error('[sync] createRoom error', err.message);
      return res.status(500).json({ error: 'Failed to create sync room' });
    }
  });

  // ─── GET /api/sync/rooms/:roomId ──────────────────────────────────────────
  // Room metadata + member count (caller must be a member).
  app.get('/api/sync/rooms/:roomId', requireDevice, (req, res) => {
    const room = syncStore.getRoom(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    const myMembership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!myMembership || myMembership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const members = syncStore.getMembers(room.room_id);
    res.json({ roomId: room.room_id, createdAt: room.created_at, memberCount: members.length, locked: room.locked === 1, createdBy: room.created_by });
  });

  // ─── PATCH /api/sync/rooms/:roomId/lock ──────────────────────────────────
  // Lock the room — only the room creator may call this.
  app.patch('/api/sync/rooms/:roomId/lock', requireDevice, (req, res) => {
    const room = syncStore.getRoom(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    if (room.created_by !== req.deviceId) {
      return res.status(403).json({ error: 'Only the room creator may lock or unlock the room' });
    }
    syncStore.lockRoom(req.params.roomId);
    res.json({ ok: true, locked: true });
  });

  // ─── PATCH /api/sync/rooms/:roomId/unlock ────────────────────────────────
  // Unlock the room — only the room creator may call this.
  app.patch('/api/sync/rooms/:roomId/unlock', requireDevice, (req, res) => {
    const room = syncStore.getRoom(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    if (room.created_by !== req.deviceId) {
      return res.status(403).json({ error: 'Only the room creator may lock or unlock the room' });
    }
    syncStore.unlockRoom(req.params.roomId);
    res.json({ ok: true, locked: false });
  });

  // ─── GET /api/sync/rooms/:roomId/members ─────────────────────────────────
  // List active members with their ECDH public keys (for key wrapping by existing members).
  app.get('/api/sync/rooms/:roomId/members', requireDevice, (req, res) => {
    const room = syncStore.getRoom(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    const myMembership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!myMembership || myMembership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const members = syncStore.getMembers(req.params.roomId).map((m) => {
      let ecdhPubKey;
      try { ecdhPubKey = JSON.parse(m.ecdh_pub_key); } catch { ecdhPubKey = null; }
      return {
        deviceId:   m.device_id,
        ecdhPubKey,
        hasKey:     !!m.wrapped_key,
        joinedAt:   m.joined_at,
        stale:      m.stale === 1,
      };
    });
    res.json({ members });
  });

  // ─── POST /api/sync/rooms/:roomId/members ─────────────────────────────────
  // Join an existing sync room.
  // Body: { ecdhPubKey: JsonWebKey }
  app.post('/api/sync/rooms/:roomId/members', requireDevice, (req, res) => {
    const room = syncStore.getRoom(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    if (room.locked === 1) {
      return res.status(423).json({ error: 'Room is locked — join requests are not accepted' });
    }
    const { ecdhPubKey } = req.body || {};
    if (!isValidEcdhPubKey(ecdhPubKey)) {
      return res.status(400).json({ error: 'Invalid ecdhPubKey — must be P-256 JWK' });
    }
    try {
      syncStore.addMember({ roomId: req.params.roomId, deviceId: req.deviceId, ecdhPubKey: JSON.stringify(ecdhPubKey) });
      // Notify online members so they can deliver the wrapped key to the new member.
      io.to(`sync:${req.params.roomId}`).emit('sync:member-join-requested', {
        roomId:   req.params.roomId,
        deviceId: req.deviceId,
        ecdhPubKey,
      });
      res.json({ ok: true });
    } catch (err) {
      console.error('[sync] addMember error', err.message);
      res.status(500).json({ error: 'Failed to join sync room' });
    }
  });

  // ─── PUT /api/sync/rooms/:roomId/members/:deviceId/wrapped-key ───────────
  // An existing member delivers a wrapped room key to a specific member.
  // Body: { wrappedKey: string (base64url) }
  app.put('/api/sync/rooms/:roomId/members/:deviceId/wrapped-key', requireDevice, (req, res) => {
    const { roomId, deviceId: targetDeviceId } = req.params;
    const callerMembership = syncStore.getMember(roomId, req.deviceId);
    if (!callerMembership || callerMembership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const { wrappedKey } = req.body || {};
    if (!isValidBase64(wrappedKey, 512)) {
      return res.status(400).json({ error: 'Invalid wrappedKey' });
    }
    const targetMembership = syncStore.getMember(roomId, targetDeviceId);
    if (!targetMembership || targetMembership.removed) {
      return res.status(404).json({ error: 'Target device not found in room' });
    }
    syncStore.setWrappedKey(roomId, targetDeviceId, wrappedKey);
    // Notify the recipient device in real time so it can unwrap immediately
    // without waiting for its next poll tick.
    io.to(`sync:${roomId}`).emit('sync:key-delivered', { roomId, deviceId: targetDeviceId });
    res.json({ ok: true });
  });

  // ─── GET /api/sync/rooms/:roomId/members/me/wrapped-key ──────────────────
  // Poll for this device's wrapped room key (delivered by an existing member).
  // NOTE: this route must be registered BEFORE the /:deviceId route to avoid
  // "me" being treated as a device ID parameter.
  app.get('/api/sync/rooms/:roomId/members/me/wrapped-key', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    if (!membership.wrapped_key) {
      // Re-broadcast join request so any online keyholder gets nudged on every poll tick.
      let ecdhPubKey;
      try { ecdhPubKey = JSON.parse(membership.ecdh_pub_key); } catch {}
      if (ecdhPubKey) {
        io.to(`sync:${req.params.roomId}`).emit('sync:member-join-requested', {
          roomId:    req.params.roomId,
          deviceId:  req.deviceId,
          ecdhPubKey,
        });
      }
      return res.json({ ready: false });
    }
    res.json({ ready: true, wrappedKey: membership.wrapped_key });
  });

  // ─── DELETE /api/sync/rooms/:roomId/members/:deviceId ────────────────────
  // Remove a member. Caller may remove themselves or any member if they hold admin/executive role.
  // For forward-secrecy the caller SHOULD include new wrapped keys for remaining members
  // and a rekey snapshot (otherwise remaining members keep using the old key).
  // Body: { newWrappedKeys?: [{deviceId, wrappedKey}], rekeySnapshot?: {iv, ct} }
  app.delete('/api/sync/rooms/:roomId/members/:deviceId', requireDevice, (req, res) => {
    const { roomId, deviceId: targetDeviceId } = req.params;
    const isSelf     = req.deviceId === targetDeviceId;
    const room       = syncStore.getRoom(roomId);
    if (!room) return res.status(404).json({ error: 'Sync room not found' });
    const isCreator  = room.created_by === req.deviceId;
    if (!isSelf && !isCreator) {
      return res.status(403).json({ error: 'Only the room creator may remove other members' });
    }
    // The creator cannot be kicked by anyone (even themselves via this path — use leaveRoom).
    if (targetDeviceId === room.created_by && !isSelf) {
      return res.status(403).json({ error: 'The room creator cannot be removed by others' });
    }
    const targetMembership = syncStore.getMember(roomId, targetDeviceId);
    if (!targetMembership || targetMembership.removed) {
      return res.status(404).json({ error: 'Target device not found in room' });
    }

    const { newWrappedKeys, rekeySnapshot } = req.body || {};

    // Apply new wrapped keys atomically before removing the member.
    if (Array.isArray(newWrappedKeys) && newWrappedKeys.length > 0) {
      const safeKeys = newWrappedKeys
        .filter((k) => typeof k?.deviceId === 'string' && isValidBase64(k?.wrappedKey, 512))
        .map((k) => ({ deviceId: k.deviceId, wrappedKey: k.wrappedKey }));
      if (safeKeys.length > 0) syncStore.rotateKeys(roomId, safeKeys);
    }

    // Store rekey snapshot (for_device = '*' = available to all remaining members).
    if (rekeySnapshot?.iv && rekeySnapshot?.ct) {
      if (
        isValidBase64(rekeySnapshot.iv, 64) &&
        isValidBase64(rekeySnapshot.ct, SYNC_SNAPSHOT_MAX_BYTES)
      ) {
        syncStore.createSnapshot({
          roomId,
          forDevice:   '*',
          iv:          rekeySnapshot.iv,
          encryptedCt: rekeySnapshot.ct,
        });
      }
    }

    syncStore.removeDevice(roomId, targetDeviceId);
    io.to(`sync:${roomId}`).emit('sync:key-rotation-required', { roomId });
    res.json({ ok: true });
  });

  // ─── GET /api/sync/rooms/:roomId/deltas ───────────────────────────────────
  // Pull all unACK'd deltas for the calling device.
  // Returns { deltas: [...], needsHistoryRequest: bool }
  // needsHistoryRequest is true when the device was marked stale (now re-activated).
  app.get('/api/sync/rooms/:roomId/deltas', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const wasStale = membership.stale === 1;
    if (wasStale) syncStore.unmarkStale(req.params.roomId, req.deviceId);

    const deltas = syncStore.pullDeltas(req.params.roomId, req.deviceId).map((d) => ({
      id:        d.id,
      iv:        d.iv,
      ct:        d.encrypted_ct,
      postedBy:  d.posted_by,
      createdAt: d.created_at,
    }));
    res.json({ deltas, needsHistoryRequest: wasStale });
  });

  // ─── POST /api/sync/rooms/:roomId/deltas ──────────────────────────────────
  // Post an encrypted CRDT delta. Auto-ACK'd for the posting device.
  // Body: { iv: string, ct: string }
  app.post('/api/sync/rooms/:roomId/deltas', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const { iv, ct } = req.body || {};
    if (!isValidBase64(iv, 64)) {
      return res.status(400).json({ error: 'Invalid iv' });
    }
    if (!isValidBase64(ct, SYNC_DELTA_MAX_BYTES)) {
      return res.status(400).json({ error: 'Delta ct too large or invalid' });
    }
    const deltaId = syncStore.postDelta({
      roomId:      req.params.roomId,
      postedBy:    req.deviceId,
      iv,
      encryptedCt: ct,
    });
    // Auto-ACK for the posting device (they already have the data).
    syncStore.ackDelta(deltaId, req.deviceId);
    // Push notification to online room members.
    io.to(`sync:${req.params.roomId}`).emit('sync:delta-posted', {
      roomId:  req.params.roomId,
      deltaId,
    });
    res.json({ ok: true, deltaId });
  });

  // ─── POST /api/sync/rooms/:roomId/deltas/:deltaId/ack ────────────────────
  // Acknowledge receipt and application of a delta.
  app.post('/api/sync/rooms/:roomId/deltas/:deltaId/ack', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    syncStore.ackDelta(req.params.deltaId, req.deviceId);
    res.json({ ok: true });
  });

  // ─── POST /api/sync/rooms/:roomId/history-request ────────────────────────
  // New or re-joining device requests a full-doc snapshot from any online peer.
  app.post('/api/sync/rooms/:roomId/history-request', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const requestId = syncStore.createHistoryRequest({
      roomId:           req.params.roomId,
      requestingDevice: req.deviceId,
    });
    // Notify online peers so they can fulfill the request.
    io.to(`sync:${req.params.roomId}`).emit('sync:history-requested', {
      roomId:    req.params.roomId,
      deviceId:  req.deviceId,
      requestId,
    });
    res.json({ ok: true, requestId });
  });

  // ─── GET /api/sync/rooms/:roomId/history-snapshot ────────────────────────
  // Poll: check if a snapshot is available for this device.
  app.get('/api/sync/rooms/:roomId/history-snapshot', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const snapshot = syncStore.getSnapshot(req.params.roomId, req.deviceId);
    if (!snapshot) return res.json({ ready: false });
    syncStore.markSnapshotDownloaded(snapshot.id);
    res.json({ ready: true, iv: snapshot.iv, ct: snapshot.encrypted_ct });
  });

  // ─── POST /api/sync/rooms/:roomId/snapshots ───────────────────────────────
  // Upload a full-doc snapshot (to fulfill a history request or as a rekey snapshot).
  // Body: { forDevice: string, iv: string, ct: string, requestId?: string }
  app.post('/api/sync/rooms/:roomId/snapshots', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const { forDevice, iv, ct, requestId } = req.body || {};
    if (typeof forDevice !== 'string' || forDevice.length < 1 || forDevice.length > 200) {
      return res.status(400).json({ error: 'Invalid forDevice' });
    }
    if (!isValidBase64(iv, 64)) return res.status(400).json({ error: 'Invalid iv' });
    if (!isValidBase64(ct, SYNC_SNAPSHOT_MAX_BYTES)) {
      return res.status(400).json({ error: 'Snapshot ct too large or invalid' });
    }
    syncStore.createSnapshot({ roomId: req.params.roomId, forDevice, iv, encryptedCt: ct });
    if (requestId && typeof requestId === 'string') {
      syncStore.fulfillHistoryRequest(requestId);
    }
    res.json({ ok: true });
  });

  // ─── POST /api/sync/rooms/:roomId/wrapped-keys/batch ─────────────────────
  // Upload new wrapped keys for multiple members at once (standalone key rotation).
  // Body: { keys: [{ deviceId: string, wrappedKey: string }] }
  app.post('/api/sync/rooms/:roomId/wrapped-keys/batch', requireDevice, (req, res) => {
    const membership = syncStore.getMember(req.params.roomId, req.deviceId);
    if (!membership || membership.removed) {
      return res.status(403).json({ error: 'Not a member of this sync room' });
    }
    const { keys } = req.body || {};
    if (!Array.isArray(keys)) return res.status(400).json({ error: 'keys must be an array' });

    const safeKeys = keys
      .filter((k) => typeof k?.deviceId === 'string' && isValidBase64(k?.wrappedKey, 512))
      .map((k) => ({ deviceId: k.deviceId, wrappedKey: k.wrappedKey }));

    if (safeKeys.length === 0) return res.status(400).json({ error: 'No valid keys provided' });
    syncStore.rotateKeys(req.params.roomId, safeKeys);
    res.json({ ok: true, updated: safeKeys.length });
  });

  // ─── DELETE /api/sync — wipe all sync data (dev reset tool) ─────────────
  // Requires a valid device JWT. Drops all rooms, members, deltas, and snapshots.
  app.delete('/api/sync', requireDevice, (req, res) => {
    try {
      syncStore.wipeAll();
      console.log('[sync] All sync data wiped by', req.deviceId);
      res.json({ ok: true });
    } catch (err) {
      console.error('[sync] wipeAll error', err.message);
      res.status(500).json({ error: 'Failed to wipe sync data' });
    }
  });

  console.log('[sync] Sovereign Sync routes registered.');
}

module.exports = registerSyncRoutes;
