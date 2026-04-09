/**
 * EphemeDevice — reads the Hub device credential from its IndexedDB.
 *
 * Pure TypeScript, zero npm dependencies.
 * Wrap in a tool-specific @Injectable Angular service that owns the signals.
 */

const DEVICE_DB_NAME = 'epheme_device';
const DEVICE_STORE   = 'credentials';
const DEVICE_KEY     = 'device';
const HUB_JWT_LS_KEY = 'epheme_hub_device_jwt';

export interface EphemeDeviceCredential {
  deviceId: string;
  displayName: string;
  status: 'pending' | 'active';
  jwt: string | null;
  jwtExpiresAt: number; // Unix ms
}

export class EphemeDevice {
  private _credential: EphemeDeviceCredential | null = null;

  get isRegistered(): boolean {
    const c = this._credential;
    return !!(c && c.status === 'active' && c.jwt && c.jwtExpiresAt > Date.now() + 30_000);
  }

  get deviceId(): string | null {
    return this._credential?.deviceId ?? null;
  }

  get jwt(): string | null {
    const c = this._credential;
    if (!c?.jwt) return null;
    if (c.jwtExpiresAt <= Date.now() + 30_000) return null;
    return c.jwt;
  }

  get displayName(): string | null {
    return this._credential?.displayName ?? null;
  }

  /**
   * Load the credential from the Hub IndexedDB.
   * Call once during app init. Silently no-ops if Hub has never registered.
   */
  async load(): Promise<void> {
    const cred = await this._readFromIdb();
    if (cred) {
      this._credential = cred;
      if (cred.jwt) {
        localStorage.setItem(HUB_JWT_LS_KEY, cred.jwt);
      }
    }
  }

  /**
   * Returns a stable device identifier regardless of Hub registration status.
   *
   * Priority:
   *   1. An existing value stored under `fallbackKey` in localStorage — preserves
   *      identity continuity if the device was previously anonymous. This prevents
   *      a device from appearing as a new identity after Hub registration.
   *   2. Hub-loaded deviceId (from load()) — used when no prior local identity exists
   *   3. A newly generated anonymous UUID written to localStorage under `fallbackKey`
   *
   * If the device carries an active Hub JWT, callers should use `jwt` directly
   * via `Authorization: Bearer` instead of calling this method.
   *
   * Call after load(). Tools should pass a namespaced key, e.g. `'mytool:device-id'`.
   */
  getStableId(fallbackKey: string): string {
    // Prefer an already-established local identity to avoid switching IDs mid-session
    // (e.g. voting anonymously then connecting Hub would otherwise orphan the prior vote).
    const existing = localStorage.getItem(fallbackKey);
    if (existing) return existing;

    // No prior local identity — use Hub deviceId if available
    if (this._credential?.deviceId) {
      localStorage.setItem(fallbackKey, this._credential.deviceId);
      return this._credential.deviceId;
    }

    // Generate a fresh anonymous UUID and persist it
    const id =
      (globalThis.crypto?.randomUUID?.() ??
        (() => {
          const b = new Uint8Array(16);
          (globalThis.crypto?.getRandomValues ?? ((arr: Uint8Array) => arr.map(() => Math.floor(Math.random() * 256))))(b);
          b[6] = (b[6] & 0x0f) | 0x40;
          b[8] = (b[8] & 0x3f) | 0x80;
          const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
          return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
        })());
    localStorage.setItem(fallbackKey, id);
    return id;
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  private _readFromIdb(): Promise<EphemeDeviceCredential | null> {
    return new Promise((resolve) => {
      const req = indexedDB.open(DEVICE_DB_NAME, 1);
      req.onerror = () => resolve(null);
      req.onupgradeneeded = (e) => {
        (e.target as IDBOpenDBRequest).result.close();
        resolve(null);
      };
      req.onsuccess = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(DEVICE_STORE)) {
          db.close();
          resolve(null);
          return;
        }
        const tx = db.transaction(DEVICE_STORE, 'readonly');
        const getReq = tx.objectStore(DEVICE_STORE).get(DEVICE_KEY);
        getReq.onsuccess = () => {
          db.close();
          resolve((getReq.result as EphemeDeviceCredential | undefined) ?? null);
        };
        getReq.onerror = () => { db.close(); resolve(null); };
      };
    });
  }
}
