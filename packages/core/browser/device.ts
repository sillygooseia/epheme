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
