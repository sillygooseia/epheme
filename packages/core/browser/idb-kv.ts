/**
 * Simple key-value IndexedDB helper for single-store scenarios.
 *
 * Useful for credentials/config blobs where callers want get/put/delete by key
 * without defining typed keyPath schemas.
 */
export class IdbKeyValueStore {
  private _db: IDBDatabase | null = null;
  private _opening: Promise<IDBDatabase> | null = null;

  constructor(
    private readonly _dbName: string,
    private readonly _version: number,
    private readonly _storeName: string,
  ) {}

  private _resetDb(): Promise<void> {
    this._db?.close();
    this._db = null;
    this._opening = null;

    return new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(this._dbName);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error(`IndexedDB delete blocked for ${this._dbName}`));
    });
  }

  private _isMissingStoreError(error: unknown): boolean {
    return error instanceof DOMException && error.name === 'NotFoundError';
  }

  private _openDb(): Promise<IDBDatabase> {
    if (this._db) return Promise.resolve(this._db);
    if (this._opening) return this._opening;

    this._opening = new Promise((resolve, reject) => {
      const req = indexedDB.open(this._dbName, this._version);
      req.onupgradeneeded = (e) => {
        const db = (e.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(this._storeName)) {
          db.createObjectStore(this._storeName);
        }
      };
      req.onsuccess = (e) => {
        const db = (e.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(this._storeName)) {
          // Stale database exists at this version without the expected store.
          // Delete it so the next open triggers onupgradeneeded and recreates it.
          this._db = db;
          this._resetDb().then(() => this._openDb().then(resolve, reject), reject);
          return;
        }
        db.onversionchange = () => {
          if (this._db === db) {
            this._db.close();
            this._db = null;
          } else {
            db.close();
          }
        };
        this._db = db;
        this._opening = null;
        resolve(this._db);
      };
      req.onerror = () => {
        this._opening = null;
        reject(req.error);
      };
    });

    return this._opening;
  }

  async get<T>(key: IDBValidKey): Promise<T | null> {
    return this._runTransaction('readonly', (store, resolve, reject) => {
      const req = store.get(key);
      req.onsuccess = () => resolve((req.result as T) ?? null);
      req.onerror = () => reject(req.error);
    });
  }

  async put(key: IDBValidKey, value: unknown): Promise<void> {
    await this._runTransaction('readwrite', (store, resolve, reject) => {
      const req = store.put(value, key);
      req.onsuccess = () => resolve(undefined as void);
      req.onerror = () => reject(req.error);
    });
  }

  async delete(key: IDBValidKey): Promise<void> {
    await this._runTransaction('readwrite', (store, resolve, reject) => {
      const req = store.delete(key);
      req.onsuccess = () => resolve(undefined as void);
      req.onerror = () => reject(req.error);
    });
  }

  private async _runTransaction<T>(
    mode: IDBTransactionMode,
    execute: (
      store: IDBObjectStore,
      resolve: (value: T | PromiseLike<T>) => void,
      reject: (reason?: unknown) => void,
    ) => void,
    retried = false,
  ): Promise<T> {
    const db = await this._openDb();

    try {
      return await new Promise<T>((resolve, reject) => {
        const store = db.transaction(this._storeName, mode).objectStore(this._storeName);
        execute(store, resolve, reject);
      });
    } catch (error) {
      if (!retried && this._isMissingStoreError(error)) {
        await this._resetDb();
        return this._runTransaction(mode, execute, true);
      }
      throw error;
    }
  }

  close(): void {
    this._db?.close();
    this._db = null;
  }
}
