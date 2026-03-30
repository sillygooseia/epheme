/**
 * idb.ts - Generic typed IndexedDB wrapper for BafGo browser tools.
 *
 * Usage:
 *   const db = new IdbDatabase('mydb', 1, [
 *     { name: 'items', keyPath: 'id', indexes: [{ name: 'active', keyPath: 'active' }] },
 *   ]);
 *   await db.open();
 *   const store = db.store<Item>('items');
 *   await store.put({ id: 'abc', name: 'foo', active: true });
 *   const all = await store.getAll();
 */

export interface IdbStoreSchema {
  name: string;
  keyPath: string;
  indexes?: Array<{ name: string; keyPath: string; unique?: boolean }>;
}

// TypedStore

export class TypedStore<T> {
  constructor(
    private readonly _db: IDBDatabase,
    private readonly _storeName: string,
  ) {}

  private _tx(mode: IDBTransactionMode): IDBObjectStore {
    return this._db.transaction(this._storeName, mode).objectStore(this._storeName);
  }

  get(id: IDBValidKey): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readonly').get(id);
      req.onsuccess = () => resolve(req.result as T | undefined);
      req.onerror = () => reject(req.error);
    });
  }

  getAll(): Promise<T[]> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readonly').getAll();
      req.onsuccess = () => resolve(req.result as T[]);
      req.onerror = () => reject(req.error);
    });
  }

  getByIndex(index: string, value: IDBValidKey): Promise<T[]> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readonly').index(index).getAll(value);
      req.onsuccess = () => resolve(req.result as T[]);
      req.onerror = () => reject(req.error);
    });
  }

  put(item: T): Promise<T> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readwrite').put(item);
      req.onsuccess = () => resolve(item);
      req.onerror = () => reject(req.error);
    });
  }

  delete(id: IDBValidKey): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readwrite').delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  clear(): Promise<void> {
    return new Promise((resolve, reject) => {
      const req = this._tx('readwrite').clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}

// IdbDatabase

export class IdbDatabase {
  private _db: IDBDatabase | null = null;

  constructor(
    private readonly _name: string,
    private readonly _version: number,
    private readonly _schemas: IdbStoreSchema[],
  ) {}

  open(): Promise<void> {
    if (this._db) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this._name, this._version);

      req.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        for (const schema of this._schemas) {
          if (!db.objectStoreNames.contains(schema.name)) {
            const store = db.createObjectStore(schema.name, { keyPath: schema.keyPath });
            for (const idx of schema.indexes ?? []) {
              store.createIndex(idx.name, idx.keyPath, { unique: idx.unique ?? false });
            }
          }
        }
      };

      req.onsuccess = () => { this._db = req.result; resolve(); };
      req.onerror = () => reject(req.error);
    });
  }

  store<T>(name: string): TypedStore<T> {
    if (!this._db) throw new Error(`IdbDatabase "${this._name}" not open - call open() first`);
    return new TypedStore<T>(this._db, name);
  }

  close(): void {
    this._db?.close();
    this._db = null;
  }
}
