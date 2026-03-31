# @epheme/core/browser

> Browser-side device identity, license verification, and Hub sync for BafGo suite tools.

Pure TypeScript. Zero npm dependencies. Uses browser-native Web Crypto, IndexedDB, and fetch — no polyfills needed.

---

## What it does

BafGo is a **device-authorization platform** — identity belongs to the device (a cryptographic key pair), not a person or account. This library is the browser-side client for that model:

| Module | What it provides |
|---|---|
| **Device** | Read the Hub-issued device credential from IndexedDB; check registration state |
| **License** | RS256 JWT verification in the browser; feature-flag gating |
| **Hub Sync** | Push/pull tool data against the Hub's KV store using the device JWT |
| **IDB** | Typed IndexedDB wrapper for per-tool local config storage |

---

## Quick start (Angular)

### 1. Wire the path alias

No build step, no npm install — point TypeScript directly at the source:

```json
// tsconfig.json
{
  "compilerOptions": {
    "paths": {
      "@epheme/core/browser": ["../../packages/core/browser/index.ts"]
    }
  }
}
```

Adjust the relative path to match your tool's depth inside the monorepo.

### 2. Add the one peer dependency

```json
"jose": "^6.0.0"
```

### 3. Bootstrap device + DB on app start

```typescript
import { ApplicationConfig, APP_INITIALIZER } from '@angular/core';
import { createEphemeClient } from '@epheme/core/browser';

const bafgo = createEphemeClient();

export const appConfig: ApplicationConfig = {
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: () => () => bafgo.init(),
      multi: true,
    },
  ],
};
```

### 4. Check device registration

```typescript
// In any component:
if (!bafgo.device.isRegistered) {
  bafgo.redirectToHub(); // sends user to Hub to register, returns them after
}

console.log(bafgo.device.deviceId);    // string | null
console.log(bafgo.device.displayName); // string | null
console.log(bafgo.device.jwt);         // raw Hub JWT | null
```

### 5. Send the device JWT to your backend

```typescript
fetch('/api/items', {
  headers: { Authorization: `Bearer ${bafgo.device.jwt}` },
});
```

Validate the JWT in your Express backend using `licenseMiddleware` from `@epheme/core`.

---

## API reference

### `createEphemeClient(opts?)`

```typescript
createEphemeClient(opts?: { hubUrl?: string }): EphemeClient
```

Creates a client instance. Pass `hubUrl` to override the default Hub URL
(defaults to `<origin>/hub`, or `localhost:8080/hub` in local dev).

Returns an `EphemeClient` with:

| Property / Method | Type | Description |
|---|---|---|
| `device` | `EphemeDeviceController` | Device identity state and loader |
| `sync` | `EphemeHubSync` | Hub KV push/pull/delete |
| `init()` | `() => Promise<void>` | Bootstrap — call once on app start |
| `redirectToHub(returnTo?)` | `(path?: string) => void` | Redirect to Hub device registration |
| `buildHubUrl(returnTo?)` | `(path?: string) => string` | Build Hub registration URL without redirecting |
| `license<TFeature>(config)` | `BafgoLicense<TFeature>` | Create a license verifier for a tool |
| `db(name, version, migrations)` | `IdbDatabase` | Create an IDB store for local config |

---

### Device (`EphemeDeviceController`)

```typescript
await bafgo.device.load();        // reads credential from Hub's IndexedDB
bafgo.device.isRegistered;        // boolean — active + valid JWT
bafgo.device.isLoaded;            // boolean — load() has completed
bafgo.device.deviceId;            // string | null
bafgo.device.displayName;         // string | null
bafgo.device.jwt;                 // string | null — null if expired
bafgo.device.onChange(listener);  // subscribe to credential changes
```

---

### Hub Sync (`BafgoHubSync`)

```typescript
const sync = bafgo.sync;

// Push (upsert) — PUT /hub/api/tools/<namespace>/data
await sync.push('mytool', { items: [...] });

// Pull — GET
const data = await sync.pull<{ items: Item[] }>('mytool');

// Delete
await sync.delete('mytool');

// Check if sync is available (valid JWT present)
sync.isConfigured(); // boolean
```

Device JWT is used automatically after `bafgo.init()`.

---

### License (`BafgoLicense<TFeature>`)

```typescript
const license = bafgo.license<'backup' | 'export'>({
  storageKey: 'mytool:license',
  publicKeyUrl: '/mytool/api/license/public-key',
  publicKeyCacheKey: 'mytool:license-public-key',
});

license.loadFromStorage();              // fast sync load — call on init
await license.verifyStoredToken();      // async RS256 signature check

const ok = await license.activate(rawJwt); // verify + store a new token
license.isPremium;                      // boolean — valid non-expired token
license.hasFeature('backup');           // boolean — specific feature flag
license.licenseExpiry;                  // number | null — Unix seconds
license.deactivate();                   // clear stored token
```

Your backend needs a `/api/license/public-key` endpoint:

```javascript
app.get('/api/license/public-key', (_req, res) => {
  const pem = process.env.LICENSE_PUBLIC_KEY_PEM;
  if (!pem) return res.status(503).json({ error: 'not configured' });
  res.type('text/plain').send(pem);
});
```

---

### IDB store (`IdbDatabase`)

```typescript
const db = bafgo.db('mytool', 1, [
  (idb) => idb.createObjectStore('config'), // v1 migration
]);

await db.open();
const store = db.store<MyConfig>('config');

await store.put({ theme: 'dark' }, 'cfg');
const config = await store.get('cfg');
```

To add a store in v2, append a new migration — never modify earlier entries:

```typescript
bafgo.db('mytool', 2, [
  (idb) => idb.createObjectStore('config'),          // v1
  (idb) => idb.createObjectStore('history', { keyPath: 'id' }), // v2
]);
```

---

## Device registration flow

Devices self-register with the Hub — no server-side user creation needed.

```
1. User visits your app
2. bafgo.device.isRegistered === false
3. Call bafgo.redirectToHub()
   → User is sent to <hubUrl>/device/register?return=<your-app-path>
   → User completes registration on the Hub
   → Hub writes credential to bafgo_device IndexedDB
   → User is returned to your app
4. bafgo.device.load() — reads the credential
5. bafgo.device.isRegistered === true
6. bafgo.device.jwt available for API requests
```

---

## Architecture overview

```
Browser
  └── @epheme/core/browser
        ├── BafgoDevice       reads Hub's bafgo_device IndexedDB (key: 'device')
        ├── BafgoHubSync      fetch ↔ Hub REST /api/tools/<ns>/data
        ├── BafgoLicense      fetch ↔ /api/license/public-key → Web Crypto verify
        └── IdbDatabase       per-tool IndexedDB (separate from Hub's DB)

Server
  ├── Hub backend             issues device JWTs, stores tool sync data
  ├── Tool backend            validates device JWT via @epheme/core licenseMiddleware
  └── License microservice    issues RS256 premium license JWTs
```

---

## License

MIT — see `LICENSE` at the repository root.
