# Epheme

**Epheme** is the open-source MIT SDK that powers [BafGo](https://bafgo.com) — a privacy-first platform where identity belongs to the device, not to a person, account, or server.

[![@epheme/core](https://img.shields.io/badge/@epheme%2Fcore-MIT-blue)](./packages/core)
[![@epheme/plugin-sdk](https://img.shields.io/badge/@epheme%2Fplugin--sdk-MIT-blue)](./packages/plugin-sdk)

---

## Packages

| Package | Description |
|---|---|
| [`packages/core`](./packages/core) | Browser + server SDK — device identity, license verification, IDB storage, real-time Hub sync client |
| [`packages/plugin-sdk`](./packages/plugin-sdk) | Type definitions and contracts for building Epheme-powered plugins |

---

## Quick start

```bash
npm install @epheme/core --registry https://npm.pkg.github.com
```

```ts
import { EphemeDeviceController } from '@epheme/core/browser';

const device = new EphemeDeviceController();
await device.load();
// device.deviceId   — stable device identifier (Ed25519 public key)
// device.isRegistered — true once registered with a Hub
```

---

## Core concepts

- **Device identity, not accounts** — identity is a keypair stored in IndexedDB. No sign-up, no passwords.
- **Accountless license verification** — RS256 JWT tokens bound to device keys, verified in the browser with no server round-trip.
- **BafGo powered by Epheme** — BafGo is the hosted commercial platform built on this SDK. Self-host with [`bafgo`](../bafgo).

---

## License

MIT — see [LICENSE](../licenses/MIT.txt).
