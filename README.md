# Epheme

> Software that belongs to you — not a platform.

[![@epheme/core](https://img.shields.io/badge/@epheme%2Fcore-0.1.7-blue)](./packages/core)
[![@epheme/plugin-sdk](https://img.shields.io/badge/@epheme%2Fplugin--sdk-0.1.0-blue)](./packages/plugin-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](../licenses/MIT.txt)
[![Status: Early](https://img.shields.io/badge/status-early%20development-orange)]()

---

## What is Epheme?

Epheme is an open-source SDK for building software where **identity belongs to the device, not to a server, account, or company.**

No sign-up flows. No password resets. No centralised user tables. Just a cryptographic keypair stored in the browser, and software that actually works without phoning home.

It's the foundation I wanted when I was tired of every tool demanding an account, storing my data somewhere I can't see, and charging a monthly fee for the privilege. So I built it.

**We're just getting started.** The SDK is functional, the first tools are live, and the roadmap is real — but this is early software built by real people with opinions about how software should work.

---

## Who we are

**sillygooseia** is a small, independent software shop. No VC. No growth team. No dark patterns.

I'm Ben — I've been building software professionally for years and I'm done with the SaaS noise. Epheme started as a foundation for tools I wanted to use myself. It's now the SDK powering [BafGo](https://bafgo.com), a hosted platform built on these same primitives.

The goal isn't to build the next platform. It's to build tools that serve the people using them.

---

## Why we're building this

Modern software has a problem. Everything needs an account. Every feature hides behind a paywall. Every app wants to track you, notify you, and lock you in.

I wanted:
- **Code I could read and understand**
- **Tools that start small and stay small**
- **Identity that lives on my device, not in someone else's database**
- **Licenses that verify without phoning home**

Epheme is the answer to all of that. It's not finished — but it's honest, open, and shipping.

---

## Packages

| Package | Version | Description |
|---|---|---|
| [`@epheme/core`](./packages/core) | `0.1.7` | Browser + server SDK — device identity, license verification, IndexedDB storage, Hub real-time sync client |
| [`@epheme/plugin-sdk`](./packages/plugin-sdk) | `0.1.0` | TypeScript contracts and type definitions for Epheme plugin authors |

---

## Quick start

Install via the Epheme npm registry:

```bash
npm install @epheme/core --registry https://npm.sillygooseia.com
```

Or configure your `.npmrc`:

```
@epheme:registry=https://npm.sillygooseia.com
```

---

## Core concepts

### Device identity

Identity in Epheme is an **Ed25519 keypair** stored in IndexedDB. No account, no server, no email.

```ts
import { EphemeDeviceController } from '@epheme/core/browser';

const device = new EphemeDeviceController();
await device.load();

console.log(device.deviceId);      // stable identifier — Ed25519 public key
console.log(device.isRegistered);  // true once registered with a Hub
```

The device ID is stable across page loads and sessions. It's also portable — export the keypair, import it somewhere else.

### Accountless licenses

Licenses are **RS256 JWTs** bound to a device key and verified entirely in the browser. No round-trip, no server, no account.

```ts
import { LicenseController } from '@epheme/core/browser';

const license = new LicenseController(device);
await license.load();

if (license.isValid) {
  // unlock features
}
```

### Hub sync

Epheme includes a real-time sync client for connecting devices to a self-hosted Hub server.

```ts
import { HubDeviceConnect } from '@epheme/core/browser';

const hub = new HubDeviceConnect(device, 'wss://your-hub.example.com');
await hub.connect();
```

### Server middleware (Node.js)

```js
const { licenseMiddleware } = require('@epheme/core/licenseMiddleware');
const { deviceRegistry }    = require('@epheme/core/deviceRegistry');
const { rateLimiter }       = require('@epheme/core/rateLimiter');
const { logger }            = require('@epheme/core/logger');

app.use(logger);
app.use(rateLimiter);
app.use('/api/protected', licenseMiddleware);
```

---

## Built on Epheme

**[BafGo](https://bafgo.com)** is the hosted commercial platform built entirely on this SDK. It's where Epheme gets battle-tested: real users, real devices, real licenses. Everything BafGo does, you can self-host with the same code.

- Hub server — real-time device collaboration
- SFU — self-hosted media relay
- Plugin system — extend with your own features via `@epheme/plugin-sdk`

---

## Project structure

```
epheme/
  packages/
    core/           # @epheme/core — browser SDK + server middleware
      browser/      # TypeScript browser modules (device, license, hub, IDB)
      db/           # Plugin storage (IndexedDB wrappers)
    plugin-sdk/     # @epheme/plugin-sdk — plugin author contracts
```

---

## Status

This is **early software.** The core primitives work. The API will change. Breaking changes will be documented in releases.

What's stable:
- Device identity (keypair generation, stable ID, IDB persistence)
- License verification (RS256 JWT, browser-side)
- Hub sync client (WebSocket, real-time)
- Server middleware (logger, rate limiter, license, device registry)

What's coming:
- Plugin authoring docs and examples
- Self-host quickstart guide
- More tools built on the SDK (open for contributions)

---

## Contributing

The project is MIT-licensed and open to contributions. Read the code, open issues, send PRs.

This is early days — if you have opinions about how software identity should work, we're genuinely interested in hearing them.

---

## License

MIT — see [LICENSE](../licenses/MIT.txt).

Built by [sillygooseia](https://epheme.org) — open software for builders.
