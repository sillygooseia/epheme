/**
 * @epheme/core/browser — shared pure-TypeScript browser library for Epheme-powered tools.
 *
 * Zero npm dependencies. All Angular/framework-specific wrapping lives in
 * each tool's own service layer.
 */

// Top-level convenience factory — recommended entry point
export { createEphemeClient } from './client';
export type { EphemeClient, EphemeClientOptions } from './client';

export { IdbDatabase, TypedStore } from './idb';
export type { IdbStoreSchema } from './idb';
export { IdbKeyValueStore } from './idb-kv';

export { EphemeDevice } from './device';
export type { EphemeDeviceCredential } from './device';
export { EphemeDeviceController } from './device-controller';

export { EphemeHubSync } from './hub-sync';
export type { HubSyncResult } from './hub-sync';
export { resolveEphemeHubBaseUrl, getCurrentEphemeReturnPath } from './hub-url';
export { buildEphemeHubDeviceRegistrationUrl, redirectToEphemeHubDeviceRegistration } from './hub-device-connect';

export { EphemeLicense } from './license';
export type { EphemeLicenseToken, EphemeLicenseState, EphemeLicenseConfig } from './license';
export { EphemeLicenseController } from './license-controller';

export { createEphemeDeviceDbBootstrap } from './app-bootstrap';
export type { EphemeBootDevice, EphemeBootDb } from './app-bootstrap';

// Plugin system — browser side
// EphemePluginRegistry is framework-agnostic; import and wrap in your own Angular service.
export { EphemePluginRegistry } from './plugin-registry';
export type { EphemeBrowserPlugin, EphemePluginPanel, EphemeSlot } from './plugin-registry';
// EphemePluginSlotComponent (Angular) — copy browser/plugin-slot.component.ts into your Angular app.
// It is not exported here to avoid introducing @angular/core as a core package dependency.
