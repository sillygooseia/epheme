/**
 * createEphemeClient — top-level convenience factory for the Epheme browser SDK.
 *
 * Wraps EphemeDeviceController, EphemeHubSync, EphemeLicense, and IdbDatabase
 * behind a single initialisation point so tools don't need to wire up each
 * controller individually.
 *
 * Usage:
 *   const bafgo = createEphemeClient();
 *   await bafgo.init();                        // device.load()
 *   bafgo.device.isRegistered                  // bool
 *   bafgo.redirectToHub()                      // → Hub device registration
 *   await bafgo.sync.push('mytool', data)      // Hub KV sync
 *   const lic = bafgo.license({ ... })         // RS256 license verifier
 *   const db  = bafgo.db('mytool', 1, [...])   // local IDB store
 */

import { EphemeDeviceController } from './device-controller';
import { EphemeHubSync } from './hub-sync';
import { EphemeLicense } from './license';
import type { EphemeLicenseConfig } from './license';
import { IdbDatabase } from './idb';
import type { IdbStoreSchema } from './idb';
import {
  redirectToEphemeHubDeviceRegistration,
  buildEphemeHubDeviceRegistrationUrl,
} from './hub-device-connect';

export interface EphemeClientOptions {
  /**
   * Override the Hub base URL (no trailing slash).
   * Defaults to <origin>/hub, or localhost:8080/hub in local dev.
   * Stored in localStorage as 'epheme_hub_url'.
   */
  hubUrl?: string;
}

export interface EphemeClient {
  /** Device identity state. Call init() before reading. */
  readonly device: EphemeDeviceController;

  /** Hub KV sync. Automatically uses device JWT after init(). */
  readonly sync: EphemeHubSync;

  /**
   * Bootstrap the client. Loads the device credential from Hub's IndexedDB.
   * Call once, typically via APP_INITIALIZER or the app root ngOnInit.
   */
  init(): Promise<void>;

  /**
   * Redirect the browser to the Hub device registration page.
   * The Hub will return the user to `returnTo` (defaults to current path).
   */
  redirectToHub(returnTo?: string): void;

  /**
   * Build the Hub registration URL without redirecting.
   * Useful for rendering a link rather than an immediate redirect.
   */
  buildHubUrl(returnTo?: string): string;

  /**
   * Create an RS256 license verifier for a tool.
   * Returns an EphemeLicense instance bound to the given config.
   */
  license<TFeature extends string>(config: EphemeLicenseConfig): EphemeLicense<TFeature>;

  /**
   * Create a typed IndexedDB store for per-tool local config.
   * @param name        DB name (use a tool-scoped string, e.g. 'mytool')
   * @param version     Schema version (increment when adding stores)
   * @param migrations  Array of IdbStoreSchema descriptors, one per store
   */
  db(
    name: string,
    version: number,
    migrations: IdbStoreSchema[],
  ): IdbDatabase;
}

export function createEphemeClient(opts?: EphemeClientOptions): EphemeClient {
  if (opts?.hubUrl) {
    localStorage.setItem('epheme_hub_url', opts.hubUrl.replace(/\/$/, ''));
  }

  const device = new EphemeDeviceController();
  const sync   = new EphemeHubSync();

  return {
    device,
    sync,

    async init(): Promise<void> {
      await device.load();
      sync.ensureAutoConfigured();
    },

    redirectToHub(returnTo?: string): void {
      redirectToEphemeHubDeviceRegistration(returnTo);
    },

    buildHubUrl(returnTo?: string): string {
      return buildEphemeHubDeviceRegistrationUrl(returnTo);
    },

    license<TFeature extends string>(config: EphemeLicenseConfig): EphemeLicense<TFeature> {
      return new EphemeLicense<TFeature>(config);
    },

    db(
      name: string,
      version: number,
      migrations: IdbStoreSchema[],
    ): IdbDatabase {
      return new IdbDatabase(name, version, migrations);
    },
  };
}
