/**
 * @epheme/plugin-sdk
 *
 * Type definitions and contracts for Epheme plugin authors.
 *
 * Install in your plugin:
 *   npm install --save-dev @epheme/plugin-sdk
 *
 * Backend entry point:
 *   import type { EphemeBackendPlugin, PluginContext } from '@epheme/plugin-sdk';
 *
 * Browser entry point:
 *   import type { EphemeBrowserPlugin, EphemeSlot } from '@epheme/plugin-sdk';
 *
 * Manifest (in your package.json):
 *   import type { EphemePluginManifest } from '@epheme/plugin-sdk';
 */

// Manifest + Hub event types
export type {
  EphemePluginManifest,
  HubEventName,
  HubEventPayloads,
} from './manifest';

// Backend plugin interface + PluginContext
export type {
  EphemeBackendPlugin,
  PluginContext,
  PluginHubEmitter,
  PluginKv,
  PluginLicense,
  PluginMetrics,
  PluginConfig,
  PluginLogger,
  ExpressRequestHandler,
} from './backend';

// Database interface
export type { PluginDb } from './db';

// Browser plugin interface + slots
export type {
  EphemeBrowserPlugin,
  EphemePluginPanel,
  EphemeSlot,
} from './browser';
