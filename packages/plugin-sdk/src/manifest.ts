/**
 * EphemePluginManifest
 *
 * Declared in the plugin's package.json under the "epheme" key:
 *
 *   {
 *     "name": "@acme/epheme-plugin-todo",
 *     "epheme": {
 *       "pluginId": "todo",
 *       "displayName": "Todo",
 *       ...
 *     }
 *   }
 *
 * The pluginId must be 2–32 characters, lowercase alphanumeric + hyphens.
 * It is used as:
 *   - The route prefix:  /plugins/todo/
 *   - The KV namespace:  plugin:todo:{tenant}:{deviceId}:{key}
 *   - The DB schema key: data/plugins/todo.db (SQLite) or schema prefix (Postgres)
 *   - The logger prefix: [plugin:todo]
 *   - The env var prefix: EPHEME_PLUGIN_TODO_*
 */
export interface EphemePluginManifest {
  /** Stable identifier. Must match /^[a-z0-9][a-z0-9-]{1,31}$/ */
  pluginId: string;

  /** Human-readable name shown in admin UIs */
  displayName: string;

  /**
   * Path to the backend CJS entry point (resolved from the plugin package root).
   * The module must export a { EphemeBackendPlugin } named export, or default-export
   * an object implementing EphemeBackendPlugin.
   */
  backendEntry?: string;

  /**
   * Path to the browser ESM entry point (resolved from the plugin package root).
   * The module must export a { EphemeBrowserPlugin } named export, or default-export
   * an object implementing EphemeBrowserPlugin.
   */
  browserEntry?: string;

  /**
   * Semver range of @epheme/core that this plugin is compatible with.
   * The plugin host will refuse to load the plugin if the installed core version
   * does not satisfy this range.
   */
  requiredCoreVersion?: string;

  /**
   * Hub events this plugin wants to receive. The plugin host will only forward
   * events declared here — undeclared events are filtered out.
   * @see HubEventName
   */
  hubEvents?: HubEventName[];

  /**
   * License feature strings this plugin contributes. These are informational
   * for tooling and admin UIs — enforcement is done via ctx.license.requireFeature().
   */
  licenseFeatures?: string[];
}

/**
 * All Hub events that plugins can subscribe to.
 * Emitted by bafgo/hub/backend/lib/eventBus.js after each successful operation.
 */
export type HubEventName =
  | 'device.registered'
  | 'device.activated'
  | 'device.revoked'
  | 'device.authenticated'
  | 'room.created'
  | 'room.deleted'
  | 'invite.redeemed'
  | 'tools.data.written';

/** Payload shapes for each Hub event */
export interface HubEventPayloads {
  'device.registered':    { pendingId: string; displayName: string; tenant: string; mode: string };
  'device.activated':     { deviceId: string; tenant: string; role: string };
  'device.revoked':       { deviceId: string; tenant: string };
  'device.authenticated': { deviceId: string; tenant: string };
  'room.created':         { roomId: string; deviceId: string; tenant: string };
  'room.deleted':         { roomId: string; tenant: string };
  'invite.redeemed':      { token: string; deviceId: string; roomId: string; tenant: string };
  'tools.data.written':   { namespace: string; deviceId: string; tenant: string };
}
