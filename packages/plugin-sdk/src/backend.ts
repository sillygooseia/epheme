import type { PluginDb } from './db';
import type { HubEventName, HubEventPayloads } from './manifest';

/** Express RequestHandler — typed as unknown to avoid @types/express peer dep in the SDK. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type ExpressRequestHandler = (req: any, res: any, next: any) => void;

/**
 * PluginContext — the full API surface available to a backend plugin's
 * register(ctx) function.
 *
 * The plugin host constructs and injects this — plugin authors never
 * instantiate it directly.
 */
export interface PluginContext {
  /**
   * Express Router pre-configured with the plugin's base path.
   * Mounted at /plugins/:pluginId/ by the host.
   * Typed as unknown in the SDK to avoid @types/express peer dep — cast in your plugin:
   *   import type { Router } from 'express';
   *   const router = ctx.router as Router;
   *
   * @example
   * (ctx.router as Router).get('/api/items', ctx.license.requireFeature('todo_premium') as any, handler);
   * // Accessible at: /plugins/todo/api/items
   */
  router: unknown;

  /**
   * Subscribe to Hub events. Only events declared in the plugin manifest's
   * hubEvents[] are forwarded — all others are silently filtered.
   *
   * @example
   * ctx.hub.on('device.registered', (payload) => {
   *   ctx.logger.info(`New device: ${payload.pendingId}`);
   * });
   */
  hub: PluginHubEmitter;

  /**
   * Key-value store namespaced to this plugin and the requesting device.
   * Backed by Redis. Key format: plugin:{pluginId}:{tenant}:{deviceId}:{key}
   * TTL: 90 days (same as Hub tools KV).
   *
   * Intended for lightweight per-device state. For relational data, use ctx.db.
   */
  kv: PluginKv;

  /** Dialect-neutral database access. See PluginDb for full docs. */
  db: PluginDb;

  /**
   * License enforcement helpers. Wraps the core makeFeatureLicenseMiddleware.
   *
   * @example
   * ctx.router.post('/api/premium', ctx.license.requireFeature('todo_premium'), handler);
   */
  license: PluginLicense;

  /**
   * Telemetry. Records named events against the platform metrics store.
   * These appear alongside core metrics in the admin dashboard.
   */
  metrics: PluginMetrics;

  /**
   * Read plugin-scoped configuration from environment variables.
   * Variables must be prefixed with EPHEME_PLUGIN_{PLUGIN_ID_UPPERCASE}_.
   *
   * @example
   * // Plugin id: "todo"
   * // Env var:   EPHEME_PLUGIN_TODO_WEBHOOK_URL=https://...
   * const url = ctx.config('WEBHOOK_URL');
   */
  config: PluginConfig;

  /** Structured logger with pluginId prefix. Output goes to the host's log stream. */
  logger: PluginLogger;
}

// ---------------------------------------------------------------------------
// Supporting interfaces
// ---------------------------------------------------------------------------

export interface PluginHubEmitter {
  on<E extends HubEventName>(
    event: E,
    handler: (payload: HubEventPayloads[E]) => void | Promise<void>
  ): void;
  off<E extends HubEventName>(
    event: E,
    handler: (payload: HubEventPayloads[E]) => void | Promise<void>
  ): void;
}

export interface PluginKv {
  get(deviceId: string, key: string): Promise<string | null>;
  set(deviceId: string, key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(deviceId: string, key: string): Promise<void>;
  /** List all keys for a device in this plugin's namespace */
  keys(deviceId: string): Promise<string[]>;
}

export interface PluginLicense {
  /**
   * Express middleware that rejects requests (403) whose Bearer JWT does not
   * include the given feature. Attaches req.licensePayload on success.
   * Returns unknown to avoid @types/express peer dep — cast to RequestHandler in your plugin.
   */
  requireFeature(feature: string): ExpressRequestHandler;
}

export interface PluginMetrics {
  /** Record a single occurrence of a named event */
  record(event: string): void;
}

export interface PluginConfig {
  /** Returns the env var value for EPHEME_PLUGIN_{ID}_{key}, or undefined */
  (key: string): string | undefined;
}

export interface PluginLogger {
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

// ---------------------------------------------------------------------------
// Plugin interfaces — what plugin packages export
// ---------------------------------------------------------------------------

/**
 * EphemeBackendPlugin — the interface a plugin package's backend entry must satisfy.
 *
 * The simplest backend plugin:
 *
 * @example
 * // plugin.js
 * module.exports = {
 *   id: 'todo',
 *   async register(ctx) {
 *     await ctx.db.migrate([`CREATE TABLE IF NOT EXISTS ...`]);
 *     ctx.router.get('/api/items', async (req, res) => { ... });
 *   },
 * };
 */
export interface EphemeBackendPlugin {
  /** Must match the pluginId in the manifest */
  id: string;

  /**
   * Called once by the plugin host at startup.
   * Set up routes, event listeners, migrations, etc. here.
   * Any error thrown here will abort host startup.
   */
  register(ctx: PluginContext): Promise<void>;

  /**
   * Optional. Called when the host is shutting down gracefully.
   * Close DB connections, flush buffers, etc.
   */
  onShutdown?(): Promise<void>;
}
