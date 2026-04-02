/**
 * createPluginHost — BafGo backend plugin host.
 *
 * Discovers, validates, and mounts backend plugins onto an Express app.
 * Each plugin receives a PluginContext with scoped router, KV, DB, license,
 * metrics, Hub event bus, config, and logger.
 *
 * Usage:
 *
 *   const { createPluginHost } = require('@epheme/core/pluginHost');
 *
 *   await createPluginHost(app, {
 *     redis,                                          // ioredis instance (optional — KV disabled if absent)
 *     licensePublicKeyPem: process.env.LICENSE_PUBLIC_KEY,
 *     eventBus,                                       // Hub event bus (from hub/backend/lib/eventBus.js)
 *     db: { dialect: 'sqlite', file: './data/plugins.db' },
 *     // OR: db: { dialect: 'postgres', url: process.env.DATABASE_URL },
 *     plugins: [
 *       require('@acme/bafgo-plugin-todo'),
 *     ],
 *   });
 *
 * Plugin auto-discovery (scanning node_modules) is not performed by default
 * to keep startup deterministic. Pass explicit plugins[] for all tools.
 */

'use strict';

const express        = require('express');
const semver         = require('semver');
const { makeFeatureLicenseMiddleware } = require('./licenseMiddleware');
const { recordHit }  = require('./metrics');
const { createPluginDb } = require('./db/pluginDb');

const CORE_VERSION = require('./package.json').version;
const PLUGIN_ID_RE = /^[a-z0-9][a-z0-9-]{1,31}$/;

/**
 * @param {import('express').Application} app
 * @param {PluginHostOptions} options
 */
async function createPluginHost(app, options = {}) {
  const {
    redis         = null,
    licensePublicKeyPem = null,
    tenantLicenseClaims = null,
    eventBus      = null,
    db: dbOptions = null,
    plugins       = [],
  } = options;

  const loadedPlugins = [];

  for (const pluginExport of plugins) {
    // Support both module.exports = plugin and module.exports.default = plugin
    const plugin = pluginExport?.default ?? pluginExport;

    if (!plugin || typeof plugin.register !== 'function') {
      throw new Error(
        `BafGo plugin host: a plugin entry does not implement EphemeBackendPlugin ` +
        `(missing register() function). Got: ${JSON.stringify(Object.keys(plugin || {}))}`
      );
    }

    const pluginId = String(plugin.id || '');
    if (!PLUGIN_ID_RE.test(pluginId)) {
      throw new Error(
        `BafGo plugin host: invalid pluginId "${pluginId}". ` +
        `Must match /^[a-z0-9][a-z0-9-]{1,31}$/`
      );
    }

    // Check requiredCoreVersion if present in package.json bafgo manifest
    // The plugin export may carry a static manifest property for tooling convenience
    const manifest = plugin.manifest ?? null;
    if (manifest?.requiredCoreVersion) {
      if (!semver.satisfies(CORE_VERSION, manifest.requiredCoreVersion)) {
        throw new Error(
          `BafGo plugin host: plugin "${pluginId}" requires @epheme/core@` +
          `${manifest.requiredCoreVersion} but installed version is ${CORE_VERSION}`
        );
      }
    }

    const ctx = buildPluginContext({
      pluginId,
      redis,
      licensePublicKeyPem,
      tenantLicenseClaims,
      eventBus,
      dbOptions,
      declaredHubEvents: manifest?.hubEvents ?? [],
    });

    await plugin.register(ctx);

    app.use(`/plugins/${pluginId}`, ctx.router);

    loadedPlugins.push({ pluginId, plugin, ctx });
    ctx.logger.info(`loaded — routes mounted at /plugins/${pluginId}`);
  }

  // Return a shutdown handle
  return {
    async shutdown() {
      for (const { pluginId, plugin, ctx } of loadedPlugins) {
        try {
          await plugin.onShutdown?.();
          await ctx._db?.close?.();
        } catch (err) {
          console.error(`[plugin:${pluginId}] error during shutdown:`, err);
        }
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Internal: build a PluginContext for one plugin
// ---------------------------------------------------------------------------

function buildPluginContext({ pluginId, redis, licensePublicKeyPem, tenantLicenseClaims, eventBus, dbOptions, declaredHubEvents }) {
  const router = express.Router();

  // --- KV ---
  const kv = buildKv({ pluginId, redis });

  // --- DB ---
  let dbInstance = null;
  const db = {
    query:       (...args) => getDb().query(...args),
    run:         (...args) => getDb().run(...args),
    transaction: (...args) => getDb().transaction(...args),
    migrate:     (...args) => getDb().migrate(...args),
  };

  function getDb() {
    if (!dbInstance) {
      if (!dbOptions) throw new Error(`[plugin:${pluginId}] ctx.db used but no db options passed to createPluginHost`);
      const file = dbOptions.dialect === 'sqlite'
        ? (dbOptions.file ?? `./data/plugins/${pluginId}.db`)
        : undefined;
      dbInstance = createPluginDb({ ...dbOptions, file, pluginId });
    }
    return dbInstance;
  }

  // --- License ---
  const license = {
    requireFeature(feature) {
      if (!licensePublicKeyPem) {
        return (_req, res) => res.status(503).json({ error: 'License enforcement not configured' });
      }
      return makeFeatureLicenseMiddleware({
        getPublicKeyPem:  () => licensePublicKeyPem,
        requiredLicense:  'premium',
        requiredFeatures: [feature],
        attachProperty:   'licensePayload',
      });
    },
    tenantHasFeature(feature) {
      if (!tenantLicenseClaims) return false;
      const f = tenantLicenseClaims.features;
      if (!f) return false;
      // Features may be stored as an object map (bool) or an array of strings.
      return Array.isArray(f) ? f.includes(feature) : f[feature] === true;
    },
    requireTenantFeature(feature) {
      return (_req, res, next) => {
        if (this.tenantHasFeature(feature)) return next();
        return res.status(403).json({ error: `Feature '${feature}' is not enabled for this tenant.` });
      };
    },
  };

  // --- Metrics ---
  const metrics = {
    record(event) {
      recordHit(`plugin.${pluginId}.${event}`);
    },
  };

  // --- Hub event bus (filtered to declared events) ---
  const hub = buildFilteredHub({ pluginId, eventBus, declaredHubEvents });

  // --- Config ---
  const envPrefix = `EPHEME_PLUGIN_${pluginId.toUpperCase().replace(/-/g, '_')}_`;
  const config = (key) => process.env[`${envPrefix}${key}`];

  // --- Logger ---
  const logger = buildLogger(pluginId);

  return {
    router,
    kv,
    db,
    license,
    metrics,
    hub,
    config,
    logger,
    // Internal — used by shutdown handler to close the DB
    get _db() { return dbInstance; },
  };
}

// ---------------------------------------------------------------------------
// KV — Redis-backed, namespaced per plugin + tenant + device
// ---------------------------------------------------------------------------

function buildKv({ pluginId, redis }) {
  const DEFAULT_TTL = 60 * 60 * 24 * 90; // 90 days — matches Hub tools KV

  function redisKey(deviceId, key, tenant = 'default') {
    return `plugin:${pluginId}:${tenant}:${deviceId}:${key}`;
  }

  return {
    async get(deviceId, key, tenant) {
      if (!redis) return null;
      return redis.get(redisKey(deviceId, key, tenant));
    },
    async set(deviceId, key, value, ttlSeconds = DEFAULT_TTL, tenant) {
      if (!redis) return;
      await redis.set(redisKey(deviceId, key, tenant), value, 'EX', ttlSeconds);
    },
    async del(deviceId, key, tenant) {
      if (!redis) return;
      await redis.del(redisKey(deviceId, key, tenant));
    },
    async keys(deviceId, tenant = 'default') {
      if (!redis) return [];
      // SCAN instead of KEYS to avoid blocking in production
      const pattern = `plugin:${pluginId}:${tenant}:${deviceId}:*`;
      const found = [];
      let cursor = '0';
      do {
        const [next, batch] = await redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = next;
        found.push(...batch);
      } while (cursor !== '0');
      // Return just the key suffix (strip the namespace prefix)
      const prefixLen = `plugin:${pluginId}:${tenant}:${deviceId}:`.length;
      return found.map(k => k.slice(prefixLen));
    },
  };
}

// ---------------------------------------------------------------------------
// Hub event bus — filtered view
// ---------------------------------------------------------------------------

function buildFilteredHub({ pluginId, eventBus, declaredHubEvents }) {
  const allowedSet = new Set(declaredHubEvents);

  return {
    on(event, handler) {
      if (!eventBus) return;
      if (!allowedSet.has(event)) {
        console.warn(
          `[plugin:${pluginId}] attempted to subscribe to Hub event "${event}" ` +
          `which is not declared in the plugin manifest's hubEvents[]. Ignored.`
        );
        return;
      }
      eventBus.on(event, handler);
    },
    off(event, handler) {
      if (!eventBus) return;
      eventBus.off(event, handler);
    },
  };
}

// ---------------------------------------------------------------------------
// Logger
// ---------------------------------------------------------------------------

function buildLogger(pluginId) {
  const prefix = `[plugin:${pluginId}]`;
  return {
    info:  (msg, ...args) => console.log(prefix, msg, ...args),
    warn:  (msg, ...args) => console.warn(prefix, msg, ...args),
    error: (msg, ...args) => console.error(prefix, msg, ...args),
  };
}

module.exports = { createPluginHost };
