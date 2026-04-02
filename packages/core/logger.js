'use strict';

/**
 * logger.js — Privacy-safe structured logger for the BafGo / Epheme suite.
 *
 * Design principles
 * ─────────────────
 * • NEVER logs device IDs, user IDs, room IDs, tokens, IP addresses, or
 *   request bodies. Logging exists only for: abuse detection, performance
 *   investigation, and bug diagnosis — at the service/infrastructure level,
 *   never at the identity or user-activity level.
 *   This is a hard product promise (see corp/selfhostedagreement.md §5 and §8,
 *   ideas/premiumaccesstokens.md §Security & Privacy Model).
 *
 * • Allowlist mindset: the REDACT_PATHS list removes forbidden fields at
 *   serialisation time — defence-in-depth against accidental logging.
 *
 * • Route patterns (/api/rooms/:id) are logged instead of resolved URLs so
 *   opaque IDs never reach the log store even via the request middleware.
 *
 * • WARNING — string interpolation bypasses redaction:
 *     log.info(`Device ${deviceId} joined`);   // ← NOT caught, never do this
 *     log.info({ err }, 'Device joined');       // ← safe structured form
 *
 * Usage
 * ─────
 *   const { createLogger, requestLogger } = require('@epheme/core/logger');
 *
 *   // In your service entry point:
 *   const log = createLogger({ service: 'hub-backend', tenant: 'hub' });
 *   app.use(requestLogger(log));
 *
 *   // Throughout your code:
 *   log.info('Server started');
 *   log.warn({ route: '/api/rooms/:id', statusCode: 429 }, 'Rate limit hit');
 *   log.error({ err }, 'Unexpected failure in room creation');
 *
 * Environment variables
 * ─────────────────────
 *   LOG_LEVEL     — pino log level (default: 'info' in production, 'debug' in dev)
 *   LOG_SERVICE   — fallback service name if not passed to createLogger
 *   LOG_PRETTY    — 'true' forces pino-pretty; 'false' forces JSON even on a TTY
 *   TENANT_SLUG   — fallback tenant label
 *   K8S_NAMESPACE — injected by the Helm/k8s deployment; labels all logs from the pod
 */

const pino     = require('pino');
const pinoHttp = require('pino-http');
const { randomUUID } = require('node:crypto');

// ─── Fields that must NEVER appear in any log event ──────────────────────────
//
// Pino removes these at serialisation time via its `redact` option.
// This list is the authoritative source — the CI test in
// test/logger.redaction.test.js asserts every entry here is actually removed.
//
// DO NOT add exceptions. If you believe a field should be loggable, that is a
// product-level decision requiring a privacy review — not a logger change.

const REDACT_PATHS = [
  // Device / user / session identity
  'deviceId',
  'deviceJwt',
  'userId',
  'jwt',
  'token',
  'pat',
  'patId',
  'sessionId',

  // Collaboration identifiers (rooms, shares, invites)
  'roomId',
  'shareId',
  'inviteToken',

  // Network identity
  'ip',
  'remoteAddress',

  // HTTP fields that carry identity or content
  'req.headers',
  'req.remoteAddress',
  'req.url',       // always use route pattern instead — see safeRoute()
  'req.id',
  'req.params',
  'req.query',
  'res.headers',

  // Common credential / secret field names
  'authorization',
  'cookie',
  'password',
  'secret',
  'apiKey',

  // Request / response bodies — never log user-generated content
  'body',
];

// ─── Error serialiser (allowlist) ────────────────────────────────────────────
//
// pino.stdSerializers.err copies ALL enumerable own properties from an Error,
// which would leak any identity field accidentally attached (e.g. err.deviceId).
// This serialiser strips everything except the four safe diagnostic fields.

function serializeErr(err) {
  if (!err || typeof err !== 'object') return err;
  const out = {};
  if (err.name    || err.constructor?.name) out.type       = err.name ?? err.constructor.name;
  if (err.message !== undefined)            out.message    = String(err.message);
  if (err.stack   !== undefined)            out.stack      = String(err.stack);
  if (err.code    !== undefined)            out.code       = err.code;       // Node.js system codes (ENOENT etc.)
  if (err.statusCode !== undefined)         out.statusCode = err.statusCode; // HTTP error codes
  return out;
}

// ─── Route sanitiser ─────────────────────────────────────────────────────────
//
// Logs the matched Express route template (/api/rooms/:id) rather than the
// resolved URL (/api/rooms/550e8400-e29b-41d4-a716-446655440000).
// Falls back to stripping UUID/hex/numeric ID-shaped segments from the raw path.

function safeRoute(req) {
  if (req.route && req.route.path) return req.route.path;

  return (req.url || '/')
    .split('?')[0]                                               // strip query string
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:id') // UUID
    .replace(/\/[0-9a-f]{16,}/gi, '/:id')                       // long hex token
    .replace(/\/\d{4,}/g, '/:id');                              // numeric ID (≥4 digits)
}

// ─── Logger factory ──────────────────────────────────────────────────────────

/**
 * Creates a pino logger instance with the BafGo privacy-safe configuration.
 *
 * @param {object} [opts]
 * @param {string} [opts.service]      Service name. Falls back to LOG_SERVICE env var.
 * @param {string} [opts.component]    Sub-component within the service (optional).
 * @param {string} [opts.tenant]       Tenant slug. Falls back to TENANT_SLUG env var.
 * @param {object} [opts.destination]  Custom writable destination — for testing only.
 *                                     In production, leave undefined (writes to stdout).
 * @returns {import('pino').Logger}
 */
function createLogger({ service, component, tenant, destination } = {}) {
  const env   = process.env.NODE_ENV  || 'development';
  const level = process.env.LOG_LEVEL || (env === 'production' ? 'info' : 'debug');

  // Use pino-pretty only when output is a terminal or explicitly requested.
  // Never in test environments or when a custom destination is provided.
  const usePretty = !destination
    && process.env.LOG_PRETTY !== 'false'
    && (process.env.LOG_PRETTY === 'true' || (process.stdout.isTTY && env !== 'test'));

  // Build base fields — omit keys with no value to keep events lean.
  const base = { environment: env };
  const svc = service || process.env.LOG_SERVICE;
  if (svc)       base.service   = svc;
  if (component) base.component = component;
  const ten = tenant || process.env.TENANT_SLUG;
  if (ten)       base.tenant    = ten;
  const ns  = process.env.K8S_NAMESPACE;
  if (ns)        base.namespace = ns;

  const opts = {
    level,
    redact: { paths: REDACT_PATHS, remove: true },
    serializers: { err: serializeErr },
    base,
  };

  if (usePretty) {
    return pino(opts, pino.transport({
      target: 'pino-pretty',
      options: { colorize: true, translateTime: 'SYS:standard', ignore: 'pid,hostname' },
    }));
  }

  return destination ? pino(opts, destination) : pino(opts);
}

// ─── Request middleware ───────────────────────────────────────────────────────

/**
 * Returns a pino-http middleware that logs one structured line per
 * request/response containing ONLY:
 *   requestId, method, route pattern, statusCode, responseTime
 *
 * No resolved URLs, no headers, no IPs, no request bodies.
 *
 * @param {import('pino').Logger} logger  Logger created by createLogger().
 * @returns Express/Connect middleware
 */
function requestLogger(logger) {
  return pinoHttp({
    logger,

    // Generate a fresh UUID per request for intra-request correlation.
    // requestId is ephemeral — it is never stored alongside any identity field.
    genReqId: () => randomUUID(),
    customAttributeKeys: { reqId: 'requestId' },

    serializers: {
      req(req) {
        // Only route pattern + method — never the resolved URL with IDs.
        return { method: req.method, route: safeRoute(req) };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },

    // Skip noisy health/readiness probes.
    autoLogging: {
      ignore(req) {
        const path = (req.url || '').split('?')[0];
        return path === '/health' || path === '/healthz' || path === '/api/healthz';
      },
    },

    // Map HTTP response status to an appropriate log level.
    customLogLevel(_req, res, err) {
      if (err || res.statusCode >= 500) return 'error';
      if (res.statusCode >= 400)        return 'warn';
      return 'info';
    },
  });
}

module.exports = { createLogger, requestLogger, REDACT_PATHS, _safeRoute: safeRoute };
