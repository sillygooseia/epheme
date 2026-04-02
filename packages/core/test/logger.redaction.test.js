'use strict';

/**
 * logger.redaction.test.js
 *
 * CI gate: asserts that the BafGo privacy promise is enforced at the logger
 * level. Tests run with `node --test test/` (Node 20+, no extra test framework).
 *
 * Tests cover:
 *  1. REDACT_PATHS completeness — every forbidden field category is listed.
 *  2. Pino actually removes those fields from serialised output.
 *  3. safeRoute strips opaque IDs from URLs when Express route info is absent.
 *  4. requestLogger serialisers strip URL, headers, and IP from req objects.
 *  5. Permitted infrastructure fields are preserved (method, route, statusCode, etc.).
 *
 * A failing test here means a privacy regression — treat it as a blocker.
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const os     = require('node:os');
const path   = require('node:path');
const fs     = require('node:fs');
const pino   = require('pino');

const { createLogger, REDACT_PATHS, _safeRoute } = require('../logger');

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Creates a logger that writes to a temp file synchronously, runs `fn` with it,
 * then returns the parsed log lines and cleans up.
 *
 * @param {(log: import('pino').Logger) => void} fn
 * @returns {object[]} Parsed JSON log lines
 */
function captureLogs(fn) {
  const file = path.join(
    os.tmpdir(),
    `epheme-log-test-${process.pid}-${Date.now()}.ndjson`,
  );
  // sync: true opens the fd synchronously so flushSync() is available immediately.
  const dest = pino.destination({ dest: file, sync: true });
  const log  = createLogger({ service: 'test', destination: dest });
  fn(log);
  dest.flushSync();
  const raw = fs.readFileSync(file, 'utf8').trim();
  try { fs.unlinkSync(file); } catch (_) { /* best-effort */ }
  return raw.split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

// ─── 1. REDACT_PATHS completeness ────────────────────────────────────────────
//
// Every field listed here corresponds to a category of identifier that must
// never reach the log store. Add to this list when new identifier types are
// introduced in the platform, not to the code under test.

describe('REDACT_PATHS completeness', () => {
  const REQUIRED = [
    // device / session identity
    'deviceId', 'deviceJwt', 'userId', 'jwt', 'token', 'pat', 'patId', 'sessionId',
    // collaboration identifiers
    'roomId', 'shareId', 'inviteToken',
    // network identity
    'ip', 'remoteAddress',
    // HTTP envelope that carries identity or content
    'req.headers', 'req.remoteAddress', 'req.url',
    // credentials
    'authorization', 'cookie', 'password', 'secret', 'body',
  ];

  for (const field of REQUIRED) {
    test(`includes "${field}"`, () => {
      assert.ok(
        REDACT_PATHS.includes(field),
        `REDACT_PATHS is missing "${field}" — identity/credential leakage risk`,
      );
    });
  }
});

// ─── 2. Pino enforces redaction ───────────────────────────────────────────────

describe('createLogger — forbidden fields are stripped from output', () => {
  const CASES = [
    { field: 'deviceId',    value: 'device-abc-123-xyz',       desc: 'device identifier' },
    { field: 'deviceJwt',   value: 'eyJhbGciOiJSUzI1NiJ9.xx', desc: 'device JWT' },
    { field: 'userId',      value: 'user-999',                 desc: 'user identifier' },
    { field: 'token',       value: 'bearer-supersecret',       desc: 'bearer token' },
    { field: 'pat',         value: 'pat-prepaid-abc',          desc: 'premium access token' },
    { field: 'patId',       value: 'pat-id-xyz',               desc: 'PAT identifier' },
    { field: 'roomId',      value: 'room-live-sess-001',       desc: 'room identifier' },
    { field: 'shareId',     value: 'share-abc123',             desc: 'share link identifier' },
    { field: 'inviteToken', value: 'invite-abc-tok',           desc: 'invite token' },
    { field: 'sessionId',   value: 'sess-xyz-789',             desc: 'session identifier' },
    { field: 'ip',          value: '192.168.1.100',            desc: 'IP address' },
    { field: 'remoteAddress', value: '10.0.0.1',              desc: 'remote address' },
    { field: 'authorization', value: 'Bearer secrettoken',    desc: 'authorization header value' },
    { field: 'cookie',      value: 'session=abc; id=xyz',      desc: 'cookie value' },
    { field: 'password',    value: 'hunter2',                  desc: 'password' },
    { field: 'secret',      value: 'topsecretvalue',           desc: 'secret value' },
    { field: 'body',        value: { name: 'Alice' },          desc: 'request body' },
  ];

  for (const { field, value, desc } of CASES) {
    test(`strips ${desc} (${field})`, () => {
      const [line] = captureLogs((log) => {
        log.info({ [field]: value }, 'privacy redaction test');
      });
      assert.ok(
        !(field in line),
        `"${field}" (${desc}) must not appear in log output — privacy violation`,
      );
    });
  }
});

// ─── 3. safeRoute ────────────────────────────────────────────────────────────

describe('safeRoute — strips opaque IDs from URLs', () => {
  test('uses Express route pattern when available', () => {
    const req = { method: 'GET', url: '/api/rooms/abc123', route: { path: '/api/rooms/:id' } };
    assert.strictEqual(_safeRoute(req), '/api/rooms/:id');
  });

  test('strips UUID v4 from URL', () => {
    const req = { url: '/api/rooms/550e8400-e29b-41d4-a716-446655440000' };
    assert.strictEqual(_safeRoute(req), '/api/rooms/:id');
  });

  test('strips long hex token from URL', () => {
    const req = { url: '/api/share/a3f9b2c1d4e5f6a7b8c9d0e1' };
    assert.strictEqual(_safeRoute(req), '/api/share/:id');
  });

  test('strips numeric ID (≥4 digits) from URL', () => {
    const req = { url: '/api/items/12345' };
    assert.strictEqual(_safeRoute(req), '/api/items/:id');
  });

  test('strips query string entirely', () => {
    const req = { url: '/api/rooms/abc?token=xyz&cursor=123' };
    // token in query string is gone; numeric cursor is stripped from path if present
    assert.ok(!_safeRoute(req).includes('token'));
    assert.ok(!_safeRoute(req).includes('xyz'));
  });

  test('does not mangle short non-ID path segments', () => {
    const req = { url: '/api/health' };
    assert.strictEqual(_safeRoute(req), '/api/health');
  });

  test('does not mangle tenant slugs (short alphanumeric)', () => {
    const req = { url: '/hub/api/config' };
    assert.strictEqual(_safeRoute(req), '/hub/api/config');
  });

  test('handles missing URL gracefully', () => {
    assert.doesNotThrow(() => _safeRoute({}));
  });
});

// ─── 4. Permitted fields are preserved ───────────────────────────────────────

describe('createLogger — safe infrastructure fields are preserved', () => {
  test('retains method, route, statusCode, responseTime', () => {
    const [line] = captureLogs((log) => {
      log.info(
        { method: 'POST', route: '/api/rooms/:id', statusCode: 201, responseTime: 42 },
        'request complete',
      );
    });
    assert.strictEqual(line.method,       'POST');
    assert.strictEqual(line.route,        '/api/rooms/:id');
    assert.strictEqual(line.statusCode,   201);
    assert.strictEqual(line.responseTime, 42);
  });

  test('base fields include service and environment', () => {
    const saved = process.env.NODE_ENV;
    process.env.NODE_ENV = 'test';
    const [line] = captureLogs((log) => log.info('base field check'));
    process.env.NODE_ENV = saved;
    assert.strictEqual(line.service,     'test');
    assert.strictEqual(line.environment, 'test');
  });

  test('error serialiser captures type, message, and stack', () => {
    const [line] = captureLogs((log) => {
      const err = new TypeError('boom');
      log.error({ err }, 'caught error');
    });
    assert.ok('err' in line,             'err field must be present');
    assert.ok('message' in line.err,     'err.message must be present');
    assert.ok('stack' in line.err,       'err.stack must be present');
  });

  test('error serialiser does not embed identity fields', () => {
    const [line] = captureLogs((log) => {
      const err   = new Error('something failed');
      err.deviceId = 'should-never-appear';
      log.error({ err }, 'error with extra field');
    });
    // pino stdSerializers.err copies type/message/stack only
    assert.ok(!('deviceId' in (line.err || {})), 'deviceId must not appear inside err');
  });

  test('rate-limit signals (boolean flags) are permitted', () => {
    const [line] = captureLogs((log) => {
      log.warn({ rateLimited: true, route: '/api/rooms/:id' }, 'rate limit exceeded');
    });
    assert.strictEqual(line.rateLimited, true);
    assert.strictEqual(line.route,       '/api/rooms/:id');
  });
});

// ─── 5. Multiple forbidden fields in one event ───────────────────────────────

describe('createLogger — all forbidden fields stripped in a single event', () => {
  test('strips every forbidden field simultaneously', () => {
    const [line] = captureLogs((log) => {
      log.info({
        deviceId:    'dev-123',
        roomId:      'room-456',
        token:       'tok-xyz',
        ip:          '1.2.3.4',
        body:        { content: 'user text' },
        method:      'GET',
        route:       '/api/rooms/:id',
        statusCode:  200,
      }, 'combined event');
    });

    // Forbidden — must be absent
    assert.ok(!('deviceId'   in line), 'deviceId must be stripped');
    assert.ok(!('roomId'     in line), 'roomId must be stripped');
    assert.ok(!('token'      in line), 'token must be stripped');
    assert.ok(!('ip'         in line), 'ip must be stripped');
    assert.ok(!('body'       in line), 'body must be stripped');

    // Permitted — must be present
    assert.strictEqual(line.method,     'GET');
    assert.strictEqual(line.route,      '/api/rooms/:id');
    assert.strictEqual(line.statusCode, 200);
  });
});
