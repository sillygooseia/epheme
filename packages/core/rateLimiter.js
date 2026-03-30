'use strict';
const crypto = require('crypto');

/**
 * rateLimiter.js - Redis-backed, privacy-safe rate limiting helpers.
 *
 * All client IPs are hashed with SHA-256 before being written to Redis.
 * Raw IP addresses are never stored.  Keys use configurable TTLs so they
 * auto-expire; no historical data is retained beyond the active window.
 *
 * Two exported factories:
 *
 *   buildIpRateLimiter(redis, keyPrefix, windowSeconds, limit, envKey?)
 *     Returns an Express middleware that counts requests per hashed-IP per
 *     time-window and returns 429 + Retry-After when the limit is exceeded.
 *
 *   buildFailurePenalty(redis, namespace)
 *     Returns { penaltyMiddleware, recordFailure }.
 *     recordFailure(hashedIp) increments a hit counter and writes a block key
 *     with an escalating TTL when thresholds are crossed.
 *     penaltyMiddleware checks for an active block and returns 429 early.
 *
 * Usage in index.js:
 *   const { buildIpRateLimiter, buildFailurePenalty } = require('./lib/rateLimiter');
 *   const roomInfoLimiter = buildIpRateLimiter(pubClient, 'room_info', 60, 30, 'ROOM_INFO_RATE_LIMIT');
 *   const { penaltyMiddleware: roomPenalty, recordFailure: recordRoomMiss }
 *     = buildFailurePenalty(pubClient, 'room_enum');
 *   app.get('/api/rooms/:roomId/info', roomInfoLimiter, roomPenalty, async (req, res) => {
 *     ...
 *     if (!info) { recordRoomMiss(hashIp(req)); return res.status(404).json({...}); }
 *   });
 */

/** SHA-256 hash of an IP, truncated to 16 hex chars (64-bit prefix). */
function hashIp(ip) {
  return crypto.createHash('sha256').update(String(ip || '')).digest('hex').slice(0, 16);
}

/**
 * Resolve the real client IP, honouring Express's `trust proxy` setting.
 * Falls back through a chain of known forwarding headers.
 */
function clientIp(req) {
  return req.ip
    || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || (req.socket && req.socket.remoteAddress)
    || 'unknown';
}

/**
 * Redis INCR + conditional EXPIRE counter (sliding window).
 * Returns { allowed: boolean, count: number, ttl: number }.
 * Uses a single key per (ip, window-start) so each window resets cleanly.
 */
async function redisCount(redis, key, windowSeconds, limit) {
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, windowSeconds);
  const ttl = await redis.ttl(key);
  return { allowed: count <= limit, count, ttl: ttl > 0 ? ttl : windowSeconds };
}

/**
 * buildIpRateLimiter
 *
 * @param {object}  redis          - ioredis client
 * @param {string}  keyPrefix      - Redis key namespace (e.g. 'room_info')
 * @param {number}  windowSeconds  - sliding-window duration
 * @param {number}  defaultLimit   - max requests allowed per window
 * @param {string}  [envKey]       - env var name that can override defaultLimit at runtime
 * @returns {function} Express middleware
 */
function buildIpRateLimiter(redis, keyPrefix, windowSeconds, defaultLimit, envKey) {
  return async function ipRateLimiterMiddleware(req, res, next) {
    const limit = envKey ? (parseInt(process.env[envKey], 10) || defaultLimit) : defaultLimit;
    const ip = clientIp(req);
    const hashed = hashIp(ip);
    // Bucket key: one per (prefix, hashed-ip, window-start epoch)
    const windowStart = Math.floor(Date.now() / 1000 / windowSeconds);
    const key = `ratelimit:${keyPrefix}:${hashed}:${windowStart}`;
    let result;
    try {
      result = await redisCount(redis, key, windowSeconds, limit);
    } catch (err) {
      // Redis unavailable - fail open to avoid blocking legitimate traffic
      console.warn(`[rateLimiter] Redis error for key ${key}:`, err.message);
      return next();
    }
    if (!result.allowed) {
      res.set('Retry-After', String(result.ttl));
      return res.status(429).json({
        error: 'Too many requests. Please try again later.',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: result.ttl,
      });
    }
    next();
  };
}

/**
 * Escalating failure penalty - block an IP for progressively longer windows
 * as it accumulates 404 / deny events (e.g. room ID enumeration).
 *
 * Tiers (evaluated in order):
 *   > 5  failures in  2 min -> 60 s block
 *   > 15 failures in  5 min -> 300 s block
 *   > 30 failures in 10 min -> 1800 s block
 *
 * @param {object} redis      - ioredis client
 * @param {string} namespace  - key namespace (e.g. 'room_enum')
 * @returns {{ penaltyMiddleware: function, recordFailure: function }}
 */
function buildFailurePenalty(redis, namespace) {
  const TIERS = [
    // { window (s), hitThreshold, blockDuration (s) } - evaluated largest-to-smallest
    { window: 600, threshold: 30, block: 1800 },
    { window: 300, threshold: 15, block: 300  },
    { window: 120, threshold:  5, block: 60   },
  ];

  const blockKey  = (h) => `penalty:${namespace}:${h}:block`;
  const hitsKey   = (h, winBucket) => `penalty:${namespace}:${h}:hits:${winBucket}`;

  async function recordFailure(hashedIp) {
    try {
      // Increment counters for every tier window simultaneously (pipeline)
      const now = Math.floor(Date.now() / 1000);
      const pipeline = redis.pipeline();
      for (const tier of TIERS) {
        const bucket = Math.floor(now / tier.window);
        const k = hitsKey(hashedIp, `${tier.window}:${bucket}`);
        pipeline.incr(k);
        pipeline.expire(k, tier.window * 2); // generous TTL to survive clock skew
      }
      const results = await pipeline.exec();

      // Check tiers from most-severe to least-severe; apply the first match.
      for (let i = 0; i < TIERS.length; i++) {
        const tier = TIERS[i];
        const count = results[i * 2]?.[1]; // incr result (odd index = expire result)
        if (count >= tier.threshold) {
          await redis.set(blockKey(hashedIp), '1', 'EX', tier.block);
          break;
        }
      }
    } catch (err) {
      console.warn(`[failurePenalty:${namespace}] Redis error in recordFailure:`, err.message);
    }
  }

  async function penaltyMiddleware(req, res, next) {
    const ip = clientIp(req);
    const hashed = hashIp(ip);
    let blocked = false;
    let ttl = 0;
    try {
      const pipeline = redis.pipeline();
      pipeline.exists(blockKey(hashed));
      pipeline.ttl(blockKey(hashed));
      const [[, exists], [, t]] = await pipeline.exec();
      blocked = exists === 1;
      ttl = t > 0 ? t : 60;
    } catch (err) {
      console.warn(`[failurePenalty:${namespace}] Redis error in penaltyMiddleware:`, err.message);
      return next(); // fail open
    }
    if (blocked) {
      res.set('Retry-After', String(ttl));
      return res.status(429).json({
        error: 'Too many failed requests. Please try again later.',
        code: 'PENALTY_BLOCK',
        retryAfter: ttl,
      });
    }
    next();
  }

  return { penaltyMiddleware, recordFailure, hashIp };
}

module.exports = { buildIpRateLimiter, buildFailurePenalty, hashIp, clientIp };
