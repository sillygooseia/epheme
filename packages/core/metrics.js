/**
 * Aggregate traffic metrics - privacy-safe, ephemeral.
 *
 * Tracks only anonymous counts, never IPs, sessions, or identities.
 * Redis is fully optional: if REDIS_URL is not set, all calls are no-ops
 * and getStats() returns nulls so the app starts fine without it.
 *
 * Keys used:
 *   metrics:hits:<YYYY-MM-DD>   - integer hit count for a UTC day (TTL 8 days)
 *   metrics:window:5m           - sorted set of timestamps for sliding 5-min window (TTL 10 min)
 */

let redis = null;

if (process.env.REDIS_URL) {
  try {
    const Redis = require('ioredis');
    redis = new Redis(process.env.REDIS_URL, {
      lazyConnect: false,
      maxRetriesPerRequest: 1,
      enableReadyCheck: false,
    });
    redis.on('error', (err) => {
      // Log but never crash the app over metrics
      console.warn('[metrics] Redis error:', err.message);
    });
    console.log('[metrics] Redis connected for traffic metrics.');
  } catch (e) {
    console.warn('[metrics] ioredis not available, metrics disabled:', e.message);
    redis = null;
  }
} else {
  console.log('[metrics] REDIS_URL not set - traffic metrics disabled.');
}

/**
 * Record a single anonymous page hit.
 * Fire-and-forget; errors are swallowed so a Redis blip never affects users.
 */
function recordHit() {
  if (!redis) return;

  const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
  const now = Date.now();
  const member = `${now}:${Math.random().toString(36).slice(2, 9)}`; // unique, not reusable
  const windowKey = 'metrics:window:5m';
  const dayKey = `metrics:hits:${day}`;
  const cutoff = now - 5 * 60 * 1000;

  Promise.all([
    // Daily counter - expires after 8 days
    redis.incr(dayKey).then(() => redis.expire(dayKey, 8 * 24 * 60 * 60)),
    // Sliding 5-minute window sorted set
    redis.zadd(windowKey, now, member)
      .then(() => redis.zremrangebyscore(windowKey, '-inf', cutoff))
      .then(() => redis.expire(windowKey, 600)),
  ]).catch((err) => {
    console.warn('[metrics] recordHit error:', err.message);
  });
}

/**
 * Returns aggregate stats. Never throws.
 * @returns {Promise<{hitsToday: number|null, hitsPast5m: number|null}>}
 */
async function getStats() {
  if (!redis) return { hitsToday: null, hitsPast5m: null };

  try {
    const day = new Date().toISOString().slice(0, 10);
    const now = Date.now();
    const cutoff = now - 5 * 60 * 1000;

    const [hitsToday, hitsPast5m] = await Promise.all([
      redis.get(`metrics:hits:${day}`).then((v) => (v ? parseInt(v, 10) : 0)),
      redis.zcount('metrics:window:5m', cutoff, '+inf'),
    ]);

    return { hitsToday, hitsPast5m };
  } catch (err) {
    console.warn('[metrics] getStats error:', err.message);
    return { hitsToday: null, hitsPast5m: null };
  }
}

module.exports = { recordHit, getStats };
