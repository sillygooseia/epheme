/**
 * @epheme/core
 *
 * Shared middleware and utilities for the BafGo suite.
 * Each module is independently importable:
 *
 *   const { buildIpRateLimiter, buildFailurePenalty } = require('@epheme/core/rateLimiter');
 *   const mailer  = require('@epheme/core/mailer');
 *   const metrics = require('@epheme/core/metrics');
 *
 * Or all at once:
 *   const { rateLimiter, mailer, metrics } = require('@epheme/core');
 */
module.exports = {
  rateLimiter:      require('./rateLimiter'),
  mailer:           require('./mailer'),
  metrics:          require('./metrics'),
  licenseMiddleware: require('./licenseMiddleware'),
  deviceRegistry:   require('./deviceRegistry'),
  pluginHost:       require('./pluginHost'),
  db:               require('./db/pluginDb'),
  logger:           require('./logger'),
};
