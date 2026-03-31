/**
 * BafGo Hub Event Bus
 *
 * A singleton EventEmitter that emits typed events after successful Hub operations.
 * Consumed by createPluginHost to forward events to registered plugins (filtered
 * to each plugin's declared hubEvents[]).
 *
 * Usage in Hub routes (hub/backend/index.js):
 *
 *   const { emitHubEvent } = require('./lib/eventBus');
 *
 *   // After a successful device activation:
 *   emitHubEvent('device.activated', { deviceId, tenant, role });
 *
 * Usage in plugin host (packages/core/pluginHost.js):
 *
 *   const { eventBus } = require('./lib/eventBus');
 *   createPluginHost(app, { eventBus, ... });
 */

'use strict';

const EventEmitter = require('events');

const eventBus = new EventEmitter();

// Prevent accidental memory leak warnings — plugins may add many listeners
// for the same event across multiple subscriptions.
eventBus.setMaxListeners(100);

/**
 * Emit a typed Hub event. Called from Hub route handlers after successful operations.
 *
 * Errors thrown by event handlers are caught and logged to avoid crashing the request.
 *
 * @param {string} name    - One of the HubEventName values from @epheme/plugin-sdk
 * @param {object} payload - Event-specific payload (see HubEventPayloads)
 */
function emitHubEvent(name, payload) {
  // Fire-and-forget — we don't want plugin handler failures to affect Hub responses.
  // Async handlers: we let them run without awaiting.
  try {
    eventBus.emit(name, payload);
  } catch (err) {
    console.error(`[eventBus] uncaught error in handler for "${name}":`, err);
  }
}

module.exports = { eventBus, emitHubEvent };
