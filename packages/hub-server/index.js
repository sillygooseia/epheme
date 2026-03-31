'use strict';

const { registerDeviceRoutes, requireDeviceAdmin } = require('./deviceRoutes');

module.exports = {
  DeviceStore:                 require('./deviceStore'),
  CertManager:                 require('./certManager'),
  eventBus:                    require('./eventBus'),
  SyncStore:                   require('./sync/SyncStore'),
  registerDeviceRoutes,
  requireDeviceAdmin,
  registerSyncRoutes:          require('./sync/syncRoutes'),
  registerQuickConnectRoutes:  require('./quickconnect/quickConnectRoutes'),
};
