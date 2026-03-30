/**
 * Shared startup sequence for tools that need device identity and local DB.
 *
 * Stays framework-agnostic (no Angular imports) so it can be reused anywhere.
 */
export interface EphemeBootDevice {
  load(): Promise<void>;
}

export interface EphemeBootDb {
  open(): Promise<void>;
}

export function createEphemeDeviceDbBootstrap(
  device: EphemeBootDevice,
  db: EphemeBootDb,
): () => Promise<void> {
  return async () => {
    await device.load();
    await db.open();
  };
}
