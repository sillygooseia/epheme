import { EphemeDevice } from './device';
import type { EphemeDeviceCredential } from './device';

/**
 * Shared controller around EphemeDevice with change notifications.
 *
 * Framework wrappers can subscribe and project state into signals/observables
 * without duplicating device-loading lifecycle logic.
 */
export class EphemeDeviceController {
  private readonly _core = new EphemeDevice();
  private readonly _listeners = new Set<() => void>();
  private _loaded = false;

  onChange(listener: () => void): () => void {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  get isLoaded(): boolean {
    return this._loaded;
  }

  get isRegistered(): boolean {
    return this._loaded && this._core.isRegistered;
  }

  get deviceId(): string | null {
    return this._core.deviceId;
  }

  get jwt(): string | null {
    return this._core.jwt;
  }

  get displayName(): string | null {
    return this._core.displayName;
  }

  async load(): Promise<void> {
    await this._core.load();
    this._loaded = true;
    this._emit();
  }

  private _emit(): void {
    for (const listener of this._listeners) {
      try {
        listener();
      } catch {
        // Ignore listener failures to avoid breaking other subscribers.
      }
    }
  }
}

export type { EphemeDeviceCredential };
