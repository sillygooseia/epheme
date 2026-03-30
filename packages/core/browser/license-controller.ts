import { EphemeLicense } from './license';
import type { EphemeLicenseConfig, EphemeLicenseToken } from './license';

/**
 * Shared controller around EphemeLicense with change notifications.
 *
 * This keeps framework wrappers thin: each app can subscribe to changes and
 * project state into its own reactive primitives (Angular signals, etc.).
 */
export class EphemeLicenseController<TFeature extends string> {
  private readonly _core: EphemeLicense<TFeature>;
  private readonly _listeners = new Set<() => void>();

  constructor(cfg: EphemeLicenseConfig) {
    this._core = new EphemeLicense<TFeature>(cfg);
    this._core.loadFromStorage();
    void this._core.verifyStoredToken().then(() => this._emit());
  }

  onChange(listener: () => void): () => void {
    this._listeners.add(listener);
    return () => this._listeners.delete(listener);
  }

  get isPremium(): boolean {
    return this._core.isPremium;
  }

  get licenseExpiry(): number | null {
    return this._core.licenseExpiry;
  }

  get licenseJti(): string | null {
    return this._core.licenseJti;
  }

  get token(): string | null {
    return this._core.token;
  }

  async activate(rawToken: string): Promise<boolean> {
    const ok = await this._core.activate(rawToken);
    this._emit();
    return ok;
  }

  deactivate(): void {
    this._core.deactivate();
    this._emit();
  }

  getLicense(): EphemeLicenseToken | null {
    return this._core.getLicense();
  }

  isExpired(): boolean {
    return this._core.isExpired();
  }

  hasFeature(feature: TFeature): boolean {
    return this._core.hasFeature(feature);
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
