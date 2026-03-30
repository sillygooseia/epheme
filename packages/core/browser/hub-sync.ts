/**
 * EphemeHubSync — canonical Hub Tool Sync client for all Epheme-powered tools.
 *
 * Pure TypeScript, zero npm dependencies.
 * Wrap in a tool-specific @Injectable Angular service for DI.
 *
 * Usage: await hub.push('medlist', data) / hub.pull<T>('medlist') / hub.delete('medlist')
 */

import { resolveEphemeHubBaseUrl } from './hub-url';

const HUB_URL_KEY        = 'epheme_hub_url';
const HUB_DEVICE_JWT_KEY = 'epheme_hub_device_jwt';

export interface HubSyncResult {
  ok: boolean;
  error?: string;
}

export class EphemeHubSync {

  /** Resolves the Hub base URL (no trailing slash). */
  getResolvedHubUrl(): string {
    return resolveEphemeHubBaseUrl();
  }

  /** True when a valid device JWT is in localStorage. */
  isConfigured(): boolean {
    return this._isJwtUsable(localStorage.getItem(HUB_DEVICE_JWT_KEY));
  }

  /**
   * Re-checks whether a valid device JWT is in localStorage.
   * Returns true if sync is ready to use.
   * Useful to call after DeviceService.load() to pick up the mirrored JWT.
   */
  ensureAutoConfigured(): boolean {
    return this.isConfigured();
  }

  /** Explicitly configure Hub URL and device JWT (e.g. from a settings UI). */
  configure(hubUrl: string, deviceJwt: string): void {
    localStorage.setItem(HUB_URL_KEY, hubUrl.replace(/\/$/, ''));
    localStorage.setItem(HUB_DEVICE_JWT_KEY, deviceJwt);
  }

  clear(): void {
    localStorage.removeItem(HUB_DEVICE_JWT_KEY);
  }

  async push(namespace: string, data: unknown): Promise<HubSyncResult> {
    const jwt = this._getJwt();
    if (!jwt) return { ok: true };
    try {
      const res = await fetch(`${this.getResolvedHubUrl()}/api/tools/${namespace}/data`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({ data }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        return { ok: false, error: (body as any).error || `HTTP ${res.status}` };
      }
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err?.message ?? 'Network error' };
    }
  }

  async pull<T = unknown>(namespace: string): Promise<T | null> {
    const jwt = this._getJwt();
    if (!jwt) return null;
    try {
      const res = await fetch(`${this.getResolvedHubUrl()}/api/tools/${namespace}/data`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${jwt}` },
      });
      if (!res.ok) return null;
      const body = await res.json();
      return (body.data as T) ?? null;
    } catch {
      return null;
    }
  }

  async delete(namespace: string): Promise<HubSyncResult> {
    const jwt = this._getJwt();
    if (!jwt) return { ok: true };
    try {
      const res = await fetch(`${this.getResolvedHubUrl()}/api/tools/${namespace}/data`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${jwt}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        return { ok: false, error: (body as any).error || `HTTP ${res.status}` };
      }
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err?.message ?? 'Network error' };
    }
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  private _getJwt(): string | null {
    const jwt = localStorage.getItem(HUB_DEVICE_JWT_KEY);
    return this._isJwtUsable(jwt) ? jwt : null;
  }

  private _isJwtUsable(jwt: string | null): boolean {
    if (!jwt) return false;
    try {
      const [, payload] = jwt.split('.');
      const { exp } = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
      return typeof exp === 'number' && exp > Math.floor(Date.now() / 1000) + 30;
    } catch {
      return true; // non-standard JWT — treat as usable
    }
  }
}
