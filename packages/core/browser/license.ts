/**
 * EphemeLicense<TFeature> — RS256 JWT license verifier for BafGo tools.
 *
 * Pure TypeScript. Zero npm dependencies — uses browser Web Crypto API
 * and fetch instead of jose/HttpClient/rxjs.
 *
 * Wrap in a tool-specific @Injectable Angular service that owns the signals.
 *
 * Usage:
 *   const lic = new EphemeLicense<MyFeature>({
 *     storageKey: 'mytool:license',
 *     publicKeyUrl: '/api/license/public-key',
 *     publicKeyCacheKey: 'mytool:license-public-key',
 *   });
 *   lic.loadFromStorage();            // call on init (sync fast-load)
 *   await lic.activate(rawJwt);       // verify + store
 *   lic.hasFeature('backup');         // true/false
 */

export interface EphemeLicenseToken {
  jti: string;
  lic: 'premium';
  features: string[];
  exp: number;
  iat: number;
  v: number;
}

export interface EphemeLicenseState {
  token: string;
  claims: EphemeLicenseToken;
}

export interface EphemeLicenseConfig {
  storageKey: string;
  publicKeyUrl: string;
  publicKeyCacheKey: string;
}

export class EphemeLicense<TFeature extends string> {
  private _state: EphemeLicenseState | null = null;
  private _publicKey: CryptoKey | null = null;
  private _publicKeyLoading: Promise<CryptoKey> | null = null;

  constructor(private readonly cfg: EphemeLicenseConfig) {}

  get isPremium(): boolean {
    if (!this._state) return false;
    return this._state.claims.exp > Math.floor(Date.now() / 1000);
  }

  get licenseExpiry(): number | null {
    return this._state?.claims.exp ?? null;
  }

  get licenseJti(): string | null {
    return this._state?.claims.jti ?? null;
  }

  get token(): string | null {
    return this._state?.token ?? null;
  }

  /**
   * Synchronous fast-load from localStorage.
   * Call once on construction/init — does NOT do crypto verification.
   * A background verify is kicked off automatically via verifyStoredToken().
   */
  loadFromStorage(): void {
    const raw = localStorage.getItem(this.cfg.storageKey);
    if (!raw) return;
    try {
      const claims = this._decodePayload(raw);
      if (claims.exp <= Math.floor(Date.now() / 1000)) {
        console.warn('[license] Stored license expired — clearing');
        localStorage.removeItem(this.cfg.storageKey);
        return;
      }
      this._state = { token: raw, claims };
      console.log('[license] Loaded from storage, jti:', claims.jti);
    } catch {
      console.warn('[license] Failed to parse stored license — clearing');
      localStorage.removeItem(this.cfg.storageKey);
    }
  }

  /**
   * Background crypto verification — call after loadFromStorage().
   * Deactivates if the stored token fails RS256 signature check.
   */
  async verifyStoredToken(): Promise<void> {
    const raw = this._state?.token;
    if (!raw) return;
    try {
      const key = await this._getPublicKey();
      await this._verifySignature(raw, key);
    } catch (err) {
      console.warn('[license] Background verification failed — deactivating:', err);
      this.deactivate();
    }
  }

  /** Verify and activate a raw JWT string. Returns true on success. */
  async activate(rawToken: string): Promise<boolean> {
    try {
      let key: CryptoKey;
      let claims: EphemeLicenseToken;
      try {
        key = await this._getPublicKey();
        await this._verifySignature(rawToken, key);
        claims = this._decodePayload(rawToken);
      } catch {
        // Self-heal on key rotation — clear cache and retry once
        this._clearCachedPublicKey();
        key = await this._getPublicKey();
        await this._verifySignature(rawToken, key);
        claims = this._decodePayload(rawToken);
      }
      if (claims.lic !== 'premium') {
        console.warn('[license] Token lic field is not "premium"');
        return false;
      }
      localStorage.setItem(this.cfg.storageKey, rawToken);
      this._state = { token: rawToken, claims };
      console.log('[license] Activated, jti:', claims.jti);
      return true;
    } catch (err) {
      console.warn('[license] Activation failed:', err);
      return false;
    }
  }

  deactivate(): void {
    localStorage.removeItem(this.cfg.storageKey);
    this._state = null;
    console.log('[license] Deactivated');
  }

  getLicense(): EphemeLicenseToken | null {
    return this._state?.claims ?? null;
  }

  isExpired(): boolean {
    if (!this._state) return false;
    return this._state.claims.exp <= Math.floor(Date.now() / 1000);
  }

  hasFeature(feature: TFeature): boolean {
    if (!this.isPremium) return false;
    return (this._state?.claims.features as TFeature[] | undefined)?.includes(feature) ?? false;
  }

  // ─── Private ────────────────────────────────────────────────────────────────

  private _decodePayload(raw: string): EphemeLicenseToken {
    const parts = raw.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');
    return JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))) as EphemeLicenseToken;
  }

  private async _verifySignature(raw: string, key: CryptoKey): Promise<void> {
    const parts = raw.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sig = Uint8Array.from(
      atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')),
      c => c.charCodeAt(0),
    );
    const valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, data);
    if (!valid) throw new Error('JWT signature invalid');
  }

  private _clearCachedPublicKey(): void {
    this._publicKey = null;
    this._publicKeyLoading = null;
    localStorage.removeItem(this.cfg.publicKeyCacheKey);
  }

  private _getPublicKey(): Promise<CryptoKey> {
    if (this._publicKey) return Promise.resolve(this._publicKey);
    if (!this._publicKeyLoading) {
      this._publicKeyLoading = this._fetchPublicKey().finally(() => {
        this._publicKeyLoading = null;
      });
    }
    return this._publicKeyLoading;
  }

  private async _fetchPublicKey(): Promise<CryptoKey> {
    const cached = localStorage.getItem(this.cfg.publicKeyCacheKey);
    if (cached) {
      try {
        const key = await this._importSpki(cached);
        this._publicKey = key;
        return key;
      } catch {
        localStorage.removeItem(this.cfg.publicKeyCacheKey);
      }
    }
    const res = await fetch(this.cfg.publicKeyUrl);
    if (!res.ok) throw new Error(`Failed to fetch public key: HTTP ${res.status}`);
    const raw = (await res.text()).trim();
    const pem = raw.startsWith('{')
      ? (JSON.parse(raw) as { publicKey: string }).publicKey
      : raw;
    localStorage.setItem(this.cfg.publicKeyCacheKey, pem);
    const key = await this._importSpki(pem);
    this._publicKey = key;
    return key;
  }

  private _importSpki(pem: string): Promise<CryptoKey> {
    const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Uint8Array.from(atob(body), c => c.charCodeAt(0));
    return crypto.subtle.importKey(
      'spki',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
  }
}
