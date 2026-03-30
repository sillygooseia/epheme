/** Resolve the canonical Hub base URL (no trailing slash). */
export function resolveEphemeHubBaseUrl(): string {
  const stored = localStorage.getItem('epheme_hub_url')?.trim();
  if (stored) return stored.replace(/\/$/, '');

  const { protocol, hostname, port, origin } = window.location;
  const isLocalDev = hostname === 'localhost' || hostname === '127.0.0.1';
  if (isLocalDev && port !== '8080') {
    return `${protocol}//${hostname}:8080/hub`;
  }
  return `${origin}/hub`;
}

/** Current relative path inside the suite origin, including search/hash. */
export function getCurrentEphemeReturnPath(): string {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}
