import { getCurrentEphemeReturnPath, resolveEphemeHubBaseUrl } from './hub-url';

export function buildEphemeHubDeviceRegistrationUrl(returnTo?: string): string {
  const hubBase = resolveEphemeHubBaseUrl();
  const target = returnTo ?? getCurrentEphemeReturnPath();
  const url = new URL(`${hubBase}/device/register`, window.location.origin);
  url.searchParams.set('return', target);
  return url.toString();
}

export function redirectToEphemeHubDeviceRegistration(returnTo?: string): void {
  window.location.assign(buildEphemeHubDeviceRegistrationUrl(returnTo));
}
