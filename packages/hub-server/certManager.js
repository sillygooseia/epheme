'use strict';

const forge  = require('node-forge');
const fs     = require('fs');
const crypto = require('crypto');

const CERT_TTL_DAYS = parseInt(process.env.DEVICE_CERT_TTL_DAYS || '365', 10);

// node-forge's publicKeyToAsn1 only handles RSA. Patch it once at module load
// to support EC device keys stored as a raw SPKI ASN.1 passthrough object.
const _origPublicKeyToAsn1 = forge.pki.publicKeyToAsn1;
forge.pki.publicKeyToAsn1 = forge.pki.publicKeyToSubjectPublicKeyInfo = function(key) {
  if (key && key._ecSpkiAsn1) return key._ecSpkiAsn1;
  return _origPublicKeyToAsn1.call(this, key);
};

/**
 * CertManager — issues and verifies X.509 device certificates.
 *
 * The BafGo backend acts as a Certificate Authority (CA). When an admin approves
 * a device registration, the CA signs the device's browser-generated public key
 * into a proper X.509 certificate.
 *
 * Two cert tiers (controlled by license params.certTier):
 *   consumer   — Non-extractable Web Crypto key; cert used at application layer only.
 *   enterprise — Extractable key; cert exported as PKCS#12 for OS cert store; path
 *                to Nginx ssl_verify_client mutual TLS.
 *
 * Requires node-forge: npm install node-forge
 *
 * Environment variables (set in .env or k8s Secret):
 *   DEVICE_CA_CERT      — PEM string (\n-escaped) OR
 *   DEVICE_CA_CERT_FILE — path to ca_cert.pem (from gen-ca.js)
 *   DEVICE_CA_KEY       — PEM string (\n-escaped) OR
 *   DEVICE_CA_KEY_FILE  — path to ca_private.pem (from gen-ca.js)
 *   DEVICE_CERT_TTL_DAYS — default 365
 */
class CertManager {
  constructor() {
    this._caKey     = null;
    this._caCert    = null;   // forge object — RSA, used by issueCert to sign
    this._caCertPem = null;   // raw PEM — used by verifyCert and getCaCertPem
    this._load();
  }

  _load() {
    // ---- Load CA certificate ----
    let certPem = (process.env.DEVICE_CA_CERT || '').replace(/\\n/g, '\n').trim();
    if (!certPem && process.env.DEVICE_CA_CERT_FILE) {
      try {
        certPem = fs.readFileSync(process.env.DEVICE_CA_CERT_FILE, 'utf8').trim();
      } catch (e) {
        console.warn('[cert] Could not read DEVICE_CA_CERT_FILE:', e.message);
      }
    }

    // ---- Load CA private key ----
    let keyPem = (process.env.DEVICE_CA_KEY || '').replace(/\\n/g, '\n').trim();
    if (!keyPem && process.env.DEVICE_CA_KEY_FILE) {
      try {
        keyPem = fs.readFileSync(process.env.DEVICE_CA_KEY_FILE, 'utf8').trim();
      } catch (e) {
        console.warn('[cert] Could not read DEVICE_CA_KEY_FILE:', e.message);
      }
    }

    if (!certPem || !keyPem) {
      console.warn('[cert] DEVICE_CA_CERT/DEVICE_CA_KEY not configured — device cert issuance unavailable.');
      return;
    }

    try {
      this._caCert    = forge.pki.certificateFromPem(certPem);
      this._caKey     = forge.pki.privateKeyFromPem(keyPem);
      this._caCertPem = certPem;
      console.log('[cert] CA loaded. Device certificate issuance ready.');
    } catch (e) {
      console.error('[cert] Failed to load CA key/cert:', e.message);
    }
  }

  /** True when the CA is loaded and cert issuance is available. */
  isLoaded() {
    return !!(this._caKey && this._caCert);
  }

  /**
   * Issue a device certificate signed by this CA.
   *
   * @param {string} deviceId         — device UUID (stored in CN and SAN)
   * @param {string} tenant           — tenant slug (stored as O)
   * @param {string} role             — device role (stored as OU)
   * @param {string} publicKeySpkiB64 — DER-encoded SPKI public key, base64
   *                                    (from browser: btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('spki', key)))))
   * @returns {{ certPem: string, fingerprint: string }}
   */
  issueCert(deviceId, tenant, role, publicKeySpkiB64) {
    if (!this.isLoaded()) throw new Error('CA not loaded — configure DEVICE_CA_CERT and DEVICE_CA_KEY');

    // node-forge cannot parse EC (P-256) public keys via publicKeyFromAsn1 — it only
    // supports RSA. Instead, store the raw SPKI ASN.1 on a stub key object. The
    // module-level patch to pki.publicKeyToAsn1 recognises _ecSpkiAsn1 and returns
    // the pre-parsed ASN.1 directly, so forge embeds the correct SubjectPublicKeyInfo
    // in the TBSCertificate without needing to interpret the EC key bytes.
    const spkiDer  = Buffer.from(publicKeySpkiB64, 'base64');
    const spkiAsn1 = forge.asn1.fromDer(forge.util.createBuffer(spkiDer));

    const cert = forge.pki.createCertificate();
    cert.publicKey = { _ecSpkiAsn1: spkiAsn1 };
    // Unique random serial (16 bytes hex)
    cert.serialNumber = crypto.randomBytes(16).toString('hex');

    const now = new Date();
    const exp = new Date(now);
    exp.setDate(exp.getDate() + CERT_TTL_DAYS);
    cert.validity.notBefore = now;
    cert.validity.notAfter  = exp;

    cert.setSubject([
      { name: 'commonName',             value: `device:${deviceId}` },
      { name: 'organizationName',       value: tenant              },
      { name: 'organizationalUnitName', value: role                },
    ]);
    // Issuer matches the CA's subject
    cert.setIssuer(this._caCert.subject.attributes);

    cert.setExtensions([
      { name: 'basicConstraints', cA: false },
      {
        name: 'subjectAltName',
        altNames: [{ type: 2, value: `device.${deviceId}.bafgo.internal` }],
      },
      { name: 'keyUsage', digitalSignature: true, nonRepudiation: true },
      { name: 'extKeyUsage', clientAuth: true },
      {
        name: 'authorityKeyIdentifier',
        keyIdentifier: this._caCert.generateSubjectKeyIdentifier().getBytes(),
      },
    ]);

    cert.sign(this._caKey, forge.md.sha256.create());

    const certPem     = forge.pki.certificateToPem(cert);
    const fingerprint = this.getCertFingerprint(certPem);

    return { certPem, fingerprint };
  }

  /**
   * Verify a certificate was signed by our CA and is not expired.
   * @param {string} certPem
   * @returns {boolean}
   */
  verifyCert(certPem) {
    if (!this.isLoaded()) return false;
    try {
      // Use Node's built-in X509Certificate — forge cannot load certs with EC public keys.
      const cert   = new crypto.X509Certificate(certPem);
      const now    = new Date();
      if (now < new Date(cert.validFrom) || now > new Date(cert.validTo)) return false;
      const caCert = new crypto.X509Certificate(this._caCertPem);
      return cert.verify(caCert.publicKey);
    } catch {
      return false;
    }
  }

  /**
   * Returns SHA-256 fingerprint of a certificate (lowercase hex, no colons).
   * @param {string} certPem
   * @returns {string}
   */
  getCertFingerprint(certPem) {
    try {
      // Strip PEM headers and hash the raw DER bytes.
      // Avoids forge trying to parse the EC public key in the cert.
      const b64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const der = Buffer.from(b64, 'base64');
      return crypto.createHash('sha256').update(der).digest('hex');
    } catch {
      return '';
    }
  }

  /**
   * Returns the public CA certificate in PEM format (for distribution to clients).
   * @returns {string | null}
   */
  getCaCertPem() {
    return this._caCertPem;
  }
}

module.exports = CertManager;
