const jwt = require('jsonwebtoken');

function extractBearerToken(authorizationHeader) {
  const header = String(authorizationHeader || '').trim();
  if (!header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  return token || null;
}

function formatMissingFeatureError(requiredFeatures) {
  if (requiredFeatures.length === 1) return `${requiredFeatures[0]} feature required`;
  return `Missing required license features: ${requiredFeatures.join(', ')}`;
}

function makeLicensePublicKeyHandler(options = {}) {
  const {
    getPublicKeyPem,
    missingMessage = 'License public key not configured',
  } = options;

  if (typeof getPublicKeyPem !== 'function') {
    throw new Error('makeLicensePublicKeyHandler requires getPublicKeyPem function');
  }

  return function licensePublicKeyHandler(_req, res) {
    const pem = getPublicKeyPem();
    if (!pem) {
      return res.status(503).json({ error: missingMessage });
    }
    return res.type('text/plain').send(pem);
  };
}

/**
 * Build an Express middleware that verifies an RS256 license JWT and checks
 * required license fields/features.
 */
function makeFeatureLicenseMiddleware(options = {}) {
  const {
    getPublicKeyPem,
    requiredLicense = 'premium',
    requiredFeatures = [],
    attachProperty = 'licensePayload',
    precheck,
    validatePayload,
    logPrefix = 'license',
  } = options;

  if (typeof getPublicKeyPem !== 'function') {
    throw new Error('makeFeatureLicenseMiddleware requires getPublicKeyPem function');
  }

  return async function featureLicenseMiddleware(req, res, next) {
    const precheckError = typeof precheck === 'function' ? precheck(req) : null;
    if (precheckError) {
      return res.status(503).json({ error: precheckError });
    }

    const publicKeyPem = getPublicKeyPem(req);
    if (!publicKeyPem) {
      return res.status(503).json({ error: 'License verification not configured' });
    }

    const token = extractBearerToken(req.headers?.authorization);
    if (!token) {
      return res.status(401).json({ error: 'Missing Authorization header' });
    }

    try {
      const verified = jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] });
      const payload = (verified && typeof verified === 'object') ? verified : null;
      if (!payload) {
        return res.status(401).json({ error: 'Invalid or expired license' });
      }

      if (requiredLicense && payload.lic !== requiredLicense) {
        return res.status(403).json({ error: 'Premium license required' });
      }

      if (requiredFeatures.length > 0) {
        const features = Array.isArray(payload.features) ? payload.features : [];
        const missing = requiredFeatures.filter(f => !features.includes(f));
        if (missing.length > 0) {
          return res.status(403).json({ error: formatMissingFeatureError(requiredFeatures) });
        }
      }

      if (typeof validatePayload === 'function') {
        const validationError = validatePayload(req, payload);
        if (validationError) {
          const status = Number(validationError.status) || 403;
          const error = validationError.error || 'License validation failed';
          return res.status(status).json({ error });
        }
      }

      req[attachProperty] = payload;
      return next();
    } catch (err) {
      console.warn(`[${logPrefix}] License verification failed:`, err && err.message ? err.message : err);
      return res.status(401).json({ error: 'Invalid or expired license' });
    }
  };
}

module.exports = {
  extractBearerToken,
  makeFeatureLicenseMiddleware,
  makeLicensePublicKeyHandler,
};
