/**
 * Centralized environment configuration and validation.
 * All secrets are read from process.env — never hard-coded.
 */

const isProduction = process.env.NODE_ENV === 'production';

const config = {
  port: Number(process.env.PORT) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction,
  jwtSecret: process.env.JWT_SECRET || '',
  cookieMaxAgeMs: Number(process.env.COOKIE_MAX_AGE_MS) || 86400000,
  mongodbUri: (process.env.MONGODB_URI || '').trim(),
  dbEncryptionKey: (process.env.DB_ENCRYPTION_KEY || '').trim(),
};

function isMongoUriUnset(uri) {
  return !uri || uri.trim().length === 0;
}

/**
 * Validate required environment variables.
 */
function validateEnv({ exitOnError = false } = {}) {
  const errors = [];
  const warnings = [];

  const minLen = isProduction ? 16 : 8;

  if (!config.jwtSecret || config.jwtSecret.length < minLen) {
    errors.push(`JWT_SECRET must be set and at least ${minLen} characters.`);
  }

  if (isMongoUriUnset(config.mongodbUri)) {
    errors.push('MONGODB_URI is not set. A valid MongoDB URI is required.');
  }

  if (!config.dbEncryptionKey) {
    if (isProduction) {
      errors.push('DB_ENCRYPTION_KEY must be set in production.');
    } else {
      warnings.push('DB_ENCRYPTION_KEY is not set. A temporary fallback key will be generated for development.');
    }
  }

  if (errors.length) {
    console.error('[Config] Environment validation failed:');
    errors.forEach((e) => console.error(`  - ${e}`));
    if (exitOnError) process.exit(1);
  }
  if (warnings.length) {
    console.warn('[Config] Warnings:');
    warnings.forEach((w) => console.warn(`  - ${w}`));
  }

  return { valid: errors.length === 0, errors, warnings, config };
}

module.exports = {
  config,
  validateEnv,
  isMongoUriUnset,
};
