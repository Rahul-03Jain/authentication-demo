const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

/**
 * Helmet Security Headers
 * Configures Content Security Policy (CSP) to permit Tailwind CSS CDN and Google Fonts.
 */
function applySecurityHeaders(app) {
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "'unsafe-inline'",
            "https://cdn.tailwindcss.com"
          ],
          styleSrc: [
            "'self'",
            "'unsafe-inline'",
            "https://fonts.googleapis.com"
          ],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: false,
    })
  );
}

/**
 * Login Rate Limiter
 * 15 minutes, maximum 100 requests per IP on login/signup routes
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * MongoDB Injection protection middleware
 * Recursively deletes keys starting with '$' to prevent query injection attacks.
 */
function sanitizeMongoQuery(obj) {
  if (obj instanceof Object) {
    for (const key in obj) {
      if (key.startsWith('$')) {
        delete obj[key];
      } else {
        sanitizeMongoQuery(obj[key]);
      }
    }
  }
}

function mongoSanitize(req, res, next) {
  sanitizeMongoQuery(req.body);
  sanitizeMongoQuery(req.query);
  sanitizeMongoQuery(req.params);
  next();
}

/**
 * Double Submit Cookie CSRF Protection
 */
function setupCsrf(req, res, next) {
  if (!req.cookies['csrf-token']) {
    const token = crypto.randomBytes(32).toString('hex');
    res.cookie('csrf-token', token, {
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });
  }
  next();
}

function verifyCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const cookieToken = req.cookies['csrf-token'];
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'CSRF validation failed. Refresh the page and try again.' });
  }

  next();
}

function applySecurityMiddleware(app) {
  applySecurityHeaders(app);
  app.use(mongoSanitize);
  app.use(setupCsrf);
  app.use(verifyCsrf);
}

module.exports = {
  applySecurityMiddleware,
  loginLimiter,
};

