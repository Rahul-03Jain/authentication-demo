const jwt = require('jsonwebtoken');
const { User } = require('../models/User');

function getCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: Number(process.env.COOKIE_MAX_AGE_MS) || 24 * 60 * 60 * 1000,
  };
}

function signAuthToken(user) {
  return jwt.sign(
    {
      sub: String(user._id),
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1d' }
  );
}

function setAuthCookie(res, user) {
  res.cookie('token', signAuthToken(user), getCookieOptions());
}

function clearAuthCookie(res) {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
  });
}

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.token;
    if (!token) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);

    if (!user) {
      clearAuthCookie(res);
      return res.status(401).json({ error: 'Session user no longer exists.' });
    }

    if (user.isDisabled) {
      clearAuthCookie(res);
      return res.status(403).json({ error: 'Account is disabled.' });
    }

    req.user = user;
    next();
  } catch {
    clearAuthCookie(res);
    return res.status(401).json({ error: 'Invalid or expired session.' });
  }
}

module.exports = {
  requireAuth,
  signAuthToken,
  setAuthCookie,
  clearAuthCookie,
};
