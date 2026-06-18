const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { User, ROLES } = require('../models/User');
const { setAuthCookie, clearAuthCookie } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/security');
const {
  generateEmailOtp,
  hashEmailOtp,
  verifyEmailOtp,
  getEmailOtpExpiry,
} = require('../utils/emailOtp');
const { sendEmailOtp } = require('../utils/mailer');
const { generateTotpSetup, verifyTotpCode } = require('../utils/totp');

const router = express.Router();

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateSignup({ fullName, email, password }) {
  const errors = [];
  const normalizedEmail = normalizeEmail(email);

  if (!fullName || String(fullName).trim().length < 2 || String(fullName).trim().length > 100) {
    errors.push('Full name must be 2 to 100 characters.');
  }
  if (!isValidEmail(normalizedEmail)) {
    errors.push('Enter a valid email address.');
  }
  if (!password || String(password).length < 8 || String(password).length > 128) {
    errors.push('Password must be 8 to 128 characters.');
  }

  return { errors, normalizedEmail };
}

// 1. SIGNUP: Generate OTP and store details in temporary JWT cookie
router.post('/signup', loginLimiter, async (req, res, next) => {
  try {
    const { errors, normalizedEmail } = validateSignup(req.body);
    if (errors.length) {
      return res.status(400).json({ error: errors[0] });
    }

    const emailHash = crypto.createHash('sha256').update(normalizedEmail).digest('hex');
    const existing = await User.findOne({ emailHash });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    const otp = generateEmailOtp();
    const otpHash = await hashEmailOtp(otp);
    const otpExpiresAt = getEmailOtpExpiry().toISOString();

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(String(req.body.password), salt);

    const signupToken = jwt.sign(
      {
        fullName: String(req.body.fullName).trim(),
        email: normalizedEmail,
        passwordHash,
        otpHash,
        otpExpiresAt,
      },
      process.env.JWT_SECRET,
      { expiresIn: '10m' }
    );

    res.cookie('signup_pending', signupToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 10 * 60 * 1000,
    });

    const isProduction = process.env.NODE_ENV === 'production';

    if (!isProduction) {
      console.log(`[DEV] Signup OTP for ${normalizedEmail}: ${otp}`);
      await sendEmailOtp(normalizedEmail, otp, req.body.fullName).catch(() => {});

      return res.status(200).json({
        message: `Your OTP is: ${otp}`,
        devOtp: otp,
        redirect: '/verify-otp',
      });
    } else {
      await sendEmailOtp(normalizedEmail, otp, req.body.fullName);
      return res.status(200).json({
        message: 'A 6-digit verification code has been sent to your email.',
        redirect: '/verify-otp',
      });
    }
  } catch (error) {
    next(error);
  }
});

// 2. VERIFY OTP: Validate code and proceed to MFA Google Authenticator setup page
router.post('/verify-otp', loginLimiter, async (req, res, next) => {
  try {
    const { otp } = req.body;
    if (!otp) {
      return res.status(400).json({ error: 'Verification code is required.' });
    }

    const signupToken = req.cookies?.signup_pending;
    if (!signupToken) {
      return res.status(400).json({ error: 'Signup session expired or invalid. Please sign up again.' });
    }

    let payload;
    try {
      payload = jwt.verify(signupToken, process.env.JWT_SECRET);
    } catch {
      return res.status(400).json({ error: 'Signup session expired or invalid. Please sign up again.' });
    }

    if (new Date() > new Date(payload.otpExpiresAt)) {
      return res.status(400).json({ error: 'Verification code has expired. Please sign up again.' });
    }

    const isOtpValid = await verifyEmailOtp(otp, payload.otpHash);
    if (!isOtpValid) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }

    const emailHash = crypto.createHash('sha256').update(payload.email).digest('hex');
    const existing = await User.findOne({ emailHash });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    // Generate Google Authenticator secret
    const { base32Secret } = await generateTotpSetup(payload.email);

    // Save inactive user record to database with mfaSecret configured
    const user = await User.create({
      fullName: payload.fullName,
      email: payload.email, // encrypted on save
      password: payload.passwordHash, // pre-hashed
      role: ROLES.USER,
      emailVerified: true,
      mfaEnabled: false,
      mfaSecret: base32Secret, // encrypted on save
    });

    const mfaToken = jwt.sign(
      {
        sub: String(user._id),
        email: payload.email,
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.cookie('mfa_pending', mfaToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 15 * 60 * 1000,
    });

    res.clearCookie('signup_pending');

    return res.status(200).json({
      message: 'Email verified successfully. Redirecting to MFA configuration...',
      redirect: '/mfa-setup',
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/auth/mfa-setup-details: Fetch QR and secret fallback for pending sessions
router.get('/mfa-setup-details', async (req, res, next) => {
  try {
    const mfaToken = req.cookies?.mfa_pending;
    if (!mfaToken) {
      console.log('[MFA DETAILS] Access denied: No pending setup session found.');
      return res.status(401).json({ error: 'MFA setup session expired or invalid.' });
    }

    let payload;
    try {
      payload = jwt.verify(mfaToken, process.env.JWT_SECRET);
    } catch {
      console.log('[MFA DETAILS] Access denied: JWT validation failed.');
      return res.status(401).json({ error: 'MFA setup session expired or invalid.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      console.log(`[MFA DETAILS] Access denied: User ${payload.sub} not found.`);
      return res.status(404).json({ error: 'User account not found.' });
    }

    let base32Secret = user.mfaSecret;
    if (!base32Secret) {
      const setup = await generateTotpSetup(user.email);
      base32Secret = setup.base32Secret;
      user.mfaSecret = base32Secret;
      await user.save();
      console.log(`[MFA] Secret generated dynamically for ${user.email}`);
    }

    // Generate QR Code from secret
    const qrCodeDataUrl = await require('../utils/totp').qrFromSecret(user.email, base32Secret);
    console.log(`[MFA] QR code generated successfully for ${user.email}`);
    console.log(`[MFA] Secret existence checked for ${user.email}: ${Boolean(base32Secret)}`);

    return res.status(200).json({
      qrCodeDataUrl,
      manualSecret: base32Secret, // decrypted automatically via getter
      email: user.email,
    });
  } catch (error) {
    next(error);
  }
});

// 3. VERIFY MFA SETUP: Scan QR, verify token, activate account
router.post('/verify-mfa-setup', loginLimiter, async (req, res, next) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'Google Authenticator code is required.' });
    }

    const mfaToken = req.cookies?.mfa_pending;
    if (!mfaToken) {
      console.log('[MFA SETUP] Verification failed: No pending setup session found.');
      return res.status(401).json({ error: 'MFA setup session expired or invalid.' });
    }

    let payload;
    try {
      payload = jwt.verify(mfaToken, process.env.JWT_SECRET);
    } catch {
      console.log('[MFA SETUP] Verification failed: JWT validation failed.');
      return res.status(401).json({ error: 'MFA setup session expired or invalid.' });
    }

    const user = await User.findById(payload.sub);
    if (!user) {
      console.log(`[MFA SETUP] Verification failed: User ID ${payload.sub} not found.`);
      return res.status(404).json({ error: 'User account not found.' });
    }

    // Verify TOTP code against the stored secret
    const isTotpValid = verifyTotpCode(user.mfaSecret, code);
    console.log(`[MFA] MFA verification code checked for ${user.email}. Result: ${isTotpValid}`);

    if (!isTotpValid) {
      console.log(`[MFA SETUP] Failure: Invalid Google Authenticator code for ${user.email}`);
      return res.status(400).json({ error: 'Invalid Google Authenticator code. Try again.' });
    }

    // Set MFA enabled, activating the account
    user.mfaEnabled = true;
    user.lastLogin = new Date();
    await user.save();

    console.log(`[MFA SETUP] Success: MFA enabled and account activated for ${user.email}`);

    res.clearCookie('mfa_pending');
    setAuthCookie(res, user);

    const redirect = user.role === ROLES.ADMIN ? '/admin' : '/dashboard';
    return res.status(200).json({
      message: 'Multi-Factor Authentication enabled successfully. Welcome!',
      redirect,
    });
  } catch (error) {
    console.log(`[MFA SETUP] Verification error: ${error.message}`);
    next(error);
  }
});

// 4. USER LOGIN: Authenticate credentials and verify MFA challenge
router.post('/login', loginLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const code = String(req.body.code || '').trim();

    if (!isValidEmail(email) || !password) {
      console.log('[LOGIN] Failure: Invalid email format or empty password field.');
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const user = await User.findOne({ emailHash });

    if (!user) {
      console.log(`[LOGIN] User not found for email: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    console.log(`[LOGIN] User found in DB: ${email}`);

    const isMatch = await user.comparePassword(password);
    console.log(`[LOGIN] Password verification result for ${email}: ${isMatch}`);

    if (!isMatch) {
      console.log(`[LOGIN] Failure: Password mismatch for ${email}`);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.role !== ROLES.USER) {
      console.log(`[LOGIN] Forbidden: Admin account ${email} attempted standard user login.`);
      return res.status(403).json({ error: 'Admin accounts must use the admin login page.' });
    }

    if (user.isDisabled) {
      console.log(`[LOGIN] Forbidden: Account ${email} is disabled.`);
      return res.status(403).json({ error: 'Account is disabled.' });
    }

    if (!user.emailVerified) {
      console.log(`[LOGIN] Forbidden: Email verification incomplete for ${email}`);
      return res.status(403).json({ error: 'Account setup is incomplete. Please verify your email.' });
    }

    console.log(`[MFA] Checking secret existence for ${email}: ${Boolean(user.mfaSecret)}`);

    // If MFA is not enabled yet
    if (!user.mfaEnabled) {
      if (!user.mfaSecret) {
        const setup = await generateTotpSetup(user.email);
        user.mfaSecret = setup.base32Secret;
        await user.save();
        console.log(`[MFA] Autogenerated initial secret for user ${email}`);
      }

      const mfaToken = jwt.sign(
        { sub: String(user._id), email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      res.cookie('mfa_pending', mfaToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000,
      });

      console.log(`[LOGIN] Redirecting user ${email} to /mfa-setup`);
      return res.status(200).json({
        requiresMfaSetup: true,
        redirect: '/mfa-setup',
        message: 'MFA setup required. Redirecting to setup page...',
      });
    }

    // MFA challenge check for active user
    if (!code) {
      console.log(`[LOGIN] MFA challenge code requested for user ${email}`);
      return res.status(200).json({
        requiresMfa: true,
        message: 'Google Authenticator code required.',
      });
    }

    const isTotpValid = verifyTotpCode(user.mfaSecret, code);
    console.log(`[MFA] Code verification result for user ${email}: ${isTotpValid}`);

    if (!isTotpValid) {
      console.log(`[LOGIN] Failure: Invalid MFA code for user ${email}`);
      return res.status(401).json({ error: 'Invalid Google Authenticator code.' });
    }

    user.lastLogin = new Date();
    await user.save();

    setAuthCookie(res, user);
    console.log(`[LOGIN] Success: User ${email} authenticated.`);
    return res.status(200).json({
      message: 'Login successful.',
      redirect: '/dashboard',
    });
  } catch (error) {
    console.log(`[LOGIN] Internal error: ${error.message}`);
    next(error);
  }
});

// 5. ADMIN LOGIN: Authenticate credentials, trigger setup if first-time, or check MFA challenge
router.post('/admin-login', loginLimiter, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const code = String(req.body.code || '').trim();

    if (!isValidEmail(email) || !password) {
      console.log('[LOGIN] Failure: Invalid email format or empty password field.');
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const emailHash = crypto.createHash('sha256').update(email).digest('hex');
    const user = await User.findOne({ emailHash });

    if (!user) {
      console.log(`[LOGIN] Admin not found for email: ${email}`);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    console.log(`[LOGIN] Admin found in DB: ${email}`);

    const isMatch = await user.comparePassword(password);
    console.log(`[LOGIN] Password verification result for ${email}: ${isMatch}`);

    if (!isMatch) {
      console.log(`[LOGIN] Failure: Password mismatch for ${email}`);
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    if (user.role !== ROLES.ADMIN) {
      console.log(`[LOGIN] Forbidden: User ${email} does not have admin role.`);
      return res.status(403).json({ error: 'This account is not an admin.' });
    }

    if (user.isDisabled) {
      console.log(`[LOGIN] Forbidden: Admin account ${email} is disabled.`);
      return res.status(403).json({ error: 'Account is disabled.' });
    }

    console.log(`[MFA] Checking secret existence for ${email}: ${Boolean(user.mfaSecret)}`);

    // If MFA is not enabled yet (first login flow for seeded admin)
    if (!user.mfaEnabled) {
      // Automatically generate a secret if not present
      if (!user.mfaSecret) {
        const setup = await generateTotpSetup(user.email);
        user.mfaSecret = setup.base32Secret;
        await user.save();
        console.log(`[MFA] Autogenerated initial secret for admin ${email}`);
      }

      // Set pending cookie
      const mfaToken = jwt.sign(
        { sub: String(user._id), email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: '15m' }
      );
      res.cookie('mfa_pending', mfaToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000,
      });

      console.log(`[LOGIN] Redirecting admin ${email} to /admin-mfa-setup`);
      return res.status(200).json({
        requiresMfaSetup: true,
        redirect: '/admin-mfa-setup',
        message: 'MFA setup required. Redirecting to setup page...',
      });
    }

    // MFA challenge check for active admin
    if (!code) {
      console.log(`[LOGIN] MFA challenge code requested for admin ${email}`);
      return res.status(200).json({
        requiresMfa: true,
        message: 'Google Authenticator code required.',
      });
    }

    const isTotpValid = verifyTotpCode(user.mfaSecret, code);
    console.log(`[MFA] Code verification result for admin ${email}: ${isTotpValid}`);

    if (!isTotpValid) {
      console.log(`[LOGIN] Failure: Invalid MFA code for admin ${email}`);
      return res.status(401).json({ error: 'Invalid Google Authenticator code.' });
    }

    user.lastLogin = new Date();
    await user.save();

    setAuthCookie(res, user);
    console.log(`[LOGIN] Success: Admin ${email} authenticated.`);
    return res.status(200).json({
      message: 'Login successful.',
      redirect: '/admin',
    });
  } catch (error) {
    console.log(`[LOGIN] Internal error: ${error.message}`);
    next(error);
  }
});

// LOGOUT: Clear cookies
router.post('/logout', (req, res) => {
  clearAuthCookie(res);
  res.clearCookie('signup_pending');
  res.clearCookie('mfa_pending');
  res.json({ message: 'Logged out successfully.' });
});

module.exports = router;
