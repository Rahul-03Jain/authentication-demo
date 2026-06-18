require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const { applySecurityMiddleware } = require('./middleware/security');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

const app = express();

app.disable('x-powered-by');

// Enable cookies and body parser
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Apply rate limiting, CSRF, Mongo query sanitization, and Helmet CSP
applySecurityMiddleware(app);

// Serve static assets directly
app.use(express.static(path.join(__dirname, 'public')));

// Clean page routing (routes without .html extension)
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin-login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/admin-mfa-setup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-mfa-setup.html'));
});

app.get('/mfa-setup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'mfa-setup.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Database connection
async function connectDB() {
  const uri = process.env.MONGODB_URI;

  if (!uri) {
    throw new Error('[DB] MONGODB_URI is not set. A valid MongoDB connection is required.');
  }

  try {
    await mongoose.connect(uri, { serverSelectionTimeoutMS: 5000 });
    console.log('[DB] Successfully connected to MongoDB.');
    
    // Automatically seed default admin
    const { seedDefaultAdmin } = require('./scripts/seed-admin');
    await seedDefaultAdmin();
  } catch (err) {
    console.error(`[DB] Failed to connect to MongoDB: ${err.message}`);
    throw err;
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);

// Fallback for API routes
app.use('/api', (req, res) => {
  res.status(404).json({ error: 'API route not found.' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.code === 11000) {
    return res.status(409).json({ error: 'Email already registered.' });
  }

  console.error(err);
  res.status(err.status || 500).json({
    error: err.status && err.status < 500 ? err.message : 'Internal server error.',
  });
});

module.exports = {
  app,
  connectDB,
};

