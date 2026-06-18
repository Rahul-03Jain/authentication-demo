#!/usr/bin/env node
/**
 * Create or verify default admin account automatically.
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const mongoose = require('mongoose');
const crypto = require('crypto');
const { User, ROLES } = require('../models/User');

async function seedDefaultAdmin() {
  const email = 'admin1@gmail.com';
  const name = 'admin1';
  const password = 'Admin01';

  const emailHash = crypto.createHash('sha256').update(email).digest('hex');
  const existing = await User.findOne({ emailHash });

  if (!existing) {
    await User.create({
      fullName: name,
      email: email,
      password: password,
      role: ROLES.ADMIN,
      emailVerified: true,
      mfaEnabled: false,
    });
    console.log('[SEED] Default admin account created successfully.');
  } else {
    let modified = false;
    if (existing.role !== ROLES.ADMIN) {
      existing.role = ROLES.ADMIN;
      modified = true;
    }
    if (existing.emailVerified !== true) {
      existing.emailVerified = true;
      modified = true;
    }
    if (modified) {
      await existing.save();
      console.log('[SEED] Default admin account verified and updated.');
    } else {
      console.log('[SEED] Default admin account already exists.');
    }
  }
}

async function runCli() {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) {
    console.error('Error: MONGODB_URI is not set in environment.');
    process.exit(1);
  }

  try {
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 3000 });
    console.log('Connected to MongoDB.');
    await seedDefaultAdmin();
  } catch (err) {
    console.error(`Failed to connect or seed: ${err.message}`);
    process.exit(1);
  } finally {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }
  }
  process.exit(0);
}

if (require.main === module) {
  runCli();
}

module.exports = { seedDefaultAdmin };
