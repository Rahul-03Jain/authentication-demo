const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { encryptField, decryptField } = require('../utils/fieldCrypto');

const ROLES = Object.freeze({
  USER: 'user',
  ADMIN: 'admin',
});

// Getter and setter helpers for date values stored encrypted
const dateEncryptor = {
  get: (val) => {
    const decrypted = decryptField(val);
    return decrypted ? new Date(decrypted) : null;
  },
  set: (val) => {
    if (!val) return null;
    const dateStr = val instanceof Date ? val.toISOString() : new Date(val).toISOString();
    return encryptField(dateStr);
  }
};

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
      required: true,
      trim: true,
      minlength: 2,
      maxlength: 100,
    },
    email: {
      type: String,
      required: true,
      get: decryptField,
      set: encryptField,
    },
    emailHash: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: Object.values(ROLES),
      default: ROLES.USER,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    mfaEnabled: {
      type: Boolean,
      default: false,
    },
    mfaSecret: {
      type: String,
      default: null,
      get: decryptField,
      set: encryptField,
    },
    otpCode: {
      type: String,
      default: null,
    },
    otpExpiresAt: {
      type: String,
      default: null,
      ...dateEncryptor,
    },
    resetToken: {
      type: String,
      default: null,
      get: decryptField,
      set: encryptField,
    },
    lastLogin: {
      type: Date,
      default: null,
    },
    isDisabled: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
    toJSON: { getters: true },
    toObject: { getters: true },
  }
);

// Pre-validate hook to calculate emailHash before schema validation
userSchema.pre('validate', async function () {
  if (this.isModified('email') && this.email) {
    this.emailHash = crypto
      .createHash('sha256')
      .update(this.email.toLowerCase().trim())
      .digest('hex');
  }
});

// Pre-save hook for encryption and hashing
userSchema.pre('save', async function () {
  // Sanitize fullName to prevent basic XSS
  if (this.isModified('fullName') && typeof this.fullName === 'string') {
    this.fullName = this.fullName.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Hash password if modified and not already hashed
  if (this.isModified('password') && !this.password.startsWith('$2')) {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
  }
});

// Compare bcrypt password
userSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

// Profile view (names only to protect privacy)
userSchema.methods.toUserProfile = function () {
  return {
    fullName: this.fullName,
  };
};

// Admin view (does not expose plain passwords, password hashes, or MFA secrets)
userSchema.methods.toAdminView = function () {
  return {
    id: String(this._id),
    fullName: this.fullName,
    email: this.email, // automatically decrypted when read via getter
    role: this.role,
    isDisabled: this.isDisabled,
    createdAt: this.createdAt,
    lastLogin: this.lastLogin,
  };
};

const User = mongoose.models.User || mongoose.model('User', userSchema);

module.exports = {
  User,
  ROLES,
};
