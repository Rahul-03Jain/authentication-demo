const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const { User, ROLES } = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');

const router = express.Router();

router.use(requireAuth, requireRole(ROLES.ADMIN));

function isValidId(id) {
  return mongoose.Types.ObjectId.isValid(id);
}

async function findTargetUser(req, res) {
  if (!isValidId(req.params.id)) {
    res.status(400).json({ error: 'Invalid user id.' });
    return null;
  }

  const user = await User.findById(req.params.id);
  if (!user) {
    res.status(404).json({ error: 'User not found.' });
    return null;
  }

  return user;
}

router.get('/users', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.max(1, parseInt(req.query.limit) || 10);
    const skip = (page - 1) * limit;

    // Retrieve all users from DB
    const allUsers = await User.find({});

    // Filter in memory (emails are decrypted on access because of getter)
    let filteredUsers = allUsers;

    // Search filter (name or email)
    if (req.query.search) {
      const searchStr = String(req.query.search).trim().toLowerCase();
      filteredUsers = filteredUsers.filter((u) => {
        const nameMatch = u.fullName && u.fullName.toLowerCase().includes(searchStr);
        const emailMatch = u.email && u.email.toLowerCase().includes(searchStr);
        return nameMatch || emailMatch;
      });
    }

    // Role filter
    if (req.query.role && req.query.role !== 'all') {
      filteredUsers = filteredUsers.filter((u) => u.role === req.query.role);
    }

    // Status filter
    if (req.query.status && req.query.status !== 'all') {
      const wantDisabled = req.query.status === 'disabled';
      filteredUsers = filteredUsers.filter((u) => u.isDisabled === wantDisabled);
    }

    // Sort by createdAt descending
    filteredUsers.sort((a, b) => {
      return new Date(b.createdAt) - new Date(a.createdAt);
    });

    // Stats calculations (on all users in system)
    const totalUsers = allUsers.filter((u) => u.role === ROLES.USER).length;
    const totalAdmins = allUsers.filter((u) => u.role === ROLES.ADMIN).length;
    const activeUsers = allUsers.filter((u) => !u.isDisabled).length;
    const disabledUsers = allUsers.filter((u) => u.isDisabled).length;

    // Pagination
    const totalMatching = filteredUsers.length;
    const totalPages = Math.ceil(totalMatching / limit);
    const paginatedUsers = filteredUsers.slice(skip, skip + limit);

    res.json({
      users: paginatedUsers.map((user) => user.toAdminView()),
      pagination: {
        total: totalMatching,
        page,
        pages: totalPages,
        limit,
      },
      stats: {
        totalUsers,
        totalAdmins,
        activeUsers,
        disabledUsers,
      },
    });
  } catch (error) {
    next(error);
  }
});

router.post('/create-user', async (req, res, next) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
    const existing = await User.findOne({ emailHash });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    // Create user with verified email but disabled MFA initially (set up on first login)
    const user = await User.create({
      fullName,
      email: email.toLowerCase().trim(),
      password,
      role: ROLES.USER,
      emailVerified: true,
      mfaEnabled: false,
    });

    res.status(201).json({
      message: 'User created successfully.',
      user: user.toAdminView(),
    });
  } catch (error) {
    next(error);
  }
});

router.post('/create-admin', async (req, res, next) => {
  try {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const emailHash = crypto.createHash('sha256').update(email.toLowerCase().trim()).digest('hex');
    const existing = await User.findOne({ emailHash });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered.' });
    }

    // Create admin with verified email but disabled MFA initially (set up on first login)
    const user = await User.create({
      fullName,
      email: email.toLowerCase().trim(),
      password,
      role: ROLES.ADMIN,
      emailVerified: true,
      mfaEnabled: false,
    });

    res.status(201).json({
      message: 'Admin created successfully.',
      user: user.toAdminView(),
    });
  } catch (error) {
    next(error);
  }
});

router.patch('/users/:id/disable', async (req, res, next) => {
  try {
    if (String(req.user._id) === req.params.id) {
      return res.status(400).json({ error: 'You cannot disable your own account.' });
    }

    const user = await findTargetUser(req, res);
    if (!user) return;

    user.isDisabled = true;
    await user.save();
    res.json({ message: 'User disabled.', user: user.toAdminView() });
  } catch (error) {
    next(error);
  }
});

router.patch('/users/:id/enable', async (req, res, next) => {
  try {
    const user = await findTargetUser(req, res);
    if (!user) return;

    user.isDisabled = false;
    await user.save();
    res.json({ message: 'User enabled.', user: user.toAdminView() });
  } catch (error) {
    next(error);
  }
});

router.patch('/users/:id/promote', async (req, res, next) => {
  try {
    const user = await findTargetUser(req, res);
    if (!user) return;

    user.role = ROLES.ADMIN;
    await user.save();
    res.json({ message: 'User promoted to admin.', user: user.toAdminView() });
  } catch (error) {
    next(error);
  }
});

router.patch('/users/:id/demote', async (req, res, next) => {
  try {
    if (String(req.user._id) === req.params.id) {
      return res.status(400).json({ error: 'You cannot demote your own admin account.' });
    }

    const user = await findTargetUser(req, res);
    if (!user) return;

    const remainingAdmins = await User.countDocuments({
      role: ROLES.ADMIN,
      _id: { $ne: user._id },
    });
    if (remainingAdmins === 0) {
      return res.status(400).json({ error: 'At least one admin must remain.' });
    }

    user.role = ROLES.USER;
    await user.save();
    res.json({ message: 'Admin demoted to user.', user: user.toAdminView() });
  } catch (error) {
    next(error);
  }
});

router.delete('/users/:id', async (req, res, next) => {
  try {
    if (String(req.user._id) === req.params.id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const user = await findTargetUser(req, res);
    if (!user) return;

    if (user.role === ROLES.ADMIN) {
      const remainingAdmins = await User.countDocuments({
        role: ROLES.ADMIN,
        _id: { $ne: user._id },
      });
      if (remainingAdmins === 0) {
        return res.status(400).json({ error: 'At least one admin must remain.' });
      }
    }

    await user.deleteOne();
    res.json({ message: 'User deleted.' });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
