const express = require('express');
const { User, ROLES } = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { requireRole } = require('../middleware/roles');

const router = express.Router();

router.use(requireAuth, requireRole(ROLES.USER, ROLES.ADMIN));

router.get('/profile', (req, res) => {
  res.json({ user: req.user.toUserProfile() });
});

router.get('/list', async (req, res, next) => {
  try {
    const users = await User.find({ role: ROLES.USER }).sort({ fullName: 1 }).select('fullName');
    res.json({
      users: users.map((user) => ({
        fullName: user.fullName,
      })),
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;

