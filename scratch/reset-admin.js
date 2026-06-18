const mongoose = require('mongoose');
const crypto = require('crypto');
require('dotenv').config({ path: 'd:/coding/bsp project/web-dev-main/.env' });

const { User } = require('d:/coding/bsp project/web-dev-main/models/User');

async function reset() {
  const uri = process.env.MONGODB_URI;
  console.log('Connecting to:', uri);
  await mongoose.connect(uri);
  const emailHash = crypto.createHash('sha256').update('admin1@gmail.com').digest('hex');
  await User.updateOne({ emailHash }, { mfaEnabled: false, mfaSecret: null });
  console.log('Admin user reset successfully (mfaEnabled = false, mfaSecret = null).');
  await mongoose.disconnect();
}

reset().catch(err => {
  console.error(err);
  process.exit(1);
});
