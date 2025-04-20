const mongoose = require('mongoose');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  verificationToken: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
});

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const hash = crypto.createHash('sha256').update(this.password).digest('hex');
  this.password = hash;
  next();
});

module.exports = mongoose.model('SecureUser', userSchema);