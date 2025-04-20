const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const SecureUser = require('../models/User');

dotenv.config();

// Email transporter setup
const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Check transporter
transporter.verify((error, success) => {
  if (error) {
    console.error('Transporter error:', error);
  } else {
    console.log('Email transporter is ready');
  }
});

// REGISTER ROUTE
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  console.log(password);
  try {
    let user = await SecureUser.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const hashedPassword = crypto.createHash('sha256').update(password.trim()).digest('hex');

    console.log("Registering password:", password.trim());
console.log("Hashed password to store:", hashedPassword);



    user = new SecureUser({ email, password: hashedPassword, verificationToken });
    await user.save();

    const verificationUrl = `${process.env.CLIENT_URL}/verify/${verificationToken}`;

    // Send verification email
    await transporter.sendMail({
      to: email,
      subject: 'Welcome! Please Verify Your Email',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333; padding: 20px;">
          <h2 style="color: #4CAF50;">Welcome!</h2>
          <p>Thanks for signing up. Please confirm your email by clicking the button below:</p>
          <a href="${verificationUrl}" 
             style="display:inline-block;padding:10px 20px;margin:20px 0;background-color:#4CAF50;color:white;text-decoration:none;border-radius:5px;">
             Verify My Email
          </a>
          <p>If the button doesn't work, copy and paste this link:</p>
          <p style="word-break: break-all;"><a href="${verificationUrl}">${verificationUrl}</a></p>
        </div>
      `,
    }).then(() => {
      console.log(`Verification email sent to ${email}`);
    }).catch(err => {
      console.error('Error sending verification email:', err);
    });

    res.status(201).json({ msg: 'User registered. Please verify your email.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

// VERIFY EMAIL ROUTE
router.get('/verify/:token', async (req, res) => {
  try {
    const user = await SecureUser.findOne({ verificationToken: req.params.token });
    if (!user) return res.status(400).json({ msg: 'Invalid token' });

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.json({ msg: 'Email verified successfully' });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

// LOGIN ROUTE
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await SecureUser.findOne({ email });
    console.log('User found:', user);
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const hashedPassword1 = crypto.createHash('sha256').update(password.trim()).digest('hex');
    const finalpass = crypto.createHash('sha256').update(hashedPassword1.trim()).digest('hex');

    if (finalpass !== user.password) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ msg: 'Please verify your email first' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

// GET LOGGED-IN USER
router.get('/user', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await SecureUser.findById(decoded.userId).select('-password -verificationToken');
    if (!user) return res.status(404).json({ msg: 'User not found' });

    res.json(user);
  } catch (error) {
    console.error('User fetch error:', error);
    res.status(500).json({ msg: 'Server error' });
  }
});

module.exports = router;
