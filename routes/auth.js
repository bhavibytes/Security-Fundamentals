const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Email, password, and name are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Password must be at least 6 characters long'
      });
    }

    const user = await User.create({ email, password, name });
    
    res.status(201).json({
      message: 'User registered successfully',
      user
    });
  } catch (error) {
    if (error.message === 'User already exists') {
      return res.status(409).json({
        error: 'Conflict',
        message: 'User with this email already exists'
      });
    }

    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Registration failed'
    });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Email and password are required'
      });
    }

    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials'
      });
    }

    const isValidPassword = await User.validatePassword(email, password);
    if (!isValidPassword) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid credentials'
      });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name
    };

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Login failed'
    });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'Logout failed'
      });
    }

    res.clearCookie('connect.sid');
    res.json({
      message: 'Logout successful'
    });
  });
});

router.get('/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Not authenticated'
    });
  }

  res.json({
    user: req.session.user
  });
});

module.exports = router;
