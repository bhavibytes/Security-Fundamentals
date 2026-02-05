// ===============================
// Imports
// ===============================
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
require("dotenv").config();

// Input validation library (built-in)
const { body, validationResult } = require('express-validator');

// ===============================
// App Initialization
// ===============================
const app = express();
const PORT = 3000;

// ===============================
// Middleware
// ===============================
app.use(express.json());

// Serve static files
app.use(express.static('public'));

app.use(
  session({
    name: "secure-session",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // true in production
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

// ===============================
// Temporary In-Memory Database
// ===============================
const users = [];

// ===============================
// Auth Middleware
// ===============================
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send("Authentication required");
  }
  next();
}

// Role check middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.session.user.role !== role) {
      return res.status(403).send("Access denied");
    }
    next();
  };
}

// ===============================
// Routes
// ===============================

// Health check
app.get("/", (req, res) => {
  res.send("Auth server with RBAC running");
});

// -------------------------------
// Register
// -------------------------------
app.post("/register",
  [
    // Input validation and sanitization
    body('username')
      .trim()
      .isLength({ min: 3, max: 20 })
      .withMessage('Username must be 3-20 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores')
      .escape(),

    body('password')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage('Password must contain at least one lowercase, one uppercase, and one number'),

    body('role')
      .optional()
      .trim()
      .isIn(['user', 'admin'])
      .withMessage('Role must be either user or admin')
      .escape()
  ],
  async (req, res) => {
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: "Validation failed",
          details: errors.array()
        });
      }

      const { username, password, role } = req.body;

      // Prevent users from self-registering as admin
      const userRole = role === "admin" ? "user" : "user";

      // Check if user exists
      const existingUser = users.find(u => u.username === username);
      if (existingUser) {
        return res.status(409).json({
          error: "User already exists",
          message: "Username is already taken"
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 12);

      // Store user
      users.push({
        username,
        password: hashedPassword,
        role: userRole,
        createdAt: new Date()
      });

      res.status(201).json({
        message: "User registered successfully",
        user: { username, role: userRole }
      });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({
        error: "Server error",
        message: "Registration failed"
      });
    }
  }
);

// -------------------------------
// Login
// -------------------------------
app.post("/login",
  [
    // Input validation and sanitization
    body('username')
      .trim()
      .isLength({ min: 3, max: 20 })
      .withMessage('Username must be 3-20 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores')
      .escape(),

    body('password')
      .notEmpty()
      .withMessage('Password is required')
  ],
  async (req, res) => {
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: "Validation failed",
          details: errors.array()
        });
      }

      const { username, password } = req.body;

      const user = users.find(u => u.username === username);
      if (!user) {
        return res.status(401).json({
          error: "Invalid credentials",
          message: "Username or password is incorrect"
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({
          error: "Invalid credentials",
          message: "Username or password is incorrect"
        });
      }

      // Store identity + role in session
      req.session.user = {
        username: user.username,
        role: user.role
      };

      res.json({
        message: "Login successful",
        user: {
          username: user.username,
          role: user.role
        }
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({
        error: "Server error",
        message: "Login failed"
      });
    }
  }
);

// -------------------------------
// Protected User Route
// -------------------------------
app.get("/dashboard", requireAuth, (req, res) => {
  res.json({
    message: "User dashboard",
    user: req.session.user
  });
});

// -------------------------------
// Admin-Only Route
// -------------------------------
app.get(
  "/admin",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    res.send("Welcome admin. Sensitive data access granted.");
  }
);

// -------------------------------
// Logout
// -------------------------------
app.post("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send("Logout failed");
    }
    res.clearCookie("secure-session");
    res.send("Logged out successfully");
  });
});

// ===============================
// Server Start
// ===============================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
