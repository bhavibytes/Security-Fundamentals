// ===============================
// Imports
// ===============================
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
require("dotenv").config();

// ===============================
// App Initialization
// ===============================
const app = express();
const PORT = 3000;

// ===============================
// Middleware
// ===============================

// Parse JSON bodies
app.use(express.json());

// Serve static files
app.use(express.static('public'));

// Session configuration
app.use(
  session({
    name: "secure-session",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,        // JS cannot access cookie
      sameSite: "lax",       // Basic CSRF protection
      secure: false,         // true in production (HTTPS)
      maxAge: 1000 * 60 * 60 // 1 hour
    }
  })
);

// ===============================
// Temporary In-Memory Database
// ===============================
const users = [];

// ===============================
// Routes
// ===============================

// Health check
app.get("/", (req, res) => {
  res.send("Auth server running");
});

// -------------------------------
// Register
// -------------------------------
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password || password.length < 8) {
      return res.status(400).send("Invalid input");
    }

    // Check if user already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(409).send("User already exists");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Store user
    users.push({
      username,
      password: hashedPassword
    });

    res.status(201).send("User registered successfully");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// -------------------------------
// Login
// -------------------------------
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).send("Invalid credentials");
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send("Invalid credentials");
    }

    // Create session
    req.session.user = {
      username: user.username
    };

    res.send("Login successful");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// -------------------------------
// Protected Route
// -------------------------------
app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).send("Not authenticated");
  }

  res.json({
    message: "Authenticated user",
    user: req.session.user
  });
});

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
