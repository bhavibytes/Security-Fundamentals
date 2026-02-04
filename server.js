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
app.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;

    // Input validation
    if (!username || !password || password.length < 8) {
      return res.status(400).send("Invalid input");
    }

    // Prevent users from self-registering as admin
    const userRole = role === "admin" ? "user" : "user";

    // Check if user exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(409).send("User already exists");
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Store user
    users.push({
      username,
      password: hashedPassword,
      role: userRole
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

    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).send("Invalid credentials");
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send("Invalid credentials");
    }

    // Store identity + role in session
    req.session.user = {
      username: user.username,
      role: user.role
    };

    res.send("Login successful");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

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
