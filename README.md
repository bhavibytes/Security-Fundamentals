# Security Fundamentals

A secure authentication system built with Node.js and Express demonstrating fundamental security practices.

## Features

- ✅ User registration with password hashing (bcrypt)
- ✅ Secure login with session management
- ✅ Protected routes requiring authentication
- ✅ Session-based authentication
- ✅ Input validation and error handling
- ✅ CSRF protection with sameSite cookies
- ✅ HTTP-only cookies for security

## Tech Stack

- **Backend:** Node.js, Express.js
- **Authentication:** Express Sessions, bcrypt
- **Frontend:** Vanilla HTML/CSS/JavaScript
- **Security:** HTTP-only cookies, CSRF protection

## API Endpoints

- `POST /register` - Register new user
- `POST /login` - User authentication
- `GET /me` - Get current authenticated user
- `POST /logout` - Destroy session
- `GET /` - Health check

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create `.env` file:
```
SESSION_SECRET=your-super-secret-session-key
```

3. Start server:
```bash
node server.js
```

4. Open http://localhost:3000

## Security Features Demonstrated

- **Password Hashing:** Uses bcrypt with salt rounds of 12
- **Session Management:** Secure session configuration
- **Input Validation:** Server-side validation for all inputs
- **CSRF Protection:** sameSite cookie setting
- **HTTP-Only Cookies:** Prevents XSS attacks
- **Secure Headers:** Proper security headers

## Learning Objectives

This project demonstrates:
- Secure password storage
- Session-based authentication
- Input validation best practices
- Cookie security settings
- Error handling patterns
- Basic security middleware

## Contributing

This is a learning project for security fundamentals. Feel free to fork and experiment!
