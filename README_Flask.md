# Cybersecurity Learning Application

A comprehensive Flask-based web application demonstrating defensive security principles and threat mitigation strategies. This project showcases secure coding practices, authentication/authorization mechanisms, and protection against common web vulnerabilities.

## 🎯 Project Overview

**Project Type:** Cybersecurity & Ethical Hacking Internship Project-01  
**Technology Stack:** Python Flask, SQLite, HTML/CSS  
**Focus:** Defensive Security, Secure Development Lifecycle

## 🛡️ Security Features Implemented

### 1. Authentication & Authorization
- **User Registration & Login:** Secure account creation and authentication
- **Role-Based Access Control (RBAC):** User and Admin roles with different privileges
- **Session Management:** Secure session handling with timeout (30 minutes)

### 2. Password Security
- **bcrypt Hashing:** Passwords stored using bcrypt with unique salts
- **Strong Password Policy:**
  - Minimum 12 characters
  - Mixed case letters
  - Numbers and special characters
  - Common pattern detection
- **Account Lockout:** 5 failed attempts lock account for 5 minutes
- **Password Change:** Secure password update mechanism

### 3. Input Validation & Sanitization
- **SQL Injection Prevention:** Parameterized queries exclusively
- **Input pattern validation**
- **No string concatenation in SQL**
- **Cross-Site Scripting (XSS) Prevention:**
  - HTML entity encoding
  - Input sanitization on server-side
  - Content Security Policy headers
- **Email Validation:** Proper email format verification

### 4. Session Security
- **Secure Cookies:**
  - HTTP-only
  - Secure flags
- **Session Fixation Prevention:** Regeneration on login
- **Timeout:** Automatic session expiration
- **Forced Re-authentication:** For sensitive operations

### 5. Additional Security Controls
- **Security Headers:**
  - Content-Security-Policy
  - X-Frame-Options: DENY
  - X-Content-Type-Options: nosniff
  - Strict-Transport-Security
  - X-XSS-Protection
- **Audit Logging:** All security events logged
- **Error Handling:** Generic error messages (no information leakage)
- **Database Security:** Least privilege principle in schema design

## 🚨 Threats and Mitigations

| Threat | Mitigation Implemented |
|--------|----------------------|
| SQL Injection | Parameterized queries, input validation, SQL keyword filtering |
| Cross-Site Scripting (XSS) | Input sanitization, HTML encoding, CSP headers |
| Brute Force Attacks | Account lockout, rate limiting, strong password requirements |
| Session Hijacking | Secure cookies, session regeneration, timeouts |
| Information Disclosure | Generic error messages, no stack traces in production |
| Weak Authentication | bcrypt hashing, password complexity, account lockout |
| CSRF | State-changing operations require authentication |
| Clickjacking | X-Frame-Options: DENY header |

## 🏗️ Security Layers

### Perimeter Defense
- Security headers
- Rate limiting

### Authentication Layer
- Strong password hashing
- Session management

### Authorization Layer
- Role-based access control

### Input Validation Layer
- Sanitization
- Validation
- Encoding

### Data Layer
- Parameterized queries
- Prepared statements

### Monitoring Layer
- Audit logging
- Security event tracking

## 🔄 Application Flow

### 1. Registration Process
```
User Input → Input Validation → Password Strength Check → 
Sanitization → bcrypt Hashing → Database Insert → Success/Error Response
```

### 2. Authentication Flow
```
Login Request → Input Sanitization → Database Lookup → 
Password Verification → Session Creation → Access Control → Dashboard Redirect
```

### 3. Request Processing
```
HTTP Request → Security Headers → Session Validation → 
Input Sanitization → Business Logic → Secure Response → Audit Logging
```

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- pip package manager

### Installation Steps

1. **Clone the repository:**
```bash
git clone https://github.com/bhavibytes/Security-Fundamentals.git
cd Security-Fundamentals/secure-app
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your secret keys
```

4. **Initialize the database:**
```bash
python app.py
# The database will be created automatically
```

5. **Run the application:**
```bash
python app.py
```

6. **Access the application:**
Open your browser and navigate to `http://localhost:5000`

## 🔑 Default Credentials

**Admin Account:**
- Username: `admin`
- Password: `AdminSecure123!@#`

## 📊 Features Overview

### User Features
- Secure registration with strong password enforcement
- Login with account lockout protection
- Personal dashboard with security information
- Session management with automatic timeout

### Admin Features
- User management and monitoring
- Security audit log viewing
- Account status tracking
- System security overview

### Security Testing
- SQL injection protection testing
- XSS prevention testing
- Brute force attack simulation
- Session security verification

## 🧪 Testing Security Features

### 1. SQL Injection Testing
Try entering SQL commands in login/registration forms:
```sql
' OR '1'='1' --
'; DROP TABLE users; --
```

### 2. XSS Testing
Try entering JavaScript code:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

### 3. Brute Force Testing
Attempt multiple failed logins to trigger account lockout.

### 4. Session Security
Check browser developer tools for secure cookie settings.

## 📁 Project Structure

```
secure-app/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables
├── security_audit.log     # Audit log file
├── security_app.db        # SQLite database
├── templates/             # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Home page
│   ├── register.html     # Registration form
│   ├── login.html        # Login form
│   ├── dashboard.html    # User dashboard
│   ├── admin.html        # Admin panel
│   └── error.html        # Error pages
└── README_Flask.md       # This file
```

## 🔧 Configuration

### Environment Variables
- `SECRET_KEY`: Flask secret key for sessions
- `DATABASE_URL`: SQLite database URL
- `FLASK_ENV`: Environment (development/production)

### Security Configuration
- Session timeout: 30 minutes
- Account lockout: 5 failed attempts → 5 minutes
- Rate limiting: 5 requests per 5 minutes (login), 3 per 15 minutes (registration)

## 📈 Monitoring & Logging

### Security Events Logged
- User registration
- Login attempts (success/failure)
- Account lockouts
- Access denied events
- Page access patterns
- Error occurrences

### Log Location
- File: `security_audit.log`
- Console output during development

## 🎓 Learning Objectives

This project demonstrates:

1. **Secure Authentication**
   - Password hashing with bcrypt
   - Session management
   - Multi-factor authentication concepts

2. **Authorization & Access Control**
   - Role-based permissions
   - Resource protection
   - Privilege escalation prevention

3. **Input Validation & Sanitization**
   - SQL injection prevention
   - XSS protection
   - Data validation patterns

4. **Security Headers & Configuration**
   - HTTP security headers
   - Cookie security settings
   - CSP implementation

5. **Monitoring & Auditing**
   - Security event logging
   - Intrusion detection
   - Incident response basics

## 🐛 Common Issues & Solutions

### Python Installation Issues
If Python is not found, ensure Python is installed and added to PATH:
```bash
# Check Python installation
python --version
# or
python3 --version
```

### Dependency Installation
If pip fails, try:
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Database Issues
If database doesn't initialize, delete `security_app.db` and restart the application.

## 🤝 Contributing

This is a learning project for cybersecurity education. Feel free to:
- Fork and experiment
- Submit issues and suggestions
- Contribute security improvements
- Add new security features

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

## 🔗 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Security Documentation](https://flask.palletsprojects.com/)
- [bcrypt Password Hashing](https://pypi.org/project/bcrypt/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)

---

**⚠️ Disclaimer:** This application is for educational purposes only. Do not use in production without additional security hardening and professional security review.
