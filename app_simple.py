"""
Simple Cybersecurity Learning Application
A secure Flask application demonstrating defensive security principles
"""

import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, jsonify, session, abort, make_response
)
from functools import wraps
import time
import re

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DATABASE_URL = 'security_app.db'
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    RATE_LIMIT_STORAGE = {}

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Database Functions
def get_db():
    """Get database connection"""
    conn = sqlite3.connect(app.config['DATABASE_URL'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_locked BOOLEAN DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    ''')
    
    # Create security_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Password hashing with SHA-256 (simplified for demo)
def hash_password(password, salt=None):
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use SHA-256 with salt (in production, use bcrypt)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return salt + password_hash

def verify_password(password, password_hash):
    """Verify password against hash"""
    salt = password_hash[:32]  # First 32 characters are salt
    hash_part = password_hash[32:]
    return hash_password(password, salt) == password_hash

# Input Validation Functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < 8:  # Reduced for demo
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    return errors

def sanitize_input(input_text):
    """Sanitize input to prevent XSS"""
    if input_text:
        # Basic HTML escaping
        return (input_text.replace("&", "&amp;")
                        .replace("<", "&lt;")
                        .replace(">", "&gt;")
                        .replace('"', "&quot;")
                        .replace("'", "&#x27;"))
    return ""

# Security Decorators
def admin_required(f):
    """Decorator requiring admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or user['role'] != 'admin':
            log_security_event('access_denied', session.get('user_id'), 'Admin access denied')
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=5, window_seconds=300):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Clean old entries
            Config.RATE_LIMIT_STORAGE = {
                ip: times for ip, times in Config.RATE_LIMIT_STORAGE.items()
                if any(t > current_time - window_seconds for t in times)
            }
            
            # Check current IP
            if client_ip in Config.RATE_LIMIT_STORAGE:
                recent_requests = [
                    t for t in Config.RATE_LIMIT_STORAGE[client_ip]
                    if t > current_time - window_seconds
                ]
                if len(recent_requests) >= max_requests:
                    log_security_event('rate_limit_exceeded', None, f'Rate limit exceeded for {client_ip}')
                    abort(429)
                Config.RATE_LIMIT_STORAGE[client_ip].append(current_time)
            else:
                Config.RATE_LIMIT_STORAGE[client_ip] = [current_time]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Audit Logging Function
def log_security_event(event_type, user_id=None, details=None):
    """Log security events"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        user_id,
        event_type,
        request.remote_addr,
        request.headers.get('User-Agent', ''),
        details
    ))
    conn.commit()
    conn.close()

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# Routes
@app.route('/')
def index():
    """Home page"""
    log_security_event('page_access', details='Home page accessed')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window_seconds=900)
def register():
    """User registration"""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        email = sanitize_input(request.form.get('email', '').strip())
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        errors = []
        
        if not username or len(username) < 3 or len(username) > 20:
            errors.append("Username must be 3-20 characters long")
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append("Username can only contain letters, numbers, and underscores")
        
        if not validate_email(email):
            errors.append("Invalid email format")
        
        password_errors = validate_password(password)
        errors.extend(password_errors)
        
        if password != confirm_password:
            errors.append("Passwords do not match")
        
        # Check if user exists
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            errors.append("Username or email already exists")
        conn.close()
        
        if errors:
            log_security_event('registration_failed', details=f"Validation errors: {', '.join(errors)}")
            return render_template('register.html', errors=errors)
        
        # Create user
        conn = get_db()
        cursor = conn.cursor()
        password_hash = hash_password(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, 'user'))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        log_security_event('user_registered', user_id, f"New user registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=15, window_seconds=300)
def login():
    """User login"""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        
        if not username or not password:
            log_security_event('login_failed', details='Missing username or password')
            flash('Please provide both username and password', 'error')
            return render_template('login.html')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        
        if not user_data:
            log_security_event('login_failed', details=f'Username not found: {username}')
            flash('Invalid username or password', 'error')
            conn.close()
            return render_template('login.html')
        
        user = dict(user_data)
        
        # Check account lockout
        if user['is_locked']:
            locked_until = datetime.fromisoformat(user['locked_until']) if user['locked_until'] else None
            if locked_until and datetime.utcnow() < locked_until:
                log_security_event('login_blocked', user['id'], 'Account is locked')
                flash('Account is temporarily locked due to multiple failed attempts. Please try again later.', 'error')
                conn.close()
                return render_template('login.html')
            else:
                # Unlock account if lock time expired
                cursor.execute('UPDATE users SET is_locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
                conn.commit()
                user['is_locked'] = False
                user['failed_attempts'] = 0
        
        # Verify password
        if verify_password(password, user['password_hash']):
            # Reset failed attempts on successful login
            cursor.execute('''
                UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL, last_login = ?
                WHERE id = ?
            ''', (datetime.utcnow().isoformat(), user['id']))
            conn.commit()
            conn.close()
            
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            
            log_security_event('login_success', user['id'], f"User {username} logged in")
            flash('Login successful!', 'success')
            
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            failed_attempts = user['failed_attempts'] + 1
            
            if failed_attempts >= 5:
                locked_until = datetime.utcnow() + timedelta(minutes=5)
                cursor.execute('''
                    UPDATE users SET failed_attempts = ?, is_locked = 1, locked_until = ?
                    WHERE id = ?
                ''', (failed_attempts, locked_until.isoformat(), user['id']))
                conn.commit()
                log_security_event('account_locked', user['id'], f'Account locked after 5 failed attempts')
                flash('Account has been locked due to multiple failed attempts. Please try again in 5 minutes.', 'error')
            else:
                cursor.execute('UPDATE users SET failed_attempts = ? WHERE id = ?', (failed_attempts, user['id']))
                conn.commit()
                remaining_attempts = 5 - failed_attempts
                log_security_event('login_failed', user['id'], f'Invalid password. Attempts: {failed_attempts}')
                flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'error')
            
            conn.close()
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if not session.get('user_id'):
        return redirect(url_for('login'))
    
    log_security_event('dashboard_access', session['user_id'])
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = dict(cursor.fetchone())
    conn.close()
    
    return render_template('dashboard.html', user=user)

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin panel"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all users
    cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
    users = [dict(row) for row in cursor.fetchall()]
    
    # Get recent logs
    cursor.execute('''
        SELECT sl.*, u.username 
        FROM security_logs sl 
        LEFT JOIN users u ON sl.user_id = u.id 
        ORDER BY sl.timestamp DESC 
        LIMIT 50
    ''')
    logs = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/logout')
def logout():
    """User logout"""
    user_id = session.get('user_id')
    username = session.get('username', 'unknown')
    
    log_security_event('logout', user_id, f"User {username} logged out")
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Error Handlers
@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error_code=403, message="Access Denied"), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, message="Page Not Found"), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', error_code=429, message="Too Many Requests - Rate limit exceeded"), 429

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, message="Internal Server Error"), 500

# Initialize database and create default admin
if __name__ == '__main__':
    init_db()
    
    # Create default admin user if not exists
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        password_hash = hash_password('AdminSecure123!@#')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', ('admin', 'admin@example.com', password_hash, 'admin'))
        conn.commit()
        print("Default admin user created: username=admin, password=AdminSecure123!@#")
    
    conn.close()
    app.run(debug=True, host='0.0.0.0', port=5000)
