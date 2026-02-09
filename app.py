"""
Cybersecurity Learning Application
A secure Flask application demonstrating defensive security principles
"""

import os
import logging
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, jsonify, session, abort, make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, 
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import bleach
import re
from functools import wraps
import time

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///security_app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    RATE_LIMIT_STORAGE = {}
    ACCOUNT_LOCKOUT_STORAGE = {}

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_audit.log'),
        logging.StreamHandler()
    ]
)
audit_logger = logging.getLogger('security_audit')

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        """Hash password with bcrypt"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.is_locked and self.locked_until:
            if datetime.utcnow() > self.locked_until:
                self.is_locked = False
                self.failed_attempts = 0
                self.locked_until = None
                db.session.commit()
                return False
            return True
        return False
    
    def lock_account(self):
        """Lock account for 5 minutes after 5 failed attempts"""
        self.is_locked = True
        self.locked_until = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()

class SecurityLog(db.Model):
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref=db.backref('security_logs', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.query.get(int(user_id))

# Security Decorators
def admin_required(f):
    """Decorator requiring admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            audit_logger.warning(f"Unauthorized admin access attempt by user {current_user.id if current_user.is_authenticated else 'anonymous'} from {request.remote_addr}")
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
                    audit_logger.warning(f"Rate limit exceeded for IP {client_ip}")
                    abort(429)
                Config.RATE_LIMIT_STORAGE[client_ip].append(current_time)
            else:
                Config.RATE_LIMIT_STORAGE[client_ip] = [current_time]
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Input Validation Functions
def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number")
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character")
    
    # Check for common patterns
    common_patterns = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if any(pattern in password.lower() for pattern in common_patterns):
        errors.append("Password contains common patterns that are not allowed")
    
    return errors

def sanitize_input(input_text):
    """Sanitize input to prevent XSS"""
    if input_text:
        return bleach.clean(input_text, tags=[], strip=True)
    return ""

# Security Headers Middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Audit Logging Function
def log_security_event(event_type, user_id=None, details=None):
    """Log security events"""
    log_entry = SecurityLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
        details=details
    )
    db.session.add(log_entry)
    db.session.commit()
    
    audit_logger.info(f"Security Event: {event_type} - IP: {request.remote_addr} - User: {user_id} - Details: {details}")

# Routes
@app.route('/')
def index():
    """Home page"""
    log_security_event('page_access', details='Home page accessed')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=3, window_seconds=900)  # 3 registrations per 15 minutes
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
        if User.query.filter_by(username=username).first():
            errors.append("Username already exists")
        
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered")
        
        if errors:
            log_security_event('registration_failed', details=f"Validation errors: {', '.join(errors)}")
            return render_template('register.html', errors=errors)
        
        # Create user
        user = User(username=username, email=email, role='user')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        log_security_event('user_registered', user.id, f"New user registered: {username}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 login attempts per 5 minutes
def login():
    """User login"""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', '').strip())
        password = request.form.get('password', '')
        
        if not username or not password:
            log_security_event('login_failed', details='Missing username or password')
            flash('Please provide both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            log_security_event('login_failed', details=f'Username not found: {username}')
            flash('Invalid username or password', 'error')
            return render_template('login.html')
        
        # Check account lockout
        if user.is_account_locked():
            log_security_event('login_blocked', user.id, 'Account is locked')
            flash('Account is temporarily locked due to multiple failed attempts. Please try again later.', 'error')
            return render_template('login.html')
        
        # Verify password
        if user.check_password(password):
            # Reset failed attempts on successful login
            user.failed_attempts = 0
            user.is_locked = False
            user.locked_until = None
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user)
            session.permanent = True
            
            log_security_event('login_success', user.id, f"User {username} logged in")
            flash('Login successful!', 'success')
            
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            user.failed_attempts += 1
            
            if user.failed_attempts >= 5:
                user.lock_account()
                log_security_event('account_locked', user.id, f'Account locked after 5 failed attempts')
                flash('Account has been locked due to multiple failed attempts. Please try again in 5 minutes.', 'error')
            else:
                remaining_attempts = 5 - user.failed_attempts
                log_security_event('login_failed', user.id, f'Invalid password. Attempts: {user.failed_attempts}')
                flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'error')
            
            db.session.commit()
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    log_security_event('dashboard_access', current_user.id)
    return render_template('dashboard.html', user=current_user)

@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    """Admin panel"""
    users = User.query.all()
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).limit(50).all()
    return render_template('admin.html', users=users, logs=logs)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    log_security_event('logout', current_user.id, f"User {current_user.username} logged out")
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Error Handlers
@app.errorhandler(403)
def forbidden(error):
    log_security_event('access_denied', current_user.id if current_user.is_authenticated else None, '403 Forbidden')
    return render_template('error.html', error_code=403, message="Access Denied"), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, message="Page Not Found"), 404

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('error.html', error_code=429, message="Too Many Requests - Rate limit exceeded"), 429

@app.errorhandler(500)
def internal_error(error):
    log_security_event('server_error', current_user.id if current_user.is_authenticated else None, '500 Internal Server Error')
    return render_template('error.html', error_code=500, message="Internal Server Error"), 500

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('AdminSecure123!@#')
        db.session.add(admin)
        db.session.commit()
        print("Default admin user created: username=admin, password=AdminSecure123!@#")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
