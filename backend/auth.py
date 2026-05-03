"""
Authentication Module — Role-Based Access Control
Roles: admin (full access), analyst (read-only, no blacklist/sniffer control)
Uses JWT tokens stored in localStorage on frontend.
Passwords are bcrypt-hashed in DB.
"""

import jwt
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app

# ─── User Store ───────────────────────────────────────────────────────────────
# In production, move this to DB. For this project, seeded in-memory + DB.

DEFAULT_USERS = [
    {
        'username': 'admin',
        'password': 'admin123',   # will be hashed on first run
        'role': 'admin',
        'display_name': 'Administrator',
    },
    {
        'username': 'analyst',
        'password': 'analyst123',
        'role': 'analyst',
        'display_name': 'Security Analyst',
    },
]

JWT_SECRET = 'nids-jwt-secret-change-in-production'
JWT_EXPIRY_HOURS = 8


# ─── DB Model ─────────────────────────────────────────────────────────────────

def init_auth(app, db):
    """Create users table and seed default accounts"""
    from database import User
    with app.app_context():
        db.create_all()
        for u in DEFAULT_USERS:
            if not User.query.filter_by(username=u['username']).first():
                hashed = bcrypt.hashpw(u['password'].encode(), bcrypt.gensalt()).decode()
                user = User(
                    username=u['username'],
                    password_hash=hashed,
                    role=u['role'],
                    display_name=u['display_name'],
                )
                db.session.add(user)
        db.session.commit()
        print("✅ Auth users seeded (admin / analyst)")


# ─── Token Utils ──────────────────────────────────────────────────────────────

def generate_token(user) -> str:
    payload = {
        'sub': user.username,
        'role': user.role,
        'display_name': user.display_name,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_from_request() -> str | None:
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    # Also check cookie for browser sessions
    return request.cookies.get('nids_token')


# ─── Decorators ───────────────────────────────────────────────────────────────

def login_required(f):
    """Require any valid logged-in user"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authentication required', 'code': 'NO_TOKEN'}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}), 401
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authentication required', 'code': 'NO_TOKEN'}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}), 401
        if payload.get('role') != 'admin':
            return jsonify({'error': 'Admin access required', 'code': 'FORBIDDEN'}), 403
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated


def analyst_or_admin(f):
    """Require analyst or admin role (most read routes)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({'error': 'Authentication required', 'code': 'NO_TOKEN'}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}), 401
        if payload.get('role') not in ('admin', 'analyst'):
            return jsonify({'error': 'Access denied', 'code': 'FORBIDDEN'}), 403
        request.current_user = payload
        return f(*args, **kwargs)
    return decorated