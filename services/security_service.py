import html
import re
from functools import wraps
from flask import request, jsonify, session

class OWASPSecurityService:
    @staticmethod
    def sanitize_input(data: str) -> str:
        if not isinstance(data, str):
            return data
        return html.escape(data.strip())

    @staticmethod
    def validate_email(email: str) -> bool:
        regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z2-9]{2,}$'
        return bool(re.match(regex, email))

    @staticmethod
    def apply_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';"
        )
        return response

    @staticmethod
    def require_auth(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user' not in session:
                return jsonify({"error": "Unauthorized", "message": "กรุณาเข้าสู่ระบบก่อนใช้งาน"}), 401
            return f(*args, **kwargs)
        return decorated

    @staticmethod
    def require_role(required_role: str):
        """Decorator สำหรับตรวจสอบสิทธิ์เฉพาะ Role เช่น require_role('admin')"""
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                user = session.get('user')
                if not user:
                    return jsonify({"error": "Unauthorized", "message": "กรุณาเข้าสู่ระบบก่อนใช้งาน"}), 401
                if user.get('role') != required_role:
                    return jsonify({"error": "Forbidden", "message": f"สิทธิ์ไม่เพียงพอ ต้องใช้สิทธิ์ระดับ {required_role}"}), 403
                return f(*args, **kwargs)
            return decorated
        return decorator