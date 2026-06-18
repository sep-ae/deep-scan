from flask import Blueprint, jsonify, request, current_app
from extensions import db, limiter
from models import User
from flask_jwt_extended import create_access_token
from sqlalchemy import or_
import re
import logging

logger = logging.getLogger(__name__)


def is_password_strong(password):
    if len(password) > 128:
        return False, "Password maksimal 128 karakter."
    if len(password) < 8:
        return False, "Password minimal 8 karakter."
    if not re.search(r"\d", password):
        return False, "Password harus mengandung minimal 1 angka."
    if not re.search(r"[a-z]", password):
        return False, "Password harus mengandung minimal 1 huruf kecil."
    if not re.search(r"[A-Z]", password):
        return False, "Password harus mengandung minimal 1 huruf besar."
    if not re.search(r"[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]", password):
        return False, "Password harus mengandung minimal 1 karakter khusus."
    return True, None


def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))


def sanitize_input(value, max_length=255):
    if not value:
        return value
    return str(value).strip()[:max_length]


auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    """
    Registrasi Pengguna Baru
    ---
    tags:
      - Authentication
    summary: Mendaftarkan user baru ke dalam sistem
    description: Endpoint ini menerima username, email, dan password. Password harus memenuhi kriteria keamanan.
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - email
            - password
          properties:
            username:
              type: string
              example: "admin123"
            email:
              type: string
              example: "admin@deepscan.local"
            password:
              type: string
              example: "P@ssw0rdKuat!"
    responses:
      201:
        description: Registrasi Berhasil
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Registrasi Berhasil. Silakan Login"
      400:
        description: Validasi Gagal (Input kosong, format salah, atau data duplikat)
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Password lemah: Password harus mengandung minimal 1 angka."
      429:
        description: Terlalu banyak permintaan
      500:
        description: Internal Server Error
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"msg": "Request body tidak valid"}), 400

    username = sanitize_input(data.get('username'), max_length=50)
    email = sanitize_input(data.get('email'), max_length=255)
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({"msg": "Username, Email, dan Password wajib diisi"}), 400

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({"msg": "Username hanya boleh mengandung huruf, angka, dan underscore"}), 400

    if not is_valid_email(email):
        return jsonify({"msg": "Format Email tidak valid"}), 400

    is_valid_pass, reason = is_password_strong(password)
    if not is_valid_pass:
        return jsonify({"msg": f"Password lemah: {reason}"}), 400

    existing_user = User.query.filter(
        or_(User.username == username, User.email == email)
    ).first()

    if existing_user:
        return jsonify({"msg": "Username atau Email sudah terdaftar"}), 400

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"[REGISTER SUCCESS] username={username} | IP={request.remote_addr}")
        return jsonify({"msg": "Registrasi Berhasil. Silakan Login"}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"[REGISTER ERROR] {e} | IP={request.remote_addr}")
        return jsonify({"msg": "Terjadi kesalahan server"}), 500


@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """
    Login User
    ---
    tags:
      - Authentication
    summary: Masuk ke sistem dan dapatkan Token JWT
    description: User bisa login menggunakan Username ATAU Email.
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - password
          properties:
            identifier:
              type: string
              description: Bisa diisi Username atau Email
              example: "admin@deepscan.local"
            password:
              type: string
              example: "P@ssw0rdKuat!"
    responses:
      200:
        description: Login Sukses
        schema:
          type: object
          properties:
            msg:
              type: string
              example: "Login Sukses"
            access_token:
              type: string
              description: Token JWT untuk akses endpoint lain
            user:
              type: object
              properties:
                id:
                  type: integer
                username:
                  type: string
                email:
                  type: string
      400:
        description: Input tidak lengkap
      401:
        description: Password salah atau User tidak ditemukan
      429:
        description: Terlalu banyak permintaan
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"msg": "Request body tidak valid"}), 400

    login_input = sanitize_input(
        data.get('identifier') or data.get('username') or data.get('email'),
        max_length=255
    )
    password = data.get('password', '')

    if not login_input or not password:
        return jsonify({"msg": "Harap isi Username/Email dan Password"}), 400

    if len(password) > 128:
        return jsonify({"msg": "Username/Email atau Password Salah"}), 401

    user = User.query.filter(
        or_(User.username == login_input, User.email == login_input)
    ).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.user_id))
        logger.info(f"[LOGIN SUCCESS] user_id={user.user_id} | IP={request.remote_addr}")
        return jsonify({
            "msg": "Login Sukses",
            "access_token": access_token,
            "user": {
                "id": user.user_id,
                "username": user.username,
                "email": user.email
            }
        }), 200

    logger.warning(f"[LOGIN FAILED] identifier={login_input} | IP={request.remote_addr}")
    return jsonify({"msg": "Username/Email atau Password Salah"}), 401


@auth_bp.route('/google', methods=['POST'])
@limiter.limit("10 per minute")
def google_login():
    """
    Login dengan Google
    ---
    tags:
      - Authentication
    summary: Login menggunakan akun Google (OAuth 2.0)
    description: Menerima Google ID Token dari frontend, verifikasi, dan kembalikan JWT.
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - credential
          properties:
            credential:
              type: string
              description: Google ID Token dari Google Identity Services
    responses:
      200:
        description: Login Google Sukses
      400:
        description: Token tidak diberikan
      401:
        description: Token tidak valid atau kadaluarsa
      500:
        description: Internal Server Error
    """
    data = request.get_json(silent=True)
    if not data or not data.get('credential'):
        return jsonify({"msg": "Token Google tidak valid"}), 400

    try:
        from google.oauth2 import id_token
        from google.auth.transport import requests as google_requests

        client_id = current_app.config.get('GOOGLE_CLIENT_ID', '')
        if not client_id:
            logger.error("[GOOGLE LOGIN] GOOGLE_CLIENT_ID belum di-set!")
            return jsonify({"msg": "Google Login belum dikonfigurasi di server"}), 500

        idinfo = id_token.verify_oauth2_token(
            data['credential'],
            google_requests.Request(),
            client_id
        )

        google_id = idinfo['sub']
        email = idinfo.get('email', '')
        name = idinfo.get('name', email.split('@')[0] if email else 'user')

        if not email:
            return jsonify({"msg": "Akun Google tidak memiliki email"}), 400

        # Cek user existing berdasarkan google_id atau email
        user = User.query.filter(
            or_(User.google_id == google_id, User.email == email)
        ).first()

        if not user:
            # Auto-register user baru via Google
            # Buat username unik dari nama
            base_username = re.sub(r'[^a-zA-Z0-9_]', '_', name)[:40]
            username = base_username
            counter = 1
            while User.query.filter_by(username=username).first():
                username = f"{base_username}_{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                auth_provider='google',
                google_id=google_id
            )
            db.session.add(user)
            db.session.commit()
            logger.info(f"[GOOGLE REGISTER] email={email} | IP={request.remote_addr}")

        elif not user.google_id:
            # Link akun lokal yang sudah ada dengan Google
            user.google_id = google_id
            if user.auth_provider == 'local':
                user.auth_provider = 'google'
            db.session.commit()
            logger.info(f"[GOOGLE LINK] user_id={user.user_id} linked to Google | IP={request.remote_addr}")

        access_token = create_access_token(identity=str(user.user_id))
        logger.info(f"[GOOGLE LOGIN SUCCESS] user_id={user.user_id} | IP={request.remote_addr}")

        return jsonify({
            "msg": "Login Google Sukses",
            "access_token": access_token,
            "user": {
                "id": user.user_id,
                "username": user.username,
                "email": user.email
            }
        }), 200

    except ValueError as e:
        logger.warning(f"[GOOGLE LOGIN FAILED] Invalid token: {e} | IP={request.remote_addr}")
        return jsonify({"msg": "Token Google tidak valid atau sudah kadaluarsa"}), 401
    except Exception as e:
        db.session.rollback()
        logger.error(f"[GOOGLE LOGIN ERROR] {e} | IP={request.remote_addr}")
        return jsonify({"msg": "Terjadi kesalahan server"}), 500
