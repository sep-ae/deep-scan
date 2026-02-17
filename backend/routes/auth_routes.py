from flask import Blueprint, jsonify, request
from extensions import db
from models import User
from flask_jwt_extended import create_access_token
from sqlalchemy import or_ 
from flasgger import swag_from 
import re

# --- HELPER FUNCTIONS ---
def is_password_strong(password):
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
    if re.match(pattern, email):
        return True
    return False

# --- BLUEPRINT SETUP ---
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# --- ROUTES ---

@auth_bp.route('/register', methods=['POST'])
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
      500:
        description: Internal Server Error
    """
    data = request.json
    username = data.get('username')
    email = data.get('email')    
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"msg": "Username, Email, dan Password wajib diisi"}), 400
    
    if not is_valid_email(email):
        return jsonify({"msg": "Format Email tidak valid"}), 400

    is_valid_pass, reason = is_password_strong(password)
    if not is_valid_pass:
        return jsonify({"msg": f"Password lemah: {reason}"}), 400
    
    existing_user = User.query.filter(
        or_(User.username == username, User.email == email)
    ).first()

    if existing_user:
        if existing_user.username == username:
            return jsonify({"msg": "Username sudah dipakai"}), 400
        if existing_user.email == email:
            return jsonify({"msg": "Email sudah terdaftar"}), 400

    new_user = User(username=username, email=email) 
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "Registrasi Berhasil. Silakan Login"}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error Database: {e}")
        return jsonify({"msg": "Terjadi kesalahan server"}), 500

@auth_bp.route('/login', methods=['POST'])
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
    """
    data = request.json
    login_input = data.get('identifier') or data.get('username') or data.get('email')
    password = data.get('password')

    if not login_input or not password:
        return jsonify({"msg": "Harap isi Username/Email dan Password"}), 400

    user = User.query.filter(
        or_(User.username == login_input, User.email == login_input)
    ).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=str(user.user_id))
        return jsonify({
            "msg": "Login Sukses",
            "access_token": access_token,
            "user": {
                "id": user.user_id,
                "username": user.username,
                "email": user.email
            }
        }), 200
    
    return jsonify({"msg": "Username/Email atau Password Salah"}), 401