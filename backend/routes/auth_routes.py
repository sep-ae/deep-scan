from flask import Blueprint, jsonify, request
from extensions import db
from models import User
from flask_jwt_extended import create_access_token
import re

# Fungsi Validasi Kekuatan Password
def is_password_strong(password):
    if len(password) < 8:
        return False, "Minimal 8 karakter."
    if not re.search(r"\d", password):
        return False, "Harus mengandung minimal 1 angka."
    if not re.search(r"[a-z]", password):
        return False, "Harus mengandung minimal 1 huruf kecil."
    if not re.search(r"[A-Z]", password):
        return False, "Harus mengandung minimal 1 huruf besar."
    if not re.search(r"[!@#$%^&*()_+{}\[\]:;<>,.?~\\-]", password):
        return False, "Harus mengandung minimal 1 karakter khusus."
    return True, None


auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Daftar User Baru
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username: {type: string}
            password: {type: string}
    responses:
      201:
        description: User berhasil dibuat
      400:
        description: Gagal/Username sudah ada
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username dan Password wajib diisi"}), 400
    
    is_valid, reason = is_password_strong(password)
    if not is_valid:
        return jsonify({"msg": f"Password tidak kuat: {reason}"}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username sudah dipakai"}), 400

    new_user = User(username=username)
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "Registrasi Berhasil. Silakan Login"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login User (Dapatkan Token JWT)
    ---
    tags:
      - Authentication
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            username: {type: string}
            password: {type: string}
    responses:
      200:
        description: Login sukses, mengembalikan token
      401:
        description: Username atau Password salah
    """
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify({
            "msg": "Login Sukses",
            "access_token": access_token
        }), 200
    
    return jsonify({"msg": "Username atau Password Salah"}), 401