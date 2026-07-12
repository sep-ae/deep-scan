# app.py
from flask import Flask, jsonify
from config import Config, IS_DEV
from extensions import db, jwt, limiter
from flask_cors import CORS
from flasgger import Swagger
import logging
import os

from routes.auth_routes import auth_bp
from routes.scan_routes import scan_bp
from routes.dashboard_routes import dashboard_bp
import models


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    _configure_logging(app)

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    CORS(app, resources={
        r"/api/*": {
            "origins": [
                "http://localhost:5173", 
                "http://localhost:3000",
                "https://deepscan.web.id",
                "https://www.deepscan.web.id"
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })

    if IS_DEV:
        swagger = Swagger(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(dashboard_bp)

    _register_error_handlers(app)

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        if not IS_DEV:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.route('/')
    def index():
        res = {"status": "Scanner API Online"}
        if IS_DEV:
            res["docs"] = "/apidocs"
        return jsonify(res)

    with app.app_context():
        db.create_all()
        print(">>> Database MySQL Berhasil Terkoneksi. Tabel Tercipta/Terupdate. <<<")

    return app


def _configure_logging(app):
    log_level = logging.DEBUG if app.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("app.log", encoding="utf-8")
        ]
    )


def _register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"msg": "Request tidak valid"}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"msg": "Akses tidak diizinkan"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"msg": "Akses ditolak"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"msg": "Resource tidak ditemukan"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"msg": "Method tidak diizinkan"}), 405

    @app.errorhandler(429)
    def too_many_requests(e):
        return jsonify({"msg": "Terlalu banyak permintaan. Coba lagi nanti."}), 429

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        return jsonify({"msg": "Terjadi kesalahan server"}), 500


app = create_app()

if __name__ == '__main__':
    app.run(
        debug=True,
        port=5000,
        host='0.0.0.0',
        use_reloader=False,
        threaded=True  
    )
