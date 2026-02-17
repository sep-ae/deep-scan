from flask import Flask, jsonify
from config import Config
from extensions import db, jwt  
from flask_cors import CORS  
from flasgger import Swagger

from routes.auth_routes import auth_bp
from routes.scan_routes import scan_bp
from routes.dashboard_routes import dashboard_bp
import models 

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 1. Inisialisasi Ekstensi
    db.init_app(app)
    jwt.init_app(app)
    
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:5173", "http://localhost:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }
    })
    
    swagger = Swagger(app) 

    # 2. Registrasi Blueprint
    app.register_blueprint(auth_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(dashboard_bp)
    
    # 3. Route Utama
    @app.route('/')
    def index():
        return jsonify({"status": "Scanner API Online", "docs": "/apidocs"})

    # 4. Auto Database Migration (db.create_all)
    with app.app_context():
        db.create_all() 
        print(">>> Database MySQL Berhasil Terkoneksi. Tabel Tercipta/Terupdate. <<<")

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5000, host='0.0.0.0') 
