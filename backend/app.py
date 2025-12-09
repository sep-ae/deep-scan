from flask import Flask, jsonify
from config import Config
from extensions import db, cors, jwt
from flasgger import Swagger

from routes.auth_routes import auth_bp
import models 

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 1. Inisialisasi Ekstensi
    db.init_app(app)
    cors.init_app(app)
    jwt.init_app(app)
    swagger = Swagger(app) 

    # 2. Registrasi Blueprint (Menjahit Modul Auth)
    app.register_blueprint(auth_bp)
    
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
    app.run(debug=True, port=5000)