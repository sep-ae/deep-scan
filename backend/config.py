import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

IS_DEV = os.getenv('FLASK_ENV', 'production') == 'development'


def _get_env(key):
    value = os.getenv(key)
    if not value:
        if IS_DEV:
            import warnings
            warnings.warn(f"[WARNING] Environment variable '{key}' belum di-set!", stacklevel=2)
            return None
        raise ValueError(f"Environment variable '{key}' belum di-set. Cek file .env!")
    return value


class Config:
    SECRET_KEY = _get_env('SECRET_KEY') or 'dev-only-secret-key-ganti-di-production'
    JWT_SECRET_KEY = _get_env('JWT_SECRET_KEY') or 'dev-only-jwt-key-ganti-di-production'

    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')

    SQLALCHEMY_DATABASE_URI = _get_env('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300
    }

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_ALGORITHM = 'HS256'

    SWAGGER = {
        'title': 'API Scanner Documentation',
        'uiversion': 3
    }
