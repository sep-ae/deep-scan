import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    JWT_SECRET_KEY = os.getenv('SECRET_KEY', 'default-key-kalo-lupa-set-env')
    
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    SWAGGER = {
        'title': 'API Scanner Documentation',
        'uiversion': 3
    }