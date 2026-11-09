import os
import json
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
    FIREBASE_URL = os.getenv("FIREBASE_URL")
    SUPABASE_URL = os.getenv("SUPABASE_URL")
    SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "portfolio-images")
    SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    OMISE_PUBLIC_KEY = os.getenv('OMISE_PUBLIC_KEY', '')
    OMISE_SECRET_KEY = os.getenv('OMISE_SECRET_KEY', '')
    
    @staticmethod
    def get_firebase_credentials():
        creds = os.getenv("FIREBASE_CREDENTIALS")
        if isinstance(creds, str):
            return json.loads(creds)
        return creds

    @staticmethod
    def get_firebase_config():
        config = os.getenv("FIREBASE_CONFIG")
        if isinstance(config, str):
            return json.loads(config)
        return config