import time
import requests
from config import Config

class SupabaseService:
    def __init__(self):
        self.url = Config.SUPABASE_URL
        self.key = Config.SUPABASE_SERVICE_ROLE_KEY
        self.bucket = Config.SUPABASE_BUCKET

    def upload_file(self, file_bytes: bytes, filename: str, content_type: str) -> str:
        """อัปโหลดไฟล์รูปภาพ 1 ไฟล์ไปยัง Supabase Storage"""
        timestamp = int(time.time() * 1000)
        safe_filename = f"{timestamp}_{filename.replace(' ', '_')}"
        upload_url = f"{self.url}/storage/v1/object/{self.bucket}/{safe_filename}"
        
        headers = {
            "Authorization": f"Bearer {self.key}",
            "apiKey": self.key,
            "Content-Type": content_type
        }
        
        response = requests.post(upload_url, headers=headers, data=file_bytes)
        if response.status_code in [200, 201]:
            return f"{self.url}/storage/v1/object/public/{self.bucket}/{safe_filename}"
        else:
            raise Exception(f"Supabase Upload Error: {response.text}")

    def upload_multiple_files(self, files_list) -> list:
        """อัปโหลดหลายรูปภาพพร้อมกันแล้วคืนค่า List ของ Image URLs"""
        urls = []
        for file in files_list:
            if file and file.filename != '':
                url = self.upload_file(file.read(), file.filename, file.content_type or 'image/jpeg')
                urls.append(url)
        return urls