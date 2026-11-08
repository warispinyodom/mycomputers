from datetime import datetime
import firebase_admin
from firebase_admin import credentials, db, auth
from config import Config

class FirebaseService:
    _instance = None

    def __init__(self):
        if not firebase_admin._apps:
            cred_dict = Config.get_firebase_credentials()
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred, {
                'databaseURL': Config.FIREBASE_URL
            })
        self.db_ref = db.reference('computers')
        self.users_ref = db.reference('users')

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def verify_id_token(self, id_token: str):
        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            user_info = auth.get_user(uid)
            
            if not user_info.email_verified:
                raise ValueError("อีเมลยังไม่ได้ผ่านการยืนยัน")
                
            user_data = self.users_ref.child(uid).get() or {}
            role = decoded_token.get('role') or user_data.get('role', 'user')

            return {
                "uid": uid,
                "email": user_info.email,
                "email_verified": user_info.email_verified,
                "role": role
            }
        except Exception as e:
            raise Exception(f"Authentication failed: {str(e)}")

    def add_computer(self, data: dict) -> str:
        """เพิ่มสินค้าใหม่ พร้อมบันทึก Log เวลาเข้าสินค้าครั้งแรก"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        initial_stock = int(data.get('stock', 0))
        
        # โครงสร้าง Log เข้า-ออก
        logs = [{
            "type": "IN",
            "quantity": initial_stock,
            "note": "นำเข้าสินค้าครั้งแรก (Initial Stock)",
            "timestamp": now,
            "by": data.get('created_by', 'Admin')
        }]
        
        data['logs'] = logs
        data['created_at'] = now
        data['updated_at'] = now
        
        new_ref = self.db_ref.push()
        new_ref.set(data)
        return new_ref.key

    def update_computer(self, comp_id: str, update_data: dict) -> bool:
        """แก้ไขข้อมูลสินค้า"""
        update_data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db_ref.child(comp_id).update(update_data)
        return True

    def adjust_stock(self, comp_id: str, action_type: str, qty: int, note: str, user_email: str) -> dict:
        """ปรับปรุงจำนวนสินค้าเข้า/ออก พร้อมบันทึกประวัติเวลาเข้า-ออก"""
        comp = self.db_ref.child(comp_id).get()
        if not comp:
            raise Exception("ไม่พบรายการสินค้า")

        current_stock = int(comp.get('stock', 0))
        new_stock = current_stock + qty if action_type == 'IN' else current_stock - qty
        
        if new_stock < 0:
            raise Exception("จำนวนสินค้าในคลังไม่พอสำหรับตัดออก")

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_log = {
            "type": action_type,
            "quantity": qty,
            "note": note or ("เติมสต็อกสินค้า" if action_type == 'IN' else "ตัดจ่ายสินค้า/ขาย"),
            "timestamp": now,
            "by": user_email
        }

        logs = comp.get('logs', [])
        logs.append(new_log)

        self.db_ref.child(comp_id).update({
            "stock": new_stock,
            "logs": logs,
            "updated_at": now
        })
        return {"new_stock": new_stock, "log": new_log}

    def get_all_computers(self) -> list:
        snapshot = self.db_ref.get()
        if not snapshot:
            return []
        result = []
        for key, val in snapshot.items():
            val['id'] = key
            result.append(val)
        return result

    def delete_computer(self, comp_id: str) -> bool:
        self.db_ref.child(comp_id).delete()
        return True