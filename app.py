from datetime import timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from config import Config
from services.security_service import OWASPSecurityService
from services.firebase_service import FirebaseService
from services.supabase_service import SupabaseService

app = Flask(__name__)
app.config.from_object(Config)

# ---------------------------------------------------------
# 1. ตั้งค่าความปลอดภัย Cookie & Session (Session Hardening)
# ---------------------------------------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # ป้องกัน JavaScript แอบอ่าน Cookie (ป้องกัน XSS)
    SESSION_COOKIE_SECURE=True,         # ส่ง Cookie ผ่าน HTTPS เท่านั้น (เปิด True เมื่อใช้งานบน Production)
    SESSION_COOKIE_SAMESITE='Lax',      # ป้องกันการโจมตีแบบ CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)  #Session หมดอายุอัตโนมัติภายใน 30 นาทีหากไม่มีการเคลื่อนไหว
)

CORS(app)

firebase_svc = FirebaseService.get_instance()
supabase_svc = SupabaseService()

@app.after_request
def apply_security(response):
    return OWASPSecurityService.apply_security_headers(response)

@app.route('/')
def index():
    return render_template('index.html', firebase_config=Config.get_firebase_config())

@app.route('/api/auth/verify-session', methods=['POST'])
def verify_session():
    try:
        data = request.json or {}
        id_token = data.get('id_token')
        if not id_token:
            return jsonify({"error": "Missing token"}), 400
        
        user_info = firebase_svc.verify_id_token(id_token)
        
        # ---------------------------------------------------------
        # 2. ป้องกัน Session Fixation Attack (Session Rotation)
        # ---------------------------------------------------------
        session.clear()            # ล้าง Session ID เดิมทิ้งทันทีหลังพิสูจน์ตัวตนสำเร็จ
        session.permanent = True    # บังคับให้นับเวลาหมดอายุตาม PERMANENT_SESSION_LIFETIME
        session['user'] = user_info
        
        return jsonify({"status": "success", "user": user_info}), 200
    except Exception as e:
        return jsonify({"error": "Unauthorized", "message": str(e)}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "ออกจากระบบสำเร็จ"}), 200

@app.route('/api/computers', methods=['GET'])
@OWASPSecurityService.require_auth
def get_computers():
    data = firebase_svc.get_all_computers()
    return jsonify({"status": "success", "data": data}), 200

@app.route('/api/computers', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def add_computer():
    """API เพิ่มสินค้า 1 รายการ"""
    try:
        name = OWASPSecurityService.sanitize_input(request.form.get('name', ''))
        brand = OWASPSecurityService.sanitize_input(request.form.get('brand', ''))
        cost_price = float(request.form.get('cost_price', 0))
        price = float(request.form.get('price', 0))
        stock = int(request.form.get('stock', 0))
        
        if not name or not brand:
            return jsonify({"error": "Validation Error", "message": "กรุณากรอกข้อมูลสินค้าให้ครบถ้วน"}), 400

        # จัดการรูปภาพหลายรูป
        image_files = request.files.getlist('images')
        image_urls = supabase_svc.upload_multiple_files(image_files)

        computer_data = {
            "name": name,
            "brand": brand,
            "cost_price": cost_price,
            "price": price,
            "stock": stock,
            "images": image_urls if image_urls else ["https://via.placeholder.com/400x300?text=No+Image"],
            "created_by": session['user']['email']
        }
        
        key = firebase_svc.add_computer(computer_data)
        return jsonify({"status": "success", "id": key, "data": computer_data}), 201
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/computers/batch', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def add_computers_batch():
    """API เพิ่มสินค้าหลายรายการพร้อมกัน (Batch Add System)"""
    try:
        total_items = int(request.form.get('total_items', 0))
        if total_items <= 0:
            return jsonify({"error": "Validation Error", "message": "ไม่พบรายการสินค้าที่ต้องการบันทึก"}), 400

        created_items = []
        user_email = session['user']['email']

        for i in range(total_items):
            name = OWASPSecurityService.sanitize_input(request.form.get(f'items[{i}][name]', ''))
            brand = OWASPSecurityService.sanitize_input(request.form.get(f'items[{i}][brand]', ''))
            cost_price = float(request.form.get(f'items[{i}][cost_price]', 0))
            price = float(request.form.get(f'items[{i}][price]', 0))
            stock = int(request.form.get(f'items[{i}][stock]', 0))

            # ข้ามรายการที่ไม่ได้กรอกชื่อหรือแบรนด์
            if not name or not brand:
                continue

            # ดึงไฟล์รูปภาพประจำรายการนั้นๆ อัปโหลดขึ้น Supabase Storage Bucket
            image_files = request.files.getlist(f'items[{i}][images]')
            image_urls = supabase_svc.upload_multiple_files(image_files)

            item_data = {
                "name": name,
                "brand": brand,
                "cost_price": cost_price,
                "price": price,
                "stock": stock,
                "images": image_urls if image_urls else ["https://via.placeholder.com/400x300?text=No+Image"],
                "created_by": user_email
            }
            
            key = firebase_svc.add_computer(item_data)
            item_data['id'] = key
            created_items.append(item_data)

        return jsonify({
            "status": "success", 
            "count": len(created_items), 
            "data": created_items
        }), 201

    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/computers/<comp_id>/stock', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def adjust_stock(comp_id):
    """API ปรับสต็อกเข้า-ออกสินค้า (Stock IN / OUT)"""
    try:
        data = request.json or {}
        action_type = data.get('type') # 'IN' หรือ 'OUT'
        qty = int(data.get('quantity', 0))
        note = OWASPSecurityService.sanitize_input(data.get('note', ''))

        if action_type not in ['IN', 'OUT'] or qty <= 0:
            return jsonify({"error": "Invalid Data", "message": "ระบุประเภทรายการและจำนวนให้ถูกต้อง"}), 400

        res = firebase_svc.adjust_stock(comp_id, action_type, qty, note, session['user']['email'])
        return jsonify({"status": "success", "data": res}), 200
    except Exception as e:
        return jsonify({"error": "Stock Error", "message": str(e)}), 400

@app.route('/api/computers/<comp_id>', methods=['DELETE'])
@OWASPSecurityService.require_role('admin')
def delete_computer(comp_id):
    clean_id = OWASPSecurityService.sanitize_input(comp_id)
    firebase_svc.delete_computer(clean_id)
    return jsonify({"status": "success", "message": "ลบข้อมูลสำเร็จ"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)