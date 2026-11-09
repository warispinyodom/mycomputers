import os
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from firebase_admin import auth as admin_auth
from config import Config
from services.security_service import OWASPSecurityService
from services.firebase_service import FirebaseService
from services.supabase_service import SupabaseService

app = Flask(__name__)
app.config.from_object(Config)

# ---------------------------------------------------------
# 1. ตั้งค่าความปลอดภัย Session & Cookie
# ---------------------------------------------------------
is_production = not app.debug

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=is_production,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

CORS(app, supports_credentials=True)

firebase_svc = FirebaseService.get_instance()
supabase_svc = SupabaseService()

@app.after_request
def apply_security(response):
    return OWASPSecurityService.apply_security_headers(response)

@app.route('/')
def index():
    return render_template('index.html', firebase_config=Config.get_firebase_config())

# ---------------------------------------------------------
# Authentication & User Management APIs
# ---------------------------------------------------------
@app.route('/api/auth/verify-session', methods=['POST'])
def verify_session():
    try:
        data = request.json or {}
        id_token = data.get('id_token')
        if not id_token:
            return jsonify({"error": "Validation Error", "message": "Missing token"}), 400
        
        user_info = firebase_svc.verify_id_token(id_token)
        
        session.clear()
        session.permanent = True
        session['user'] = user_info
        
        return jsonify({"status": "success", "user": user_info}), 200
    except Exception as e:
        return jsonify({"error": "Unauthorized", "message": str(e)}), 401

@app.route('/api/auth/check-email', methods=['POST'])
@OWASPSecurityService.require_auth
def check_email_exists():
    try:
        data = request.json or {}
        email = OWASPSecurityService.sanitize_input(data.get('email', '')).strip()
        if not email:
            return jsonify({"error": "Validation Error", "message": "กรุณาระบุอีเมลที่ต้องการตรวจสอบ"}), 400

        try:
            user = admin_auth.get_user_by_email(email)
            if user:
                return jsonify({"status": "success", "exists": True, "message": "อีเมลนี้มีผู้ใช้งานในระบบแล้ว"}), 200
        except admin_auth.UserNotFoundError:
            return jsonify({"status": "success", "exists": False}), 200
        except Exception as e:
            return jsonify({"error": "Firebase Error", "message": str(e)}), 500

        return jsonify({"status": "success", "exists": False}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/auth/password-changed', methods=['POST'])
@OWASPSecurityService.require_auth
def password_changed():
    try:
        user_info = session.get('user', {})
        uid = user_info.get('uid')
        if uid:
            admin_auth.revoke_refresh_tokens(uid)
        return jsonify({"status": "success", "message": "ยกเลิก Session บนอุปกรณ์อื่นทั้งหมดเรียบร้อยแล้ว"}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"status": "success", "message": "ออกจากระบบสำเร็จ"}), 200

# ---------------------------------------------------------
# Inventory & Product APIs
# ---------------------------------------------------------
@app.route('/api/computers', methods=['GET'])
@OWASPSecurityService.require_auth
def get_computers():
    try:
        data = firebase_svc.get_all_computers()
        return jsonify({"status": "success", "data": data}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/computers', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def add_computer():
    try:
        name = OWASPSecurityService.sanitize_input(request.form.get('name', ''))
        brand = OWASPSecurityService.sanitize_input(request.form.get('brand', ''))
        
        try:
            cost_price = float(request.form.get('cost_price', 0))
            price = float(request.form.get('price', 0))
            stock = int(request.form.get('stock', 0))
        except ValueError:
            return jsonify({"error": "Validation Error", "message": "กรุณาระบุตัวเลขราคาทุน ราคาขาย และสต็อกให้ถูกต้อง"}), 400
        
        if not name or not brand or cost_price < 0 or price < 0 or stock < 0:
            return jsonify({"error": "Validation Error", "message": "ข้อมูลไม่ถูกต้องหรือติดลบ"}), 400

        image_files = request.files.getlist('images')
        image_urls = supabase_svc.upload_multiple_files(image_files)
        user_email = session.get('user', {}).get('email', 'unknown')

        computer_data = {
            "name": name,
            "brand": brand,
            "cost_price": cost_price,
            "price": price,
            "stock": stock,
            "images": image_urls if image_urls else ["https://via.placeholder.com/400x300?text=No+Image"],
            "created_by": user_email
        }
        
        key = firebase_svc.add_computer(computer_data)
        return jsonify({"status": "success", "id": key, "data": computer_data}), 201
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/computers/batch', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def add_computers_batch():
    try:
        total_items = int(request.form.get('total_items', 0))
        if total_items <= 0:
            return jsonify({"error": "Validation Error", "message": "ไม่พบรายการสินค้าที่ต้องการบันทึก"}), 400

        created_items = []
        user_email = session.get('user', {}).get('email', 'unknown')

        for i in range(total_items):
            name = OWASPSecurityService.sanitize_input(request.form.get(f'items[{i}][name]', ''))
            brand = OWASPSecurityService.sanitize_input(request.form.get(f'items[{i}][brand]', ''))
            
            try:
                cost_price = float(request.form.get(f'items[{i}][cost_price]', 0))
                price = float(request.form.get(f'items[{i}][price]', 0))
                stock = int(request.form.get(f'items[{i}][stock]', 0))
            except ValueError:
                continue

            if not name or not brand or cost_price < 0 or price < 0 or stock < 0:
                continue

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

        return jsonify({"status": "success", "count": len(created_items), "data": created_items}), 201
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

@app.route('/api/computers/<comp_id>/stock', methods=['POST'])
@OWASPSecurityService.require_role('admin')
def adjust_stock(comp_id):
    try:
        data = request.json or {}
        action_type = data.get('type')
        qty = int(data.get('quantity', 0))
        note = OWASPSecurityService.sanitize_input(data.get('note', ''))

        if action_type not in ['IN', 'OUT'] or qty <= 0:
            return jsonify({"error": "Invalid Data", "message": "ข้อมูลปรับสต็อกไม่ถูกต้อง"}), 400

        user_email = session.get('user', {}).get('email', 'unknown')
        res = firebase_svc.adjust_stock(comp_id, action_type, qty, note, user_email)
        return jsonify({"status": "success", "data": res}), 200
    except Exception as e:
        return jsonify({"error": "Stock Error", "message": str(e)}), 400

@app.route('/api/computers/<comp_id>', methods=['DELETE'])
@OWASPSecurityService.require_role('admin')
def delete_computer(comp_id):
    try:
        clean_id = OWASPSecurityService.sanitize_input(comp_id)
        if not clean_id:
            return jsonify({"error": "Validation Error", "message": "ไม่พบ ID สินค้าที่ต้องการลบ"}), 400

        firebase_svc.delete_computer(clean_id)
        return jsonify({"status": "success", "message": "ลบข้อมูลสำเร็จ"}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500

# ---------------------------------------------------------
# OMISE PROMPTPAY & ORDER MANAGEMENT APIs
# ---------------------------------------------------------
@app.route('/api/checkout/create-qr', methods=['POST'])
@OWASPSecurityService.require_auth
def create_qr_checkout():
    """สร้าง PromptPay QR Code พร้อมบันทึกที่อยู่จัดส่ง"""
    try:
        data = request.json or {}
        cart_items = data.get('items', [])
        shipping_address = OWASPSecurityService.sanitize_input(data.get('shipping_address', '')).strip()

        if not cart_items or not isinstance(cart_items, list):
            return jsonify({"error": "Validation Error", "message": "ตะกร้าสินค้าว่างเปล่า"}), 400

        if not shipping_address:
            return jsonify({"error": "Validation Error", "message": "กรุณาระบุที่อยู่จัดส่งสินค้า"}), 400

        all_computers = firebase_svc.get_all_computers()
        comp_dict = {item['id']: item for item in all_computers}
        
        total_amount = 0.0
        verified_items = []

        for cart_item in cart_items:
            comp_id = cart_item.get('id')
            qty = int(cart_item.get('quantity', 0))

            if comp_id not in comp_dict:
                return jsonify({"error": "Stock Error", "message": f"ไม่พบสินค้า ID: {comp_id} ในระบบ"}), 400

            comp = comp_dict[comp_id]
            current_stock = int(comp.get('stock', 0))

            if qty <= 0:
                continue
            if qty > current_stock:
                return jsonify({
                    "error": "Stock Error", 
                    "message": f"สินค้า '{comp.get('name')}' คงเหลือไม่เพียงพอ (เหลือเพียง {current_stock} ชิ้น)"
                }), 400

            price = float(comp.get('price', 0))
            total_amount += (price * qty)
            verified_items.append({
                'id': comp_id, 
                'name': comp.get('name'), 
                'price': price, 
                'quantity': qty,
                'image': comp.get('images', [''])[0] if comp.get('images') else ''
            })

        if total_amount <= 0 or not verified_items:
            return jsonify({"error": "Validation Error", "message": "ยอดเงินรวมในการสั่งซื้อต้องมากกว่า 0 บาท"}), 400

        omise_secret_key = getattr(Config, 'OMISE_SECRET_KEY', os.getenv('OMISE_SECRET_KEY', ''))
        amount_in_satang = int(round(total_amount * 100))
        user_email = session.get('user', {}).get('email', 'unknown')

        omise_response = requests.post(
            'https://api.omise.co/charges',
            auth=(omise_secret_key, ''),
            data={
                'amount': amount_in_satang,
                'currency': 'thb',
                'source[type]': 'promptpay',
                'description': f'Order by {user_email} | Total: {total_amount:.2f} THB'
            },
            timeout=30
        )

        charge_data = omise_response.json()

        if omise_response.status_code != 200 or charge_data.get('object') == 'error':
            error_msg = charge_data.get('message') or 'ไม่สามารถสร้าง QR Code ชำระเงินได้'
            return jsonify({"error": "Omise Error", "message": error_msg}), 400

        source_data = charge_data.get('source', {})
        scannable_code = source_data.get('scannable_code', {})
        image_data = scannable_code.get('image', {})
        qr_code_url = image_data.get('download_uri')

        if not qr_code_url:
            return jsonify({"error": "Omise Error", "message": "ไม่พบข้อมูลรูปภาพ QR Code จาก Omise"}), 500

        session[f"pending_order_{charge_data.get('id')}"] = {
            "items": verified_items,
            "total_amount": total_amount,
            "shipping_address": shipping_address,
            "user_email": user_email,
            "processed": False
        }

        return jsonify({
            "status": "success",
            "charge_id": charge_data.get('id'),
            "qr_code_url": qr_code_url,
            "amount": total_amount
        }), 200

    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route('/api/checkout/verify/<charge_id>', methods=['GET'])
@OWASPSecurityService.require_auth
def verify_qr_payment(charge_id):
    """ตรวจสอบสถานะการชำระเงิน ตัดสต็อก และสร้าง Order ลง Database"""
    try:
        clean_charge_id = OWASPSecurityService.sanitize_input(charge_id)
        omise_secret_key = getattr(Config, 'OMISE_SECRET_KEY', os.getenv('OMISE_SECRET_KEY', ''))

        omise_response = requests.get(
            f'https://api.omise.co/charges/{clean_charge_id}',
            auth=(omise_secret_key, ''),
            timeout=30
        )

        charge_data = omise_response.json()
        charge_status = charge_data.get('status')
        is_paid = charge_data.get('paid', False)

        if charge_status == 'successful' and is_paid:
            session_key = f"pending_order_{clean_charge_id}"
            pending_order = session.get(session_key)

            if pending_order and not pending_order.get('processed'):
                user_email = pending_order.get('user_email', session.get('user', {}).get('email', 'unknown'))
                
                # 1. ตัดสต็อกสินค้า
                for item in pending_order.get('items', []):
                    comp_id = item['id']
                    qty = item['quantity']
                    note = f"ชำระเงินผ่าน PromptPay QR (Omise: {clean_charge_id})"
                    firebase_svc.adjust_stock(comp_id, 'OUT', qty, note, user_email)

                # 2. บันทึกคำสั่งซื้อลง Firebase Database สำหรับระบบติดตามสถานะจัดส่ง
                order_record = {
                    "charge_id": clean_charge_id,
                    "user_email": user_email,
                    "items": pending_order.get('items', []),
                    "total_amount": pending_order.get('total_amount', 0),
                    "shipping_address": pending_order.get('shipping_address', 'ไม่ระบุที่อยู่'),
                    "status": "preparing",  # 'preparing', 'shipped', 'delivered'
                    "status_text": "กำลังเตรียมจัดส่ง",
                    "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                }
                
                firebase_svc.db.child("orders").child(clean_charge_id).set(order_record)

                pending_order['processed'] = True
                session[session_key] = pending_order

            return jsonify({
                "status": "success",
                "payment_status": "paid",
                "message": "การชำระเงินสำเร็จเรียบร้อยแล้ว!"
            }), 200

        elif charge_status == 'failed':
            return jsonify({
                "status": "failed",
                "payment_status": "failed",
                "message": charge_data.get('failure_message') or "การชำระเงินไม่สำเร็จ"
            }), 400

        else:
            return jsonify({
                "status": "pending",
                "payment_status": "pending",
                "message": "กำลังรอการสแกนและชำระเงิน..."
            }), 200

    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route('/api/orders', methods=['GET'])
@OWASPSecurityService.require_auth
def get_user_orders():
    """ดึงรายการสั่งซื้อทั้งหมด (User เห็นเฉพาะของตัวเอง / Admin เห็นทั้งหมด)"""
    try:
        user_info = session.get('user', {})
        user_email = user_info.get('email')
        role = user_info.get('role', 'user')

        orders_data = firebase_svc.db.child("orders").get().val() or {}
        orders_list = []

        if isinstance(orders_data, dict):
            for charge_id, order in orders_data.items():
                if isinstance(order, dict):
                    if role == 'admin' or order.get('user_email') == user_email:
                        orders_list.append(order)

        orders_list.sort(key=lambda x: str(x.get('created_at', '')), reverse=True)

        return jsonify({"status": "success", "data": orders_list}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500


@app.route('/api/orders/<charge_id>/status', methods=['PUT'])
@OWASPSecurityService.require_role('admin')
def update_order_status(charge_id):
    """อัปเดตสถานะการจัดส่ง (Admin Only)"""
    try:
        clean_id = OWASPSecurityService.sanitize_input(charge_id)
        data = request.json or {}
        new_status = data.get('status')

        status_map = {
            'preparing': 'กำลังเตรียมจัดส่ง',
            'shipped': 'อยู่ระหว่างจัดส่ง',
            'delivered': 'จัดส่งสำเร็จ'
        }

        if new_status not in status_map:
            return jsonify({"error": "Validation Error", "message": "สถานะจัดส่งไม่ถูกต้อง"}), 400

        firebase_svc.db.child("orders").child(clean_id).update({
            "status": new_status,
            "status_text": status_map[new_status]
        })

        return jsonify({"status": "success", "message": f"อัปเดตสถานะเป็น '{status_map[new_status]}' สำเร็จ"}), 200
    except Exception as e:
        return jsonify({"error": "Server Error", "message": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)