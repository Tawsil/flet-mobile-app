import flet as ft
import sqlite3
import json
from datetime import datetime, timedelta
import os
import shutil
from typing import Optional, List, Dict, Any
import webbrowser
import socket
import random
import pandas as pd
import io
import base64
import hashlib
import time
import secrets
import threading
import qrcode
from PIL import Image, ImageDraw, ImageFont
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # استخدام الواجهة الخلفية غير التفاعلية
import numpy as np
from flet.security import encrypt, decrypt
import re
import pyotp
import requests

# إعدادات التشفير
ENCRYPTION_KEY = "your_secure_encryption_key_here"  # في التطبيق الحقيقي، استخدم مفتاحاً آمناً

# وظائف التجزئة والتشفير للأمان
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"

def verify_password(stored_password, provided_password):
    try:
        salt, hashed = stored_password.split('$')
        new_hash = hash_password(provided_password, salt)
        return new_hash == stored_password
    except:
        return False

def encrypt_data(data):
    return encrypt(data, ENCRYPTION_KEY)

def decrypt_data(encrypted_data):
    return decrypt(encrypted_data, ENCRYPTION_KEY)

# إدارة قاعدة البيانات مع تحسين الأداء
class DatabaseManager:
    def __init__(self):
        self.db_path = 'martyrs.db'
        self.lock = threading.Lock()
        self.init_db()
        
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
        
    def init_db(self):
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # جدول المستخدمين
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                profile_image TEXT,
                is_admin BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT,
                session_token TEXT,
                two_factor_secret TEXT,
                failed_login_attempts INTEGER DEFAULT 0,
                account_locked BOOLEAN DEFAULT 0,
                lock_until TEXT
            )
            ''')
            
            # جدول الشهداء
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS martyrs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER,
                date_of_martyrdom TEXT,
                location TEXT,
                details TEXT,
                image_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                updated_at TEXT,
                tags TEXT,
                encrypted_data TEXT
            )
            ''')
            
            # جدول الجرحى
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS wounded (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER,
                injury_date TEXT,
                injury_location TEXT,
                injury_details TEXT,
                medical_status TEXT,
                image_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                updated_at TEXT,
                tags TEXT,
                encrypted_data TEXT
            )
            ''')
            
            # جدول الأسرى
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS prisoners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER,
                arrest_date TEXT,
                arrest_location TEXT,
                prison_name TEXT,
                details TEXT,
                image_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                updated_at TEXT,
                tags TEXT,
                encrypted_data TEXT
            )
            ''')
            
            # جدول الإحصائيات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                martyrs_count INTEGER DEFAULT 0,
                wounded_count INTEGER DEFAULT 0,
                prisoners_count INTEGER DEFAULT 0,
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # جدول الإعدادات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                setting_name TEXT NOT NULL,
                setting_value TEXT,
                description TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, setting_name)
            )
            ''')
            
            # جدول سجلات النشاط
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                table_name TEXT,
                record_id INTEGER,
                details TEXT,
                ip_address TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # جدول الجلسات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                device_info TEXT,
                login_time TEXT,
                last_activity TEXT,
                ip_address TEXT,
                session_token TEXT,
                is_active BOOLEAN DEFAULT 1
            )
            ''')
            
            # جدول النسخ الاحتياطي
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                size INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                description TEXT
            )
            ''')
            
            # جدول التقارير
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                parameters TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                file_path TEXT
            )
            ''')
            
            # جدول الإشعارات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                type TEXT NOT NULL,
                is_read BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # جدول الصلاحيات
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                granted BOOLEAN DEFAULT 1,
                granted_at TEXT DEFAULT CURRENT_TIMESTAMP,
                granted_by INTEGER
            )
            ''')
            
            # إضافة المستخدم المسؤول إذا لم يكن موجودًا
            cursor.execute("SELECT COUNT(*) FROM users WHERE email='admin@sture.com'")
            if cursor.fetchone()[0] == 0:
                admin_password = hash_password("admin123")
                salt = admin_password.split('$')[0]
                cursor.execute(
                    "INSERT INTO users (username, email, password, salt, is_admin) VALUES (?, ?, ?, ?, ?)",
                    ("admin", "admin@sture.com", admin_password, salt, 1)
                )
            
            # إضافة سجل إحصائي أولي
            cursor.execute("SELECT COUNT(*) FROM statistics")
            if cursor.fetchone()[0] == 0:
                cursor.execute(
                    "INSERT INTO statistics (martyrs_count, wounded_count, prisoners_count) VALUES (?, ?, ?)",
                    (0, 0, 0)
                )
            
            # إضافة الإعدادات الافتراضية
            default_settings = [
                (None, "theme", "light", "المظهر الافتراضي للتطبيق (light/dark)"),
                (None, "language", "ar", "لغة التطبيق الافتراضية"),
                (None, "notifications", "true", "تفعيل الإشعارات"),
                (None, "auto_backup", "false", "النسخ احتياطي التلقائي"),
                (None, "backup_interval", "7", "فترة النسخ الاحتياطي بالأيام"),
                (None, "privacy_mode", "false", "وضع الخصوصية"),
                (None, "font_size", "14", "حجم الخط الافتراضي"),
                (None, "font_family", "Cairo", "عائلة الخط الافتراضية"),
                (None, "primary_color", "#1a237e", "اللون الرئيسي للتطبيق"),
                (None, "two_factor_auth", "false", "المصادقة الثنائية"),
                (None, "app_lock", "false", "قفل التطبيق"),
                (None, "show_age_field", "true", "إظهار حقل العمر"),
                (None, "show_location_field", "true", "إظهار حقل الموقع"),
                (None, "show_date_field", "true", "إظهار حقل التاريخ"),
                (None, "default_sort", "date", "ترتيب العرض الافتراضي"),
                (None, "notification_new_martyr", "true", "إشعار إضافة شهيد جديد"),
                (None, "notification_new_wounded", "true", "إشعار إضافة جريح جديد"),
                (None, "notification_new_prisoner", "true", "إشعار إضافة أسير جديد"),
                (None, "backup_encryption", "true", "تشفير النسخ الاحتياطية"),
                (None, "data_retention_days", "365", "فترة الاحتفاظ بالبيانات بالأيام"),
                (None, "session_timeout_minutes", "30", "مهلة الجلسة بالدقائق"),
                (None, "max_login_attempts", "5", "الحد الأقصى لمحاولات تسجيل الدخول"),
                (None, "lockout_duration_minutes", "15", "مدة قفل الحساب بالدقائق")
            ]
            
            for user_id, name, value, description in default_settings:
                cursor.execute("SELECT COUNT(*) FROM settings WHERE user_id IS ? AND setting_name=?", (user_id, name))
                if cursor.fetchone()[0] == 0:
                    cursor.execute(
                        "INSERT INTO settings (user_id, setting_name, setting_value, description) VALUES (?, ?, ?, ?)",
                        (user_id, name, value, description)
                    )
            
            conn.commit()
            conn.close()
    
    def execute_query(self, query, params=None, fetch=False, fetch_all=False, commit=False):
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if commit:
                    conn.commit()
                
                if fetch:
                    result = cursor.fetchone()
                elif fetch_all:
                    result = cursor.fetchall()
                else:
                    result = None
                
                return result
            except Exception as e:
                conn.rollback()
                raise e
            finally:
                conn.close()
    
    def get_setting(self, setting_name, user_id=None):
        result = self.execute_query(
            "SELECT setting_value FROM settings WHERE user_id IS ? AND setting_name=?",
            (user_id, setting_name),
            fetch=True
        )
        return result[0] if result else None
    
    def update_setting(self, setting_name, setting_value, user_id=None):
        self.execute_query(
            "UPDATE settings SET setting_value=?, updated_at=CURRENT_TIMESTAMP WHERE user_id IS ? AND setting_name=?",
            (setting_value, user_id, setting_name),
            commit=True
        )
        return True
    
    def log_activity(self, user_id, action, table_name=None, record_id=None, details=None, ip_address=None):
        self.execute_query(
            "INSERT INTO activity_logs (user_id, action, table_name, record_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, table_name, record_id, details, ip_address),
            commit=True
        )
    
    def create_backup(self, filename, size, user_id, description):
        self.execute_query(
            "INSERT INTO backups (filename, size, user_id, description) VALUES (?, ?, ?, ?)",
            (filename, size, user_id, description),
            commit=True
        )
    
    def get_backups(self):
        return self.execute_query(
            "SELECT * FROM backups ORDER BY created_at DESC",
            fetch_all=True
        )
    
    def delete_backup(self, backup_id):
        backup = self.execute_query(
            "SELECT filename FROM backups WHERE id=?",
            (backup_id,),
            fetch=True
        )
        if backup:
            filename = backup[0]
            if os.path.exists(filename):
                os.remove(filename)
            self.execute_query(
                "DELETE FROM backups WHERE id=?",
                (backup_id,),
                commit=True
            )
            return True
        return False
    
    def get_user_permissions(self, user_id):
        return self.execute_query(
            "SELECT resource, action FROM permissions WHERE user_id=? AND granted=1",
            (user_id,),
            fetch_all=True
        )
    
    def check_permission(self, user_id, resource, action):
        result = self.execute_query(
            "SELECT COUNT(*) FROM permissions WHERE user_id=? AND resource=? AND action=? AND granted=1",
            (user_id, resource, action),
            fetch=True
        )
        return result[0] > 0 if result else False
    
    def add_notification(self, user_id, title, message, notification_type):
        self.execute_query(
            "INSERT INTO notifications (user_id, title, message, type) VALUES (?, ?, ?, ?)",
            (user_id, title, message, notification_type),
            commit=True
        )
    
    def get_unread_notifications(self, user_id):
        return self.execute_query(
            "SELECT * FROM notifications WHERE user_id=? AND is_read=0 ORDER BY created_at DESC",
            (user_id,),
            fetch_all=True
        )
    
    def mark_notification_read(self, notification_id):
        self.execute_query(
            "UPDATE notifications SET is_read=1 WHERE id=?",
            (notification_id,),
            commit=True
        )
    
    def get_user_sessions(self, user_id):
        return self.execute_query(
            "SELECT * FROM user_sessions WHERE user_id=? ORDER BY last_activity DESC",
            (user_id,),
            fetch_all=True
        )
    
    def terminate_session(self, session_id):
        self.execute_query(
            "UPDATE user_sessions SET is_active=0 WHERE id=?",
            (session_id,),
            commit=True
        )
    
    def cleanup_expired_sessions(self):
        # تنظيف الجلسات المنتهية الصلاحية (أكثر من 30 يوماً)
        self.execute_query(
            "DELETE FROM user_sessions WHERE date(last_activity) < date('now', '-30 days')",
            commit=True
        )
    
    def cleanup_old_data(self):
        # تنظيف البيانات القديمة حسب إعدادات الاحتفاظ بالبيانات
        retention_days = int(self.get_setting("data_retention_days") or "365")
        self.execute_query(
            "DELETE FROM activity_logs WHERE date(created_at) < date('now', '-{} days')".format(retention_days),
            commit=True
        )
        self.execute_query(
            "DELETE FROM notifications WHERE date(created_at) < date('now', '-{} days')".format(retention_days),
            commit=True
        )
    
    def optimize_database(self):
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # تحسين قاعدة البيانات
            cursor.execute("VACUUM")
            cursor.execute("ANALYZE")
            
            # إعادة بناء الفهارس
            tables = ["users", "martyrs", "wounded", "prisoners", "statistics", "settings", 
                     "activity_logs", "user_sessions", "backups", "reports", "notifications", "permissions"]
            
            for table in tables:
                cursor.execute(f"REINDEX INDEX IF EXISTS idx_{table}_id")
            
            conn.commit()
            conn.close()

# تهيئة قاعدة البيانات
db = DatabaseManager()

# إدارة الجلسات
class SessionManager:
    def __init__(self):
        self.current_user = None
        self.session_token = None
        self.session_timeout = int(db.get_setting("session_timeout_minutes") or "30") * 60  # تحويل إلى ثواني
        self.last_activity = time.time()
    
    def login(self, user):
        self.current_user = user
        self.session_token = secrets.token_urlsafe(32)
        self.last_activity = time.time()
        
        # تسجيل الجلسة في قاعدة البيانات
        device_info = f"{os.name} {os.uname().release if hasattr(os, 'uname') else ''}"
        ip_address = self.get_ip_address()
        
        db.execute_query(
            "INSERT INTO user_sessions (user_id, device_info, login_time, last_activity, ip_address, session_token) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)",
            (user["id"], device_info, ip_address, self.session_token),
            commit=True
        )
        
        # تحديث آخر تسجيل دخول للمستخدم
        db.execute_query(
            "UPDATE users SET last_login=CURRENT_TIMESTAMP, session_token=?, failed_login_attempts=0, account_locked=0 WHERE id=?",
            (self.session_token, user["id"]),
            commit=True
        )
        
        db.log_activity(user["id"], "login", details=f"تسجيل دخول للمستخدم {user['username']}", ip_address=ip_address)
        
        return self.session_token
    
    def logout(self):
        if self.current_user:
            # تحديث حالة الجلسة
            db.execute_query(
                "UPDATE user_sessions SET is_active=0 WHERE session_token=?",
                (self.session_token,),
                commit=True
            )
            
            # مسح جلسة المستخدم
            db.execute_query(
                "UPDATE users SET session_token=NULL WHERE id=?",
                (self.current_user["id"],),
                commit=True
            )
            
            db.log_activity(self.current_user["id"], "logout", details=f"تسجيل خروج للمستخدم {self.current_user['username']}")
            
            self.current_user = None
            self.session_token = None
    
    def is_active(self):
        if not self.current_user or not self.session_token:
            return False
        
        # التحقق من انتهاء صلاحية الجلسة
        if time.time() - self.last_activity > self.session_timeout:
            self.logout()
            return False
        
        # تحديث وقت النشاط الأخير
        self.last_activity = time.time()
        db.execute_query(
            "UPDATE user_sessions SET last_activity=CURRENT_TIMESTAMP WHERE session_token=?",
            (self.session_token,),
            commit=True
        )
        
        return True
    
    def get_ip_address(self):
        try:
            # محاولة الحصول على IP العام
            response = requests.get('https://api.ipify.org?format=json', timeout=2)
            if response.status_code == 200:
                return response.json()['ip']
        except:
            pass
        
        # العودة إلى IP المحلي في حالة الفشل
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except:
            return "127.0.0.1"
    
    def validate_session(self, session_token):
        if not session_token:
            return False
        
        result = db.execute_query(
            "SELECT u.* FROM users u JOIN user_sessions s ON u.id = s.user_id WHERE s.session_token=? AND s.is_active=1",
            (session_token,),
            fetch=True
        )
        
        if result:
            user_data = dict(result)
            self.current_user = {
                "id": user_data["id"],
                "username": user_data["username"],
                "email": user_data["email"],
                "profile_image": user_data["profile_image"],
                "is_admin": bool(user_data["is_admin"]),
                "two_factor_secret": user_data["two_factor_secret"]
            }
            self.session_token = session_token
            self.last_activity = time.time()
            return True
        
        return False

# تهيئة مدير الجلسات
session_manager = SessionManager()

# إدارة الإعدادات
class SettingsManager:
    def __init__(self):
        self.settings = {}
        self.load_settings()
    
    def load_settings(self):
        # تحميل الإعدادات العامة
        global_settings = db.execute_query(
            "SELECT setting_name, setting_value FROM settings WHERE user_id IS NULL",
            fetch_all=True
        )
        
        for setting in global_settings:
            self.settings[setting["setting_name"]] = setting["setting_value"]
        
        # تحميل إعدادات المستخدم الحالي
        if session_manager.current_user:
            user_settings = db.execute_query(
                "SELECT setting_name, setting_value FROM settings WHERE user_id=?",
                (session_manager.current_user["id"],),
                fetch_all=True
            )
            
            for setting in user_settings:
                self.settings[setting["setting_name"]] = setting["setting_value"]
    
    def get(self, setting_name, default=None):
        return self.settings.get(setting_name, default)
    
    def set(self, setting_name, setting_value, is_global=False):
        user_id = None if is_global else (session_manager.current_user["id"] if session_manager.current_user else None)
        
        # تحديث الإعداد في قاعدة البيانات
        db.update_setting(setting_name, setting_value, user_id)
        
        # تحديث الإعداد في الذاكرة
        self.settings[setting_name] = setting_value
        
        # تسجيل النشاط
        if session_manager.current_user:
            db.log_activity(
                session_manager.current_user["id"],
                "update_setting",
                details=f"تحديث الإعداد: {setting_name} = {setting_value}"
            )
    
    def apply_to_page(self, page):
        # تطبيق الإعدادات على الصفحة
        theme_mode = self.get("theme", "light")
        font_size = int(self.get("font_size", "14"))
        font_family = self.get("font_family", "Cairo")
        primary_color = self.get("primary_color", "#1a237e")
        
        page.theme_mode = ft.ThemeMode.LIGHT if theme_mode == "light" else ft.ThemeMode.DARK
        page.fonts = {
            "Cairo": "https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&display=swap",
            "Tajawal": "https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700&display=swap",
            "Amiri": "https://fonts.googleapis.com/css2?family=Amiri:wght@400;700&display=swap"
        }
        page.theme = ft.Theme(font_family=font_family)
        
        # إعدادات الصفحة لجعلها متجاوبة مع اللمس
        page.scroll = ft.ScrollMode.ADAPTIVE
        page.adaptive = True
        
        # تمكين التفاعل باللمس والسحب
        page.on_pointer_move = lambda e: None
        page.on_pointer_down = lambda e: None
        
        return {
            "primary_color": primary_color,
            "font_size": font_size,
            "font_family": font_family,
            "theme_mode": theme_mode
        }

# تهيئة مدير الإعدادات
settings_manager = SettingsManager()

# إدارة الإشعارات
class NotificationManager:
    def __init__(self):
        self.notifications = []
    
    def load_notifications(self):
        if session_manager.current_user:
            self.notifications = db.get_unread_notifications(session_manager.current_user["id"])
    
    def add_notification(self, title, message, notification_type="info"):
        if session_manager.current_user:
            db.add_notification(
                session_manager.current_user["id"],
                title,
                message,
                notification_type
            )
            self.load_notifications()
    
    def mark_as_read(self, notification_id):
        db.mark_notification_read(notification_id)
        self.load_notifications()
    
    def get_count(self):
        return len(self.notifications)

# تهيئة مدير الإشعارات
notification_manager = NotificationManager()

# إدارة التقارير
class ReportManager:
    def __init__(self):
        self.reports = []
    
    def generate_statistics_report(self, report_format="pdf"):
        if not session_manager.current_user:
            return None
        
        # الحصول على الإحصائيات
        cursor = db.get_connection().cursor()
        
        # إحصائيات الشهداء
        cursor.execute("SELECT COUNT(*) FROM martyrs")
        martyrs_count = cursor.fetchone()[0]
        
        # إحصائيات الجرحى
        cursor.execute("SELECT COUNT(*) FROM wounded")
        wounded_count = cursor.fetchone()[0]
        
        # إحصائيات الأسرى
        cursor.execute("SELECT COUNT(*) FROM prisoners")
        prisoners_count = cursor.fetchone()[0]
        
        # إحصائيات حسب الشهر
        cursor.execute('''
            SELECT 
                strftime('%Y-%m', created_at) as month,
                COUNT(*) as count
            FROM martyrs
            GROUP BY month
            ORDER BY month
        ''')
        martyrs_by_month = cursor.fetchall()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m', created_at) as month,
                COUNT(*) as count
            FROM wounded
            GROUP BY month
            ORDER BY month
        ''')
        wounded_by_month = cursor.fetchall()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m', created_at) as month,
                COUNT(*) as count
            FROM prisoners
            GROUP BY month
            ORDER BY month
        ''')
        prisoners_by_month = cursor.fetchall()
        
        cursor.close()
        
        # إنشاء الرسم البياني
        plt.figure(figsize=(10, 6))
        
        # إعداد البيانات
        months = set()
        for month, _ in martyrs_by_month:
            months.add(month)
        for month, _ in wounded_by_month:
            months.add(month)
        for month, _ in prisoners_by_month:
            months.add(month)
        
        months = sorted(list(months))
        
        martyrs_data = {month: 0 for month in months}
        for month, count in martyrs_by_month:
            martyrs_data[month] = count
        
        wounded_data = {month: 0 for month in months}
        for month, count in wounded_by_month:
            wounded_data[month] = count
        
        prisoners_data = {month: 0 for month in months}
        for month, count in prisoners_by_month:
            prisoners_data[month] = count
        
        # رسم البيانات
        plt.plot(months, [martyrs_data[month] for month in months], 'o-', label='الشهداء')
        plt.plot(months, [wounded_data[month] for month in months], 's-', label='الجرحى')
        plt.plot(months, [prisoners_data[month] for month in months], 'd-', label='الأسرى')
        
        plt.title('إحصائيات الشهداء والجرحى والأسرى حسب الشهر')
        plt.xlabel('الشهر')
        plt.ylabel('العدد')
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # حفظ الرسم البياني
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        chart_path = f"reports/statistics_chart_{timestamp}.png"
        plt.savefig(chart_path)
        plt.close()
        
        # إنشاء التقرير
        report_data = {
            "martyrs_count": martyrs_count,
            "wounded_count": wounded_count,
            "prisoners_count": prisoners_count,
            "martyrs_by_month": martyrs_by_month,
            "wounded_by_month": wounded_by_month,
            "prisoners_by_month": prisoners_by_month,
            "chart_path": chart_path
        }
        
        # حفظ التقرير في قاعدة البيانات
        report_path = f"reports/statistics_report_{timestamp}.{report_format}"
        db.execute_query(
            "INSERT INTO reports (name, type, parameters, user_id, file_path) VALUES (?, ?, ?, ?, ?)",
            (f"تقرير إحصائي {timestamp}", report_format, json.dumps(report_data), session_manager.current_user["id"], report_path),
            commit=True
        )
        
        return report_path
    
    def generate_location_report(self, report_format="pdf"):
        if not session_manager.current_user:
            return None
        
        # الحصول على بيانات المواقع
        cursor = db.get_connection().cursor()
        
        # مواقع الشهداء
        cursor.execute('''
            SELECT location, COUNT(*) as count
            FROM martyrs
            WHERE location IS NOT NULL AND location != ''
            GROUP BY location
            ORDER BY count DESC
        ''')
        martyrs_locations = cursor.fetchall()
        
        # مواقع الجرحى
        cursor.execute('''
            SELECT injury_location as location, COUNT(*) as count
            FROM wounded
            WHERE injury_location IS NOT NULL AND injury_location != ''
            GROUP BY location
            ORDER BY count DESC
        ''')
        wounded_locations = cursor.fetchall()
        
        # مواقع الأسرى
        cursor.execute('''
            SELECT arrest_location as location, COUNT(*) as count
            FROM prisoners
            WHERE arrest_location IS NOT NULL AND arrest_location != ''
            GROUP BY location
            ORDER BY count DESC
        ''')
        prisoners_locations = cursor.fetchall()
        
        cursor.close()
        
        # إنشاء الرسم البياني
        plt.figure(figsize=(12, 8))
        
        # إعداد البيانات
        locations = set()
        for location, _ in martyrs_locations[:10]:  # أفضل 10 مواقع
            locations.add(location)
        for location, _ in wounded_locations[:10]:
            locations.add(location)
        for location, _ in prisoners_locations[:10]:
            locations.add(location)
        
        locations = sorted(list(locations))
        
        martyrs_data = {location: 0 for location in locations}
        for location, count in martyrs_locations:
            if location in martyrs_data:
                martyrs_data[location] = count
        
        wounded_data = {location: 0 for location in locations}
        for location, count in wounded_locations:
            if location in wounded_data:
                wounded_data[location] = count
        
        prisoners_data = {location: 0 for location in locations}
        for location, count in prisoners_locations:
            if location in prisoners_data:
                prisoners_data[location] = count
        
        # رسم البيانات
        x = np.arange(len(locations))
        width = 0.25
        
        plt.bar(x - width, [martyrs_data[location] for location in locations], width, label='الشهداء')
        plt.bar(x, [wounded_data[location] for location in locations], width, label='الجرحى')
        plt.bar(x + width, [prisoners_data[location] for location in locations], width, label='الأسرى')
        
        plt.title('توزيع الشهداء والجرحى والأسرى حسب الموقع')
        plt.xlabel('الموقع')
        plt.ylabel('العدد')
        plt.xticks(x, locations, rotation=45, ha='right')
        plt.legend()
        plt.grid(True, axis='y')
        plt.tight_layout()
        
        # حفظ الرسم البياني
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        chart_path = f"reports/location_chart_{timestamp}.png"
        plt.savefig(chart_path)
        plt.close()
        
        # إنشاء التقرير
        report_data = {
            "martyrs_locations": martyrs_locations,
            "wounded_locations": wounded_locations,
            "prisoners_locations": prisoners_locations,
            "chart_path": chart_path
        }
        
        # حفظ التقرير في قاعدة البيانات
        report_path = f"reports/location_report_{timestamp}.{report_format}"
        db.execute_query(
            "INSERT INTO reports (name, type, parameters, user_id, file_path) VALUES (?, ?, ?, ?, ?)",
            (f"تقرير المواقع {timestamp}", report_format, json.dumps(report_data), session_manager.current_user["id"], report_path),
            commit=True
        )
        
        return report_path
    
    def get_reports(self):
        if not session_manager.current_user:
            return []
        
        reports = db.execute_query(
            "SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC",
            (session_manager.current_user["id"],),
            fetch_all=True
        )
        
        return reports

# تهيئة مدير التقارير
report_manager = ReportManager()

# إدارة البحث المتقدم
class SearchManager:
    def __init__(self):
        self.search_history = []
    
    def search_martyrs(self, query, filters=None):
        if not session_manager.current_user:
            return []
        
        # بناء استعلام البحث
        sql = "SELECT * FROM martyrs WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (name LIKE ? OR details LIKE ? OR location LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
        
        if filters:
            if filters.get("min_age"):
                sql += " AND age >= ?"
                params.append(filters["min_age"])
            
            if filters.get("max_age"):
                sql += " AND age <= ?"
                params.append(filters["max_age"])
            
            if filters.get("date_from"):
                sql += " AND date_of_martyrdom >= ?"
                params.append(filters["date_from"])
            
            if filters.get("date_to"):
                sql += " AND date_of_martyrdom <= ?"
                params.append(filters["date_to"])
            
            if filters.get("location"):
                sql += " AND location LIKE ?"
                params.append(f"%{filters['location']}%")
        
        sql += " ORDER BY created_at DESC"
        
        results = db.execute_query(sql, params, fetch_all=True)
        
        # حفظ البحث في السجل
        if query or filters:
            search_data = {
                "query": query,
                "filters": filters,
                "timestamp": datetime.now().isoformat(),
                "results_count": len(results)
            }
            
            self.search_history.append(search_data)
            
            # الاحتفاظ بآخر 20 بحث فقط
            if len(self.search_history) > 20:
                self.search_history = self.search_history[-20:]
            
            # تسجيل نشاط البحث
            db.log_activity(
                session_manager.current_user["id"],
                "search",
                "martyrs",
                details=f"بحث: {query}, النتائج: {len(results)}"
            )
        
        return results
    
    def search_wounded(self, query, filters=None):
        if not session_manager.current_user:
            return []
        
        # بناء استعلام البحث
        sql = "SELECT * FROM wounded WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (name LIKE ? OR injury_details LIKE ? OR injury_location LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
        
        if filters:
            if filters.get("min_age"):
                sql += " AND age >= ?"
                params.append(filters["min_age"])
            
            if filters.get("max_age"):
                sql += " AND age <= ?"
                params.append(filters["max_age"])
            
            if filters.get("date_from"):
                sql += " AND injury_date >= ?"
                params.append(filters["date_from"])
            
            if filters.get("date_to"):
                sql += " AND injury_date <= ?"
                params.append(filters["date_to"])
            
            if filters.get("location"):
                sql += " AND injury_location LIKE ?"
                params.append(f"%{filters['location']}%")
            
            if filters.get("medical_status"):
                sql += " AND medical_status = ?"
                params.append(filters["medical_status"])
        
        sql += " ORDER BY created_at DESC"
        
        results = db.execute_query(sql, params, fetch_all=True)
        
        # حفظ البحث في السجل
        if query or filters:
            search_data = {
                "query": query,
                "filters": filters,
                "timestamp": datetime.now().isoformat(),
                "results_count": len(results)
            }
            
            self.search_history.append(search_data)
            
            # الاحتفاظ بآخر 20 بحث فقط
            if len(self.search_history) > 20:
                self.search_history = self.search_history[-20:]
            
            # تسجيل نشاط البحث
            db.log_activity(
                session_manager.current_user["id"],
                "search",
                "wounded",
                details=f"بحث: {query}, النتائج: {len(results)}"
            )
        
        return results
    
    def search_prisoners(self, query, filters=None):
        if not session_manager.current_user:
            return []
        
        # بناء استعلام البحث
        sql = "SELECT * FROM prisoners WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (name LIKE ? OR details LIKE ? OR arrest_location LIKE ? OR prison_name LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"])
        
        if filters:
            if filters.get("min_age"):
                sql += " AND age >= ?"
                params.append(filters["min_age"])
            
            if filters.get("max_age"):
                sql += " AND age <= ?"
                params.append(filters["max_age"])
            
            if filters.get("date_from"):
                sql += " AND arrest_date >= ?"
                params.append(filters["date_from"])
            
            if filters.get("date_to"):
                sql += " AND arrest_date <= ?"
                params.append(filters["date_to"])
            
            if filters.get("location"):
                sql += " AND arrest_location LIKE ?"
                params.append(f"%{filters['location']}%")
            
            if filters.get("prison_name"):
                sql += " AND prison_name LIKE ?"
                params.append(f"%{filters['prison_name']}%")
        
        sql += " ORDER BY created_at DESC"
        
        results = db.execute_query(sql, params, fetch_all=True)
        
        # حفظ البحث في السجل
        if query or filters:
            search_data = {
                "query": query,
                "filters": filters,
                "timestamp": datetime.now().isoformat(),
                "results_count": len(results)
            }
            
            self.search_history.append(search_data)
            
            # الاحتفاظ بآخر 20 بحث فقط
            if len(self.search_history) > 20:
                self.search_history = self.search_history[-20:]
            
            # تسجيل نشاط البحث
            db.log_activity(
                session_manager.current_user["id"],
                "search",
                "prisoners",
                details=f"بحث: {query}, النتائج: {len(results)}"
            )
        
        return results
    
    def get_search_history(self):
        return self.search_history
    
    def clear_search_history(self):
        self.search_history = []
        if session_manager.current_user:
            db.log_activity(
                session_manager.current_user["id"],
                "clear_search_history",
                details="مسح سجل البحث"
            )

# تهيئة مدير البحث
search_manager = SearchManager()

# إدارة النسخ الاحتياطي
class BackupManager:
    def __init__(self):
        self.backup_dir = "backups"
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def create_backup(self, description="نسخة احتياطية يدوية"):
        if not session_manager.current_user:
            return False
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{self.backup_dir}/backup_{timestamp}.db"
        
        # نسخ قاعدة البيانات
        shutil.copy2(db.db_path, backup_filename)
        
        # تشفير النسخة الاحتياطية إذا كان مطلوباً
        if settings_manager.get("backup_encryption", "true") == "true":
            encrypted_filename = f"{backup_filename}.enc"
            with open(backup_filename, 'rb') as f:
                data = f.read()
            
            encrypted_data = encrypt_data(data)
            
            with open(encrypted_filename, 'wb') as f:
                f.write(encrypted_data)
            
            os.remove(backup_filename)
            backup_filename = encrypted_filename
        
        # تسجيل النسخة الاحتياطية في قاعدة البيانات
        file_size = os.path.getsize(backup_filename)
        db.create_backup(backup_filename, file_size, session_manager.current_user["id"], description)
        
        # تسجيل النشاط
        db.log_activity(
            session_manager.current_user["id"],
            "create_backup",
            details=f"إنشاء نسخة احتياطية: {backup_filename}"
        )
        
        # إضافة إشعار
        notification_manager.add_notification(
            "نسخة احتياطية",
            f"تم إنشاء نسخة احتياطية جديدة بنجاح: {description}",
            "success"
        )
        
        return True
    
    def restore_backup(self, backup_id):
        if not session_manager.current_user:
            return False
        
        # الحصول على معلومات النسخة الاحتياطية
        backup = db.execute_query(
            "SELECT * FROM backups WHERE id=?",
            (backup_id,),
            fetch=True
        )
        
        if not backup:
            return False
        
        backup_filename = backup["filename"]
        
        # فك تشفير النسخة الاحتياطية إذا كانت مشفرة
        if backup_filename.endswith(".enc"):
            decrypted_filename = backup_filename[:-4]  # إزالة .enc
            
            with open(backup_filename, 'rb') as f:
                encrypted_data = f.read()
            
            try:
                decrypted_data = decrypt_data(encrypted_data)
                
                with open(decrypted_filename, 'wb') as f:
                    f.write(decrypted_data)
                
                backup_filename = decrypted_filename
            except Exception as e:
                return False
        
        # إنشاء نسخة احتياطية من قاعدة البيانات الحالية قبل الاستعادة
        self.create_backup("نسخة احتياطية قبل الاستعادة")
        
        # استعادة قاعدة البيانات
        try:
            shutil.copy2(backup_filename, db.db_path)
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "restore_backup",
                details=f"استعادة النسخة الاحتياطية: {backup['description']}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "استعادة النسخة الاحتياطية",
                f"تم استعادة النسخة الاحتياطية بنجاح: {backup['description']}",
                "success"
            )
            
            return True
        except Exception as e:
            return False
    
    def get_backups(self):
        return db.get_backups()
    
    def delete_backup(self, backup_id):
        if not session_manager.current_user:
            return False
        
        result = db.delete_backup(backup_id)
        
        if result:
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "delete_backup",
                details=f"حذف النسخة الاحتياطية: {backup_id}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "حذف النسخة الاحتياطية",
                "تم حذف النسخة الاحتياطية بنجاح",
                "info"
            )
        
        return result
    
    def schedule_auto_backup(self):
        # جدولة النسخ الاحتياطي التلقائي
        auto_backup = settings_manager.get("auto_backup", "false") == "true"
        backup_interval = int(settings_manager.get("backup_interval", "7"))
        
        if auto_backup:
            # التحقق من وقت آخر نسخة احتياطي
            last_backup = db.execute_query(
                "SELECT MAX(created_at) FROM backups",
                fetch=True
            )
            
            if last_backup and last_backup[0]:
                last_backup_date = datetime.strptime(last_backup[0], "%Y-%m-%d %H:%M:%S")
                days_since_last_backup = (datetime.now() - last_backup_date).days
                
                if days_since_last_backup >= backup_interval:
                    self.create_backup("نسخة احتياطية تلقائية")
            else:
                # لا توجد نسخ احتياطية سابقة، إنشاء نسخة الآن
                self.create_backup("نسخة احتياطية تلقائية أولية")

# تهيئة مدير النسخ الاحتياطي
backup_manager = BackupManager()

# إدارة الصور
class ImageManager:
    def __init__(self):
        self.images_dir = "images"
        self.thumbnails_dir = "thumbnails"
        
        if not os.path.exists(self.images_dir):
            os.makedirs(self.images_dir)
        
        if not os.path.exists(self.thumbnails_dir):
            os.makedirs(self.thumbnails_dir)
    
    def save_image(self, image_data, image_type="martyr"):
        if not session_manager.current_user:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_filename = f"{self.images_dir}/{image_type}_{timestamp}_{session_manager.current_user['id']}.jpg"
        
        try:
            # فك تشفير البيانات إذا كانت مشفرة
            if isinstance(image_data, str) and image_data.startswith("encrypted:"):
                encrypted_data = base64.b64decode(image_data[10:])
                image_data = decrypt_data(encrypted_data)
            elif isinstance(image_data, str):
                image_data = base64.b64decode(image_data)
            
            # حفظ الصورة
            with open(image_filename, 'wb') as f:
                f.write(image_data)
            
            # إنشاء صورة مصغرة
            self.create_thumbnail(image_filename)
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "save_image",
                details=f"حفظ صورة: {image_filename}"
            )
            
            return image_filename
        except Exception as e:
            return None
    
    def create_thumbnail(self, image_path, size=(150, 150)):
        try:
            img = Image.open(image_path)
            img.thumbnail(size)
            
            # إنشاء اسم الصورة المصغرة
            filename = os.path.basename(image_path)
            thumbnail_path = os.path.join(self.thumbnails_dir, f"thumb_{filename}")
            
            img.save(thumbnail_path)
            return thumbnail_path
        except Exception as e:
            return None
    
    def get_thumbnail(self, image_path):
        filename = os.path.basename(image_path)
        thumbnail_path = os.path.join(self.thumbnails_dir, f"thumb_{filename}")
        
        if os.path.exists(thumbnail_path):
            return thumbnail_path
        else:
            return self.create_thumbnail(image_path)
    
    def delete_image(self, image_path):
        try:
            if os.path.exists(image_path):
                os.remove(image_path)
            
            # حذف الصورة المصغرة
            filename = os.path.basename(image_path)
            thumbnail_path = os.path.join(self.thumbnails_dir, f"thumb_{filename}")
            
            if os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
            
            # تسجيل النشاط
            if session_manager.current_user:
                db.log_activity(
                    session_manager.current_user["id"],
                    "delete_image",
                    details=f"حذف صورة: {image_path}"
                )
            
            return True
        except Exception as e:
            return False
    
    def compress_image(self, image_path, quality=85):
        try:
            img = Image.open(image_path)
            
            # حفظ الصورة مع ضغط الجودة
            img.save(image_path, "JPEG", quality=quality)
            
            # إنشاء صورة مصغرة جديدة
            self.create_thumbnail(image_path)
            
            return True
        except Exception as e:
            return False

# تهيئة مدير الصور
image_manager = ImageManager()

# إدارة المصادقة الثنائية
class TwoFactorAuthManager:
    def __init__(self):
        pass
    
    def generate_secret(self):
        return pyotp.random_base32()
    
    def generate_qr_code(self, username, secret):
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="نظام توثيق الشهداء")
        
        # إنشاء رمز QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # حفظ الصورة
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        qr_path = f"qrcodes/qr_{timestamp}.png"
        
        if not os.path.exists("qrcodes"):
            os.makedirs("qrcodes")
        
        img.save(qr_path)
        
        return qr_path
    
    def verify_code(self, secret, code):
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
    
    def enable_2fa(self, user_id, secret):
        db.execute_query(
            "UPDATE users SET two_factor_secret=? WHERE id=?",
            (secret, user_id),
            commit=True
        )
        
        # تسجيل النشاط
        db.log_activity(
            user_id,
            "enable_2fa",
            details="تفعيل المصادقة الثنائية"
        )
        
        return True
    
    def disable_2fa(self, user_id):
        db.execute_query(
            "UPDATE users SET two_factor_secret=NULL WHERE id=?",
            (user_id,),
            commit=True
        )
        
        # تسجيل النشاط
        db.log_activity(
            user_id,
            "disable_2fa",
            details="تعطيل المصادقة الثنائية"
        )
        
        return True

# تهيئة مدير المصادقة الثنائية
two_factor_auth_manager = TwoFactorAuthManager()

# إدارة قفل التطبيق
class AppLockManager:
    def __init__(self):
        self.pin_code = None
        self.is_locked = False
    
    def set_pin(self, pin_code):
        if not session_manager.current_user:
            return False
        
        # تشفير رمز PIN
        encrypted_pin = encrypt_data(pin_code)
        
        # حفظ رمز PIN في إعدادات المستخدم
        settings_manager.set("app_lock_pin", encrypted_pin)
        settings_manager.set("app_lock", "true")
        
        # تسجيل النشاط
        db.log_activity(
            session_manager.current_user["id"],
            "set_app_lock_pin",
            details="تعيين رمز PIN لقفل التطبيق"
        )
        
        return True
    
    def verify_pin(self, pin_code):
        encrypted_pin = settings_manager.get("app_lock_pin")
        
        if not encrypted_pin:
            return False
        
        try:
            stored_pin = decrypt_data(encrypted_pin)
            return stored_pin == pin_code
        except:
            return False
    
    def lock_app(self):
        self.is_locked = True
        
        # تسجيل النشاط
        if session_manager.current_user:
            db.log_activity(
                session_manager.current_user["id"],
                "lock_app",
                details="قفل التطبيق"
            )
    
    def unlock_app(self):
        self.is_locked = False
        
        # تسجيل النشاط
        if session_manager.current_user:
            db.log_activity(
                session_manager.current_user["id"],
                "unlock_app",
                details="فتح قفل التطبيق"
            )

# تهيئة مدير قفل التطبيق
app_lock_manager = AppLockManager()

# الوظائف الرئيسية للتطبيق
def main(page: ft.Page):
    # تطبيق الإعدادات على الصفحة
    theme_settings = settings_manager.apply_to_page(page)
    
    # متغيرات التطبيق
    current_view = None
    drag_start_x = 0
    drag_start_y = 0
    
    # ألوان التصميم مع إمكانية التخصيص
    colors = {
        "primary": theme_settings["primary_color"],
        "primary_light": f"{theme_settings['primary_color']}88",
        "primary_dark": f"{theme_settings['primary_color']}44",
        "secondary": "#f50057",
        "secondary_light": "#ff5983",
        "secondary_dark": "#bb002f",
        "background": "#f5f5f5" if theme_settings["theme_mode"] == "light" else "#1a1a1a",
        "surface": "#ffffff" if theme_settings["theme_mode"] == "light" else "#2d2d2d",
        "on_primary": "#ffffff",
        "on_secondary": "#ffffff",
        "on_background": "#000000" if theme_settings["theme_mode"] == "light" else "#ffffff",
        "on_surface": "#000000" if theme_settings["theme_mode"] == "light" else "#ffffff",
        "success": "#4caf50",
        "warning": "#ff9800",
        "error": "#f44336",
    }
    
    # أنماط التصميم
    button_style = ft.ButtonStyle(
        color=ft.Colors.WHITE,
        bgcolor=colors["primary"],
        padding=8,
        shape=ft.RoundedRectangleBorder(radius=6),
    )
    
    secondary_button_style = ft.ButtonStyle(
        color=ft.Colors.WHITE,
        bgcolor=colors["secondary"],
        padding=8,
        shape=ft.RoundedRectangleBorder(radius=6),
    )
    
    small_button_style = ft.ButtonStyle(
        color=ft.Colors.WHITE,
        bgcolor=colors["primary"],
        padding=5,
        shape=ft.RoundedRectangleBorder(radius=5),
    )
    
    settings_button_style = ft.ButtonStyle(
        color=ft.Colors.WHITE,
        bgcolor=colors["primary"],
        padding=ft.padding.symmetric(horizontal=10, vertical=5),
        shape=ft.RoundedRectangleBorder(radius=5),
    )
    
    # وظائف المساعدة
    def show_snackbar(message, color=colors["secondary"]):
        page.snack_bar = ft.SnackBar(ft.Text(message), bgcolor=color)
        page.snack_bar.open = True
        page.update()
    
    def navigate_to(view):
        nonlocal current_view
        current_view = view
        page.views.clear()
        page.views.append(view)
        page.update()
    
    # وظائف السحب والتحريك
    def on_pan_start(e: ft.DragStartEvent):
        nonlocal drag_start_x, drag_start_y
        drag_start_x = e.global_x
        drag_start_y = e.global_y
    
    def on_pan_update(e: ft.DragUpdateEvent):
        # تمكين التمرير بالسحب
        if current_view and hasattr(current_view, 'scroll'):
            current_view.scroll -= e.delta_y / 100
    
    def on_pan_end(e: ft.DragEndEvent):
        nonlocal drag_start_x, drag_start_y
        delta_x = e.global_x - drag_start_x
        if abs(delta_x) > 100:
            if delta_x > 0 and current_view and hasattr(current_view, 'route') and current_view.route != "/login":
                if session_manager.current_user and session_manager.current_user["is_admin"]:
                    show_admin_dashboard()
                else:
                    show_user_dashboard()
    
    # وظائف المصادقة
    def login_user(email, password):
        # التحقق من قفل الحساب
        user_data = db.execute_query(
            "SELECT * FROM users WHERE email = ?",
            (email,),
            fetch=True
        )
        
        if user_data:
            user = dict(user_data)
            
            # التحقق من حالة قفل الحساب
            if user["account_locked"]:
                lock_until = user["lock_until"]
                if lock_until:
                    lock_until_time = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
                    if datetime.now() < lock_until_time:
                        remaining_time = (lock_until_time - datetime.now()).seconds // 60
                        show_snackbar(f"الحساب مقفل. يرجى المحاولة بعد {remaining_time} دقيقة", colors["error"])
                        return False
                    else:
                        # فتح الحساب تلقائياً بعد انتهاء مدة القفل
                        db.execute_query(
                            "UPDATE users SET account_locked=0, lock_until=NULL WHERE id=?",
                            (user["id"],),
                            commit=True
                        )
        
        # محاولة تسجيل الدخول
        if user_data and verify_password(user["password"], password):
            # تسجيل الدخول بنجاح
            user = {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "profile_image": user["profile_image"],
                "is_admin": bool(user["is_admin"]),
                "two_factor_secret": user["two_factor_secret"]
            }
            
            # التحقق من المصادقة الثنائية
            if user["two_factor_secret"]:
                show_2fa_verification(user)
                return True
            
            # تسجيل الدخول
            session_manager.login(user)
            
            # تحميل إعدادات المستخدم
            settings_manager.load_settings()
            notification_manager.load_notifications()
            
            # التحقق من قفل التطبيق
            if settings_manager.get("app_lock") == "true":
                app_lock_manager.lock_app()
                show_app_lock()
                return True
            
            # الانتقال إلى لوحة التحكم المناسبة
            if user["is_admin"]:
                show_admin_dashboard()
            else:
                show_user_dashboard()
            
            return True
        else:
            # زيادة عدد محاولات تسجيل الدخول الفاشلة
            if user_data:
                failed_attempts = user["failed_login_attempts"] + 1
                max_attempts = int(settings_manager.get("max_login_attempts") or "5")
                lockout_duration = int(settings_manager.get("lockout_duration_minutes") or "15")
                
                db.execute_query(
                    "UPDATE users SET failed_login_attempts=? WHERE id=?",
                    (failed_attempts, user["id"]),
                    commit=True
                )
                
                # قفل الحساب إذا تجاوز عدد المحاولات المسموح بها
                if failed_attempts >= max_attempts:
                    lock_until = datetime.now() + timedelta(minutes=lockout_duration)
                    db.execute_query(
                        "UPDATE users SET account_locked=1, lock_until=? WHERE id=?",
                        (lock_until.strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
                        commit=True
                    )
                    
                    show_snackbar(f"الحساب مقفل لمدة {lockout_duration} دقيقة بسبب محاولات تسجيل دخول متعددة", colors["error"])
                else:
                    remaining_attempts = max_attempts - failed_attempts
                    show_snackbar(f"البريد الإلكتروني أو كلمة المرور غير صحيحة. محاولات متبقية: {remaining_attempts}", colors["error"])
            else:
                show_snackbar("البريد الإلكتروني أو كلمة المرور غير صحيحة", colors["error"])
            
            return False
    
    def register_user(username, email, password, confirm_password):
        if password != confirm_password:
            show_snackbar("كلمات المرور غير متطابقة", colors["error"])
            return False
        
        if len(password) < 8:
            show_snackbar("كلمة المرور يجب أن تكون على الأقل 8 أحرف", colors["error"])
            return False
        
        # التحقق من قوة كلمة المرور
        if not re.search(r'[A-Z]', password):
            show_snackbar("كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل", colors["error"])
            return False
        
        if not re.search(r'[a-z]', password):
            show_snackbar("كلمة المرور يجب أن تحتوي على حرف صغير واحد على الأقل", colors["error"])
            return False
        
        if not re.search(r'[0-9]', password):
            show_snackbar("كلمة المرور يجب أن تحتوي على رقم واحد على الأقل", colors["error"])
            return False
        
        if not re.search(r'[^A-Za-z0-9]', password):
            show_snackbar("كلمة المرور يجب أن تحتوي على رمز خاص واحد على الأقل", colors["error"])
            return False
        
        try:
            hashed_password = hash_password(password)
            salt = hashed_password.split('$')[0]
            
            db.execute_query(
                "INSERT INTO users (username, email, password, salt) VALUES (?, ?, ?, ?)",
                (username, email, hashed_password, salt),
                commit=True
            )
            
            show_snackbar("تم إنشاء الحساب بنجاح، يرجى تسجيل الدخول", colors["primary"])
            show_login_page()
            return True
        except sqlite3.IntegrityError:
            show_snackbar("البريد الإلكتروني أو اسم المستخدم موجود مسبقاً", colors["error"])
            return False
    
    def verify_2fa_code(user, code):
        if two_factor_auth_manager.verify_code(user["two_factor_secret"], code):
            # تسجيل الدخول
            session_manager.login(user)
            
            # تحميل إعدادات المستخدم
            settings_manager.load_settings()
            notification_manager.load_notifications()
            
            # التحقق من قفل التطبيق
            if settings_manager.get("app_lock") == "true":
                app_lock_manager.lock_app()
                show_app_lock()
                return True
            
            # الانتقال إلى لوحة التحكم المناسبة
            if user["is_admin"]:
                show_admin_dashboard()
            else:
                show_user_dashboard()
            
            return True
        else:
            show_snackbar("رمز التحقق غير صحيح", colors["error"])
            return False
    
    def unlock_app_with_pin(pin_code):
        if app_lock_manager.verify_pin(pin_code):
            app_lock_manager.unlock_app()
            
            # العودة إلى الصفحة السابقة
            if session_manager.current_user and session_manager.current_user["is_admin"]:
                show_admin_dashboard()
            else:
                show_user_dashboard()
            
            return True
        else:
            show_snackbar("رمز PIN غير صحيح", colors["error"])
            return False
    
    # واجهة تسجيل الدخول
    def show_login_page():
        email_field = ft.TextField(
            label="📧 البريد الإلكتروني",
            hint_text="أدخل بريدك الإلكتروني",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        password_field = ft.TextField(
            label="🔒 كلمة المرور",
            password=True,
            hint_text="أدخل كلمة المرور",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        login_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تسجيل الدخول", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                email_field,
                password_field,
                ft.ElevatedButton(
                    text="🚀 تسجيل الدخول",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: login_user(
                        email_field.value,
                        password_field.value
                    )
                ),
                ft.TextButton(
                    text="📝 ليس لديك حساب؟ إنشاء حساب",
                    on_click=lambda e: show_signup_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/login",
            controls=[
                ft.Container(
                    content=login_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=400,
                    alignment=ft.alignment.center
                )
            ],
            padding=30,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # واجهة التسجيل
    def show_signup_page():
        username_field = ft.TextField(
            label="👤 اسم المستخدم",
            hint_text="اختر اسم مستخدم",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        email_field = ft.TextField(
            label="📧 البريد الإلكتروني",
            hint_text="أدخل بريدك الإلكتروني",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        password_field = ft.TextField(
            label="🔒 كلمة المرور",
            password=True,
            hint_text="اختر كلمة مرور قوية",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        confirm_password_field = ft.TextField(
            label="✅ تأكيد كلمة المرور",
            password=True,
            hint_text="أعد إدخال كلمة المرور",
            width=300,
            border_radius=8,
            border_color=colors["primary"]
        )
        
        signup_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إنشاء حساب جديد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                username_field,
                email_field,
                password_field,
                confirm_password_field,
                ft.ElevatedButton(
                    text="✨ إنشاء الحساب",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: register_user(
                        username_field.value,
                        email_field.value,
                        password_field.value,
                        confirm_password_field.value
                    )
                ),
                ft.TextButton(
                    text="🔐 لديك حساب؟ تسجيل الدخول",
                    on_click=lambda e: show_login_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/signup",
            controls=[
                ft.Container(
                    content=signup_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=400,
                    alignment=ft.alignment.center
                )
            ],
            padding=30,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # واجهة التحقق من المصادقة الثنائية
    def show_2fa_verification(user):
        code_field = ft.TextField(
            label="🔑 رمز التحقق",
            hint_text="أدخل رمز التحقق من تطبيق المصادقة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        verification_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("التحقق بخطوتين", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("أدخل رمز التحقق من تطبيق المصادقة", size=14),
                code_field,
                ft.ElevatedButton(
                    text="✅ تحقق",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: verify_2fa_code(user, code_field.value)
                ),
                ft.TextButton(
                    text="🔄 العودة لتسجيل الدخول",
                    on_click=lambda e: show_login_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/2fa_verification",
            controls=[
                ft.Container(
                    content=verification_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=400,
                    alignment=ft.alignment.center
                )
            ],
            padding=30,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # واجهة قفل التطبيق
    def show_app_lock():
        pin_field = ft.TextField(
            label="🔒 رمز PIN",
            password=True,
            hint_text="أدخل رمز PIN لفتح القفل",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        lock_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔒", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("التطبيق مقفل", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("أدخل رمز PIN لفتح القفل", size=14),
                pin_field,
                ft.ElevatedButton(
                    text="🔓 فتح القفل",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: unlock_app_with_pin(pin_field.value)
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/app_lock",
            controls=[
                ft.Container(
                    content=lock_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=400,
                    alignment=ft.alignment.center
                )
            ],
            padding=30,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # لوحة تحكم المدير
    def show_admin_dashboard():
        # إحصائيات سريعة
        martyrs_count = db.execute_query("SELECT COUNT(*) FROM martyrs", fetch=True)[0]
        wounded_count = db.execute_query("SELECT COUNT(*) FROM wounded", fetch=True)[0]
        prisoners_count = db.execute_query("SELECT COUNT(*) FROM prisoners", fetch=True)[0]
        users_count = db.execute_query("SELECT COUNT(*) FROM users", fetch=True)[0]
        
        stats_cards = ft.Row(
            controls=[
                ft.Container(
                    content=ft.Column([
                        ft.Text("⭐", size=25),
                        ft.Text(str(martyrs_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الشهداء", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("🏥", size=25),
                        ft.Text(str(wounded_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الجرحى", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("🛡️", size=25),
                        ft.Text(str(prisoners_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الأسرى", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("👥", size=25),
                        ft.Text(str(users_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("المستخدمين", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
            ],
            spacing=10,
            wrap=True
        )
        
        # أزرار الإدارة
        admin_buttons = ft.Column(
            controls=[
                ft.ElevatedButton(
                    text="⭐ إدارة الشهداء",
                    style=button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_martyrs_list()
                ),
                ft.ElevatedButton(
                    text="🏥 إدارة الجرحى",
                    style=button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_wounded_list()
                ),
                ft.ElevatedButton(
                    text="🛡️ إدارة الأسرى",
                    style=button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_prisoners_list()
                ),
                ft.ElevatedButton(
                    text="👥 إدارة المستخدمين",
                    style=secondary_button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_users_list()
                ),
                ft.ElevatedButton(
                    text="📊 التقارير",
                    style=secondary_button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_reports_page()
                ),
                ft.ElevatedButton(
                    text="⚙️ الإعدادات",
                    style=secondary_button_style,
                    width=250,
                    height=40,
                    on_click=lambda e: show_settings_page()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        dashboard_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text(f"👋 مرحباً {session_manager.current_user['username']}", 
                           size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.Row([
                        ft.IconButton(
                            icon=ft.icons.NOTIFICATIONS,
                            tooltip="الإشعارات",
                            icon_size=20,
                            on_click=lambda e: show_notifications_page()
                        ),
                        ft.Badge(
                            text=str(notification_manager.get_count()),
                            color=colors["error"],
                            small=True,
                            visible=notification_manager.get_count() > 0
                        ),
                        ft.IconButton(
                            icon=ft.icons.EXIT_TO_APP,
                            tooltip="تسجيل الخروج",
                            icon_size=20,
                            on_click=lambda e: logout_user()
                        )
                    ])
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Text("📊 الإحصائيات", size=16, weight=ft.FontWeight.BOLD),
                stats_cards,
                ft.Divider(),
                ft.Text("🎯 إدارة النظام", size=16, weight=ft.FontWeight.BOLD),
                admin_buttons,
            ],
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/admin_dashboard",
            controls=[
                ft.Container(
                    content=dashboard_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # لوحة تحكم المستخدم العادي
    def show_user_dashboard():
        # إحصائيات سريعة
        martyrs_count = db.execute_query("SELECT COUNT(*) FROM martyrs", fetch=True)[0]
        wounded_count = db.execute_query("SELECT COUNT(*) FROM wounded", fetch=True)[0]
        prisoners_count = db.execute_query("SELECT COUNT(*) FROM prisoners", fetch=True)[0]
        
        stats_cards = ft.Row(
            controls=[
                ft.Container(
                    content=ft.Column([
                        ft.Text("⭐", size=25),
                        ft.Text(str(martyrs_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الشهداء", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("🏥", size=25),
                        ft.Text(str(wounded_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الجرحى", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
                ft.Container(
                    content=ft.Column([
                        ft.Text("🛡️", size=25),
                        ft.Text(str(prisoners_count), size=18, weight=ft.FontWeight.BOLD),
                        ft.Text("الأسرى", size=12)
                    ], horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                    bgcolor=colors["surface"],
                    padding=12,
                    border_radius=10,
                    width=100,
                    shadow=ft.BoxShadow(spread_radius=1, blur_radius=5, color="#e0e0e0")
                ),
            ],
            spacing=10,
            wrap=True
        )
        
        # أزرار المستخدم العادي
        user_buttons = ft.Column(
            controls=[
                ft.ElevatedButton(
                    text="⭐ إضافة شهيد",
                    style=button_style,
                    width=220,
                    height=40,
                    on_click=lambda e: add_martyr_page()
                ),
                ft.ElevatedButton(
                    text="🏥 إضافة جريح",
                    style=button_style,
                    width=220,
                    height=40,
                    on_click=lambda e: add_wounded_page()
                ),
                ft.ElevatedButton(
                    text="🛡️ إضافة أسير",
                    style=button_style,
                    width=220,
                    height=40,
                    on_click=lambda e: add_prisoner_page()
                ),
                ft.ElevatedButton(
                    text="🔍 البحث المتقدم",
                    style=secondary_button_style,
                    width=220,
                    height=40,
                    on_click=lambda e: show_search_page()
                ),
                ft.ElevatedButton(
                    text="👤 إدارة الحساب",
                    style=secondary_button_style,
                    width=220,
                    height=40,
                    on_click=lambda e: show_user_account_settings()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        user_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text(f"👤 مرحباً {session_manager.current_user['username']}", size=18, weight=ft.FontWeight.BOLD),
                    ft.Row([
                        ft.IconButton(
                            icon=ft.icons.NOTIFICATIONS,
                            tooltip="الإشعارات",
                            icon_size=20,
                            on_click=lambda e: show_notifications_page()
                        ),
                        ft.Badge(
                            text=str(notification_manager.get_count()),
                            color=colors["error"],
                            small=True,
                            visible=notification_manager.get_count() > 0
                        ),
                        ft.IconButton(
                            icon=ft.icons.EXIT_TO_APP,
                            tooltip="تسجيل الخروج",
                            icon_size=20,
                            on_click=lambda e: logout_user()
                        )
                    ])
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Text("📊 الإحصائيات", size=16, weight=ft.FontWeight.BOLD),
                stats_cards,
                ft.Divider(),
                ft.Text("🎯 الخيارات المتاحة", size=16, weight=ft.FontWeight.BOLD),
                user_buttons,
            ],
            spacing=12,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/user_dashboard",
            controls=[
                ft.Container(
                    content=user_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # تسجيل الخروج
    def logout_user():
        session_manager.logout()
        show_login_page()
    
    # صفحة إضافة شهيد
    def add_martyr_page():
        name_field = ft.TextField(
            label="👤 الاسم",
            hint_text="أدخل اسم الشهيد",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            hint_text="أدخل عمر الشهيد",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الاستشهاد",
            hint_text="أدخل تاريخ الاستشهاد",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الاستشهاد",
            hint_text="أدخل مكان الاستشهاد",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 التفاصيل",
            hint_text="أدخل تفاصيل الاستشهاد",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            hint_text="أدخل وسوم مفصولة بفواصل",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e, "martyr")
        )
        
        image_preview = ft.Image(
            src="",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e, image_type):
            if e.files:
                # قراءة الصورة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة
                image_path = image_manager.save_image(image_data, image_type)
                
                if image_path:
                    # عرض الصورة
                    image_preview.src = image_path
                    page.update()
                    
                    # تشفير البيانات الحساسة
                    encrypted_data = encrypt_data(json.dumps({
                        "name": name_field.value,
                        "age": age_field.value,
                        "date": date_field.value,
                        "location": location_field.value,
                        "details": details_field.value,
                        "tags": tags_field.value
                    }))
                    
                    # حفظ البيانات في قاعدة البيانات
                    db.execute_query(
                        "INSERT INTO martyrs (name, age, date_of_martyrdom, location, details, image_path, created_by, tags, encrypted_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name_field.value,
                            age_field.value,
                            date_field.value,
                            location_field.value,
                            details_field.value,
                            image_path,
                            session_manager.current_user["id"],
                            tags_field.value,
                            encrypted_data
                        ),
                        commit=True
                    )
                    
                    # تحديث الإحصائيات
                    db.execute_query(
                        "UPDATE statistics SET martyrs_count = (SELECT COUNT(*) FROM martyrs), last_updated = CURRENT_TIMESTAMP",
                        commit=True
                    )
                    
                    # تسجيل النشاط
                    db.log_activity(
                        session_manager.current_user["id"],
                        "add_martyr",
                        "martyrs",
                        details=f"إضافة شهيد: {name_field.value}"
                    )
                    
                    # إضافة إشعار
                    notification_manager.add_notification(
                        "إضافة شهيد",
                        f"تم إضافة شهيد جديد: {name_field.value}",
                        "success"
                    )
                    
                    show_snackbar("تم إضافة الشهيد بنجاح", colors["primary"])
                    
                    # العودة إلى القائمة
                    if session_manager.current_user["is_admin"]:
                        show_martyrs_list()
                    else:
                        show_user_dashboard()
        
        add_martyr_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("⭐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إضافة شهيد جديد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                details_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 اختيار صورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="✨ إضافة الشهيد",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: handle_image_upload(None, "martyr")
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard() if session_manager.current_user["is_admin"] else show_user_dashboard()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/add_martyr",
            controls=[
                ft.Container(
                    content=add_martyr_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة إضافة جريح
    def add_wounded_page():
        name_field = ft.TextField(
            label="👤 الاسم",
            hint_text="أدخل اسم الجريح",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            hint_text="أدخل عمر الجريح",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الإصابة",
            hint_text="أدخل تاريخ الإصابة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الإصابة",
            hint_text="أدخل مكان الإصابة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 تفاصيل الإصابة",
            hint_text="أدخل تفاصيل الإصابة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        medical_status_field = ft.Dropdown(
            label="🏥 الحالة الطبية",
            hint_text="اختر الحالة الطبية",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("مستقر"),
                ft.dropdown.Option("حرج"),
                ft.dropdown.Option("تحسن"),
                ft.dropdown.Option("علاج"),
                ft.dropdown.Option("شفى"),
            ]
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            hint_text="أدخل وسوم مفصولة بفواصل",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e, "wounded")
        )
        
        image_preview = ft.Image(
            src="",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e, image_type):
            if e.files:
                # قراءة الصورة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة
                image_path = image_manager.save_image(image_data, image_type)
                
                if image_path:
                    # عرض الصورة
                    image_preview.src = image_path
                    page.update()
                    
                    # تشفير البيانات الحساسة
                    encrypted_data = encrypt_data(json.dumps({
                        "name": name_field.value,
                        "age": age_field.value,
                        "date": date_field.value,
                        "location": location_field.value,
                        "details": details_field.value,
                        "medical_status": medical_status_field.value,
                        "tags": tags_field.value
                    }))
                    
                    # حفظ البيانات في قاعدة البيانات
                    db.execute_query(
                        "INSERT INTO wounded (name, age, injury_date, injury_location, injury_details, medical_status, image_path, created_by, tags, encrypted_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name_field.value,
                            age_field.value,
                            date_field.value,
                            location_field.value,
                            details_field.value,
                            medical_status_field.value,
                            image_path,
                            session_manager.current_user["id"],
                            tags_field.value,
                            encrypted_data
                        ),
                        commit=True
                    )
                    
                    # تحديث الإحصائيات
                    db.execute_query(
                        "UPDATE statistics SET wounded_count = (SELECT COUNT(*) FROM wounded), last_updated = CURRENT_TIMESTAMP",
                        commit=True
                    )
                    
                    # تسجيل النشاط
                    db.log_activity(
                        session_manager.current_user["id"],
                        "add_wounded",
                        "wounded",
                        details=f"إضافة جريح: {name_field.value}"
                    )
                    
                    # إضافة إشعار
                    notification_manager.add_notification(
                        "إضافة جريح",
                        f"تم إضافة جريح جديد: {name_field.value}",
                        "success"
                    )
                    
                    show_snackbar("تم إضافة الجريح بنجاح", colors["primary"])
                    
                    # العودة إلى القائمة
                    if session_manager.current_user["is_admin"]:
                        show_wounded_list()
                    else:
                        show_user_dashboard()
        
        add_wounded_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🏥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إضافة جريح جديد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                details_field,
                medical_status_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 اختيار صورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="✨ إضافة الجريح",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: handle_image_upload(None, "wounded")
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard() if session_manager.current_user["is_admin"] else show_user_dashboard()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/add_wounded",
            controls=[
                ft.Container(
                    content=add_wounded_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة إضافة أسير
    def add_prisoner_page():
        name_field = ft.TextField(
            label="👤 الاسم",
            hint_text="أدخل اسم الأسير",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            hint_text="أدخل عمر الأسير",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الاعتقال",
            hint_text="أدخل تاريخ الاعتقال",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الاعتقال",
            hint_text="أدخل مكان الاعتقال",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        prison_field = ft.TextField(
            label="🏢 اسم السجن",
            hint_text="أدخل اسم السجن",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 التفاصيل",
            hint_text="أدخل تفاصيل الاعتقال",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            hint_text="أدخل وسوم مفصولة بفواصل",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e, "prisoner")
        )
        
        image_preview = ft.Image(
            src="",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e, image_type):
            if e.files:
                # قراءة الصورة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة
                image_path = image_manager.save_image(image_data, image_type)
                
                if image_path:
                    # عرض الصورة
                    image_preview.src = image_path
                    page.update()
                    
                    # تشفير البيانات الحساسة
                    encrypted_data = encrypt_data(json.dumps({
                        "name": name_field.value,
                        "age": age_field.value,
                        "date": date_field.value,
                        "location": location_field.value,
                        "prison": prison_field.value,
                        "details": details_field.value,
                        "tags": tags_field.value
                    }))
                    
                    # حفظ البيانات في قاعدة البيانات
                    db.execute_query(
                        "INSERT INTO prisoners (name, age, arrest_date, arrest_location, prison_name, details, image_path, created_by, tags, encrypted_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            name_field.value,
                            age_field.value,
                            date_field.value,
                            location_field.value,
                            prison_field.value,
                            details_field.value,
                            image_path,
                            session_manager.current_user["id"],
                            tags_field.value,
                            encrypted_data
                        ),
                        commit=True
                    )
                    
                    # تحديث الإحصائيات
                    db.execute_query(
                        "UPDATE statistics SET prisoners_count = (SELECT COUNT(*) FROM prisoners), last_updated = CURRENT_TIMESTAMP",
                        commit=True
                    )
                    
                    # تسجيل النشاط
                    db.log_activity(
                        session_manager.current_user["id"],
                        "add_prisoner",
                        "prisoners",
                        details=f"إضافة أسير: {name_field.value}"
                    )
                    
                    # إضافة إشعار
                    notification_manager.add_notification(
                        "إضافة أسير",
                        f"تم إضافة أسير جديد: {name_field.value}",
                        "success"
                    )
                    
                    show_snackbar("تم إضافة الأسير بنجاح", colors["primary"])
                    
                    # العودة إلى القائمة
                    if session_manager.current_user["is_admin"]:
                        show_prisoners_list()
                    else:
                        show_user_dashboard()
        
        add_prisoner_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🛡️", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إضافة أسير جديد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                prison_field,
                details_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 اختيار صورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="✨ إضافة الأسير",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: handle_image_upload(None, "prisoner")
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard() if session_manager.current_user["is_admin"] else show_user_dashboard()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/add_prisoner",
            controls=[
                ft.Container(
                    content=add_prisoner_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # قائمة الشهداء
    def show_martyrs_list():
        martyrs = db.execute_query("SELECT * FROM martyrs ORDER BY created_at DESC", fetch_all=True)
        
        martyr_cards = []
        for martyr in martyrs:
            martyr_data = dict(martyr)
            
            # فك تشفير البيانات إذا كانت مشفرة
            if martyr_data["encrypted_data"]:
                try:
                    decrypted_data = decrypt_data(martyr_data["encrypted_data"])
                    decrypted_dict = json.loads(decrypted_data)
                    martyr_data.update(decrypted_dict)
                except:
                    pass
            
            # إنشاء بطاقة الشهيد
            martyr_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(martyr_data["name"], size=16, weight=ft.FontWeight.BOLD),
                            ft.Text(f"العمر: {martyr_data['age'] or 'غير محدد'}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"التاريخ: {martyr_data['date_of_martyrdom'] or 'غير محدد'}", size=14),
                        ft.Text(f"المكان: {martyr_data['location'] or 'غير محدد'}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.EDIT,
                                tooltip="تعديل",
                                icon_size=18,
                                on_click=lambda e, m=martyr_data: edit_martyr(m)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, m=martyr_data: delete_martyr(m)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            martyr_cards.append(martyr_card)
        
        martyrs_list_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("قائمة الشهداء", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.ElevatedButton(
                        text="➕ إضافة شهيد",
                        style=button_style,
                        height=40,
                        on_click=lambda e: add_martyr_page()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Column(martyr_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/martyrs_list",
            controls=[
                ft.Container(
                    content=martyrs_list_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # قائمة الجرحى
    def show_wounded_list():
        wounded = db.execute_query("SELECT * FROM wounded ORDER BY created_at DESC", fetch_all=True)
        
        wounded_cards = []
        for person in wounded:
            person_data = dict(person)
            
            # فك تشفير البيانات إذا كانت مشفرة
            if person_data["encrypted_data"]:
                try:
                    decrypted_data = decrypt_data(person_data["encrypted_data"])
                    decrypted_dict = json.loads(decrypted_data)
                    person_data.update(decrypted_dict)
                except:
                    pass
            
            # إنشاء بطاقة الجريح
            wounded_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(person_data["name"], size=16, weight=ft.FontWeight.BOLD),
                            ft.Text(f"العمر: {person_data['age'] or 'غير محدد'}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"التاريخ: {person_data['injury_date'] or 'غير محدد'}", size=14),
                        ft.Text(f"المكان: {person_data['injury_location'] or 'غير محدد'}", size=14),
                        ft.Text(f"الحالة: {person_data['medical_status'] or 'غير محدد'}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.EDIT,
                                tooltip="تعديل",
                                icon_size=18,
                                on_click=lambda e, p=person_data: edit_wounded(p)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, p=person_data: delete_wounded(p)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            wounded_cards.append(wounded_card)
        
        wounded_list_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("قائمة الجرحى", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.ElevatedButton(
                        text="➕ إضافة جريح",
                        style=button_style,
                        height=40,
                        on_click=lambda e: add_wounded_page()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Column(wounded_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/wounded_list",
            controls=[
                ft.Container(
                    content=wounded_list_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # قائمة الأسرى
    def show_prisoners_list():
        prisoners = db.execute_query("SELECT * FROM prisoners ORDER BY created_at DESC", fetch_all=True)
        
        prisoner_cards = []
        for prisoner in prisoners:
            prisoner_data = dict(prisoner)
            
            # فك تشفير البيانات إذا كانت مشفرة
            if prisoner_data["encrypted_data"]:
                try:
                    decrypted_data = decrypt_data(prisoner_data["encrypted_data"])
                    decrypted_dict = json.loads(decrypted_data)
                    prisoner_data.update(decrypted_dict)
                except:
                    pass
            
            # إنشاء بطاقة الأسير
            prisoner_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(prisoner_data["name"], size=16, weight=ft.FontWeight.BOLD),
                            ft.Text(f"العمر: {prisoner_data['age'] or 'غير محدد'}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"التاريخ: {prisoner_data['arrest_date'] or 'غير محدد'}", size=14),
                        ft.Text(f"المكان: {prisoner_data['arrest_location'] or 'غير محدد'}", size=14),
                        ft.Text(f"السجن: {prisoner_data['prison_name'] or 'غير محدد'}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.EDIT,
                                tooltip="تعديل",
                                icon_size=18,
                                on_click=lambda e, p=prisoner_data: edit_prisoner(p)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, p=prisoner_data: delete_prisoner(p)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            prisoner_cards.append(prisoner_card)
        
        prisoners_list_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("قائمة الأسرى", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.ElevatedButton(
                        text="➕ إضافة أسير",
                        style=button_style,
                        height=40,
                        on_click=lambda e: add_prisoner_page()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Column(prisoner_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/prisoners_list",
            controls=[
                ft.Container(
                    content=prisoners_list_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # تعديل شهيد
    def edit_martyr(martyr_data):
        name_field = ft.TextField(
            label="👤 الاسم",
            value=martyr_data["name"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            value=str(martyr_data["age"] or ""),
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الاستشهاد",
            value=martyr_data["date_of_martyrdom"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الاستشهاد",
            value=martyr_data["location"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 التفاصيل",
            value=martyr_data["details"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            value=martyr_data["tags"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e)
        )
        
        image_preview = ft.Image(
            src=martyr_data["image_path"] or "",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e):
            if e.files:
                # قراءة الصورة الجديدة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة الجديدة
                new_image_path = image_manager.save_image(image_data, "martyr")
                
                if new_image_path:
                    # حذف الصورة القديمة
                    if martyr_data["image_path"]:
                        image_manager.delete_image(martyr_data["image_path"])
                    
                    # عرض الصورة الجديدة
                    image_preview.src = new_image_path
                    page.update()
                    
                    # تحديث مسار الصورة
                    martyr_data["image_path"] = new_image_path
        
        def save_changes():
            # تشفير البيانات الحساسة
            encrypted_data = encrypt_data(json.dumps({
                "name": name_field.value,
                "age": age_field.value,
                "date": date_field.value,
                "location": location_field.value,
                "details": details_field.value,
                "tags": tags_field.value
            }))
            
            # تحديث البيانات في قاعدة البيانات
            db.execute_query(
                "UPDATE martyrs SET name=?, age=?, date_of_martyrdom=?, location=?, details=?, image_path=?, tags=?, encrypted_data=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    name_field.value,
                    age_field.value,
                    date_field.value,
                    location_field.value,
                    details_field.value,
                    martyr_data["image_path"],
                    tags_field.value,
                    encrypted_data,
                    martyr_data["id"]
                ),
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "edit_martyr",
                "martyrs",
                martyr_data["id"],
                details=f"تعديل شهيد: {name_field.value}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تعديل شهيد",
                f"تم تعديل بيانات الشهيد: {name_field.value}",
                "info"
            )
            
            show_snackbar("تم تحديث بيانات الشهيد بنجاح", colors["primary"])
            show_martyrs_list()
        
        edit_martyr_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("⭐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تعديل بيانات الشهيد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                details_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 تغيير الصورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="💾 حفظ التغييرات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_changes()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_martyrs_list()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/edit_martyr",
            controls=[
                ft.Container(
                    content=edit_martyr_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # تعديل جريح
    def edit_wounded(wounded_data):
        name_field = ft.TextField(
            label="👤 الاسم",
            value=wounded_data["name"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            value=str(wounded_data["age"] or ""),
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الإصابة",
            value=wounded_data["injury_date"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الإصابة",
            value=wounded_data["injury_location"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 تفاصيل الإصابة",
            value=wounded_data["injury_details"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        medical_status_field = ft.Dropdown(
            label="🏥 الحالة الطبية",
            value=wounded_data["medical_status"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("مستقر"),
                ft.dropdown.Option("حرج"),
                ft.dropdown.Option("تحسن"),
                ft.dropdown.Option("علاج"),
                ft.dropdown.Option("شفى"),
            ]
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            value=wounded_data["tags"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e)
        )
        
        image_preview = ft.Image(
            src=wounded_data["image_path"] or "",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e):
            if e.files:
                # قراءة الصورة الجديدة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة الجديدة
                new_image_path = image_manager.save_image(image_data, "wounded")
                
                if new_image_path:
                    # حذف الصورة القديمة
                    if wounded_data["image_path"]:
                        image_manager.delete_image(wounded_data["image_path"])
                    
                    # عرض الصورة الجديدة
                    image_preview.src = new_image_path
                    page.update()
                    
                    # تحديث مسار الصورة
                    wounded_data["image_path"] = new_image_path
        
        def save_changes():
            # تشفير البيانات الحساسة
            encrypted_data = encrypt_data(json.dumps({
                "name": name_field.value,
                "age": age_field.value,
                "date": date_field.value,
                "location": location_field.value,
                "details": details_field.value,
                "medical_status": medical_status_field.value,
                "tags": tags_field.value
            }))
            
            # تحديث البيانات في قاعدة البيانات
            db.execute_query(
                "UPDATE wounded SET name=?, age=?, injury_date=?, injury_location=?, injury_details=?, medical_status=?, image_path=?, tags=?, encrypted_data=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    name_field.value,
                    age_field.value,
                    date_field.value,
                    location_field.value,
                    details_field.value,
                    medical_status_field.value,
                    wounded_data["image_path"],
                    tags_field.value,
                    encrypted_data,
                    wounded_data["id"]
                ),
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "edit_wounded",
                "wounded",
                wounded_data["id"],
                details=f"تعديل جريح: {name_field.value}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تعديل جريح",
                f"تم تعديل بيانات الجريح: {name_field.value}",
                "info"
            )
            
            show_snackbar("تم تحديث بيانات الجريح بنجاح", colors["primary"])
            show_wounded_list()
        
        edit_wounded_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🏥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تعديل بيانات الجريح", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                details_field,
                medical_status_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 تغيير الصورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="💾 حفظ التغييرات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_changes()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_wounded_list()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/edit_wounded",
            controls=[
                ft.Container(
                    content=edit_wounded_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # تعديل أسير
    def edit_prisoner(prisoner_data):
        name_field = ft.TextField(
            label="👤 الاسم",
            value=prisoner_data["name"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        age_field = ft.TextField(
            label="🎂 العمر",
            value=str(prisoner_data["age"] or ""),
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_field = ft.TextField(
            label="📅 تاريخ الاعتقال",
            value=prisoner_data["arrest_date"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 مكان الاعتقال",
            value=prisoner_data["arrest_location"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        prison_field = ft.TextField(
            label="🏢 اسم السجن",
            value=prisoner_data["prison_name"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        details_field = ft.TextField(
            label="📝 التفاصيل",
            value=prisoner_data["details"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            multiline=True,
            min_lines=3,
            max_lines=5,
        )
        
        tags_field = ft.TextField(
            label="🏷️ الوسوم",
            value=prisoner_data["tags"] or "",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e)
        )
        
        image_preview = ft.Image(
            src=prisoner_data["image_path"] or "",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e):
            if e.files:
                # قراءة الصورة الجديدة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة الجديدة
                new_image_path = image_manager.save_image(image_data, "prisoner")
                
                if new_image_path:
                    # حذف الصورة القديمة
                    if prisoner_data["image_path"]:
                        image_manager.delete_image(prisoner_data["image_path"])
                    
                    # عرض الصورة الجديدة
                    image_preview.src = new_image_path
                    page.update()
                    
                    # تحديث مسار الصورة
                    prisoner_data["image_path"] = new_image_path
        
        def save_changes():
            # تشفير البيانات الحساسة
            encrypted_data = encrypt_data(json.dumps({
                "name": name_field.value,
                "age": age_field.value,
                "date": date_field.value,
                "location": location_field.value,
                "prison": prison_field.value,
                "details": details_field.value,
                "tags": tags_field.value
            }))
            
            # تحديث البيانات في قاعدة البيانات
            db.execute_query(
                "UPDATE prisoners SET name=?, age=?, arrest_date=?, arrest_location=?, prison_name=?, details=?, image_path=?, tags=?, encrypted_data=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    name_field.value,
                    age_field.value,
                    date_field.value,
                    location_field.value,
                    prison_field.value,
                    details_field.value,
                    prisoner_data["image_path"],
                    tags_field.value,
                    encrypted_data,
                    prisoner_data["id"]
                ),
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "edit_prisoner",
                "prisoners",
                prisoner_data["id"],
                details=f"تعديل أسير: {name_field.value}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تعديل أسير",
                f"تم تعديل بيانات الأسير: {name_field.value}",
                "info"
            )
            
            show_snackbar("تم تحديث بيانات الأسير بنجاح", colors["primary"])
            show_prisoners_list()
        
        edit_prisoner_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🛡️", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تعديل بيانات الأسير", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                name_field,
                age_field,
                date_field,
                location_field,
                prison_field,
                details_field,
                tags_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 تغيير الصورة",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="💾 حفظ التغييرات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_changes()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_prisoners_list()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/edit_prisoner",
            controls=[
                ft.Container(
                    content=edit_prisoner_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # حذف شهيد
    def delete_martyr(martyr_data):
        def confirm_delete():
            # حذف الصورة
            if martyr_data["image_path"]:
                image_manager.delete_image(martyr_data["image_path"])
            
            # حذف السجل من قاعدة البيانات
            db.execute_query(
                "DELETE FROM martyrs WHERE id=?",
                (martyr_data["id"],),
                commit=True
            )
            
            # تحديث الإحصائيات
            db.execute_query(
                "UPDATE statistics SET martyrs_count = (SELECT COUNT(*) FROM martyrs), last_updated = CURRENT_TIMESTAMP",
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "delete_martyr",
                "martyrs",
                martyr_data["id"],
                details=f"حذف شهيد: {martyr_data['name']}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "حذف شهيد",
                f"تم حذف الشهيد: {martyr_data['name']}",
                "warning"
            )
            
            show_snackbar("تم حذف الشهيد بنجاح", colors["warning"])
            show_martyrs_list()
        
        dialog = ft.AlertDialog(
            title=ft.Text("تأكيد الحذف"),
            content=ft.Text(f"هل أنت متأكد من حذف الشهيد: {martyr_data['name']}؟"),
            actions=[
                ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                ft.TextButton(text="حذف", on_click=lambda e: [confirm_delete(), page.close(dialog)]),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        page.dialog = dialog
        dialog.open = True
        page.update()
    
    # حذف جريح
    def delete_wounded(wounded_data):
        def confirm_delete():
            # حذف الصورة
            if wounded_data["image_path"]:
                image_manager.delete_image(wounded_data["image_path"])
            
            # حذف السجل من قاعدة البيانات
            db.execute_query(
                "DELETE FROM wounded WHERE id=?",
                (wounded_data["id"],),
                commit=True
            )
            
            # تحديث الإحصائيات
            db.execute_query(
                "UPDATE statistics SET wounded_count = (SELECT COUNT(*) FROM wounded), last_updated = CURRENT_TIMESTAMP",
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "delete_wounded",
                "wounded",
                wounded_data["id"],
                details=f"حذف جريح: {wounded_data['name']}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "حذف جريح",
                f"تم حذف الجريح: {wounded_data['name']}",
                "warning"
            )
            
            show_snackbar("تم حذف الجريح بنجاح", colors["warning"])
            show_wounded_list()
        
        dialog = ft.AlertDialog(
            title=ft.Text("تأكيد الحذف"),
            content=ft.Text(f"هل أنت متأكد من حذف الجريح: {wounded_data['name']}؟"),
            actions=[
                ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                ft.TextButton(text="حذف", on_click=lambda e: [confirm_delete(), page.close(dialog)]),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        page.dialog = dialog
        dialog.open = True
        page.update()
    
    # حذف أسير
    def delete_prisoner(prisoner_data):
        def confirm_delete():
            # حذف الصورة
            if prisoner_data["image_path"]:
                image_manager.delete_image(prisoner_data["image_path"])
            
            # حذف السجل من قاعدة البيانات
            db.execute_query(
                "DELETE FROM prisoners WHERE id=?",
                (prisoner_data["id"],),
                commit=True
            )
            
            # تحديث الإحصائيات
            db.execute_query(
                "UPDATE statistics SET prisoners_count = (SELECT COUNT(*) FROM prisoners), last_updated = CURRENT_TIMESTAMP",
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "delete_prisoner",
                "prisoners",
                prisoner_data["id"],
                details=f"حذف أسير: {prisoner_data['name']}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "حذف أسير",
                f"تم حذف الأسير: {prisoner_data['name']}",
                "warning"
            )
            
            show_snackbar("تم حذف الأسير بنجاح", colors["warning"])
            show_prisoners_list()
        
        dialog = ft.AlertDialog(
            title=ft.Text("تأكيد الحذف"),
            content=ft.Text(f"هل أنت متأكد من حذف الأسير: {prisoner_data['name']}؟"),
            actions=[
                ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                ft.TextButton(text="حذف", on_click=lambda e: [confirm_delete(), page.close(dialog)]),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        page.dialog = dialog
        dialog.open = True
        page.update()
    
    # قائمة المستخدمين
    def show_users_list():
        users = db.execute_query("SELECT * FROM users ORDER BY created_at DESC", fetch_all=True)
        
        user_cards = []
        for user in users:
            user_data = dict(user)
            
            # إنشاء بطاقة المستخدم
            user_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(user_data["username"], size=16, weight=ft.FontWeight.BOLD),
                            ft.Text(f"البريد: {user_data['email']}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"الدور: {'مدير' if user_data['is_admin'] else 'مستخدم'}", size=14),
                        ft.Text(f"تاريخ الإنشاء: {user_data['created_at']}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.EDIT,
                                tooltip="تعديل",
                                icon_size=18,
                                on_click=lambda e, u=user_data: edit_user(u)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, u=user_data: delete_user(u)
                            ),
                            ft.IconButton(
                                icon=ft.icons.ADMIN_PANEL_SETTINGS,
                                tooltip="صلاحيات",
                                icon_size=18,
                                on_click=lambda e, u=user_data: manage_user_permissions(u)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            user_cards.append(user_card)
        
        users_list_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("قائمة المستخدمين", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.ElevatedButton(
                        text="➕ إضافة مستخدم",
                        style=button_style,
                        height=40,
                        on_click=lambda e: show_add_user_page()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                ft.Column(user_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/users_list",
            controls=[
                ft.Container(
                    content=users_list_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إضافة مستخدم
    def show_add_user_page():
        username_field = ft.TextField(
            label="👤 اسم المستخدم",
            hint_text="اختر اسم مستخدم",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        email_field = ft.TextField(
            label="📧 البريد الإلكتروني",
            hint_text="أدخل البريد الإلكتروني",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        password_field = ft.TextField(
            label="🔒 كلمة المرور",
            password=True,
            hint_text="اختر كلمة مرور قوية",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        confirm_password_field = ft.TextField(
            label="✅ تأكيد كلمة المرور",
            password=True,
            hint_text="أعد إدخال كلمة المرور",
            width=300,
            border_radius=8,
            border_color=colors["primary"]
        )
        
        is_admin_field = ft.Checkbox(
            label="منح صلاحيات المدير",
            value=False,
        )
        
        def add_user():
            if password_field.value != confirm_password_field.value:
                show_snackbar("كلمات المرور غير متطابقة", colors["error"])
                return
            
            if len(password_field.value) < 8:
                show_snackbar("كلمة المرور يجب أن تكون على الأقل 8 أحرف", colors["error"])
                return
            
            # التحقق من قوة كلمة المرور
            if not re.search(r'[A-Z]', password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[a-z]', password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على حرف صغير واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[0-9]', password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على رقم واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[^A-Za-z0-9]', password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على رمز خاص واحد على الأقل", colors["error"])
                return
            
            try:
                hashed_password = hash_password(password_field.value)
                salt = hashed_password.split('$')[0]
                
                db.execute_query(
                    "INSERT INTO users (username, email, password, salt, is_admin) VALUES (?, ?, ?, ?, ?)",
                    (username_field.value, email_field.value, hashed_password, salt, 1 if is_admin_field.value else 0),
                    commit=True
                )
                
                # تسجيل النشاط
                db.log_activity(
                    session_manager.current_user["id"],
                    "add_user",
                    details=f"إضافة مستخدم: {username_field.value}"
                )
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إضافة مستخدم",
                    f"تم إضافة مستخدم جديد: {username_field.value}",
                    "success"
                )
                
                show_snackbar("تم إنشاء المستخدم بنجاح", colors["primary"])
                show_users_list()
            except sqlite3.IntegrityError:
                show_snackbar("البريد الإلكتروني أو اسم المستخدم موجود مسبقاً", colors["error"])
        
        add_user_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إضافة مستخدم جديد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                username_field,
                email_field,
                password_field,
                confirm_password_field,
                is_admin_field,
                ft.ElevatedButton(
                    text="✨ إضافة المستخدم",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: add_user()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_users_list()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/add_user",
            controls=[
                ft.Container(
                    content=add_user_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # تعديل مستخدم
    def edit_user(user_data):
        username_field = ft.TextField(
            label="👤 اسم المستخدم",
            value=user_data["username"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        email_field = ft.TextField(
            label="📧 البريد الإلكتروني",
            value=user_data["email"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        is_admin_field = ft.Checkbox(
            label="منح صلاحيات المدير",
            value=bool(user_data["is_admin"]),
        )
        
        def save_changes():
            try:
                db.execute_query(
                    "UPDATE users SET username=?, email=?, is_admin=? WHERE id=?",
                    (username_field.value, email_field.value, 1 if is_admin_field.value else 0, user_data["id"]),
                    commit=True
                )
                
                # تسجيل النشاط
                db.log_activity(
                    session_manager.current_user["id"],
                    "edit_user",
                    "users",
                    user_data["id"],
                    details=f"تعديل مستخدم: {username_field.value}"
                )
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "تعديل مستخدم",
                    f"تم تعديل بيانات المستخدم: {username_field.value}",
                    "info"
                )
                
                show_snackbar("تم تحديث بيانات المستخدم بنجاح", colors["primary"])
                show_users_list()
            except sqlite3.IntegrityError:
                show_snackbar("البريد الإلكتروني أو اسم المستخدم موجود مسبقاً", colors["error"])
        
        def reset_password():
            def confirm_reset():
                # إنشاء كلمة مرور عشوائية
                new_password = secrets.token_urlsafe(10)
                hashed_password = hash_password(new_password)
                salt = hashed_password.split('$')[0]
                
                db.execute_query(
                    "UPDATE users SET password=?, salt=? WHERE id=?",
                    (hashed_password, salt, user_data["id"]),
                    commit=True
                )
                
                # تسجيل النشاط
                db.log_activity(
                    session_manager.current_user["id"],
                    "reset_password",
                    "users",
                    user_data["id"],
                    details=f"إعادة تعيين كلمة مرور المستخدم: {username_field.value}"
                )
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إعادة تعيين كلمة المرور",
                    f"تم إعادة تعيين كلمة مرور المستخدم: {username_field.value}",
                    "warning"
                )
                
                show_snackbar(f"تم إعادة تعيين كلمة المرور بنجاح. كلمة المرور الجديدة: {new_password}", colors["warning"])
                page.close(dialog)
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد إعادة تعيين كلمة المرور"),
                content=ft.Text(f"هل أنت متأكد من إعادة تعيين كلمة مرور المستخدم: {username_field.value}؟"),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="إعادة تعيين", on_click=lambda e: confirm_reset()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        edit_user_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تعديل بيانات المستخدم", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                username_field,
                email_field,
                is_admin_field,
                ft.ElevatedButton(
                    text="🔑 إعادة تعيين كلمة المرور",
                    style=secondary_button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: reset_password()
                ),
                ft.ElevatedButton(
                    text="💾 حفظ التغييرات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_changes()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_users_list()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/edit_user",
            controls=[
                ft.Container(
                    content=edit_user_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # حذف مستخدم
    def delete_user(user_data):
        def confirm_delete():
            # حذف صورة الملف الشخصي
            if user_data["profile_image"]:
                image_manager.delete_image(user_data["profile_image"])
            
            # حذف السجل من قاعدة البيانات
            db.execute_query(
                "DELETE FROM users WHERE id=?",
                (user_data["id"],),
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "delete_user",
                "users",
                user_data["id"],
                details=f"حذف مستخدم: {user_data['username']}"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "حذف مستخدم",
                f"تم حذف المستخدم: {user_data['username']}",
                "warning"
            )
            
            show_snackbar("تم حذف المستخدم بنجاح", colors["warning"])
            show_users_list()
        
        dialog = ft.AlertDialog(
            title=ft.Text("تأكيد الحذف"),
            content=ft.Text(f"هل أنت متأكد من حذف المستخدم: {user_data['username']}؟"),
            actions=[
                ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                ft.TextButton(text="حذف", on_click=lambda e: [confirm_delete(), page.close(dialog)]),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        page.dialog = dialog
        dialog.open = True
        page.update()
    
    # إدارة صلاحيات المستخدم
    def manage_user_permissions(user_data):
        # الحصول على الصلاحيات الحالية
        current_permissions = db.get_user_permissions(user_data["id"])
        current_permissions_set = set((p["resource"], p["action"]) for p in current_permissions)
        
        # قائمة الموارد والإجراءات
        resources = [
            "martyrs", "wounded", "prisoners", "users", "reports", "settings", "backups"
        ]
        
        actions = [
            "create", "read", "update", "delete", "admin"
        ]
        
        # إنشاء مربعات الاختيار للصلاحيات
        permission_checkboxes = []
        
        for resource in resources:
            resource_checkboxes = []
            
            for action in actions:
                is_checked = (resource, action) in current_permissions_set
                
                checkbox = ft.Checkbox(
                    label=f"{resource}.{action}",
                    value=is_checked,
                    on_change=lambda e, r=resource, a=action: toggle_permission(r, a, e.control.value)
                )
                
                resource_checkboxes.append(checkbox)
            
            permission_checkboxes.append(ft.Column(resource_checkboxes))
        
        def toggle_permission(resource, action, granted):
            if granted:
                # إضافة الصلاحية
                db.execute_query(
                    "INSERT INTO permissions (user_id, resource, action, granted, granted_by) VALUES (?, ?, ?, 1, ?)",
                    (user_data["id"], resource, action, session_manager.current_user["id"]),
                    commit=True
                )
            else:
                # إزالة الصلاحية
                db.execute_query(
                    "DELETE FROM permissions WHERE user_id=? AND resource=? AND action=?",
                    (user_data["id"], resource, action),
                    commit=True
                )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "update_permission",
                "permissions",
                details=f"تحديث صلاحية المستخدم {user_data['username']}: {resource}.{action} = {granted}"
            )
        
        def save_permissions():
            # إضافة إشعار
            notification_manager.add_notification(
                "تحديث الصلاحيات",
                f"تم تحديث صلاحيات المستخدم: {user_data['username']}",
                "info"
            )
            
            show_snackbar("تم تحديث الصلاحيات بنجاح", colors["primary"])
            page.close(dialog)
        
        permissions_content = ft.Column(
            controls=[
                ft.Text(f"صلاحيات المستخدم: {user_data['username']}", size=18, weight=ft.FontWeight.BOLD),
                ft.Divider(),
                ft.Row(permission_checkboxes, spacing=20),
                ft.Divider(),
                ft.ElevatedButton(
                    text="💾 حفظ الصلاحيات",
                    style=button_style,
                    width=200,
                    height=40,
                    on_click=lambda e: save_permissions()
                ),
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        dialog = ft.AlertDialog(
            title=ft.Text("إدارة الصلاحيات"),
            content=permissions_content,
            actions=[
                ft.TextButton(text="إغلاق", on_click=lambda e: page.close(dialog)),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        
        page.dialog = dialog
        dialog.open = True
        page.update()
    
    # صفحة الإعدادات
    def show_settings_page():
        # إنشاء علامات تبويب للإعدادات
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(
                    text="الحساب",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات الحساب", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="👤 تغيير المعلومات الشخصية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_personal_info_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔑 تغيير كلمة المرور",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_password_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔐 المصادقة الثنائية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_2fa_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📱 إدارة الجلسات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_sessions_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="التطبيق",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات التطبيق", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="🌐 اللغة",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_language_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🎨 المظهر",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_theme_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔤 الخط",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_font_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🎨 الألوان",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_color_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📐 التخطيط",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_layout_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="البيانات",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات البيانات", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="💾 النسخ الاحتياطي",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_backup_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📤 تصدير البيانات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_export_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📥 استيراد البيانات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_import_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🗜️ ضغط قاعدة البيانات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_database_optimization_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📊 إحصائيات التخزين",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_storage_statistics_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="الأمان",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات الأمان", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="🔐 المصادقة الثنائية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_2fa_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔒 قفل التطبيق",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_app_lock_settings()
                                ),
                                ft.ElevatedButton(
                                    text="👥 الصلاحيات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_permissions_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔐 تشفير البيانات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_encryption_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📝 سجل النشاطات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_activity_log_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="التخصيص",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات التخصيص", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="👁️ إظهار/إخفاء الحقول",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_field_visibility_settings()
                                ),
                                ft.ElevatedButton(
                                    text="➕ حقول مخصصة",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_custom_fields_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📂 أقسام مخصصة",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_custom_sections_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔄 ترتيب العرض",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_display_order_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📋 القوالب",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_templates_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="الإشعارات",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("إعدادات الإشعارات", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="🔔 إشعارات الأقسام",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_section_notifications_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔊 التنبيهات الصوتية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_sound_notifications_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📧 إشعارات البريد",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_email_notifications_settings()
                                ),
                                ft.ElevatedButton(
                                    text="⚠️ تنبيهات الأحداث",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_event_alerts_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
            ],
            expand=1,
        )
        
        settings_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("الإعدادات", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_admin_dashboard()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                tabs,
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/settings",
            controls=[
                ft.Container(
                    content=settings_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات المعلومات الشخصية
    def show_personal_info_settings():
        # الحصول على بيانات المستخدم الحالي
        user_data = db.execute_query(
            "SELECT * FROM users WHERE id=?",
            (session_manager.current_user["id"],),
            fetch=True
        )
        
        if not user_data:
            show_snackbar("لم يتم العثور على بيانات المستخدم", colors["error"])
            return
        
        user_data = dict(user_data)
        
        username_field = ft.TextField(
            label="👤 اسم المستخدم",
            value=user_data["username"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        email_field = ft.TextField(
            label="📧 البريد الإلكتروني",
            value=user_data["email"],
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        image_field = ft.FilePicker(
            on_result=lambda e: handle_image_upload(e)
        )
        
        image_preview = ft.Image(
            src=user_data["profile_image"] or "",
            width=100,
            height=100,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def handle_image_upload(e):
            if e.files:
                # قراءة الصورة الجديدة
                with open(e.files[0].path, 'rb') as f:
                    image_data = f.read()
                
                # حفظ الصورة الجديدة
                new_image_path = image_manager.save_image(image_data, "profile")
                
                if new_image_path:
                    # حذف الصورة القديمة
                    if user_data["profile_image"]:
                        image_manager.delete_image(user_data["profile_image"])
                    
                    # عرض الصورة الجديدة
                    image_preview.src = new_image_path
                    page.update()
                    
                    # تحديث مسار الصورة
                    user_data["profile_image"] = new_image_path
        
        def save_changes():
            try:
                db.execute_query(
                    "UPDATE users SET username=?, email=?, profile_image=? WHERE id=?",
                    (username_field.value, email_field.value, user_data["profile_image"], session_manager.current_user["id"]),
                    commit=True
                )
                
                # تحديث بيانات الجلسة
                session_manager.current_user["username"] = username_field.value
                session_manager.current_user["email"] = email_field.value
                session_manager.current_user["profile_image"] = user_data["profile_image"]
                
                # تسجيل النشاط
                db.log_activity(
                    session_manager.current_user["id"],
                    "update_personal_info",
                    details="تحديث المعلومات الشخصية"
                )
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "تحديث المعلومات الشخصية",
                    "تم تحديث المعلومات الشخصية بنجاح",
                    "success"
                )
                
                show_snackbar("تم تحديث المعلومات الشخصية بنجاح", colors["primary"])
                show_settings_page()
            except sqlite3.IntegrityError:
                show_snackbar("البريد الإلكتروني أو اسم المستخدم موجود مسبقاً", colors["error"])
        
        personal_info_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👤", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("المعلومات الشخصية", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                username_field,
                email_field,
                ft.Container(
                    content=image_preview,
                    margin=ft.margin.only(bottom=10)
                ),
                ft.ElevatedButton(
                    text="📷 تغيير الصورة الشخصية",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: image_field.pick_files(allow_multiple=False, allowed_extensions=["jpg", "jpeg", "png"])
                ),
                ft.ElevatedButton(
                    text="💾 حفظ التغييرات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_changes()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/personal_info_settings",
            controls=[
                ft.Container(
                    content=personal_info_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات كلمة المرور
    def show_password_settings():
        current_password_field = ft.TextField(
            label="🔒 كلمة المرور الحالية",
            password=True,
            hint_text="أدخل كلمة المرور الحالية",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        new_password_field = ft.TextField(
            label="🔑 كلمة المرور الجديدة",
            password=True,
            hint_text="أدخل كلمة المرور الجديدة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        confirm_password_field = ft.TextField(
            label="✅ تأكيد كلمة المرور الجديدة",
            password=True,
            hint_text="أعد إدخال كلمة المرور الجديدة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        def change_password():
            # التحقق من كلمة المرور الحالية
            user_data = db.execute_query(
                "SELECT password FROM users WHERE id=?",
                (session_manager.current_user["id"],),
                fetch=True
            )
            
            if not user_data or not verify_password(user_data[0], current_password_field.value):
                show_snackbar("كلمة المرور الحالية غير صحيحة", colors["error"])
                return
            
            if new_password_field.value != confirm_password_field.value:
                show_snackbar("كلمات المرور الجديدة غير متطابقة", colors["error"])
                return
            
            if len(new_password_field.value) < 8:
                show_snackbar("كلمة المرور يجب أن تكون على الأقل 8 أحرف", colors["error"])
                return
            
            # التحقق من قوة كلمة المرور
            if not re.search(r'[A-Z]', new_password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على حرف كبير واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[a-z]', new_password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على حرف صغير واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[0-9]', new_password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على رقم واحد على الأقل", colors["error"])
                return
            
            if not re.search(r'[^A-Za-z0-9]', new_password_field.value):
                show_snackbar("كلمة المرور يجب أن تحتوي على رمز خاص واحد على الأقل", colors["error"])
                return
            
            # تحديث كلمة المرور
            hashed_password = hash_password(new_password_field.value)
            salt = hashed_password.split('$')[0]
            
            db.execute_query(
                "UPDATE users SET password=?, salt=? WHERE id=?",
                (hashed_password, salt, session_manager.current_user["id"]),
                commit=True
            )
            
            # تسجيل النشاط
            db.log_activity(
                session_manager.current_user["id"],
                "change_password",
                details="تغيير كلمة المرور"
            )
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تغيير كلمة المرور",
                "تم تغيير كلمة المرور بنجاح",
                "success"
            )
            
            show_snackbar("تم تغيير كلمة المرور بنجاح", colors["primary"])
            show_settings_page()
        
        password_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔑", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تغيير كلمة المرور", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                current_password_field,
                new_password_field,
                confirm_password_field,
                ft.ElevatedButton(
                    text="🔄 تغيير كلمة المرور",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: change_password()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/password_settings",
            controls=[
                ft.Container(
                    content=password_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات المصادقة الثنائية
    def show_2fa_settings():
        # الحصول على إعدادات المصادقة الثنائية الحالية
        two_factor_enabled = session_manager.current_user["two_factor_secret"] is not None
        
        if two_factor_enabled:
            content = ft.Column(
                controls=[
                    ft.Container(
                        content=ft.Text("🔐", size=60),
                        margin=ft.margin.only(bottom=15)
                    ),
                    ft.Text("المصادقة الثنائية مفعلة", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.Text("المصادقة الثنائية مفعلة لحسابك. هذا يوفر طبقة إضافية من الأمان.", size=14),
                    ft.ElevatedButton(
                        text="🔓 تعطيل المصادقة الثنائية",
                        style=secondary_button_style,
                        width=300,
                        height=40,
                        on_click=lambda e: disable_2fa()
                    ),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_settings_page()
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=12
            )
        else:
            content = ft.Column(
                controls=[
                    ft.Container(
                        content=ft.Text("🔐", size=60),
                        margin=ft.margin.only(bottom=15)
                    ),
                    ft.Text("تفعيل المصادقة الثنائية", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.Text("المصادقة الثنائية توفر طبقة إضافية من الأمان لحسابك.", size=14),
                    ft.ElevatedButton(
                        text="🔐 تفعيل المصادقة الثنائية",
                        style=button_style,
                        width=300,
                        height=40,
                        on_click=lambda e: enable_2fa()
                    ),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_settings_page()
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=12
            )
        
        def enable_2fa():
            # إنشاء سر للمصادقة الثنائية
            secret = two_factor_auth_manager.generate_secret()
            
            # إنشاء رمز QR
            qr_path = two_factor_auth_manager.generate_qr_code(session_manager.current_user["email"], secret)
            
            # عرض صفحة تفعيل المصادقة الثنائية
            show_2fa_enable_page(secret, qr_path)
        
        def disable_2fa():
            def confirm_disable():
                # تعطيل المصادقة الثنائية
                two_factor_auth_manager.disable_2fa(session_manager.current_user["id"])
                
                # تحديث بيانات الجلسة
                session_manager.current_user["two_factor_secret"] = None
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "تعطيل المصادقة الثنائية",
                    "تم تعطيل المصادقة الثنائية بنجاح",
                    "warning"
                )
                
                show_snackbar("تم تعطيل المصادقة الثنائية بنجاح", colors["warning"])
                page.close(dialog)
                show_2fa_settings()
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد تعطيل المصادقة الثنائية"),
                content=ft.Text("هل أنت متأكد من تعطيل المصادقة الثنائية؟ هذا سيقلل من أمان حسابك."),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="تعطيل", on_click=lambda e: confirm_disable()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        view = ft.View(
            "/2fa_settings",
            controls=[
                ft.Container(
                    content=content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة تفعيل المصادقة الثنائية
    def show_2fa_enable_page(secret, qr_path):
        code_field = ft.TextField(
            label="🔑 رمز التحقق",
            hint_text="أدخل رمز التحقق من تطبيق المصادقة",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        qr_image = ft.Image(
            src=qr_path,
            width=200,
            height=200,
            fit=ft.ImageFit.CONTAIN,
            border_radius=8,
        )
        
        def verify_code():
            if two_factor_auth_manager.verify_code(secret, code_field.value):
                # تفعيل المصادقة الثنائية
                two_factor_auth_manager.enable_2fa(session_manager.current_user["id"], secret)
                
                # تحديث بيانات الجلسة
                session_manager.current_user["two_factor_secret"] = secret
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "تفعيل المصادقة الثنائية",
                    "تم تفعيل المصادقة الثنائية بنجاح",
                    "success"
                )
                
                show_snackbar("تم تفعيل المصادقة الثنائية بنجاح", colors["primary"])
                show_2fa_settings()
            else:
                show_snackbar("رمز التحقق غير صحيح", colors["error"])
        
        enable_2fa_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تفعيل المصادقة الثنائية", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("1. قم بتحميل تطبيق المصادقة مثل Google Authenticator أو Authy", size=14),
                ft.Text("2. امسح رمز QR ضوئياً باستخدام التطبيق", size=14),
                ft.Text("3. أدخل الرمز الذي يظهر في التطبيق", size=14),
                qr_image,
                code_field,
                ft.ElevatedButton(
                    text="✅ تحقق",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: verify_code()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_2fa_settings()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/2fa_enable",
            controls=[
                ft.Container(
                    content=enable_2fa_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الجلسات
    def show_sessions_settings():
        # الحصول على جلسات المستخدم
        sessions = db.get_user_sessions(session_manager.current_user["id"])
        
        session_cards = []
        for session in sessions:
            session_data = dict(session)
            
            # تحديد إذا كانت الجلسة الحالية
            is_current = session_data["session_token"] == session_manager.session_token
            
            # إنشاء بطاقة الجلسة
            session_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(
                                f"الجهاز: {session_data['device_info'] or 'غير معروف'}", 
                                size=16, 
                                weight=ft.FontWeight.BOLD
                            ),
                            ft.Container(
                                content=ft.Text("الجلسة الحالية", size=12),
                                bgcolor=colors["success"],
                                padding=ft.padding.symmetric(horizontal=6, vertical=2),
                                border_radius=4,
                                visible=is_current
                            )
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"تسجيل الدخول: {session_data['login_time']}", size=14),
                        ft.Text(f"آخر نشاط: {session_data['last_activity']}", size=14),
                        ft.Text(f"عنوان IP: {session_data['ip_address'] or 'غير معروف'}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="إنهاء الجلسة",
                                icon_size=18,
                                on_click=lambda e, s=session_data: terminate_session(s),
                                disabled=is_current
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            session_cards.append(session_card)
        
        sessions_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📱", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إدارة الجلسات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("يمكنك إدارة جميع الجلسات النشطة لحسابك من هنا.", size=14),
                ft.Divider(),
                ft.Column(session_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.ElevatedButton(
                    text="🔄 إنهاء جميع الجلسات الأخرى",
                    style=secondary_button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: terminate_all_other_sessions()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        def terminate_session(session_data):
            def confirm_terminate():
                # إنهاء الجلسة
                db.terminate_session(session_data["id"])
                
                # إذا كانت الجلسة الحالية، تسجيل الخروج
                if session_data["session_token"] == session_manager.session_token:
                    session_manager.logout()
                    show_login_page()
                else:
                    # إعادة تحميل الصفحة
                    show_sessions_settings()
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إنهاء الجلسة",
                    "تم إنهاء الجلسة بنجاح",
                    "warning"
                )
                
                show_snackbar("تم إنهاء الجلسة بنجاح", colors["warning"])
                page.close(dialog)
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد إنهاء الجلسة"),
                content=ft.Text("هل أنت متأكد من إنهاء هذه الجلسة؟"),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="إنهاء", on_click=lambda e: confirm_terminate()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        def terminate_all_other_sessions():
            def confirm_terminate():
                # إنهاء جميع الجلسات الأخرى
                for session in sessions:
                    session_data = dict(session)
                    if session_data["session_token"] != session_manager.session_token:
                        db.terminate_session(session_data["id"])
                
                # إعادة تحميل الصفحة
                show_sessions_settings()
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إنهاء الجلسات",
                    "تم إنهاء جميع الجلسات الأخرى بنجاح",
                    "warning"
                )
                
                show_snackbar("تم إنهاء جميع الجلسات الأخرى بنجاح", colors["warning"])
                page.close(dialog)
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد إنهاء جميع الجلسات الأخرى"),
                content=ft.Text("هل أنت متأكد من إنهاء جميع الجلسات الأخرى؟"),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="إنهاء الكل", on_click=lambda e: confirm_terminate()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        view = ft.View(
            "/sessions_settings",
            controls=[
                ft.Container(
                    content=sessions_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات اللغة
    def show_language_settings():
        current_language = settings_manager.get("language", "ar")
        
        language_options = [
            ft.dropdown.Option("ar", "العربية"),
            ft.dropdown.Option("en", "English"),
        ]
        
        language_dropdown = ft.Dropdown(
            label="🌐 اللغة",
            value=current_language,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=language_options,
        )
        
        def save_language():
            settings_manager.set("language", language_dropdown.value)
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تغيير اللغة",
                "تم تغيير لغة التطبيق بنجاح",
                "success"
            )
            
            show_snackbar("تم تغيير اللغة بنجاح", colors["primary"])
            show_settings_page()
        
        language_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🌐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات اللغة", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر اللغة المفضلة للتطبيق", size=14),
                language_dropdown,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_language()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/language_settings",
            controls=[
                ft.Container(
                    content=language_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات المظهر
    def show_theme_settings():
        current_theme = settings_manager.get("theme", "light")
        
        theme_options = [
            ft.dropdown.Option("light", "فاتح"),
            ft.dropdown.Option("dark", "داكن"),
        ]
        
        theme_dropdown = ft.Dropdown(
            label="🎨 المظهر",
            value=current_theme,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=theme_options,
        )
        
        def save_theme():
            settings_manager.set("theme", theme_dropdown.value)
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تغيير المظهر",
                "تم تغيير مظهر التطبيق بنجاح",
                "success"
            )
            
            show_snackbar("تم تغيير المظهر بنجاح", colors["primary"])
            show_settings_page()
        
        theme_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🎨", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات المظهر", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر المظهر المفضل للتطبيق", size=14),
                theme_dropdown,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_theme()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/theme_settings",
            controls=[
                ft.Container(
                    content=theme_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الخط
    def show_font_settings():
        current_font = settings_manager.get("font_family", "Cairo")
        current_size = settings_manager.get("font_size", "14")
        
        font_options = [
            ft.dropdown.Option("Cairo", "Cairo"),
            ft.dropdown.Option("Tajawal", "Tajawal"),
            ft.dropdown.Option("Amiri", "Amiri"),
        ]
        
        font_dropdown = ft.Dropdown(
            label="🔤 نوع الخط",
            value=current_font,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=font_options,
        )
        
        size_slider = ft.Slider(
            label="حجم الخط",
            value=float(current_size),
            min=10,
            max=24,
            divisions=14,
            width=300,
        )
        
        def save_font():
            settings_manager.set("font_family", font_dropdown.value)
            settings_manager.set("font_size", str(int(size_slider.value)))
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تغيير الخط",
                "تم تغيير خط التطبيق بنجاح",
                "success"
            )
            
            show_snackbar("تم تغيير الخط بنجاح", colors["primary"])
            show_settings_page()
        
        font_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔤", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات الخط", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر نوع وحجم الخط المفضل للتطبيق", size=14),
                font_dropdown,
                size_slider,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_font()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/font_settings",
            controls=[
                ft.Container(
                    content=font_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الألوان
    def show_color_settings():
        current_color = settings_manager.get("primary_color", "#1a237e")
        
        color_field = ft.TextField(
            label="🎨 اللون الرئيسي",
            value=current_color,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        color_preview = ft.Container(
            width=100,
            height=100,
            bgcolor=current_color,
            border_radius=8,
        )
        
        def update_color_preview(e):
            color_preview.bgcolor = color_field.value
            page.update()
        
        def save_color():
            settings_manager.set("primary_color", color_field.value)
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تغيير اللون",
                "تم تغيير لون التطبيق بنجاح",
                "success"
            )
            
            show_snackbar("تم تغيير اللون بنجاح", colors["primary"])
            show_settings_page()
        
        color_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🎨", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات الألوان", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر اللون الرئيسي للتطبيق", size=14),
                color_field,
                color_preview,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_color()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/color_settings",
            controls=[
                ft.Container(
                    content=color_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات التخطيط
    def show_layout_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات التخطيط
        layout_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات التخطيط", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات التخطيط قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/layout_settings",
            controls=[
                ft.Container(
                    content=layout_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات النسخ الاحتياطي
    def show_backup_settings():
        auto_backup = settings_manager.get("auto_backup", "false") == "true"
        backup_interval = settings_manager.get("backup_interval", "7")
        backup_encryption = settings_manager.get("backup_encryption", "true") == "true"
        
        auto_backup_switch = ft.Switch(
            label="النسخ الاحتياطي التلقائي",
            value=auto_backup,
        )
        
        interval_options = [
            ft.dropdown.Option("1", "يومياً"),
            ft.dropdown.Option("7", "أسبوعياً"),
            ft.dropdown.Option("30", "شهرياً"),
        ]
        
        interval_dropdown = ft.Dropdown(
            label="فترة النسخ الاحتياطي",
            value=backup_interval,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=interval_options,
        )
        
        encryption_switch = ft.Switch(
            label="تشفير النسخ الاحتياطية",
            value=backup_encryption,
        )
        
        # الحصول على قائمة النسخ الاحتياطية
        backups = backup_manager.get_backups()
        
        backup_cards = []
        for backup in backups:
            backup_data = dict(backup)
            
            # تنسيق الحجم
            size_mb = backup_data["size"] / (1024 * 1024)
            size_str = f"{size_mb:.2f} ميجابايت"
            
            # إنشاء بطاقة النسخة الاحتياطية
            backup_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(
                                f"النسخة: {backup_data['description'] or 'غير محدد'}", 
                                size=16, 
                                weight=ft.FontWeight.BOLD
                            ),
                            ft.Text(f"الحجم: {size_str}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"التاريخ: {backup_data['created_at']}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.DOWNLOAD,
                                tooltip="تحميل",
                                icon_size=18,
                                on_click=lambda e, b=backup_data: download_backup(b)
                            ),
                            ft.IconButton(
                                icon=ft.icons.RESTORE,
                                tooltip="استعادة",
                                icon_size=18,
                                on_click=lambda e, b=backup_data: restore_backup(b)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, b=backup_data: delete_backup(b)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            backup_cards.append(backup_card)
        
        def save_settings():
            settings_manager.set("auto_backup", "true" if auto_backup_switch.value else "false")
            settings_manager.set("backup_interval", interval_dropdown.value)
            settings_manager.set("backup_encryption", "true" if encryption_switch.value else "false")
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تحديث إعدادات النسخ الاحتياطي",
                "تم تحديث إعدادات النسخ الاحتياطي بنجاح",
                "success"
            )
            
            show_snackbar("تم تحديث إعدادات النسخ الاحتياطي بنجاح", colors["primary"])
            show_settings_page()
        
        def create_backup():
            backup_manager.create_backup("نسخة احتياطية يدوية")
            show_backup_settings()
        
        def download_backup(backup_data):
            # في تطبيق حقيقي، سيتم تنزيل الملف
            show_snackbar(f"جاري تحميل النسخة الاحتياطية: {backup_data['description']}", colors["primary"])
        
        def restore_backup(backup_data):
            def confirm_restore():
                if backup_manager.restore_backup(backup_data["id"]):
                    show_snackbar("تم استعادة النسخة الاحتياطية بنجاح", colors["primary"])
                    show_backup_settings()
                else:
                    show_snackbar("فشل استعادة النسخة الاحتياطية", colors["error"])
                page.close(dialog)
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد استعادة النسخة الاحتياطية"),
                content=ft.Text("هل أنت متأكد من استعادة هذه النسخة الاحتياطية؟ سيتم استبدال جميع البيانات الحالية."),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="استعادة", on_click=lambda e: confirm_restore()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        def delete_backup(backup_data):
            def confirm_delete():
                if backup_manager.delete_backup(backup_data["id"]):
                    show_snackbar("تم حذف النسخة الاحتياطية بنجاح", colors["warning"])
                    show_backup_settings()
                else:
                    show_snackbar("فشل حذف النسخة الاحتياطية", colors["error"])
                page.close(dialog)
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد حذف النسخة الاحتياطية"),
                content=ft.Text("هل أنت متأكد من حذف هذه النسخة الاحتياطية؟ لا يمكن التراجع عن هذا الإجراء."),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="حذف", on_click=lambda e: confirm_delete()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        backup_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("💾", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات النسخ الاحتياطي", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Divider(),
                ft.Text("الإعدادات", size=16, weight=ft.FontWeight.BOLD),
                auto_backup_switch,
                interval_dropdown,
                encryption_switch,
                ft.ElevatedButton(
                    text="💾 حفظ الإعدادات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_settings()
                ),
                ft.Divider(),
                ft.Row([
                    ft.Text("النسخ الاحتياطية", size=16, weight=ft.FontWeight.BOLD),
                    ft.ElevatedButton(
                        text="➕ إنشاء نسخة احتياطية",
                        style=button_style,
                        height=40,
                        on_click=lambda e: create_backup()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Column(backup_cards, scroll=ft.ScrollMode.AUTO, height=300),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/backup_settings",
            controls=[
                ft.Container(
                    content=backup_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات تصدير البيانات
    def show_export_settings():
        export_format = ft.Dropdown(
            label="📤 تنسيق التصدير",
            value="json",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("json", "JSON"),
                ft.dropdown.Option("csv", "CSV"),
                ft.dropdown.Option("excel", "Excel"),
            ],
        )
        
        export_type = ft.Dropdown(
            label="📂 نوع البيانات",
            value="all",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("all", "الكل"),
                ft.dropdown.Option("martyrs", "الشهداء"),
                ft.dropdown.Option("wounded", "الجرحى"),
                ft.dropdown.Option("prisoners", "الأسرى"),
            ],
        )
        
        include_images = ft.Switch(
            label="تضمين الصور",
            value=False,
        )
        
        def export_data():
            # في تطبيق حقيقي، سيتم تنفيذ تصدير البيانات حسب الخيارات المحددة
            format_type = export_format.value
            data_type = export_type.value
            include_imgs = include_images.value
            
            show_snackbar(f"جاري تصدير البيانات بتنسيق {format_type}", colors["primary"])
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تصدير البيانات",
                f"تم تصدير البيانات بنجاح بتنسيق {format_type}",
                "success"
            )
        
        export_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📤", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تصدير البيانات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر تنسيق ونوع البيانات التي تريد تصديرها", size=14),
                export_format,
                export_type,
                include_images,
                ft.ElevatedButton(
                    text="📤 تصدير",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: export_data()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/export_settings",
            controls=[
                ft.Container(
                    content=export_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات استيراد البيانات
    def show_import_settings():
        import_file = ft.FilePicker(
            on_result=lambda e: handle_file_upload(e)
        )
        
        def handle_file_upload(e):
            if e.files:
                # في تطبيق حقيقي، سيتم استيراد البيانات من الملف
                file_path = e.files[0].path
                show_snackbar(f"جاري استيراد البيانات من: {file_path}", colors["primary"])
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "استيراد البيانات",
                    "تم استيراد البيانات بنجاح",
                    "success"
                )
        
        import_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("استيراد البيانات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر ملف البيانات الذي تريد استيراده", size=14),
                ft.ElevatedButton(
                    text="📥 اختيار ملف",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda _: import_file.pick_files(allow_multiple=False)
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/import_settings",
            controls=[
                ft.Container(
                    content=import_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات تحسين قاعدة البيانات
    def show_database_optimization_settings():
        def optimize_database():
            db.optimize_database()
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تحسين قاعدة البيانات",
                "تم تحسين قاعدة البيانات بنجاح",
                "success"
            )
            
            show_snackbar("تم تحسين قاعدة البيانات بنجاح", colors["primary"])
        
        def cleanup_old_data():
            db.cleanup_old_data()
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تنظيف البيانات القديمة",
                "تم تنظيف البيانات القديمة بنجاح",
                "success"
            )
            
            show_snackbar("تم تنظيف البيانات القديمة بنجاح", colors["primary"])
        
        optimization_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🗜️", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تحسين قاعدة البيانات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("يمكنك تحسين قاعدة البيانات لتحسين الأداء", size=14),
                ft.ElevatedButton(
                    text="🗜️ ضغط قاعدة البيانات",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: optimize_database()
                ),
                ft.ElevatedButton(
                    text="🧹 تنظيف البيانات القديمة",
                    style=secondary_button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: cleanup_old_data()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/database_optimization_settings",
            controls=[
                ft.Container(
                    content=optimization_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات إحصائيات التخزين
    def show_storage_statistics_settings():
        # الحصول على إحصائيات التخزين
        db_size = os.path.getsize(db.db_path) / (1024 * 1024)  # بالـ ميجابايت
        
        # حساب عدد السجلات
        martyrs_count = db.execute_query("SELECT COUNT(*) FROM martyrs", fetch=True)[0]
        wounded_count = db.execute_query("SELECT COUNT(*) FROM wounded", fetch=True)[0]
        prisoners_count = db.execute_query("SELECT COUNT(*) FROM prisoners", fetch=True)[0]
        users_count = db.execute_query("SELECT COUNT(*) FROM users", fetch=True)[0]
        
        # حساب حجم الصور
        images_dir = "images"
        images_size = 0
        if os.path.exists(images_dir):
            for root, dirs, files in os.walk(images_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    images_size += os.path.getsize(file_path)
        
        images_size_mb = images_size / (1024 * 1024)  # بالـ ميجابايت
        
        statistics_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📊", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إحصائيات التخزين", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Divider(),
                ft.Text("قاعدة البيانات", size=16, weight=ft.FontWeight.BOLD),
                ft.Text(f"الحجم: {db_size:.2f} ميجابايت", size=14),
                ft.Text(f"الشهداء: {martyrs_count} سجل", size=14),
                ft.Text(f"الجرحى: {wounded_count} سجل", size=14),
                ft.Text(f"الأسرى: {prisoners_count} سجل", size=14),
                ft.Text(f"المستخدمين: {users_count} سجل", size=14),
                ft.Divider(),
                ft.Text("الصور", size=16, weight=ft.FontWeight.BOLD),
                ft.Text(f"الحجم: {images_size_mb:.2f} ميجابايت", size=14),
                ft.Divider(),
                ft.Text(f"إجمالي التخزين: {(db_size + images_size_mb):.2f} ميجابايت", size=16, weight=ft.FontWeight.BOLD),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/storage_statistics_settings",
            controls=[
                ft.Container(
                    content=statistics_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات قفل التطبيق
    def show_app_lock_settings():
        app_lock_enabled = settings_manager.get("app_lock", "false") == "true"
        
        app_lock_switch = ft.Switch(
            label="قفل التطبيق",
            value=app_lock_enabled,
        )
        
        pin_field = ft.TextField(
            label="🔒 رمز PIN",
            password=True,
            hint_text="أدخل رمز PIN",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            visible=app_lock_enabled,
        )
        
        confirm_pin_field = ft.TextField(
            label="✅ تأكيد رمز PIN",
            password=True,
            hint_text="أعد إدخال رمز PIN",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            visible=app_lock_enabled,
        )
        
        def toggle_app_lock(e):
            pin_field.visible = e.control.value
            confirm_pin_field.visible = e.control.value
            page.update()
        
        def save_settings():
            if app_lock_switch.value:
                if pin_field.value != confirm_pin_field.value:
                    show_snackbar("رموز PIN غير متطابقة", colors["error"])
                    return
                
                if len(pin_field.value) < 4:
                    show_snackbar("رمز PIN يجب أن يكون على الأقل 4 أرقام", colors["error"])
                    return
                
                # تعيين رمز PIN
                app_lock_manager.set_pin(pin_field.value)
            
            settings_manager.set("app_lock", "true" if app_lock_switch.value else "false")
            
            # إضافة إشعار
            notification_manager.add_notification(
                "قفل التطبيق",
                "تم تحديث إعدادات قفل التطبيق بنجاح",
                "success"
            )
            
            show_snackbar("تم تحديث إعدادات قفل التطبيق بنجاح", colors["primary"])
            show_settings_page()
        
        app_lock_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔒", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("قفل التطبيق", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("يمكنك قفل التطبيق باستخدام رمز PIN", size=14),
                app_lock_switch,
                pin_field,
                confirm_pin_field,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_settings()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        app_lock_switch.on_change = toggle_app_lock
        
        view = ft.View(
            "/app_lock_settings",
            controls=[
                ft.Container(
                    content=app_lock_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الصلاحيات
    def show_permissions_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات الصلاحيات
        permissions_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👥", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات الصلاحيات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات الصلاحيات قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/permissions_settings",
            controls=[
                ft.Container(
                    content=permissions_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات تشفير البيانات
    def show_encryption_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات تشفير البيانات
        encryption_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔐", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إعدادات تشفير البيانات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات تشفير البيانات قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/encryption_settings",
            controls=[
                ft.Container(
                    content=encryption_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات سجل النشاطات
    def show_activity_log_settings():
        # الحصول على سجل النشاطات
        activities = db.execute_query(
            "SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 50",
            fetch_all=True
        )
        
        activity_cards = []
        for activity in activities:
            activity_data = dict(activity)
            
            # إنشاء بطاقة النشاط
            activity_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(
                                f"الإجراء: {activity_data['action']}", 
                                size=16, 
                                weight=ft.FontWeight.BOLD
                            ),
                            ft.Text(f"التاريخ: {activity_data['created_at']}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"الجدول: {activity_data['table_name'] or 'غير محدد'}", size=14),
                        ft.Text(f"التفاصيل: {activity_data['details'] or 'غير محدد'}", size=14),
                        ft.Text(f"عنوان IP: {activity_data['ip_address'] or 'غير محدد'}", size=14),
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            activity_cards.append(activity_card)
        
        activity_log_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📝", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("سجل النشاطات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("آخر 50 نشاط في النظام", size=14),
                ft.Column(activity_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/activity_log_settings",
            controls=[
                ft.Container(
                    content=activity_log_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات إظهار/إخفاء الحقول
    def show_field_visibility_settings():
        show_age = settings_manager.get("show_age_field", "true") == "true"
        show_location = settings_manager.get("show_location_field", "true") == "true"
        show_date = settings_manager.get("show_date_field", "true") == "true"
        
        age_switch = ft.Switch(
            label="إظهار حقل العمر",
            value=show_age,
        )
        
        location_switch = ft.Switch(
            label="إظهار حقل الموقع",
            value=show_location,
        )
        
        date_switch = ft.Switch(
            label="إظهار حقل التاريخ",
            value=show_date,
        )
        
        def save_settings():
            settings_manager.set("show_age_field", "true" if age_switch.value else "false")
            settings_manager.set("show_location_field", "true" if location_switch.value else "false")
            settings_manager.set("show_date_field", "true" if date_switch.value else "false")
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تحديث إعدادات الحقول",
                "تم تحديث إعدادات إظهار/إخفاء الحقول بنجاح",
                "success"
            )
            
            show_snackbar("تم تحديث إعدادات إظهار/إخفاء الحقول بنجاح", colors["primary"])
            show_settings_page()
        
        field_visibility_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("👁️", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إظهار/إخفاء الحقول", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر الحقول التي تريد إظهارها أو إخفاءها", size=14),
                age_switch,
                location_switch,
                date_switch,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_settings()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/field_visibility_settings",
            controls=[
                ft.Container(
                    content=field_visibility_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الحقول المخصصة
    def show_custom_fields_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات الحقول المخصصة
        custom_fields_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("➕", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("حقول مخصصة", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات الحقول المخصصة قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/custom_fields_settings",
            controls=[
                ft.Container(
                    content=custom_fields_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات الأقسام المخصصة
    def show_custom_sections_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات الأقسام المخصصة
        custom_sections_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📂", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("أقسام مخصصة", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات الأقسام المخصصة قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/custom_sections_settings",
            controls=[
                ft.Container(
                    content=custom_sections_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات ترتيب العرض
    def show_display_order_settings():
        default_sort = settings_manager.get("default_sort", "date")
        
        sort_options = [
            ft.dropdown.Option("date", "حسب التاريخ"),
            ft.dropdown.Option("name", "حسب الاسم"),
            ft.dropdown.Option("location", "حسب الموقع"),
        ]
        
        sort_dropdown = ft.Dropdown(
            label="🔄 ترتيب العرض الافتراضي",
            value=default_sort,
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=sort_options,
        )
        
        def save_settings():
            settings_manager.set("default_sort", sort_dropdown.value)
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تحديث ترتيب العرض",
                "تم تحديث ترتيب العرض الافتراضي بنجاح",
                "success"
            )
            
            show_snackbar("تم تحديث ترتيب العرض الافتراضي بنجاح", colors["primary"])
            show_settings_page()
        
        display_order_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔄", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("ترتيب العرض", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر ترتيب العرض الافتراضي", size=14),
                sort_dropdown,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_settings()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/display_order_settings",
            controls=[
                ft.Container(
                    content=display_order_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات القوالب
    def show_templates_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات القوالب
        templates_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📋", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("القوالب", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات القوالب قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/templates_settings",
            controls=[
                ft.Container(
                    content=templates_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات إشعارات الأقسام
    def show_section_notifications_settings():
        notification_martyr = settings_manager.get("notification_new_martyr", "true") == "true"
        notification_wounded = settings_manager.get("notification_new_wounded", "true") == "true"
        notification_prisoner = settings_manager.get("notification_new_prisoner", "true") == "true"
        
        martyr_switch = ft.Switch(
            label="إشعارات الشهداء",
            value=notification_martyr,
        )
        
        wounded_switch = ft.Switch(
            label="إشعارات الجرحى",
            value=notification_wounded,
        )
        
        prisoner_switch = ft.Switch(
            label="إشعارات الأسرى",
            value=notification_prisoner,
        )
        
        def save_settings():
            settings_manager.set("notification_new_martyr", "true" if martyr_switch.value else "false")
            settings_manager.set("notification_new_wounded", "true" if wounded_switch.value else "false")
            settings_manager.set("notification_new_prisoner", "true" if prisoner_switch.value else "false")
            
            # إضافة إشعار
            notification_manager.add_notification(
                "تحديث إعدادات الإشعارات",
                "تم تحديث إعدادات إشعارات الأقسام بنجاح",
                "success"
            )
            
            show_snackbar("تم تحديث إعدادات إشعارات الأقسام بنجاح", colors["primary"])
            show_settings_page()
        
        section_notifications_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔔", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إشعارات الأقسام", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر الأقسام التي تريد تلقي إشعارات منها", size=14),
                martyr_switch,
                wounded_switch,
                prisoner_switch,
                ft.ElevatedButton(
                    text="💾 حفظ",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: save_settings()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/section_notifications_settings",
            controls=[
                ft.Container(
                    content=section_notifications_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات التنبيهات الصوتية
    def show_sound_notifications_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات التنبيهات الصوتية
        sound_notifications_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔊", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("التنبيهات الصوتية", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات التنبيهات الصوتية قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/sound_notifications_settings",
            controls=[
                ft.Container(
                    content=sound_notifications_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات إشعارات البريد
    def show_email_notifications_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات إشعارات البريد
        email_notifications_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📧", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إشعارات البريد", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات إشعارات البريد قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/email_notifications_settings",
            controls=[
                ft.Container(
                    content=email_notifications_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إعدادات تنبيهات الأحداث
    def show_event_alerts_settings():
        # هذه الوظيفة ستكون نائبة لإعدادات تنبيهات الأحداث
        event_alerts_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("⚠️", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("تنبيهات الأحداث", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("سيتم إضافة إعدادات تنبيهات الأحداث قريباً", size=14),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_settings_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/event_alerts_settings",
            controls=[
                ft.Container(
                    content=event_alerts_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة إعدادات حساب المستخدم
    def show_user_account_settings():
        # إنشاء علامات تبويب لإعدادات المستخدم
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(
                    text="المعلومات الشخصية",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("المعلومات الشخصية", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="👤 تغيير المعلومات الشخصية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_personal_info_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔑 تغيير كلمة المرور",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_password_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="الأمان",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("الأمان", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="🔐 المصادقة الثنائية",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_2fa_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔒 قفل التطبيق",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_app_lock_settings()
                                ),
                                ft.ElevatedButton(
                                    text="📱 إدارة الجلسات",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_sessions_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="التفضيلات",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("التفضيلات", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="🌐 اللغة",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_language_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🎨 المظهر",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_theme_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🔤 الخط",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_font_settings()
                                ),
                                ft.ElevatedButton(
                                    text="🎨 الألوان",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_color_settings()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
            ],
            expand=1,
        )
        
        user_account_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("إعدادات الحساب", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_user_dashboard()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                tabs,
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/user_account_settings",
            controls=[
                ft.Container(
                    content=user_account_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة البحث المتقدم
    def show_search_page():
        search_query = ft.TextField(
            label="🔍 البحث",
            hint_text="أدخل كلمة البحث",
            width=400,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        search_type = ft.Dropdown(
            label="📂 نوع البحث",
            value="all",
            width=400,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("all", "الكل"),
                ft.dropdown.Option("martyrs", "الشهداء"),
                ft.dropdown.Option("wounded", "الجرحى"),
                ft.dropdown.Option("prisoners", "الأسرى"),
            ],
        )
        
        # حقول الفلترة
        min_age_field = ft.TextField(
            label="🎂 العمر الأدنى",
            width=190,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        max_age_field = ft.TextField(
            label="🎂 العمر الأقصى",
            width=190,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_from_field = ft.TextField(
            label="📅 من تاريخ",
            width=190,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        date_to_field = ft.TextField(
            label="📅 إلى تاريخ",
            width=190,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        location_field = ft.TextField(
            label="📍 الموقع",
            width=400,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        medical_status_field = ft.Dropdown(
            label="🏥 الحالة الطبية",
            width=400,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("", "الكل"),
                ft.dropdown.Option("مستقر"),
                ft.dropdown.Option("حرج"),
                ft.dropdown.Option("تحسن"),
                ft.dropdown.Option("علاج"),
                ft.dropdown.Option("شفى"),
            ],
        )
        
        prison_field = ft.TextField(
            label="🏢 اسم السجن",
            width=400,
            border_radius=8,
            border_color=colors["primary"],
        )
        
        # نتائج البحث
        search_results = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            height=300,
        )
        
        def perform_search():
            query = search_query.value
            search_type_value = search_type.value
            
            filters = {}
            
            if min_age_field.value:
                filters["min_age"] = int(min_age_field.value)
            
            if max_age_field.value:
                filters["max_age"] = int(max_age_field.value)
            
            if date_from_field.value:
                filters["date_from"] = date_from_field.value
            
            if date_to_field.value:
                filters["date_to"] = date_to_field.value
            
            if location_field.value:
                filters["location"] = location_field.value
            
            if medical_status_field.value:
                filters["medical_status"] = medical_status_field.value
            
            if prison_field.value:
                filters["prison_name"] = prison_field.value
            
            results = []
            
            if search_type_value == "all" or search_type_value == "martyrs":
                martyrs_results = search_manager.search_martyrs(query, filters)
                for martyr in martyrs_results:
                    martyr_data = dict(martyr)
                    
                    # فك تشفير البيانات إذا كانت مشفرة
                    if martyr_data["encrypted_data"]:
                        try:
                            decrypted_data = decrypt_data(martyr_data["encrypted_data"])
                            decrypted_dict = json.loads(decrypted_data)
                            martyr_data.update(decrypted_dict)
                        except:
                            pass
                    
                    result_card = ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.Row([
                                    ft.Text(f"⭐ {martyr_data['name']}", size=16, weight=ft.FontWeight.BOLD),
                                    ft.Text(f"العمر: {martyr_data['age'] or 'غير محدد'}", size=14),
                                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                                ft.Text(f"التاريخ: {martyr_data['date_of_martyrdom'] or 'غير محدد'}", size=14),
                                ft.Text(f"المكان: {martyr_data['location'] or 'غير محدد'}", size=14),
                            ]),
                            padding=10,
                            width=500,
                        ),
                        elevation=2,
                        margin=ft.margin.only(bottom=10)
                    )
                    
                    results.append(result_card)
            
            if search_type_value == "all" or search_type_value == "wounded":
                wounded_results = search_manager.search_wounded(query, filters)
                for person in wounded_results:
                    person_data = dict(person)
                    
                    # فك تشفير البيانات إذا كانت مشفرة
                    if person_data["encrypted_data"]:
                        try:
                            decrypted_data = decrypt_data(person_data["encrypted_data"])
                            decrypted_dict = json.loads(decrypted_data)
                            person_data.update(decrypted_dict)
                        except:
                            pass
                    
                    result_card = ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.Row([
                                    ft.Text(f"🏥 {person_data['name']}", size=16, weight=ft.FontWeight.BOLD),
                                    ft.Text(f"العمر: {person_data['age'] or 'غير محدد'}", size=14),
                                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                                ft.Text(f"التاريخ: {person_data['injury_date'] or 'غير محدد'}", size=14),
                                ft.Text(f"المكان: {person_data['injury_location'] or 'غير محدد'}", size=14),
                                ft.Text(f"الحالة: {person_data['medical_status'] or 'غير محدد'}", size=14),
                            ]),
                            padding=10,
                            width=500,
                        ),
                        elevation=2,
                        margin=ft.margin.only(bottom=10)
                    )
                    
                    results.append(result_card)
            
            if search_type_value == "all" or search_type_value == "prisoners":
                prisoners_results = search_manager.search_prisoners(query, filters)
                for prisoner in prisoners_results:
                    prisoner_data = dict(prisoner)
                    
                    # فك تشفير البيانات إذا كانت مشفرة
                    if prisoner_data["encrypted_data"]:
                        try:
                            decrypted_data = decrypt_data(prisoner_data["encrypted_data"])
                            decrypted_dict = json.loads(decrypted_data)
                            prisoner_data.update(decrypted_dict)
                        except:
                            pass
                    
                    result_card = ft.Card(
                        content=ft.Container(
                            content=ft.Column([
                                ft.Row([
                                    ft.Text(f"🛡️ {prisoner_data['name']}", size=16, weight=ft.FontWeight.BOLD),
                                    ft.Text(f"العمر: {prisoner_data['age'] or 'غير محدد'}", size=14),
                                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                                ft.Text(f"التاريخ: {prisoner_data['arrest_date'] or 'غير محدد'}", size=14),
                                ft.Text(f"المكان: {prisoner_data['arrest_location'] or 'غير محدد'}", size=14),
                                ft.Text(f"السجن: {prisoner_data['prison_name'] or 'غير محدد'}", size=14),
                            ]),
                            padding=10,
                            width=500,
                        ),
                        elevation=2,
                        margin=ft.margin.only(bottom=10)
                    )
                    
                    results.append(result_card)
            
            search_results.controls = results
            page.update()
        
        def clear_search():
            search_query.value = ""
            min_age_field.value = ""
            max_age_field.value = ""
            date_from_field.value = ""
            date_to_field.value = ""
            location_field.value = ""
            medical_status_field.value = ""
            prison_field.value = ""
            search_results.controls = []
            page.update()
        
        def show_search_history():
            history = search_manager.get_search_history()
            
            history_cards = []
            for search in history:
                search_data = search
                
                history_card = ft.Card(
                    content=ft.Container(
                        content=ft.Column([
                            ft.Row([
                                ft.Text(f"البحث: {search_data['query'] or 'غير محدد'}", size=16, weight=ft.FontWeight.BOLD),
                                ft.Text(f"النتائج: {search_data['results_count']}", size=14),
                            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                            ft.Text(f"التاريخ: {search_data['timestamp']}", size=14),
                        ]),
                        padding=10,
                        width=500,
                    ),
                    elevation=2,
                    margin=ft.margin.only(bottom=10)
                )
                
                history_cards.append(history_card)
            
            history_content = ft.Column(
                controls=[
                    ft.Container(
                        content=ft.Text("🔍", size=60),
                        margin=ft.margin.only(bottom=15)
                    ),
                    ft.Text("سجل البحث", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.Column(history_cards, scroll=ft.ScrollMode.AUTO, height=400),
                    ft.ElevatedButton(
                        text="🧹 مسح السجل",
                        style=secondary_button_style,
                        width=300,
                        height=40,
                        on_click=lambda e: clear_search_history()
                    ),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_search_page()
                    ),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=12
            )
            
            view = ft.View(
                "/search_history",
                controls=[
                    ft.Container(
                        content=history_content,
                        padding=30,
                        border_radius=15,
                        bgcolor=colors["surface"],
                        shadow=ft.BoxShadow(
                            spread_radius=1,
                            blur_radius=10,
                            color=colors["primary_dark"],
                            offset=ft.Offset(0, 0),
                        ),
                        width=600,
                        alignment=ft.alignment.center
                    )
                ],
                padding=20,
                vertical_alignment=ft.MainAxisAlignment.CENTER,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                bgcolor=colors["background"],
                scroll=ft.ScrollMode.AUTO
            )
            
            navigate_to(view)
        
        def clear_search_history():
            search_manager.clear_search_history()
            show_snackbar("تم مسح سجل البحث بنجاح", colors["warning"])
            show_search_page()
        
        search_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔍", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("البحث المتقدم", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                search_query,
                search_type,
                ft.Divider(),
                ft.Text("فلترة النتائج", size=16, weight=ft.FontWeight.BOLD),
                ft.Row([min_age_field, max_age_field]),
                ft.Row([date_from_field, date_to_field]),
                location_field,
                medical_status_field,
                prison_field,
                ft.Divider(),
                ft.Row([
                    ft.ElevatedButton(
                        text="🔍 بحث",
                        style=button_style,
                        width=150,
                        height=40,
                        on_click=lambda e: perform_search()
                    ),
                    ft.ElevatedButton(
                        text="🧹 مسح",
                        style=secondary_button_style,
                        width=150,
                        height=40,
                        on_click=lambda e: clear_search()
                    ),
                    ft.ElevatedButton(
                        text="📜 سجل البحث",
                        style=secondary_button_style,
                        width=150,
                        height=40,
                        on_click=lambda e: show_search_history()
                    ),
                ]),
                ft.Divider(),
                ft.Text("النتائج", size=16, weight=ft.FontWeight.BOLD),
                search_results,
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_user_dashboard()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/search",
            controls=[
                ft.Container(
                    content=search_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة التقارير
    def show_reports_page():
        # إنشاء علامات تبويب للتقارير
        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=300,
            tabs=[
                ft.Tab(
                    text="تقارير إحصائية",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("تقارير إحصائية", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="📊 تقرير إحصائي شامل",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: generate_statistics_report()
                                ),
                                ft.ElevatedButton(
                                    text="📍 تقرير المواقع",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: generate_location_report()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
                ft.Tab(
                    text="التقارير المحفوظة",
                    content=ft.Container(
                        content=ft.Column(
                            controls=[
                                ft.Text("التقارير المحفوظة", size=16, weight=ft.FontWeight.BOLD),
                                ft.Divider(),
                                ft.ElevatedButton(
                                    text="📂 عرض التقارير",
                                    style=settings_button_style,
                                    width=250,
                                    on_click=lambda e: show_saved_reports()
                                ),
                            ],
                            spacing=10,
                            horizontal_alignment=ft.CrossAxisAlignment.CENTER
                        ),
                        padding=20
                    )
                ),
            ],
            expand=1,
        )
        
        reports_content = ft.Column(
            controls=[
                ft.Row([
                    ft.Text("التقارير", size=18, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                    ft.TextButton(
                        text="🔙 العودة",
                        on_click=lambda e: show_admin_dashboard()
                    ),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(),
                tabs,
            ],
            spacing=10,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )
        
        view = ft.View(
            "/reports",
            controls=[
                ft.Container(
                    content=reports_content,
                    padding=20,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=700,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إنشاء تقرير إحصائي
    def generate_statistics_report():
        report_format = ft.Dropdown(
            label="📄 تنسيق التقرير",
            value="pdf",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("pdf", "PDF"),
                ft.dropdown.Option("excel", "Excel"),
                ft.dropdown.Option("json", "JSON"),
            ],
        )
        
        def generate_report():
            format_type = report_format.value
            report_path = report_manager.generate_statistics_report(format_type)
            
            if report_path:
                show_snackbar(f"تم إنشاء التقرير بنجاح: {report_path}", colors["primary"])
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إنشاء تقرير",
                    f"تم إنشاء تقرير إحصائي بنجاح",
                    "success"
                )
                
                show_reports_page()
            else:
                show_snackbar("فشل إنشاء التقرير", colors["error"])
        
        generate_report_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📊", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إنشاء تقرير إحصائي", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر تنسيق التقرير الذي تريد إنشاءه", size=14),
                report_format,
                ft.ElevatedButton(
                    text="📊 إنشاء التقرير",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: generate_report()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_reports_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/generate_statistics_report",
            controls=[
                ft.Container(
                    content=generate_report_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # إنشاء تقرير المواقع
    def generate_location_report():
        report_format = ft.Dropdown(
            label="📄 تنسيق التقرير",
            value="pdf",
            width=300,
            border_radius=8,
            border_color=colors["primary"],
            options=[
                ft.dropdown.Option("pdf", "PDF"),
                ft.dropdown.Option("excel", "Excel"),
                ft.dropdown.Option("json", "JSON"),
            ],
        )
        
        def generate_report():
            format_type = report_format.value
            report_path = report_manager.generate_location_report(format_type)
            
            if report_path:
                show_snackbar(f"تم إنشاء التقرير بنجاح: {report_path}", colors["primary"])
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "إنشاء تقرير",
                    f"تم إنشاء تقرير المواقع بنجاح",
                    "success"
                )
                
                show_reports_page()
            else:
                show_snackbar("فشل إنشاء التقرير", colors["error"])
        
        generate_report_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📍", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("إنشاء تقرير المواقع", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Text("اختر تنسيق التقرير الذي تريد إنشاءه", size=14),
                report_format,
                ft.ElevatedButton(
                    text="📍 إنشاء التقرير",
                    style=button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: generate_report()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_reports_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        view = ft.View(
            "/generate_location_report",
            controls=[
                ft.Container(
                    content=generate_report_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # عرض التقارير المحفوظة
    def show_saved_reports():
        reports = report_manager.get_reports()
        
        report_cards = []
        for report in reports:
            report_data = dict(report)
            
            # إنشاء بطاقة التقرير
            report_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(
                                f"التقرير: {report_data['name']}", 
                                size=16, 
                                weight=ft.FontWeight.BOLD
                            ),
                            ft.Text(f"النوع: {report_data['type']}", size=14),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"التاريخ: {report_data['created_at']}", size=14),
                        ft.Row([
                            ft.IconButton(
                                icon=ft.icons.DOWNLOAD,
                                tooltip="تحميل",
                                icon_size=18,
                                on_click=lambda e, r=report_data: download_report(r)
                            ),
                            ft.IconButton(
                                icon=ft.icons.DELETE,
                                tooltip="حذف",
                                icon_size=18,
                                on_click=lambda e, r=report_data: delete_report(r)
                            ),
                        ])
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            report_cards.append(report_card)
        
        saved_reports_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("📂", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("التقارير المحفوظة", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Column(report_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_reports_page()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        def download_report(report_data):
            # في تطبيق حقيقي، سيتم تنزيل الملف
            show_snackbar(f"جاري تحميل التقرير: {report_data['name']}", colors["primary"])
        
        def delete_report(report_data):
            def confirm_delete():
                # حذف ملف التقرير
                if report_data["file_path"] and os.path.exists(report_data["file_path"]):
                    os.remove(report_data["file_path"])
                
                # حذف السجل من قاعدة البيانات
                db.execute_query(
                    "DELETE FROM reports WHERE id=?",
                    (report_data["id"],),
                    commit=True
                )
                
                # إضافة إشعار
                notification_manager.add_notification(
                    "حذف تقرير",
                    f"تم حذف التقرير: {report_data['name']}",
                    "warning"
                )
                
                show_snackbar("تم حذف التقرير بنجاح", colors["warning"])
                page.close(dialog)
                show_saved_reports()
            
            dialog = ft.AlertDialog(
                title=ft.Text("تأكيد حذف التقرير"),
                content=ft.Text("هل أنت متأكد من حذف هذا التقرير؟"),
                actions=[
                    ft.TextButton(text="إلغاء", on_click=lambda e: page.close(dialog)),
                    ft.TextButton(text="حذف", on_click=lambda e: confirm_delete()),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )
            
            page.dialog = dialog
            dialog.open = True
            page.update()
        
        view = ft.View(
            "/saved_reports",
            controls=[
                ft.Container(
                    content=saved_reports_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # صفحة الإشعارات
    def show_notifications_page():
        notifications = notification_manager.notifications
        
        notification_cards = []
        for notification in notifications:
            notification_data = dict(notification)
            
            # تحديد لون الإشعار حسب النوع
            if notification_data["type"] == "success":
                color = colors["success"]
            elif notification_data["type"] == "warning":
                color = colors["warning"]
            elif notification_data["type"] == "error":
                color = colors["error"]
            else:
                color = colors["primary"]
            
            # إنشاء بطاقة الإشعار
            notification_card = ft.Card(
                content=ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(
                                notification_data["title"], 
                                size=16, 
                                weight=ft.FontWeight.BOLD,
                                color=color
                            ),
                            ft.Text(notification_data["created_at"], size=12),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(notification_data["message"], size=14),
                    ]),
                    padding=10,
                    width=500,
                ),
                elevation=2,
                margin=ft.margin.only(bottom=10)
            )
            
            notification_cards.append(notification_card)
        
        notifications_content = ft.Column(
            controls=[
                ft.Container(
                    content=ft.Text("🔔", size=60),
                    margin=ft.margin.only(bottom=15)
                ),
                ft.Text("الإشعارات", size=20, weight=ft.FontWeight.BOLD, color=colors["primary"]),
                ft.Column(notification_cards, scroll=ft.ScrollMode.AUTO, height=400),
                ft.ElevatedButton(
                    text="🧹 مسح الكل",
                    style=secondary_button_style,
                    width=300,
                    height=40,
                    on_click=lambda e: clear_all_notifications()
                ),
                ft.TextButton(
                    text="🔙 العودة",
                    on_click=lambda e: show_admin_dashboard() if session_manager.current_user["is_admin"] else show_user_dashboard()
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            alignment=ft.MainAxisAlignment.CENTER,
            spacing=12
        )
        
        def clear_all_notifications():
            # تعليم جميع الإشعارات كمقروءة
            for notification in notifications:
                notification_manager.mark_as_read(notification["id"])
            
            # إعادة تحميل الإشعارات
            notification_manager.load_notifications()
            
            # إعادة تحميل الصفحة
            show_notifications_page()
        
        view = ft.View(
            "/notifications",
            controls=[
                ft.Container(
                    content=notifications_content,
                    padding=30,
                    border_radius=15,
                    bgcolor=colors["surface"],
                    shadow=ft.BoxShadow(
                        spread_radius=1,
                        blur_radius=10,
                        color=colors["primary_dark"],
                        offset=ft.Offset(0, 0),
                    ),
                    width=600,
                    alignment=ft.alignment.center
                )
            ],
            padding=20,
            vertical_alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            bgcolor=colors["background"],
            scroll=ft.ScrollMode.AUTO
        )
        
        navigate_to(view)
    
    # بدء التطبيق
    def start_app():
        # التحقق من وجود جلسة نشطة
        if session_manager.is_active():
            if session_manager.current_user["is_admin"]:
                show_admin_dashboard()
            else:
                show_user_dashboard()
        else:
            show_login_page()
    
    # تشغيل التطبيق
    start_app()

if __name__ == "__main__":
    # تشغيل التطبيق فقط عند تنفيذ الملف مباشرةً، وليس عند الاستيراد في اختبارات أو وحدات أخرى
    ft.app(target=main)