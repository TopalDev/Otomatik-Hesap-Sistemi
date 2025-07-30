from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import datetime
import os
import json
import threading
import time
import requests
from functools import wraps

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///steam_accounts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Custom Jinja filter
@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        try:
            return json.loads(value)
        except:
            return []
    return []

db = SQLAlchemy(app)

# Veritabanı modelleri
class SteamAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    password_plain = db.Column(db.String(255), nullable=True)  # Geçici şifre saklama
    platform = db.Column(db.String(50), nullable=False)  # steam, xbox, playstation
    game = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    steam_guard_code = db.Column(db.String(10), nullable=True)  # Steam Guard kodu
    backup_codes = db.Column(db.Text, nullable=True)  # Backup kodları (JSON formatında)
    used_backup_codes = db.Column(db.Text, nullable=True)  # Kullanılan backup kodları
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_used = db.Column(db.Boolean, default=False)

class AccessCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(6), unique=True, nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('steam_account.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Sınırsız süre için nullable=True
    is_used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    used_ip = db.Column(db.String(45), nullable=True)
    
    # Relationship
    account = db.relationship('SteamAccount', backref=db.backref('access_codes', cascade='all, delete-orphan'))

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    platform = db.Column(db.String(50), nullable=False)  # steam, xbox, playstation
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class GlobalBackupCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    backup_code = db.Column(db.String(10), unique=True, nullable=False)
    used_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    used_by_account_id = db.Column(db.Integer, db.ForeignKey('steam_account.id'), nullable=False)
    used_by_access_code = db.Column(db.String(6), nullable=False)

class DiscordWebhook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    webhook_url = db.Column(db.String(500), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Admin girişi kontrolü
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# 6 haneli kod oluşturma
def generate_code():
    while True:
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if not AccessCode.query.filter_by(code=code).first():
            return code

# Discord Webhook Fonksiyonları
def send_discord_alert(webhook_url, title, description, color=0x00ff00, fields=None):
    """Discord webhook ile uyarı gönder"""
    try:
        embed = {
            "title": title,
            "description": description,
            "color": color,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "footer": {
                "text": "Otomatik Hesap Sistemi"
            }
        }
        
        if fields:
            embed["fields"] = fields
        
        payload = {
            "content": "@everyone",  # Tüm üyeleri etiketle
            "embeds": [embed]
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        print(f"Discord uyarısı gönderildi: {title}")
        return True
    except Exception as e:
        print(f"Discord uyarısı gönderilemedi: {e}")
        return False

def check_stock_levels():
    """Stok seviyelerini kontrol et ve Discord'a uyarı gönder"""
    try:
        with app.app_context():
            # Platform bazında stok durumu
            platforms = ['steam', 'xbox', 'playstation']
            
            for platform in platforms:
                # Kullanılabilir hesap sayısı
                available_accounts = SteamAccount.query.filter_by(
                    platform=platform, 
                    is_used=False
                ).count()
                
                # Kullanılan hesap sayısı
                used_accounts = SteamAccount.query.filter_by(
                    platform=platform, 
                    is_used=True
                ).count()
                
                # Toplam hesap sayısı
                total_accounts = available_accounts + used_accounts
                
                # Stok uyarı seviyeleri
                if available_accounts <= 5 and total_accounts > 0:
                    # Kritik stok seviyesi
                    color = 0xff0000  # Kırmızı
                    title = f"🚨 KRİTİK STOK UYARISI - {platform.upper()}"
                    description = f"**{platform.upper()}** platformunda sadece **{available_accounts}** hesap kaldı!"
                    
                    fields = [
                        {"name": "📊 Stok Durumu", "value": f"Kullanılabilir: {available_accounts}\nKullanılan: {used_accounts}\nToplam: {total_accounts}", "inline": True},
                        {"name": "⚠️ Durum", "value": "Kritik seviye! Hemen hesap ekleyin!", "inline": True}
                    ]
                    
                    # Discord webhook URL'sini veritabanından al
                    webhook = DiscordWebhook.query.filter_by(is_active=True).first()
                    if webhook and webhook.webhook_url:
                        send_discord_alert(webhook.webhook_url, title, description, color, fields)
                
                elif available_accounts <= 15 and total_accounts > 0:
                    # Düşük stok seviyesi
                    color = 0xffa500  # Turuncu
                    title = f"⚠️ DÜŞÜK STOK UYARISI - {platform.upper()}"
                    description = f"**{platform.upper()}** platformunda **{available_accounts}** hesap kaldı."
                    
                    fields = [
                        {"name": "📊 Stok Durumu", "value": f"Kullanılabilir: {available_accounts}\nKullanılan: {used_accounts}\nToplam: {total_accounts}", "inline": True},
                        {"name": "💡 Öneri", "value": "Yakında hesap eklemeyi düşünün.", "inline": True}
                    ]
                    
                    # Discord webhook URL'sini veritabanından al
                    webhook = DiscordWebhook.query.filter_by(is_active=True).first()
                    if webhook and webhook.webhook_url:
                        send_discord_alert(webhook.webhook_url, title, description, color, fields)
                
                # Stok bitti uyarısı
                elif available_accounts == 0 and total_accounts > 0:
                    color = 0x8b0000  # Koyu kırmızı
                    title = f"💀 STOK BİTTİ - {platform.upper()}"
                    description = f"**{platform.upper()}** platformunda hiç hesap kalmadı!"
                    
                    fields = [
                        {"name": "📊 Stok Durumu", "value": f"Kullanılabilir: 0\nKullanılan: {used_accounts}\nToplam: {total_accounts}", "inline": True},
                        {"name": "🚨 Acil", "value": "Hemen hesap ekleyin!", "inline": True}
                    ]
                    
                    # Discord webhook URL'sini veritabanından al
                    webhook = DiscordWebhook.query.filter_by(is_active=True).first()
                    if webhook and webhook.webhook_url:
                        send_discord_alert(webhook.webhook_url, title, description, color, fields)
                        
    except Exception as e:
        print(f"Stok kontrolü hatası: {e}")

def stock_monitor():
    """Stok izleme thread'i - her 30 dakikada bir kontrol eder"""
    while True:
        try:
            check_stock_levels()
        except Exception as e:
            print(f"Stok izleme hatası: {e}")
        
        # 30 dakika bekle
        time.sleep(1800)  # 1800 saniye = 30 dakika

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/redeem', methods=['GET', 'POST'])
@app.route('/redeem/<platform>', methods=['GET', 'POST'])
def redeem(platform=None):
    if platform == 'steam':
        return redirect(url_for('steam_games'))
    
    if request.method == 'POST':
        code = request.form.get('code', '').upper()
        platform = request.form.get('platform', platform or 'steam')
        
        if not code or len(code) != 6:
            flash('Geçersiz kod formatı!', 'error')
            return render_template('redeem.html', platform=platform)
        
        # Xbox ve PlayStation için oyun seçimi opsiyonel
        selected_game = request.form.get('game', '')
        
        access_code = AccessCode.query.filter_by(code=code).first()
        
        if not access_code:
            flash('Kod geçersiz veya süresi dolmuş!', 'error')
            return render_template('redeem.html', platform=platform)
        
        if access_code.is_used:
            flash('Bu kod zaten kullanılmış!', 'error')
            return render_template('redeem.html', platform=platform)
        
        # Hesap bilgilerini al
        account = SteamAccount.query.get(access_code.account_id)
        
        # Xbox ve PlayStation için oyun kontrolü opsiyonel
        if platform in ['xbox', 'playstation'] and selected_game:
            if account.game != selected_game:
                flash(f'Bu kod {account.game} oyunu için geçerlidir, {selected_game} için kullanılamaz!', 'error')
                return render_template('redeem.html', platform=platform)
        
        # Kodu kullanıldı olarak işaretle
        access_code.is_used = True
        access_code.used_at = datetime.datetime.utcnow()
        access_code.used_ip = request.remote_addr
        account.is_used = True
        
        db.session.commit()
        
        return render_template('redeem_success.html', account=account, platform=platform)
    
    return render_template('redeem.html', platform=platform)
    if request.method == 'POST':
        code = request.form.get('code', '').upper()
        platform = request.form.get('platform', platform or 'steam')
        
        if not code or len(code) != 6:
            flash('Geçersiz kod formatı!', 'error')
            return render_template('redeem.html', platform=platform)
        
        access_code = AccessCode.query.filter_by(code=code).first()
        
        if not access_code:
            flash('Kod geçersiz veya süresi dolmuş!', 'error')
            return render_template('redeem.html', platform=platform)
        
        if access_code.is_used:
            flash('Bu kod zaten kullanılmış!', 'error')
            return render_template('redeem.html', platform=platform)
        
        if datetime.datetime.utcnow() > access_code.expires_at:
            flash('Kod süresi dolmuş!', 'error')
            return render_template('redeem.html', platform=platform)
        
        # Kodu kullanıldı olarak işaretle
        access_code.is_used = True
        access_code.used_at = datetime.datetime.utcnow()
        access_code.used_ip = request.remote_addr
        
        # Hesap bilgilerini al
        account = SteamAccount.query.get(access_code.account_id)
        account.is_used = True
        
        db.session.commit()
        
        return render_template('redeem_success.html', account=account, platform=platform)
    
    return render_template('redeem.html', platform=platform)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = AdminUser.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre!', 'error')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Başarıyla çıkış yapıldı!', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/change_password', methods=['GET', 'POST'])
@admin_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Admin kullanıcısını bul
        admin = AdminUser.query.first()
        
        if not admin:
            flash('Admin kullanıcısı bulunamadı!', 'error')
            return redirect(url_for('change_password'))
        
        # Mevcut şifreyi kontrol et
        if not check_password_hash(admin.password_hash, current_password):
            flash('Mevcut şifre yanlış!', 'error')
            return redirect(url_for('change_password'))
        
        # Yeni şifreleri kontrol et
        if new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor!', 'error')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash('Yeni şifre en az 6 karakter olmalıdır!', 'error')
            return redirect(url_for('change_password'))
        
        # Şifreyi güncelle
        admin.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Şifre başarıyla değiştirildi!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('change_password.html')

@app.route('/admin/discord_webhook', methods=['GET', 'POST'])
@admin_required
def discord_webhook_settings():
    if request.method == 'POST':
        webhook_url = request.form.get('webhook_url', '').strip()
        is_active = request.form.get('is_active') == 'on'
        
        # Mevcut webhook'u bul veya yeni oluştur
        webhook = DiscordWebhook.query.first()
        if not webhook:
            webhook = DiscordWebhook()
            db.session.add(webhook)
        
        webhook.webhook_url = webhook_url
        webhook.is_active = is_active
        db.session.commit()
        
        flash('Discord webhook ayarları güncellendi!', 'success')
        return redirect(url_for('discord_webhook_settings'))
    
    # Mevcut ayarları getir
    webhook = DiscordWebhook.query.first()
    return render_template('discord_webhook.html', webhook=webhook)

@app.route('/admin/test_webhook', methods=['POST'])
@admin_required
def test_webhook():
    webhook = DiscordWebhook.query.first()
    if not webhook or not webhook.webhook_url:
        return jsonify({'success': False, 'error': 'Webhook URL bulunamadı!'})
    
    try:
        success = send_discord_alert(
            webhook.webhook_url,
            "🧪 Test Uyarısı",
            "Bu bir test uyarısıdır. Discord webhook sistemi çalışıyor!",
            0x00ff00,
            [
                {"name": "✅ Durum", "value": "Webhook başarıyla çalışıyor!", "inline": True},
                {"name": "🕒 Zaman", "value": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), "inline": True}
            ]
        )
        
        if success:
            return jsonify({'success': True, 'message': 'Test uyarısı başarıyla gönderildi!'})
        else:
            return jsonify({'success': False, 'error': 'Test uyarısı gönderilemedi!'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': f'Test hatası: {str(e)}'})

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Sayfalama parametreleri
    accounts_page = request.args.get('accounts_page', 1, type=int)
    codes_page = request.args.get('codes_page', 1, type=int)
    per_page = request.args.get('per_page', 25, type=int)
    
    # Filtreleme parametreleri
    accounts_platform = request.args.get('accounts_platform', '')
    accounts_game = request.args.get('accounts_game', '')
    codes_platform = request.args.get('codes_platform', '')
    codes_game = request.args.get('codes_game', '')
    
    # Geçerli per_page değerleri
    if per_page not in [25, 50, 100]:
        per_page = 25
    
    # Hesaplar için filtreleme ve sayfalama
    accounts_query = SteamAccount.query
    if accounts_platform:
        accounts_query = accounts_query.filter(SteamAccount.platform == accounts_platform)
    if accounts_game:
        accounts_query = accounts_query.filter(SteamAccount.game == accounts_game)
    
    accounts_pagination = accounts_query.paginate(
        page=accounts_page, per_page=per_page, error_out=False
    )
    
    # Kodlar için filtreleme ve sayfalama
    codes_query = AccessCode.query.join(SteamAccount)
    if codes_platform:
        codes_query = codes_query.filter(SteamAccount.platform == codes_platform)
    if codes_game:
        codes_query = codes_query.filter(SteamAccount.game == codes_game)
    
    codes_pagination = codes_query.paginate(
        page=codes_page, per_page=per_page, error_out=False
    )
    
    # Oyunlar (sayfalama yok, hepsi gösteriliyor)
    games = Game.query.order_by(Game.platform, Game.name).all()
    now = datetime.datetime.utcnow()
    
    return render_template('admin_dashboard.html', 
                         accounts_pagination=accounts_pagination,
                         codes_pagination=codes_pagination,
                         games=games, 
                         now=now,
                         per_page=per_page,
                         accounts_page=accounts_page,
                         codes_page=codes_page,
                         accounts_platform=accounts_platform,
                         accounts_game=accounts_game,
                         codes_platform=codes_platform,
                         codes_game=codes_game)

@app.route('/admin/add_account', methods=['GET', 'POST'])
@admin_required
def add_account():
    if request.method == 'POST':
        platform = request.form.get('platform')
        game = request.form.get('game')
        username = request.form.get('username')
        password = request.form.get('password')
        description = request.form.get('description', '')
        steam_guard_code = request.form.get('steam_guard_code', '')
        backup_codes_text = request.form.get('backup_codes', '')
        
        if not platform or not username or not password:
            flash('Platform, kullanıcı adı ve şifre gerekli!', 'error')
            return render_template('add_account.html')
        
        # Xbox ve PlayStation için oyun seçimi opsiyonel
        if not game and platform not in ['xbox', 'playstation']:
            flash('Steam için oyun seçimi zorunludur!', 'error')
            return render_template('add_account.html')
        
        # Xbox ve PlayStation için oyun boşsa "Genel Hesap" olarak ayarla
        if platform in ['xbox', 'playstation'] and not game:
            game = "Genel Hesap"
        
        # Şifreyi hashle
        password_hash = generate_password_hash(password)
        
        # Backup kodlarını işle
        backup_codes_list = []
        if backup_codes_text:
            codes = [code.strip() for code in backup_codes_text.split('\n') if code.strip()]
            backup_codes_list = codes
        
        account = SteamAccount(
            username=username, 
            password_hash=password_hash,
            password_plain=password,  # Şifreyi düz metin olarak da sakla
            platform=platform,
            game=game,
            description=description,
            steam_guard_code=steam_guard_code if steam_guard_code else None,
            backup_codes=json.dumps(backup_codes_list) if backup_codes_list else None,
            used_backup_codes=json.dumps([])
        )
        db.session.add(account)
        db.session.flush()  # ID'yi almak için flush
        
        # Otomatik kod oluştur (sınırsız süre)
        code = generate_code()
        
        access_code = AccessCode(
            code=code,
            account_id=account.id,
            expires_at=None  # Sınırsız süre
        )
        
        db.session.add(access_code)
        db.session.commit()
        
        flash(f'Hesap başarıyla eklendi! Otomatik kod: {code}', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_account.html')

@app.route('/admin/add_game', methods=['GET', 'POST'])
@admin_required
def add_game():
    if request.method == 'POST':
        name = request.form.get('name')
        platform = request.form.get('platform')
        
        if not name or not platform:
            flash('Oyun adı ve platform gerekli!', 'error')
            return render_template('add_game.html')
        
        game = Game(name=name, platform=platform)
        db.session.add(game)
        db.session.commit()
        
        flash('Oyun başarıyla eklendi!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('add_game.html')

@app.route('/admin/bulk_add_games', methods=['GET', 'POST'])
@admin_required
def bulk_add_games():
    if request.method == 'POST':
        if request.is_json:
            # AJAX ile gelen veri
            data = request.get_json()
            platform = data.get('platform')
            games = data.get('games', [])
            
            print(f"Platform: {platform}")
            print(f"Games: {games}")
            
            added_count = 0
            for game_name in games:
                if game_name.strip():
                    # Oyun zaten var mı kontrol et
                    existing_game = Game.query.filter_by(name=game_name.strip(), platform=platform).first()
                    if not existing_game:
                        game = Game(name=game_name.strip(), platform=platform)
                        db.session.add(game)
                        added_count += 1
            
            db.session.commit()
            return jsonify({'success': True, 'message': f'{added_count} oyun eklendi!'})
        else:
            # Form ile gelen dosya
            platform = request.form.get('platform')
            game_file = request.files.get('game_file')
            
            if not platform or not game_file:
                flash('Platform ve dosya gerekli!', 'error')
                return render_template('bulk_add_games.html')
            
            if game_file.filename == '':
                flash('Dosya seçilmedi!', 'error')
                return render_template('bulk_add_games.html')
            
            # Dosyayı oku
            content = game_file.read().decode('utf-8')
            games = [line.strip() for line in content.split('\n') if line.strip()]
            
            return render_template('bulk_add_games.html', games=games, platform=platform)
    
    return render_template('bulk_add_games.html')

@app.route('/admin/generate_code', methods=['GET', 'POST'])
@admin_required
def generate_access_code():
    if request.method == 'POST':
        account_id = request.form.get('account_id')
        expiry_hours = int(request.form.get('expiry_hours', 24))
        
        if not account_id:
            flash('Hesap seçimi gerekli!', 'error')
            return render_template('generate_code.html')
        
        account = SteamAccount.query.get(account_id)
        if not account:
            flash('Hesap bulunamadı!', 'error')
            return render_template('generate_code.html')
        
        if account.is_used:
            flash('Bu hesap zaten kullanılmış!', 'error')
            return render_template('generate_code.html')
        
        code = generate_code()
        
        access_code = AccessCode(
            code=code,
            account_id=account_id,
            expires_at=None  # Sınırsız süre
        )
        
        db.session.add(access_code)
        db.session.commit()
        
        flash(f'Kod oluşturuldu: {code}', 'success')
        return redirect(url_for('admin_dashboard'))
    
    accounts = SteamAccount.query.filter_by(is_used=False).all()
    return render_template('generate_code.html', accounts=accounts)

@app.route('/admin/delete_account/<int:account_id>')
@admin_required
def delete_account(account_id):
    account = SteamAccount.query.get(account_id)
    if account:
        db.session.delete(account)
        db.session.commit()
        flash('Hesap ve ilişkili kodlar silindi!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/steam/games')
def steam_games():
    games = Game.query.filter_by(platform='steam', is_active=True).all()
    return render_template('steam_games.html', games=games)

@app.route('/redeem/game/<int:game_id>', methods=['GET', 'POST'])
def redeem_game(game_id):
    game = Game.query.get_or_404(game_id)
    
    if request.method == 'POST':
        code = request.form.get('code', '').upper()
        
        if not code or len(code) != 6:
            flash('Geçersiz kod formatı!', 'error')
            return render_template('redeem_game.html', game=game)
        
        access_code = AccessCode.query.filter_by(code=code).first()
        
        if not access_code:
            flash('Kod geçersiz veya süresi dolmuş!', 'error')
            return render_template('redeem_game.html', game=game)
        
        if access_code.is_used:
            flash('Bu kod zaten kullanılmış!', 'error')
            return render_template('redeem_game.html', game=game)
        
        # Süre kontrolü kaldırıldı - kodlar sınırsız süre geçerli
        # if datetime.datetime.utcnow() > access_code.expires_at:
        #     flash('Kod süresi dolmuş!', 'error')
        #     return render_template('redeem_game.html', game=game)
        
        # Hesap bilgilerini al
        account = SteamAccount.query.get(access_code.account_id)
        
        # Kod sadece ait olduğu oyun için çalışsın
        if account.game != game.name:
            flash(f'Bu kod {account.game} oyunu için geçerlidir, {game.name} için kullanılamaz!', 'error')
            return render_template('redeem_game.html', game=game)
        
        # Backup kodunu bul ve kullanıldı olarak işaretle (eğer varsa)
        used_backup_code = None
        if account.backup_codes:
            backup_codes = json.loads(account.backup_codes)
            
            # Global olarak kullanılan backup kodlarını al
            global_used_codes = [gbc.backup_code for gbc in GlobalBackupCode.query.all()]
            
            print(f"DEBUG: Account ID: {account.id}")
            print(f"DEBUG: Access Code: {code}")
            print(f"DEBUG: Backup codes: {backup_codes}")
            print(f"DEBUG: Global used codes: {global_used_codes}")
            
            # İlk kullanılabilir kodu bul
            for backup_code in backup_codes:
                if backup_code not in global_used_codes:
                    used_backup_code = backup_code
                    
                    # Global backup kodunu kullanıldı olarak işaretle
                    global_backup_record = GlobalBackupCode(
                        backup_code=backup_code,
                        used_by_account_id=account.id,
                        used_by_access_code=code
                    )
                    db.session.add(global_backup_record)
                    
                    print(f"DEBUG: Selected code: {used_backup_code}")
                    print(f"DEBUG: Added to global used codes")
                    # Hemen database'e kaydet
                    db.session.commit()
                    break
        
        # Kodu kullanıldı olarak işaretle
        access_code.is_used = True
        access_code.used_at = datetime.datetime.utcnow()
        access_code.used_ip = request.remote_addr
        
        account.is_used = True
        
        db.session.commit()
        
        return render_template('redeem_success.html', account=account, platform='steam', game=game, used_backup_code=used_backup_code)
    
    return render_template('redeem_game.html', game=game)

@app.route('/admin/delete_game/<int:game_id>')
@admin_required
def delete_game(game_id):
    game = Game.query.get(game_id)
    if game:
        db.session.delete(game)
        db.session.commit()
        flash('Oyun silindi!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk_delete_games', methods=['POST'])
@admin_required
def bulk_delete_games():
    if request.is_json:
        data = request.get_json()
        game_ids = data.get('game_ids', [])
        
        if not game_ids:
            return jsonify({'success': False, 'error': 'Oyun ID\'leri gerekli!'})
        
        deleted_count = 0
        for game_id in game_ids:
            game = Game.query.get(game_id)
            if game:
                db.session.delete(game)
                deleted_count += 1
        
        db.session.commit()
        return jsonify({'success': True, 'message': f'{deleted_count} oyun silindi!'})
    
    return jsonify({'success': False, 'error': 'Geçersiz istek!'})

@app.route('/admin/get_games_by_platform')
@admin_required
def get_games_by_platform():
    try:
        games = Game.query.filter_by(is_active=True).all()
        
        games_by_platform = {
            'steam': [],
            'xbox': [],
            'playstation': []
        }
        
        for game in games:
            platform = game.platform.lower()
            if platform in games_by_platform:
                games_by_platform[platform].append(game.name)
        
        return jsonify({
            'success': True,
            'games': games_by_platform
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/admin/bulk_add_accounts', methods=['POST'])
@admin_required
def bulk_add_accounts():
    if request.is_json:
        data = request.get_json()
        platform = data.get('platform')
        game = data.get('game')
        accounts = data.get('accounts', [])
        backup_codes_text = data.get('backup_codes', '')
        
        if not platform or not accounts:
            return jsonify({'success': False, 'error': 'Platform ve hesap listesi gerekli!'})
        
        # Xbox ve PlayStation için oyun seçimi opsiyonel
        if not game and platform not in ['xbox', 'playstation']:
            return jsonify({'success': False, 'error': 'Steam için oyun seçimi zorunludur!'})
        
        # Xbox ve PlayStation için oyun boşsa "Genel Hesap" olarak ayarla
        if platform in ['xbox', 'playstation'] and not game:
            game = "Genel Hesap"
        
        # Backup kodlarını işle
        backup_codes_list = []
        if backup_codes_text and platform == 'steam':
            codes = [code.strip() for code in backup_codes_text.split('\n') if code.strip()]
            backup_codes_list = codes
        
        added_count = 0
        generated_codes = []
        
        try:
            for account_data in accounts:
                username = account_data.get('username', '').strip()
                password = account_data.get('password', '').strip()
                description = account_data.get('description', '').strip()
                
                if not username or not password:
                    continue
                
                # Şifreyi hash'le
                password_hash = generate_password_hash(password)
                
                # Hesabı oluştur
                account = SteamAccount(
                    username=username,
                    password_hash=password_hash,
                    password_plain=password,  # Şifreyi düz metin olarak da sakla
                    platform=platform,
                    game=game,
                    description=description,
                    backup_codes=json.dumps(backup_codes_list) if backup_codes_list else None,
                    used_backup_codes=json.dumps([])
                )
                db.session.add(account)
                db.session.flush()  # ID'yi almak için
                
                # Kod oluştur
                code = generate_code()

                access_code = AccessCode(
                    code=code,
                    account_id=account.id,
                    expires_at=None  # Sınırsız süre
                )
                db.session.add(access_code)
                generated_codes.append(code)
                added_count += 1
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'added_count': added_count,
                'codes': generated_codes,
                'message': f'{added_count} hesap başarıyla eklendi!'
            })
            
        except Exception as e:
            db.session.rollback()
            return jsonify({
                'success': False,
                'error': f'Hesap eklenirken hata oluştu: {str(e)}'
            })
    
    return jsonify({'success': False, 'error': 'Geçersiz istek!'})

@app.route('/admin/delete_code/<int:code_id>')
@admin_required
def delete_code(code_id):
    code = AccessCode.query.get(code_id)
    if code:
        db.session.delete(code)
        db.session.commit()
        flash('Kod silindi!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/clear_all_data', methods=['POST'])
@admin_required
def clear_all_data():
    try:
        # Tüm kodları sil
        AccessCode.query.delete()
        
        # Tüm hesapları sil
        SteamAccount.query.delete()
        
        # Tüm oyunları sil
        Game.query.delete()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Tüm veriler başarıyla silindi!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Veri silinirken hata oluştu: {str(e)}'
        })

@app.route('/admin/clear_used_accounts', methods=['POST'])
@admin_required
def clear_used_accounts():
    try:
        # Kullanılan hesapları bul
        used_accounts = SteamAccount.query.filter_by(is_used=True).all()
        deleted_count = len(used_accounts)
        
        # Bu hesaplara ait kodları sil
        for account in used_accounts:
            AccessCode.query.filter_by(account_id=account.id).delete()
        
        # Kullanılan hesapları sil
        SteamAccount.query.filter_by(is_used=True).delete()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'deleted_count': deleted_count,
            'message': f'{deleted_count} kullanılan hesap silindi!'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Hesap silinirken hata oluştu: {str(e)}'
        })

@app.route('/admin/clear_expired_codes', methods=['POST'])
@admin_required
def clear_expired_codes():
    try:
        # Artık süresi dolmuş kod yok çünkü kodlar sınırsız süre geçerli
        return jsonify({
            'success': True,
            'deleted_count': 0,
            'message': 'Süresi dolmuş kod bulunamadı! Tüm kodlar sınırsız süre geçerlidir.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'İşlem sırasında hata oluştu: {str(e)}'
        })

# Otomatik temizleme fonksiyonu - 48 saat sonra kullanılan hesapları ve kodları sil
def auto_cleanup_old_data():
    """48 saat sonra kullanılan hesapları ve kodları otomatik sil"""
    while True:
        try:
            with app.app_context():
                # 48 saat öncesini hesapla
                cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=48)
                
                # 48 saatten eski kullanılan hesapları bul
                old_used_accounts = SteamAccount.query.filter(
                    SteamAccount.is_used == True,
                    SteamAccount.created_at < cutoff_time
                ).all()
                
                # 48 saatten eski kullanılan kodları bul
                old_used_codes = AccessCode.query.filter(
                    AccessCode.is_used == True,
                    AccessCode.used_at < cutoff_time
                ).all()
                
                deleted_accounts = 0
                deleted_codes = 0
                
                # Eski kullanılan hesapları sil
                for account in old_used_accounts:
                    db.session.delete(account)
                    deleted_accounts += 1
                
                # Eski kullanılan kodları sil
                for code in old_used_codes:
                    db.session.delete(code)
                    deleted_codes += 1
                
                if deleted_accounts > 0 or deleted_codes > 0:
                    db.session.commit()
                    print(f"Otomatik temizlik: {deleted_accounts} hesap, {deleted_codes} kod silindi")
                else:
                    print("Otomatik temizlik: Silinecek veri bulunamadı")
                    
        except Exception as e:
            print(f"Otomatik temizlik hatası: {e}")
        
        # 1 saat bekle
        time.sleep(3600)  # 3600 saniye = 1 saat

# Otomatik temizleme thread'ini başlat
cleanup_thread = None

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # İlk admin kullanıcısını oluştur (eğer yoksa)
        if not AdminUser.query.first():
            admin = AdminUser(
                username='admin',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin kullanıcısı oluşturuldu: admin/admin123")
    
    # Otomatik temizleme thread'ini başlat
    cleanup_thread = threading.Thread(target=auto_cleanup_old_data, daemon=True)
    cleanup_thread.start()
    print("Otomatik temizleme sistemi başlatıldı (48 saat sonra kullanılan veriler silinecek)")
    
    # Stok izleme thread'ini başlat
    stock_thread = threading.Thread(target=stock_monitor, daemon=True)
    stock_thread.start()
    print("Stok izleme sistemi başlatıldı (her 30 dakikada bir kontrol edilecek)")
    
    app.run(debug=True) 