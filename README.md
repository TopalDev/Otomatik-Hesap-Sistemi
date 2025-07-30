# 🎮 Otomatik Hesap Sistemi

Forum veya pazaryeri üzerinden satış yapılan oyun hesaplarını, alıcıya özel oluşturulan 6 haneli kod ile erişilebilir kılan **modern ve güvenli** web uygulaması.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)
![SQLite](https://img.shields.io/badge/SQLite-3.x-yellow.svg)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.0-purple.svg)

## 🌟 Öne Çıkan Özellikler

### 🔐 Güvenlik & Güvenilirlik
- **Şifrelenmiş Şifre Saklama**: Şifreler veritabanında güvenli şekilde hash'lenir
- **IP Loglama**: Kod kullanımında IP adresi ve zaman damgası kaydedilir
- **Sınırsız Kod Süresi**: Kodlar süresiz olarak geçerli kalır
- **Steam Guard Backup Kodları**: Her hesap için benzersiz backup kodları
- **Global Backup Code Sistemi**: Her kullanımda farklı backup kodu

### 🎯 Platform Desteği
- **Steam**: Oyun bazlı hesap yönetimi
- **Xbox**: Genel hesap sistemi
- **PlayStation**: Genel hesap sistemi

### 👨‍💼 Gelişmiş Admin Paneli
- **Hesap Yönetimi**: Toplu hesap ekleme/silme
- **Oyun Yönetimi**: Toplu oyun ekleme/silme
- **Kod Oluşturma**: Otomatik 6 haneli benzersiz kodlar
- **Durum Takibi**: Hesapların ve kodların durumunu izleme
- **Filtreleme & Sayfalama**: Gelişmiş liste yönetimi
- **Admin Şifre Değiştirme**: Güvenli şifre güncelleme
- **Discord Webhook Entegrasyonu**: Otomatik stok uyarıları

### 🤖 Otomatik Sistemler
- **Otomatik Temizleme**: 48 saat sonra kullanılan veriler silinir
- **Stok İzleme**: Her 30 dakikada bir stok kontrolü
- **Discord Uyarıları**: Kritik stok seviyelerinde @everyone ile uyarı
- **Backup Code Rotasyonu**: Her kullanımda farklı backup kodu

### 👤 Kullanıcı Deneyimi
- **Modern Tasarım**: Bootstrap 5 ile responsive tasarım
- **RGB Animasyonlar**: Canlı ve modern görünüm
- **Kolay Kullanım**: Basit kod girişi ve hesap bilgileri görüntüleme
- **İndirme Özelliği**: Hesap bilgilerini text dosyası olarak indirme
- **Platform Kategorileri**: Steam, Xbox, PlayStation ayrımı

## 🚀 Hızlı Kurulum

### Gereksinimler
- Python 3.8+
- pip (Python paket yöneticisi)
- Discord Webhook URL (opsiyonel)

### 1. Projeyi İndirin
```bash
git clone <repository-url>
cd STEAM1
```

### 2. Sanal Ortam Oluşturun
```bash
python -m venv venv
```

### 3. Sanal Ortamı Aktifleştirin
```bash
# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 4. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 5. Veritabanını Oluşturun
```bash
python create_db.py
```

### 6. Uygulamayı Çalıştırın
```bash
python app.py
```

### 7. Tarayıcıda Açın
```
http://localhost:5000
```

## 📋 Kullanım Kılavuzu

### 🔑 Admin Girişi
- **URL**: `http://localhost:5000/admin/login`
- **Varsayılan Kullanıcı**: `admin`
- **Varsayılan Şifre**: `admin123`

### 🎮 Admin Paneli İşlemleri

#### 1. Oyun Ekleme
1. Admin paneline giriş yapın
2. "Toplu Oyun Ekle" menüsüne tıklayın
3. Platform seçin (Steam/Xbox/PlayStation)
4. Text dosyası yükleyin veya manuel ekleyin
5. "Oyunları Ekle" butonuna tıklayın

#### 2. Hesap Ekleme
1. "Hesap Ekle" menüsüne tıklayın
2. Platform seçin
3. Steam için oyun seçin (Xbox/PS için opsiyonel)
4. Kullanıcı adı ve şifre girin
5. Steam Guard backup kodlarını ekleyin
6. "Hesabı Kaydet" butonuna tıklayın

#### 3. Toplu Hesap Ekleme
1. "Toplu Hesap Ekle" butonuna tıklayın
2. Platform ve oyun seçin
3. Text dosyası yükleyin (format: kullanıcı_adı:şifre)
4. Steam Guard backup kodlarını ekleyin
5. "Hesapları Ekle" butonuna tıklayın

#### 4. Discord Webhook Ayarları
1. "Discord Webhook" menüsüne tıklayın
2. Discord webhook URL'sini girin
3. "Aktif" seçeneğini işaretleyin
4. "Test Uyarısı Gönder" ile test edin

### 👤 Müşteri Kullanımı

#### Kod Kullanma
1. Ana sayfaya gidin
2. Platform seçin (Steam/Xbox/PlayStation)
3. Steam için oyun seçin
4. 6 haneli kodu girin
5. "Kodu Doğrula" butonuna tıklayın
6. Hesap bilgilerini ve Steam Guard backup kodunu alın
7. "İndir" butonu ile bilgileri kaydedin

## 🛠️ Teknik Detaylar

### Veritabanı Modelleri

#### SteamAccount
```python
- id: Benzersiz hesap ID'si
- username: Kullanıcı adı
- password_hash: Şifrelenmiş şifre
- password_plain: Düz metin şifre (görüntüleme için)
- platform: Platform (steam/xbox/playstation)
- game: Oyun adı
- steam_guard_code: Steam Guard kodu
- backup_codes: Backup kodları (JSON)
- used_backup_codes: Kullanılan backup kodları (JSON)
- created_at: Oluşturulma tarihi
- is_used: Kullanım durumu
```

#### AccessCode
```python
- id: Benzersiz kod ID'si
- code: 6 haneli erişim kodu
- account_id: Bağlı hesap ID'si
- created_at: Oluşturulma tarihi
- expires_at: Bitiş tarihi (None = sınırsız)
- is_used: Kullanım durumu
- used_at: Kullanım tarihi
- used_ip: Kullanım IP'si
```

#### GlobalBackupCode
```python
- id: Benzersiz ID
- backup_code: Backup kodu
- used_at: Kullanım tarihi
- used_by_account_id: Kullanan hesap ID'si
- used_by_access_code: Kullanan erişim kodu
```

#### DiscordWebhook
```python
- id: Benzersiz ID
- webhook_url: Discord webhook URL'si
- is_active: Aktiflik durumu
- created_at: Oluşturulma tarihi
```

### 🔧 Güvenlik Özellikleri

#### Kod Güvenliği
- **Benzersiz Kodlar**: Her kod sistemde tekrar etmez
- **Sınırsız Süre**: Kodlar süresiz olarak geçerli kalır
- **Tek Kullanım**: Kodlar sadece bir kez kullanılabilir
- **IP Takibi**: Kod kullanımında IP adresi kaydedilir
- **Platform Bazlı**: Kodlar sadece ilgili platformda çalışır

#### Steam Guard Sistemi
- **Backup Code Rotasyonu**: Her kullanımda farklı backup kodu
- **Global Tracking**: Tüm hesaplar için global backup code takibi
- **Benzersiz Kodlar**: Her backup kodu sadece bir kez kullanılır

#### Otomatik Sistemler
- **48 Saat Temizlik**: Kullanılan veriler otomatik silinir
- **Stok İzleme**: Her 30 dakikada bir kontrol
- **Discord Uyarıları**: Kritik seviyelerde otomatik uyarı

## 📁 Dosya Yapısı

```
STEAM1/
├── app.py                    # Ana Flask uygulaması
├── create_db.py              # Veritabanı oluşturma scripti
├── requirements.txt          # Python bağımlılıkları
├── README.md                # Proje dokümantasyonu
├── steam_games.txt          # Steam oyun listesi
├── xbox_games.txt           # Xbox oyun listesi
├── playstation_games.txt    # PlayStation oyun listesi
├── templates/               # HTML template'leri
│   ├── base.html            # Ana template
│   ├── index.html           # Ana sayfa
│   ├── steam_games.html     # Steam oyun seçimi
│   ├── redeem_game.html     # Oyun bazlı kod kullanımı
│   ├── redeem_success.html  # Başarılı kod kullanımı
│   ├── admin_login.html     # Admin giriş sayfası
│   ├── admin_dashboard.html # Admin paneli
│   ├── add_account.html     # Hesap ekleme sayfası
│   ├── bulk_add_games.html  # Toplu oyun ekleme
│   ├── change_password.html # Şifre değiştirme
│   └── discord_webhook.html # Discord webhook ayarları
├── static/                  # Statik dosyalar
│   ├── css/                # CSS dosyaları
│   ├── js/                 # JavaScript dosyaları
│   └── img/                # Resim dosyaları
└── instance/               # Veritabanı dosyaları
    └── steam_accounts.db   # SQLite veritabanı
```

## 🎨 Özelleştirme

### Kod Formatı Değiştirme
`app.py` dosyasındaki `generate_code()` fonksiyonunu düzenleyerek kod formatını değiştirebilirsiniz:

```python
def generate_code():
    while True:
        # Mevcut: 6 haneli harf+rakam
        code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Örnek: Sadece rakam
        # code = ''.join(random.choices(string.digits, k=6))
        if not AccessCode.query.filter_by(code=code).first():
            return code
```

### Discord Webhook Ayarları
Discord webhook URL'sini almak için:
1. Discord sunucunuzda bir kanal oluşturun
2. Kanal ayarlarına gidin
3. "Entegrasyonlar" → "Webhook" → "Yeni Webhook"
4. Webhook URL'sini kopyalayın

### Stok Uyarı Seviyeleri
`app.py` dosyasındaki `check_stock_levels()` fonksiyonunda uyarı seviyelerini değiştirebilirsiniz:

```python
# Kritik seviye (5 veya daha az hesap)
if available_accounts <= 5 and total_accounts > 0:

# Düşük seviye (15 veya daha az hesap)
elif available_accounts <= 15 and total_accounts > 0:
```

## 🚨 Güvenlik Uyarıları

### ⚠️ Önemli Güvenlik Notları
1. **Varsayılan Admin Bilgilerini Değiştirin**
   - İlk kurulumda admin/admin123 ile giriş yapın
   - Güvenlik için şifreyi hemen değiştirin

2. **Production Ortamında**
   - `SECRET_KEY`'i değiştirin
   - HTTPS kullanın
   - Güçlü şifreler belirleyin
   - Düzenli yedekleme yapın
   - Firewall kuralları ekleyin

3. **Veritabanı Güvenliği**
   - Veritabanı dosyasını güvenli bir yerde saklayın
   - Düzenli yedekleme yapın
   - Erişim izinlerini sınırlayın
   - Şifreleme kullanın

4. **Discord Webhook Güvenliği**
   - Webhook URL'sini güvenli tutun
   - Düzenli olarak yenileyin
   - Sadece güvenilir sunucularda kullanın

## 📊 Sistem Durumu

### Otomatik Sistemler
- ✅ **Otomatik Temizleme**: 48 saat sonra kullanılan veriler silinir
- ✅ **Stok İzleme**: Her 30 dakikada bir kontrol edilir
- ✅ **Discord Uyarıları**: Kritik seviyelerde @everyone ile uyarı gönderilir
- ✅ **Backup Code Rotasyonu**: Her kullanımda farklı backup kodu verilir

### Güvenlik Özellikleri
- ✅ **Şifre Hashleme**: Bcrypt ile güvenli şifreleme
- ✅ **IP Loglama**: Tüm kod kullanımları loglanır
- ✅ **Platform Bazlı Erişim**: Kodlar sadece ilgili platformda çalışır
- ✅ **Tek Kullanımlık Kodlar**: Her kod sadece bir kez kullanılabilir

## 🐛 Sorun Giderme

### Yaygın Sorunlar

#### 1. Veritabanı Hatası
```bash
# Veritabanını yeniden oluşturun
rm instance/steam_accounts.db
python create_db.py
```

#### 2. Modül Bulunamadı Hatası
```bash
# Bağımlılıkları yeniden yükleyin
pip install -r requirements.txt
```

#### 3. Discord Webhook Çalışmıyor
- Webhook URL'sinin doğru olduğundan emin olun
- Discord sunucusunda webhook izinlerini kontrol edin
- Test uyarısı göndererek bağlantıyı test edin

#### 4. Backup Code Rotasyonu Çalışmıyor
- Veritabanını yeniden oluşturun
- Global backup code tablosunu kontrol edin
- Debug loglarını inceleyin

## 📞 Destek

### Hata Raporlama
1. Hata mesajlarını tam olarak kopyalayın
2. Console loglarını inceleyin
3. Veritabanı durumunu kontrol edin
4. GitHub Issues'da detaylı açıklama yapın

### Log Dosyaları
Sistem logları console'da görüntülenir:
```
Otomatik temizleme sistemi başlatıldı (48 saat sonra kullanılan veriler silinecek)
Stok izleme sistemi başlatıldı (her 30 dakikada bir kontrol edilecek)
Discord uyarısı gönderildi: 🚨 KRİTİK STOK UYARISI - STEAM
```

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📈 Gelecek Özellikler

- [ ] Telegram Bot entegrasyonu
- [ ] Email bildirimleri
- [ ] Çoklu dil desteği
- [ ] API endpoints
- [ ] Mobile app
- [ ] Analytics dashboard
- [ ] Backup/restore sistemi
- [ ] Multi-tenant desteği

---

**⚠️ Uyarı**: Bu sistem eğitim amaçlı geliştirilmiştir. Gerçek kullanımda güvenlik önlemlerini artırmanız ve yasal gerekliliklere uymanız önerilir geliştirecek arkadaşlar discord üzerinden ulaşabilir.
discord: deliyurek
**⭐ Star vermeyi unutmayın!** 