from app import app, db

with app.app_context():
    db.create_all()
    print("Veritabanı başarıyla oluşturuldu!")
    
    # Admin kullanıcısı oluştur
    from app import AdminUser
    from werkzeug.security import generate_password_hash
    
    # Admin kullanıcısı var mı kontrol et
    admin = AdminUser.query.filter_by(username='admin').first()
    if not admin:
        admin = AdminUser(
            username='admin',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin kullanıcısı oluşturuldu: admin/admin123")
    else:
        print("Admin kullanıcısı zaten mevcut")
    
    print("Sistem hazır!") 