# WashBot Kurulum Rehberi

## Hızlı Başlangıç

### 1. Bağımlılıkları Yükle
```bash
pip install -r pyproject.toml
npm install
```

### 2. Environment Variables
```bash
cp .env.example .env
# .env dosyasını düzenleyin
```

### 3. Veritabanı
```bash
python -c "from app import db; db.create_all()"
```

### 4. Uygulamayı Başlat
```bash
gunicorn --bind 0.0.0.0:5000 main:app
```

## Özellikler
- ✅ 55 Cüzdan Yönetimi
- ✅ Gerçek Solana Mainnet
- ✅ Multi-DEX Trading
- ✅ Advanced Strategies
- ✅ Production Ready

## Güvenlik
- AES-256 Şifreleme
- Secure Session Management
- Rate Limiting
- CSRF Protection

Bu sistem production ortamında çalışır durumda!
