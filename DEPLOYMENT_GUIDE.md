# WashBot - GitHub Upload Guide

Bu rehber, WashBot projesinin tüm dosyalarını GitHub'a yükleme sürecini anlatır.

## Proje Dosyaları

### Ana Uygulama Dosyaları
- `app.py` - Ana Flask uygulaması (4465 satır)
- `main.py` - Uygulama giriş noktası
- `models.py` - Veritabanı modelleri
- `config.py` - Konfigürasyon ayarları
- `database.py` - Veritabanı bağlantı yönetimi

### Cüzdan ve Güvenlik
- `wallet_manager.py` - Cüzdan yönetimi ve şifreleme
- `security.py` - Güvenlik ve şifreleme işlemleri
- `emergency_encryption_fix.py` - Şifreleme sorunları için acil düzeltme

### Blockchain Entegrasyonları
- `real_solana_mainnet.py` - Gerçek Solana mainnet bağlantısı
- `live_trading_engine.py` - Canlı işlem motoru
- `solana_utils.py` - Solana yardımcı fonksiyonları
- `raydium_production.py` - Raydium DEX entegrasyonu
- `solana_tracker_client.py` - Solana Tracker API

### Strateji ve İşlem Yönetimi
- `strategies.py` - İşlem stratejileri
- `advanced_trading_engine.py` - Gelişmiş işlem motoru
- `api_integrations.py` - Harici API entegrasyonları
- `enhanced_trading_engine.py` - Geliştirilmiş işlem motoru

### Optimizasyon ve Yönetim
- `ultra_resilience_manager.py` - Sistem dayanıklılık yöneticisi
- `stress_test_manager.py` - Stres testi yöneticisi
- `world_class_optimization.py` - Dünya standartında optimizasyon
- `replit_optimization.py` - Replit optimize edilmiş yapılandırma

### Frontend Dosyaları
- `static/js/main.js` - Ana JavaScript dosyası (2344 satır)
- `static/js/token_creator.js` - Token oluşturucu
- `static/css/` - CSS dosyaları
- `templates/` - HTML şablonları

### Konfigürasyon
- `pyproject.toml` - Python bağımlılıkları
- `package.json` - Node.js bağımlılıkları
- `gunicorn_config.py` - Gunicorn yapılandırması
- `.gitignore` - Git ignore dosyası

## GitHub'a Yükleme Adımları

### 1. GitHub Repository Oluşturma
1. GitHub'da yeni repository oluşturun: "washbot-solana-trading"
2. Repository'yi public veya private olarak ayarlayın
3. README.md ile initialize edin

### 2. Dosyaları Manuel Yükleme
Aşağıdaki dosyaları GitHub web interface'i üzerinden yükleyebilirsiniz:

#### Ana Dosyalar (Öncelik 1)
```
app.py
main.py
models.py
wallet_manager.py
security.py
real_solana_mainnet.py
live_trading_engine.py
strategies.py
```

#### Frontend Dosyaları (Öncelik 2)
```
static/js/main.js
static/js/token_creator.js
templates/index.html
templates/wallets.html
templates/strategies.html
```

#### Konfigürasyon (Öncelik 3)
```
pyproject.toml
package.json
.gitignore
README.md
```

### 3. Klasör Yapısı
```
washbot-solana-trading/
├── README.md
├── pyproject.toml
├── package.json
├── .gitignore
├── app.py
├── main.py
├── models.py
├── wallet_manager.py
├── security.py
├── strategies.py
├── api_integrations.py
├── real_solana_mainnet.py
├── live_trading_engine.py
├── static/
│   ├── js/
│   │   ├── main.js
│   │   └── token_creator.js
│   └── css/
└── templates/
    ├── index.html
    ├── wallets.html
    ├── strategies.html
    └── modals/
```

### 4. Hassas Dosyalar
Bu dosyaları GitHub'a yüklemeyin:
- `.env` (çevre değişkenleri)
- `.encryption_key` (şifreleme anahtarı)
- `*.log` (log dosyaları)
- `__pycache__/` (Python cache)

### 5. Deployment Notları
- Replit'te çalışır durumda
- PostgreSQL veritabanı gerekli
- Solana mainnet bağlantısı aktif
- 55 cüzdan ile test edildi
- Gerçek işlem yapabilir durumda

## Önemli Güvenlik Notları
1. API anahtarlarını environment variables olarak saklayın
2. Private key'leri asla repository'ye eklemeyin
3. `.env` dosyasını .gitignore'a ekleyin
4. Production ortamında güçlü şifreleme anahtarları kullanın

## Kurulum Sonrası
1. Dependencies'leri yükleyin: `pip install -r pyproject.toml`
2. Environment variables'ları ayarlayın
3. Veritabanını initialize edin
4. Uygulamayı başlatın: `gunicorn main:app`

Bu proje şu anda tam çalışır durumda ve gerçek Solana mainnet'te işlem yapabilmektedir.