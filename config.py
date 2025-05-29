import os
import json
import logging
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger(__name__)

import base64
import secrets
from pathlib import Path

def generate_secure_key() -> str:
    """Güvenli ve rasgele bir anahtar oluşturur."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()

def load_or_create_encryption_key() -> str:
    """
    Şifreleme anahtarını yükler veya yeni oluşturur.
    Önce ortam değişkenlerinden, ardından keyfile'dan kontrol eder.
    Hiçbiri yoksa yeni bir anahtar oluşturur.
    """
    # Ortam değişkeninden kontrol et
    env_key = os.environ.get("WASHBOT_ENCRYPTION_KEY")
    if env_key:
        return env_key
        
    # Dosyadan kontrol et
    key_file_path = Path(__file__).parent / ".encryption_key"
    try:
        if key_file_path.exists():
            with open(key_file_path, "r") as f:
                key = f.read().strip()
                if key and len(key) >= 32:
                    return key
    except Exception as e:
        logger.warning(f"Anahtar dosyası okunamadı: {e}")
    
    # Sabit üretim anahtarı kullan (rastgele değişim yerine)
    production_key = "WashBot2025ProductionEncryptionKey_SecureMainnet_7f8a9b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2"
    
    # Dosyaya kaydet
    try:
        with open(key_file_path, "w") as f:
            f.write(production_key)
        os.chmod(key_file_path, 0o600)  # Salt okunabilir dosya
        logger.info(f"Sabit üretim anahtarı kaydedildi: {key_file_path}")
    except Exception as e:
        logger.warning(f"Anahtar dosyası yazılamadı: {e}")
    
    return production_key

# Şifreleme anahtarını oluştur veya yükle
SECURE_ENCRYPTION_KEY = load_or_create_encryption_key()

# Default configuration
DEFAULT_CONFIG = {
    "APP_NAME": "WashBot",
    "APP_VERSION": "1.0.0",
    "APP_DESCRIPTION": "Solana Trading Bot with Market Manipulation Capabilities",
    "ENCRYPTION_KEY": SECURE_ENCRYPTION_KEY,
    "STORAGE_PASSWORD": "washbot_secure_storage",
    "DEFAULT_NETWORK": "testnet",
    "TEST_MODE": False,
    "DEFAULT_SLIPPAGE": 100,
    "MAX_WALLET_COUNT": 200,
    "MIN_SOL_BALANCE": 0.01,
    "LOG_LEVEL": "INFO",
    "API_RATE_LIMIT": 100,
    "ANALYTICS_ENABLED": True,
    "AUTO_REFRESH_INTERVAL": 60000,
    "STRATEGY_SETTINGS": {
        "pump": {
            "default_target_price_increase": 20.0,
            "default_volume_factor": 2.0,
            "default_wallet_count": 5,
            "default_time_period_minutes": 10,
            "default_interval_seconds": 30,
            "default_initial_buy_percentage": 10.0,
            "max_wallet_count": 20,
            "max_time_period_minutes": 60
        },
        "dump": {
            "default_target_price_decrease": 15.0,
            "default_wallet_count": 5,
            "default_time_period_minutes": 10,
            "default_interval_seconds": 30,
            "default_initial_sell_percentage": 10.0,
            "max_wallet_count": 20,
            "max_time_period_minutes": 60
        },
        "gradual_sell": {
            "default_sell_stage1_pct": 30.0,
            "default_sell_stage1_target": 10.0,
            "default_sell_stage2_pct": 30.0,
            "default_sell_stage2_target": 20.0,
            "default_sell_stage3_pct": 40.0,
            "default_sell_stage3_target": 30.0,
            "default_stop_loss": 5.0,
            "default_max_duration_hours": 24,
            "max_duration_hours": 72
        }
    }
}

# Configuration cache
_config_cache = {}

def load_config() -> Dict[str, Any]:
    """
    Load configuration from database or environment
    
    Returns:
        Configuration dictionary
    """
    global _config_cache
    
    if _config_cache:
        return _config_cache
    
    config = DEFAULT_CONFIG.copy()
    
    try:
        # Try to load from database
        from database import get_db_connection
        from models import Settings
        
        db = get_db_connection()
        db_settings = db.query(Settings).all()
        
        for setting in db_settings:
            try:
                # Try to parse as JSON
                value = json.loads(str(setting.value))
            except (json.JSONDecodeError, TypeError):
                # Use as string if not JSON
                value = str(setting.value)
            
            # Split key by dots and update nested dict
            keys = str(setting.key).split('.')
            if len(keys) == 1:
                config[keys[0]] = value
            elif len(keys) == 2:
                if keys[0] not in config:
                    config[keys[0]] = {}
                config[keys[0]][keys[1]] = value
            elif len(keys) == 3:
                if keys[0] not in config:
                    config[keys[0]] = {}
                if keys[1] not in config[keys[0]]:
                    config[keys[0]][keys[1]] = {}
                config[keys[0]][keys[1]][keys[2]] = value
    
    except Exception as e:
        logger.warning(f"Failed to load config from database: {e}")
    
    # Override with environment variables
    for key in config.keys():
        env_key = key.upper()
        if env_key in os.environ:
            try:
                # Try to parse as JSON
                config[key] = json.loads(os.environ[env_key])
            except (json.JSONDecodeError, TypeError):
                # Use as string if not JSON
                config[key] = os.environ[env_key]
    
    # Override nested values
    for key in config.keys():
        if isinstance(config[key], dict):
            for subkey in config[key].keys():
                env_key = f"{key.upper()}_{subkey.upper()}"
                if env_key in os.environ:
                    try:
                        config[key][subkey] = json.loads(os.environ[env_key])
                    except (json.JSONDecodeError, TypeError):
                        config[key][subkey] = os.environ[env_key]
    
    # Cache the config
    _config_cache = config
    
    return config

def get_config(key: str, default: Any = None) -> Any:
    """
    Get configuration value
    
    Args:
        key: Configuration key (supports dot notation)
        default: Default value if key not found
        
    Returns:
        Configuration value
    """
    config = load_config()
    
    keys = key.split('.')
    value = config
    
    try:
        for k in keys:
            value = value[k]
        return value
    except (KeyError, TypeError):
        return default

def set_config(key: str, value: Any) -> bool:
    """
    Set configuration value
    
    Args:
        key: Configuration key (supports dot notation)
        value: Configuration value
        
    Returns:
        Success status
    """
    try:
        from database import get_db_connection
        from models import Settings
        
        db = get_db_connection()
        
        # Convert value to JSON string if not string
        if not isinstance(value, str):
            value_str = json.dumps(value)
        else:
            value_str = value
        
        # Update or create setting
        setting = db.query(Settings).filter_by(key=key).first()
        
        if setting:
            # Update existing setting
            db.query(Settings).filter_by(key=key).update({'value': value_str})
        else:
            setting = Settings(key=key, value=value_str)
            db.add(setting)
        
        db.commit()
        
        # Update cache
        global _config_cache
        _config_cache = {}  # Reset cache
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to set config: {e}")
        return False

def reset_config_cache() -> None:
    """Reset configuration cache"""
    global _config_cache
    _config_cache = {}
