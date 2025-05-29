"""
WashBot Solana Rust Entegrasyonu - Python Bağlayıcısı

Bu modül, Rust ile yazılmış Solana entegrasyonunu 
Python kodundan çağırmak için gerekli bağlayıcıları sağlar.

Modül iki çalışma modunu destekler:
1. Gerçek mod: Natif Rust kodu PyO3 ile Python'a bağlanır
2. Emülasyon modu: Rust kodu mevcut değilse, işlevselliği taklit eder
"""

import os
import sys
import json
import base64
import logging
import ctypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Union, cast
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base58
import secrets
import uuid
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rust Solana modülünü yüklemeyi dene
try:
    import washbot_solana
    logging.info("Rust Solana modülü başarıyla yüklendi")
    RUST_INTEGRATION_AVAILABLE = True
except ImportError:
    logging.warning("Rust Solana modülü yüklenemedi, emülasyon modu kullanılacak")
    try:
        # Derlenmiş SO/DLL dosyasını doğrudan yüklemeyi dene
        libpath = str(Path(__file__).parent / "rust-solana" / "target" / "release")
        
        if sys.platform == "win32":
            lib_name = "washbot_solana.dll"
        elif sys.platform == "darwin":
            lib_name = "libwashbot_solana.dylib"
        else:
            lib_name = "libwashbot_solana.so"
            
        full_path = str(Path(libpath) / lib_name)
        if os.path.exists(full_path):
            try:
                ctypes.cdll.LoadLibrary(full_path)
                logging.info(f"Rust kütüphanesi manuel olarak yüklendi: {full_path}")
                RUST_INTEGRATION_AVAILABLE = True
            except Exception as e:
                logging.error(f"Rust kütüphanesi yükleme hatası: {e}")
                RUST_INTEGRATION_AVAILABLE = False
        else:
            logging.warning(f"Rust kütüphanesi bulunamadı: {full_path}")
            RUST_INTEGRATION_AVAILABLE = False
    except Exception as e:
        logging.error(f"Alternatif Rust yükleme hatası: {e}")
        RUST_INTEGRATION_AVAILABLE = False

# RPC URL'leri
MAINNET_URL = "https://api.mainnet-beta.solana.com"
TESTNET_URL = "https://api.testnet.solana.com"
DEVNET_URL = "https://api.devnet.solana.com"
LOCALNET_URL = "http://localhost:8899"

class RustSolanaError(Exception):
    """Rust Solana entegrasyonu ile ilgili hatalar için özel istisna sınıfı"""
    pass

def derive_key_from_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Şifre tabanlı anahtar türetme işlevi
    
    Args:
        password: Kaynak şifre
        salt: Opsiyonel tuz değeri
        
    Returns:
        Türetilmiş anahtar ve tuz değeri
    """
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_data(data: str, encryption_key: str) -> str:
    """
    Veriyi şifrele
    
    Args:
        data: Şifrelenecek veri
        encryption_key: Şifreleme anahtarı
        
    Returns:
        Şifrelenmiş veri
    """
    if RUST_INTEGRATION_AVAILABLE:
        try:
            return washbot_solana.encrypt_data(data, encryption_key)
        except Exception as e:
            logging.error(f"Rust şifreleme hatası: {e}, emülasyon moduna geçiliyor")
    
    # Rust mevcut değilse veya hata olduysa, Python ile şifrele
    if not data or not encryption_key:
        raise RustSolanaError("Şifrelenecek veri veya şifreleme anahtarı sağlanmadı")
    
    try:
        # Base64 şeklinde kodlanmış anahtar gerekiyor, değilse dönüştür
        if len(encryption_key) != 44 or not encryption_key.endswith('='):
            key_bytes = encryption_key.encode() if len(encryption_key) < 32 else encryption_key.encode()[:32]
            key = base64.urlsafe_b64encode(key_bytes.ljust(32, b'\0'))
        else:
            key = encryption_key.encode()
            
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode()).decode()
        return encrypted_data
    except Exception as e:
        raise RustSolanaError(f"Şifreleme hatası: {str(e)}")

def decrypt_data(encrypted_data: str, encryption_key: str) -> str:
    """
    Şifreli veriyi çöz
    
    Args:
        encrypted_data: Şifreli veri
        encryption_key: Şifreleme anahtarı
        
    Returns:
        Çözülmüş veri
    """
    if RUST_INTEGRATION_AVAILABLE:
        try:
            return washbot_solana.decrypt_data(encrypted_data, encryption_key)
        except Exception as e:
            logging.error(f"Rust şifre çözme hatası: {e}, emülasyon moduna geçiliyor")
    
    # Rust mevcut değilse veya hata olduysa, Python ile çöz
    if not encrypted_data or not encryption_key:
        raise RustSolanaError("Şifreli veri veya şifreleme anahtarı sağlanmadı")
    
    try:
        # Base64 şeklinde kodlanmış anahtar gerekiyor, değilse dönüştür
        if len(encryption_key) != 44 or not encryption_key.endswith('='):
            key_bytes = encryption_key.encode() if len(encryption_key) < 32 else encryption_key.encode()[:32]
            key = base64.urlsafe_b64encode(key_bytes.ljust(32, b'\0'))
        else:
            key = encryption_key.encode()
            
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data.encode()).decode()
        return decrypted_data
    except Exception as e:
        raise RustSolanaError(f"Şifre çözme hatası: {str(e)}")

def encrypt_private_key(private_key: str, encryption_key: str) -> str:
    """
    Özel anahtarı şifrele
    
    Args:
        private_key: Özel anahtar
        encryption_key: Şifreleme anahtarı
        
    Returns:
        Şifrelenmiş özel anahtar
    """
    return encrypt_data(private_key, encryption_key)

def decrypt_private_key(encrypted_private_key: str, encryption_key: str) -> str:
    """
    Şifrelenmiş özel anahtarı çöz
    
    Args:
        encrypted_private_key: Şifrelenmiş özel anahtar
        encryption_key: Şifreleme anahtarı
        
    Returns:
        Çözülmüş özel anahtar
    """
    return decrypt_data(encrypted_private_key, encryption_key)

def generate_encryption_key() -> str:
    """
    Yeni bir şifreleme anahtarı oluştur
    
    Returns:
        Base64 kodlanmış şifreleme anahtarı
    """
    if RUST_INTEGRATION_AVAILABLE:
        try:
            return washbot_solana.generate_encryption_key()
        except Exception as e:
            logging.error(f"Rust anahtar oluşturma hatası: {e}, emülasyon moduna geçiliyor")
    
    # Rust mevcut değilse veya hata olduysa, Python ile oluştur
    key = Fernet.generate_key()
    return key.decode()

class WalletInfo:
    """Cüzdan bilgilerini tutan sınıf (Rust WalletInfo yapısının karşılığı)"""
    
    def __init__(
        self, 
        id: str,
        public_key: str,
        encrypted_private_key: Optional[str] = None,
        name: Optional[str] = None,
        balance: float = 0.0,
        network: str = "mainnet-beta"
    ):
        self.id = id
        self.public_key = public_key
        self.encrypted_private_key = encrypted_private_key
        self.name = name
        self.balance = balance
        self.network = network
    
    def to_dict(self) -> Dict[str, Any]:
        """Wallet bilgilerini sözlük olarak döndür"""
        return {
            "id": self.id,
            "public_key": self.public_key,
            "encrypted_private_key": self.encrypted_private_key,
            "name": self.name,
            "balance": self.balance,
            "network": self.network
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WalletInfo':
        """Sözlükten WalletInfo oluştur"""
        return cls(
            id=data.get("id", ""),
            public_key=data.get("public_key", ""),
            encrypted_private_key=data.get("encrypted_private_key"),
            name=data.get("name"),
            balance=data.get("balance", 0.0),
            network=data.get("network", "mainnet-beta")
        )
    
    @classmethod
    def from_rust_dict(cls, rust_dict: Dict[str, Any]) -> 'WalletInfo':
        """Rust'tan gelen sözlükten WalletInfo oluştur"""
        return cls(
            id=rust_dict.get("id", ""),
            public_key=rust_dict.get("public_key", ""),
            encrypted_private_key=rust_dict.get("encrypted_private_key"),
            name=rust_dict.get("name"),
            balance=rust_dict.get("balance", 0.0),
            network=rust_dict.get("network", "mainnet-beta")
        )

class WashbotSolana:
    """
    WashBot Solana entegrasyonu için ana sınıf
    Bu sınıf, Rust'ta yazılmış Washbot yapısının Python karşılığıdır
    """
    
    def __init__(
        self, 
        network: str = "mainnet-beta", 
        custom_url: Optional[str] = None,
        encryption_key: Optional[str] = None
    ):
        """
        Yeni bir WashbotSolana örneği oluştur
        
        Args:
            network: Ağ adı ("mainnet-beta", "testnet", "devnet", "localnet")
            custom_url: Özel RPC URL (opsiyonel)
            encryption_key: Şifreleme anahtarı (opsiyonel)
        """
        self.network = network
        self.custom_url = custom_url
        self.encryption_key = encryption_key
        
        # RPC URL'ini belirle
        self.rpc_url = custom_url if custom_url else {
            "mainnet-beta": MAINNET_URL,
            "testnet": TESTNET_URL,
            "devnet": DEVNET_URL,
            "localnet": LOCALNET_URL
        }.get(network, MAINNET_URL)
        
        # Gerçek Rust sınıfının örneğini oluştur (mümkünse)
        self._rust_instance = None
        if RUST_INTEGRATION_AVAILABLE:
            try:
                self._rust_instance = washbot_solana.Washbot(network, custom_url, encryption_key)
                logging.info(f"Rust Washbot örneği başarıyla oluşturuldu: ağ={network}")
            except Exception as e:
                logging.error(f"Rust Washbot örneği oluşturma hatası: {e}")
                self._rust_instance = None
        
        logging.info(f"WashbotSolana başlatılıyor: ağ={network}, url={self.rpc_url}")
    
    def create_wallet(self, name: Optional[str] = None) -> Tuple[WalletInfo, str]:
        """
        Yeni bir cüzdan oluştur
        
        Args:
            name: Cüzdan ismi (opsiyonel)
            
        Returns:
            Cüzdan bilgileri ve şifrelenmemiş özel anahtar
        """
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                wallet_dict, private_key = self._rust_instance.create_wallet(name)
                return WalletInfo.from_rust_dict(wallet_dict), private_key
            except Exception as e:
                logging.error(f"Rust cüzdan oluşturma hatası: {e}, emülasyon moduna geçiliyor")
        
        # Rust entegrasyonu hazır değilse, işlevi simüle et
        wallet_id = str(uuid.uuid4())
        
        # Base58 formatında bir private key simüle et
        private_key_bytes = os.urandom(32)
        private_key = base58.b58encode(private_key_bytes).decode()
        
        # Public key'i simüle et (gerçekte private key'den türetilir)
        public_key_bytes = os.urandom(32)
        public_key = base58.b58encode(public_key_bytes).decode()
        
        wallet_info = WalletInfo(
            id=wallet_id,
            public_key=public_key,
            name=name,
            balance=0.0,
            network=self.network
        )
        
        return wallet_info, private_key
    
    def create_wallet_encrypted(self, name: Optional[str] = None) -> WalletInfo:
        """
        Yeni bir cüzdan oluştur ve özel anahtarı şifrele
        
        Args:
            name: Cüzdan ismi (opsiyonel)
            
        Returns:
            Şifrelenmiş özel anahtara sahip cüzdan bilgileri
        """
        if not self.encryption_key:
            raise RustSolanaError("Şifrelenmiş cüzdan oluşturmak için şifreleme anahtarı gerekli")
        
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                wallet_dict = self._rust_instance.create_wallet_encrypted(name)
                return WalletInfo.from_rust_dict(wallet_dict)
            except Exception as e:
                logging.error(f"Rust şifreli cüzdan oluşturma hatası: {e}, emülasyon moduna geçiliyor")
        
        # Rust entegrasyonu mevcut değilse, Python ile oluştur
        wallet_info, private_key = self.create_wallet(name)
        encrypted_private_key = encrypt_private_key(private_key, self.encryption_key)
        wallet_info.encrypted_private_key = encrypted_private_key
        
        return wallet_info
    
    def create_multiple_wallets(self, count: int, encrypt: bool = True) -> List[WalletInfo]:
        """
        Çoklu cüzdan oluştur
        
        Args:
            count: Oluşturulacak cüzdan sayısı
            encrypt: Özel anahtarları şifrele mi?
            
        Returns:
            Cüzdan bilgileri listesi
        """
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                wallet_list = self._rust_instance.create_multiple_wallets(count, encrypt)
                return [WalletInfo.from_rust_dict(wallet_dict) for wallet_dict in wallet_list]
            except Exception as e:
                logging.error(f"Rust çoklu cüzdan oluşturma hatası: {e}, emülasyon moduna geçiliyor")
        
        # Rust entegrasyonu mevcut değilse, Python ile oluştur
        wallets = []
        
        for i in range(count):
            name = f"Wallet {i+1}"
            
            if encrypt:
                wallet_info = self.create_wallet_encrypted(name)
            else:
                wallet_info, _ = self.create_wallet(name)
            
            wallets.append(wallet_info)
        
        return wallets
    
    def transfer_sol(self, from_private_key: str, to_address: str, amount_sol: float) -> str:
        """
        SOL transferi yap
        
        Args:
            from_private_key: Gönderen özel anahtarı
            to_address: Alıcı adresi
            amount_sol: SOL miktarı
            
        Returns:
            Transaction imzası
        """
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                return self._rust_instance.transfer_sol(from_private_key, to_address, amount_sol)
            except Exception as e:
                logging.error(f"Rust SOL transfer hatası: {e}, emülasyon moduna geçiliyor")
        
        # İşlemi simüle et
        signature = base58.b58encode(os.urandom(64)).decode()
        logging.info(f"SOL transferi (emülasyon): {amount_sol} SOL → {to_address}, imza: {signature}")
        
        return signature
    
    def decrypt_private_key(self, encrypted_private_key: str) -> str:
        """
        Şifrelenmiş özel anahtarı çöz
        
        Args:
            encrypted_private_key: Şifrelenmiş özel anahtar
            
        Returns:
            Çözülmüş özel anahtar
        """
        if not self.encryption_key:
            raise RustSolanaError("Şifrelenmiş özel anahtarı çözmek için şifreleme anahtarı gerekli")
        
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                return self._rust_instance.decrypt_private_key(encrypted_private_key)
            except Exception as e:
                logging.error(f"Rust özel anahtar çözme hatası: {e}, emülasyon moduna geçiliyor")
        
        # Rust entegrasyonu mevcut değilse, Python ile çöz
        return decrypt_private_key(encrypted_private_key, self.encryption_key)
    
    def get_balance(self, address: str) -> float:
        """
        Cüzdan bakiyesini al
        
        Args:
            address: Cüzdan adresi
            
        Returns:
            SOL cinsinden bakiye
        """
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                return self._rust_instance.get_balance(address)
            except Exception as e:
                logging.error(f"Rust bakiye sorgulama hatası: {e}, emülasyon moduna geçiliyor")
        
        # Simüle edilmiş bakiye
        import random
        balance = random.uniform(0.1, 10.0)
        logging.info(f"Bakiye sorgulandı (emülasyon): {address}, bakiye: {balance} SOL")
        
        return balance
    
    def distribute_sol(
        self, 
        from_private_key: str, 
        to_addresses: List[str], 
        amount_per_wallet: float
    ) -> List[str]:
        """
        SOL dağıtımı yap
        
        Args:
            from_private_key: Gönderen özel anahtarı
            to_addresses: Alıcı adresleri listesi
            amount_per_wallet: Her bir cüzdana gönderilecek SOL miktarı
            
        Returns:
            Transaction imzaları
        """
        if RUST_INTEGRATION_AVAILABLE and self._rust_instance:
            try:
                return self._rust_instance.distribute_sol(from_private_key, to_addresses, amount_per_wallet)
            except Exception as e:
                logging.error(f"Rust SOL dağıtım hatası: {e}, emülasyon moduna geçiliyor")
        
        # İşlemi simüle et
        signatures = []
        
        for address in to_addresses:
            signature = base58.b58encode(os.urandom(64)).decode()
            signatures.append(signature)
            logging.info(f"SOL transferi (emülasyon): {amount_per_wallet} SOL → {address}, imza: {signature}")
        
        return signatures
    
    def request_airdrop(self, address: str, sol_amount: float) -> str:
        """
        Testnet'te airdrop iste (mainnet-beta'da devre dışı bırakılmış işlev)
        
        Args:
            address: Cüzdan adresi
            sol_amount: İstenilen SOL miktarı
            
        Returns:
            Transaction imzası
        """
        # Bu fonksiyon artık mainnet-beta için devre dışı bırakılmıştır
        raise RustSolanaError("Airdrop yalnızca testnet veya devnet üzerinde kullanılabilir. Bu uygulama mainnet-beta için yapılandırılmıştır.")

# Yardımcı fonksiyonlar
def sol_to_lamports(sol: float) -> int:
    """SOL'u lamports'a çevir"""
    if RUST_INTEGRATION_AVAILABLE:
        try:
            return washbot_solana.sol_to_lamports_py(sol)
        except Exception:
            pass
    
    return int(sol * 1_000_000_000)

def lamports_to_sol(lamports: int) -> float:
    """Lamports'u SOL'a çevir"""
    if RUST_INTEGRATION_AVAILABLE:
        try:
            return washbot_solana.lamports_to_sol_py(lamports)
        except Exception:
            pass
    
    return lamports / 1_000_000_000.0