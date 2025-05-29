import os
import json
import uuid
import random
import logging
import asyncio
import time
from decimal import Decimal
from typing import Dict, Any, List, Optional, Union
import base64

from security import SecurityManager
import solana_utils
from database import get_db_connection, init_db
from models import Wallet, TokenBalance, Transaction

# Enhanced Solana Program Addresses for wallet operations
SOLANA_PROGRAMS = {
    "SPL_TOKEN": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "ASSOCIATED_TOKEN": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 
    "SYSTEM": "11111111111111111111111111111111",
    "WRAPPED_SOL": "So11111111111111111111111111111111111111112",
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
}

# Rust entegrasyonunu içe aktar (kullanılabilirse)
try:
    import rust_solana
    from rust_solana import WashbotSolana, generate_encryption_key
    RUST_INTEGRATION_AVAILABLE = True
    logging.info("Rust Solana entegrasyonu başarıyla yüklendi")
except ImportError:
    RUST_INTEGRATION_AVAILABLE = False
    logging.warning("Rust Solana entegrasyonu yüklenemedi, standart Python uygulaması kullanılacak")
# WalletData class definition
class WalletData:
    def __init__(self, id, public_key=None, private_key=None, name=None, balance=0, network='devnet'):
        self.id = id
        self.public_key = public_key
        self.private_key = private_key  # Only in memory, never stored
        self.name = name
        self.balance = balance
        self.network = network
        
    def to_dict(self):
        return {
            "id": str(self.id) if self.id else None,
            "public_key": str(self.public_key) if self.public_key else None,
            "name": str(self.name) if self.name else None,
            "balance": float(self.balance) if self.balance is not None else 0.0,
            "network": str(self.network) if self.network else "mainnet-beta"
        }

logger = logging.getLogger(__name__)

# Constants
WALLET_STORAGE_FILE = "wallet_storage.json"

async def create_wallet(encryption_key, storage_password, network='mainnet-beta', airdrop=False, airdrop_amount=0, name=None):
    """
    Create a new wallet and store it securely
    
    Args:
        encryption_key: Key for encrypting private key
        storage_password: Password for storage access
        network: Solana network (default: mainnet-beta)
        airdrop: Whether to request airdrop (deprecated, ignored on mainnet)
        airdrop_amount: Amount of SOL to airdrop (deprecated, ignored on mainnet)
        name: Custom wallet name
        
    Returns:
        WalletData object
    """
    try:
        wallet_result = {}
        private_key = None
        
        # Rust entegrasyonunu kullan (mevcutsa)
        if RUST_INTEGRATION_AVAILABLE:
            try:
                # Rust ile cüzdan oluştur
                logger.info(f"Rust entegrasyonu ile {network} ağında cüzdan oluşturuluyor")
                washbot = WashbotSolana(network=network, encryption_key=encryption_key)
                
                # Şifrelenmiş özel anahtarla cüzdan oluştur
                if name:
                    wallet_info, private_key = washbot.create_wallet(name)
                else:
                    wallet_info, private_key = washbot.create_wallet()
                
                # Sonuçları Python yapısına dönüştür
                wallet_result = {
                    'success': True,
                    'public_key': wallet_info.public_key,
                    'private_key': private_key,
                    'balance': 0
                }
                
                # Airdrop testnet/devnet'te çalışır, üretim ortamında devre dışı bırakıldı
                # Mainnet-beta'da SOL bakiyesi sıfırdan başlar
                
            except Exception as rust_err:
                logger.warning(f"Rust entegrasyonu ile cüzdan oluşturma başarısız oldu: {rust_err}. Python'a dönülüyor.")
                # Python'a dön
                RUST_INTEGRATION_AVAILABLE = False
        
        # Rust başarısız olduysa veya mevcut değilse, Python ile devam et
        if not RUST_INTEGRATION_AVAILABLE or not wallet_result.get('success', False):
            # Create wallet on Solana (without airdrop first)
            wallet_result = await solana_utils.create_wallet(network, airdrop=False)
            
            if not wallet_result.get('success', False):
                logger.error(f"Failed to create wallet: {wallet_result.get('error')}")
                return None
                
            # Airdrop testnet/devnet'te çalışır, üretim ortamında devre dışı bırakıldı
            # Mainnet-beta'da SOL bakiyesi sıfırdan başlar
            wallet_result['balance'] = 0
            
            private_key = wallet_result['private_key']
        
        # Güvenlik yöneticisi oluştur ve anahtarı şifrele
        # Native Rust şifreleme kullanılmadıysa bu adımı gerçekleştir
        security = SecurityManager(encryption_key)
        encrypted_private_key = security.encrypt_data(private_key)
        
        # Generate unique ID for the wallet
        wallet_id = str(uuid.uuid4())
        
        # Create wallet data object
        wallet_data = WalletData(
            id=wallet_id,
            public_key=wallet_result['public_key'],
            private_key=private_key,  # Store unencrypted in memory
            name=name or f"Wallet-{wallet_id[:8]}",
            balance=wallet_result['balance'],
            network=network
        )
        
        # Store wallet in database
        db = get_db_connection()
        
        # Check if wallet already exists
        existing_wallet = db.query(Wallet).filter_by(address=wallet_result['public_key']).first()
        
        if existing_wallet:
            logger.warning(f"Wallet with public key {wallet_result['public_key']} already exists")
            
            # Return existing wallet data (without private key)
            wallet_data = WalletData(
                id=existing_wallet.id,
                public_key=existing_wallet.address,
                name=existing_wallet.label,
                balance=existing_wallet.balance,
                network=existing_wallet.network
            )
            
            return wallet_data
        
        # Create new wallet in database
        new_wallet = Wallet(
            id=wallet_id,
            address=wallet_result['public_key'],
            encrypted_private_key=encrypted_private_key,
            label=wallet_data.name,
            balance=wallet_result['balance'],
            network=network
        )
        
        db.add(new_wallet)
        db.commit()
        
        logger.info(f"Wallet created: {wallet_id} ({wallet_result['public_key']})")
        
        return wallet_data
        
    except Exception as e:
        logger.error(f"Error creating wallet: {e}")
        return None

async def create_multiple_wallets(count=1, encryption_key=None, storage_password=None, network='mainnet-beta', airdrop=False, airdrop_amount=0):
    """
    Create multiple wallets
    
    Args:
        count: Number of wallets to create
        encryption_key: Key for encryption
        storage_password: Storage password
        network: Solana network (default: mainnet-beta)
        airdrop: Whether to request airdrop (deprecated, ignored on mainnet)
        airdrop_amount: Amount of SOL to airdrop per wallet (deprecated, ignored on mainnet)
        
    Returns:
        List of WalletData objects
    """
    try:
        # Ensure count is an integer
        if isinstance(count, str):
            count = int(count)
            
        # Limit count to reasonable range
        count = max(1, min(200, count))
        
        logger.info(f"Creating {count} wallets on {network} network")
        if airdrop:
            logger.info(f"Will request airdrop of {airdrop_amount} SOL per wallet")
        
        # Rust entegrasyonunu kullan (mevcutsa)
        if RUST_INTEGRATION_AVAILABLE:
            try:
                logger.info(f"Rust entegrasyonu ile {count} cüzdan oluşturuluyor")
                # Rust ile çoklu cüzdan oluştur
                washbot = WashbotSolana(network=network, encryption_key=encryption_key)
                rust_wallets = washbot.create_multiple_wallets(count, encrypt=True)
                
                # Rust cüzdanlarını veritabanına kaydet ve WalletData nesnelerine dönüştür
                result_wallets = []
                db = get_db_connection()
                
                for i, wallet_info in enumerate(rust_wallets):
                    # Wallet ID oluştur
                    wallet_id = str(uuid.uuid4())
                    
                    # Wallet adını ayarla
                    wallet_name = f"Wallet-{i+1}"
                    
                    # Özel anahtarı al (doğrudan şifrelenmiş olarak gelir)
                    rust_private_key = washbot.decrypt_private_key(wallet_info.encrypted_private_key)
                    
                    # Python güvenlik yöneticisi ile anahtarı şifrele (veritabanında tutmak için)
                    security = SecurityManager(encryption_key)
                    encrypted_private_key = security.encrypt_data(rust_private_key)
                    
                    # Airdrop iste (gerekirse)
                    wallet_balance = 0
                    if airdrop and network in ['devnet', 'testnet']:
                        try:
                            logger.info(f"Wallet {i+1} için {airdrop_amount} SOL airdrop isteniyor")
                            washbot.request_airdrop(wallet_info.public_key, airdrop_amount)
                            wallet_balance = airdrop_amount
                        except Exception:
                            # Hata durumunda Python ile tekrar dene
                            try:
                                airdrop_result = await solana_utils.request_airdrop(
                                    public_key=wallet_info.public_key,
                                    network=network,
                                    amount_sol=airdrop_amount
                                )
                                
                                if airdrop_result.get('success', False):
                                    wallet_balance = airdrop_amount
                            except Exception as airdrop_err:
                                logger.warning(f"Airdrop failed for wallet {i+1}: {airdrop_err}")
                    
                    # Veritabanına kaydet
                    # Önce mevcut mu kontrol et
                    existing_wallet = db.query(Wallet).filter_by(address=wallet_info.public_key).first()
                    
                    if not existing_wallet:
                        new_wallet = Wallet(
                            id=wallet_id,
                            address=wallet_info.public_key,
                            encrypted_private_key=encrypted_private_key,
                            label=wallet_name,
                            balance=wallet_balance,
                            network=network
                        )
                        
                        db.add(new_wallet)
                        
                        # WalletData nesnesi oluştur
                        wallet_data = WalletData(
                            id=wallet_id,
                            public_key=wallet_info.public_key,
                            private_key=rust_private_key,  # Sadece hafızada tut
                            name=wallet_name,
                            balance=wallet_balance,
                            network=network
                        )
                    else:
                        # Varolan cüzdan bilgisini kullan
                        wallet_data = WalletData(
                            id=existing_wallet.id,
                            public_key=existing_wallet.address,
                            name=existing_wallet.label,
                            balance=existing_wallet.balance,
                            network=existing_wallet.network
                        )
                    
                    result_wallets.append(wallet_data)
                
                # Tüm değişiklikleri kaydet
                db.commit()
                
                if result_wallets:
                    logger.info(f"Rust entegrasyonu ile {len(result_wallets)} cüzdan başarıyla oluşturuldu")
                    return result_wallets
                
            except Exception as rust_err:
                logger.warning(f"Rust entegrasyonu ile çoklu cüzdan oluşturma başarısız oldu: {rust_err}. Python'a dönülüyor.")
                # Python'a dön
        
        # Python ile paralel cüzdan oluşturma
        logger.info("Python entegrasyonu ile çoklu cüzdan oluşturuluyor")
        tasks = []
        for i in range(count):
            tasks.append(create_wallet(
                encryption_key=encryption_key,
                storage_password=storage_password,
                network=network,
                airdrop=airdrop,
                airdrop_amount=airdrop_amount,
                name=f"Wallet-{i+1}"
            ))
        
        # Wait for all wallets to be created
        wallets = await asyncio.gather(*tasks)
        
        # Filter out None values (failed wallet creations)
        wallets = [w for w in wallets if w is not None]
        
        logger.info(f"Python entegrasyonu ile {len(wallets)} cüzdan başarıyla oluşturuldu")
        return wallets
        
    except Exception as e:
        logger.error(f"Error creating multiple wallets: {e}")
        return []

async def get_all_wallets(encryption_key, storage_password):
    """
    Get all stored wallets
    
    Args:
        encryption_key: Key for decryption
        storage_password: Storage password
        
    Returns:
        List of WalletData objects
    """
    try:
        # Initialize security manager
        security = SecurityManager(encryption_key)
        
        # Get wallets from database
        db = get_db_connection()
        db_wallets = db.query(Wallet).all()
        
        # Convert to WalletData objects
        wallets = []
        for db_wallet in db_wallets:
            try:
                # Decrypt private key with current encryption key
                if db_wallet.encrypted_private_key:
                    try:
                        private_key = security.decrypt_data(db_wallet.encrypted_private_key)
                    except Exception as decrypt_err:
                        # Try with different encryption keys if current fails
                        old_keys = [
                            "WashBot2025ProductionEncryptionKey_SecureMainnet_7f8a9b2c3d4e5f6g7h8i9j0k",
                            "deployment-ready-washbot-solana-2024",
                            "washbot-secure-session-key-2024"
                        ]
                        private_key = None
                        for old_key in old_keys:
                            try:
                                old_security = SecurityManager(old_key)
                                private_key = old_security.decrypt_data(db_wallet.encrypted_private_key)
                                # Re-encrypt with current key and update
                                db_wallet.encrypted_private_key = security.encrypt_data(private_key)
                                break
                            except:
                                continue
                        
                        if private_key is None:
                            logger.warning(f"Cüzdan {db_wallet.id} için şifre çözme başarısız")
                else:
                    private_key = None
                
                wallet_data = WalletData(
                    id=db_wallet.id,
                    public_key=db_wallet.address,  # Değiştirilen alan: public_key -> address
                    private_key=private_key,
                    name=db_wallet.label,  # Değiştirilen alan: name -> label
                    balance=db_wallet.balance,
                    network=db_wallet.network
                )
                
                wallets.append(wallet_data)
                
            except Exception as inner_e:
                logger.error(f"Error processing wallet {db_wallet.id}: {inner_e}")
        
        return wallets
        
    except Exception as e:
        logger.error(f"Error getting all wallets: {e}")
        return []

async def get_wallet_by_id(wallet_id, encryption_key, storage_password):
    """
    Get a wallet by ID
    
    Args:
        wallet_id: Wallet ID
        encryption_key: Key for decryption
        storage_password: Storage password
        
    Returns:
        WalletData object or None
    """
    try:
        # Initialize security manager
        security = SecurityManager(encryption_key)
        
        # Get wallet from database
        from database import db_session
        db_wallet = db_session.query(Wallet).filter_by(id=wallet_id).first()
        
        if not db_wallet:
            logger.warning(f"Wallet not found: {wallet_id}")
            return None
        
        # Decrypt private key with fallback to old encryption keys
        if db_wallet.encrypted_private_key:
            try:
                private_key = security.decrypt_data(db_wallet.encrypted_private_key)
            except Exception:
                # Try with different encryption keys if current fails
                old_keys = [
                    "WashBot2025ProductionEncryptionKey_SecureMainnet_7f8a9b2c3d4e5f6g7h8i9j0k",
                    "deployment-ready-washbot-solana-2024",
                    "washbot-secure-session-key-2024"
                ]
                private_key = None
                for old_key in old_keys:
                    try:
                        old_security = SecurityManager(old_key)
                        private_key = old_security.decrypt_data(db_wallet.encrypted_private_key)
                        # Re-encrypt with current key and update
                        db_wallet.encrypted_private_key = security.encrypt_data(private_key)
                        break
                    except:
                        continue
                
                if private_key is None:
                    logger.error(f"Could not decrypt private key for wallet {wallet_id}")
                    return None
        else:
            private_key = None
        
        # Create WalletData object
        wallet_data = WalletData(
            id=db_wallet.id,
            public_key=db_wallet.address,
            private_key=private_key,
            name=db_wallet.label,  # Database'de label olarak saklanıyor
            balance=db_wallet.balance,
            network=db_wallet.network
        )
        
        return wallet_data
        
    except Exception as e:
        logger.error(f"Error getting wallet by ID {wallet_id}: {e}")
        logger.error(f"Full error details: {type(e).__name__}: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None

async def update_wallet_balances(wallets, network='devnet'):
    """
    Update SOL balances for wallets
    
    Args:
        wallets: List of WalletData objects
        network: Solana network
        
    Returns:
        Updated list of WalletData objects
    """
    try:
        # Rust entegrasyonunu kullan (mevcutsa)
        if RUST_INTEGRATION_AVAILABLE:
            try:
                logger.info(f"Rust entegrasyonu ile {len(wallets)} cüzdan bakiyesi güncelleniyor")
                
                # Rust ile cüzdan bakiyelerini sorgula
                washbot = WashbotSolana(network=network)
                
                # Rust ile bakiyeleri tek tek sorgula (paralel sorgulama henüz desteklenmiyor)
                db = get_db_connection()
                updated_wallets = []
                
                for wallet in wallets:
                    try:
                        # Bakiyeyi sorgula
                        balance = washbot.get_balance(wallet.public_key)
                        
                        # Wallet nesnesi güncelle
                        wallet.balance = balance
                        
                        # Veritabanını güncelle
                        db_wallet = db.query(Wallet).filter_by(id=wallet.id).first()
                        if db_wallet:
                            db_wallet.balance = balance
                            db_wallet.updated_at = None  # Otomatik zaman damgası güncellemesi
                    except Exception as inner_err:
                        logger.warning(f"Rust ile bakiye sorgulaması başarısız: {wallet.public_key}, hata: {inner_err}")
                    
                    updated_wallets.append(wallet)
                
                # Değişiklikleri kaydet
                db.commit()
                
                if updated_wallets:
                    logger.info(f"Rust entegrasyonu ile {len(updated_wallets)} cüzdan bakiyesi güncellendi")
                    return updated_wallets
                
            except Exception as rust_err:
                logger.warning(f"Rust entegrasyonu ile bakiye güncellemesi başarısız oldu: {rust_err}. Python'a dönülüyor.")
        
        # Python ile bakiyeleri güncelle
        logger.info(f"Python entegrasyonu ile {len(wallets)} cüzdan bakiyesi güncelleniyor")
        
        # Update balances in parallel
        tasks = []
        for wallet in wallets:
            tasks.append(solana_utils.get_balance(wallet.public_key, network))
        
        # Wait for all balance updates
        balance_results = await asyncio.gather(*tasks)
        
        # Update wallet objects
        db = get_db_connection()
        updated_wallets = []
        
        for i, wallet in enumerate(wallets):
            balance_result = balance_results[i]
            
            if balance_result.get('success', False):
                # Update wallet balance
                wallet.balance = balance_result['balance_sol']
                
                # Update in database
                db_wallet = db.query(Wallet).filter_by(id=wallet.id).first()
                if db_wallet:
                    db_wallet.balance = wallet.balance
                    db_wallet.updated_at = None  # Trigger auto-update of timestamp
                
                updated_wallets.append(wallet)
            else:
                # Keep original wallet if update failed
                updated_wallets.append(wallet)
        
        # Commit changes
        db.commit()
        
        logger.info(f"Python entegrasyonu ile {len(updated_wallets)} cüzdan bakiyesi güncellendi")
        return updated_wallets
        
    except Exception as e:
        logger.error(f"Error updating wallet balances: {e}")
        return wallets

async def delete_wallet(wallet_id):
    """
    Delete wallet by ID
    
    Args:
        wallet_id: Wallet ID to delete
        
    Returns:
        Success status (boolean) and message
    """
    try:
        # Get database connection
        session = get_db_connection()
        
        # Get wallet from database
        wallet = session.query(Wallet).filter(Wallet.id == wallet_id).first()
        
        if not wallet:
            logger.warning(f"Wallet not found for deletion: {wallet_id}")
            return {
                "success": False,
                "error": "Cüzdan bulunamadı."
            }
        
        # Store wallet address and label for logging
        wallet_address = wallet.address
        wallet_name = wallet.label or wallet_address[:8] if wallet_address else "Cüzdan"
        
        # Delete related records first to maintain foreign key integrity
        
        # Delete token balances
        session.query(TokenBalance).filter(TokenBalance.wallet_id == wallet_id).delete()
        
        # Delete transactions
        session.query(Transaction).filter(Transaction.wallet_id == wallet_id).delete()
        
        # Delete wallet
        session.delete(wallet)
        session.commit()
        
        logger.info(f"Successfully deleted wallet: {wallet_id} ({wallet_name})")
        return {
            "success": True,
            "message": f"Cüzdan başarıyla silindi: {wallet_name}"
        }
        
    except Exception as e:
        logger.error(f"Error deleting wallet: {e}")
        try:
            session.rollback()
        except:
            pass
            
        return {
            "success": False,
            "error": f"Cüzdan silinirken hata oluştu: {str(e)}"
        }

async def distribute_sol_to_wallets(main_wallet, wallets, min_amount, max_amount=None, randomize=True, encryption_key=None):
    """
    Distribute SOL from main wallet to multiple wallets
    
    Args:
        main_wallet: Main wallet to distribute from
        wallets: List of target wallets
        min_amount: Minimum amount to send
        max_amount: Maximum amount to send (if randomizing)
        randomize: Whether to randomize amounts
        encryption_key: Key for decryption
        
    Returns:
        Success status or dict with details
    """
    try:
        # Validate parameters
        if not main_wallet or not main_wallet.private_key:
            logger.error("Main wallet private key not available")
            return {
                "success": False,
                "error": "Main wallet private key not available"
            }
        
        if not wallets:
            logger.error("No target wallets provided")
            return {
                "success": False,
                "error": "No target wallets provided"
            }
        
        # Rust entegrasyonunu kullan (mevcutsa)
        if RUST_INTEGRATION_AVAILABLE:
            try:
                logger.info(f"Rust entegrasyonu ile SOL dağıtımı başlatılıyor: {len(wallets)} cüzdana")
                
                # Hazırlık
                addresses = [wallet.public_key for wallet in wallets]
                main_private_key = main_wallet.private_key
                network = main_wallet.network
                
                # Bakiyeleri kontrol et
                washbot = WashbotSolana(network=network)
                main_balance = washbot.get_balance(main_wallet.public_key)
                
                # Gönderilecek toplam miktarı hesapla
                if randomize and max_amount is not None:
                    # Ortalama miktarı hesapla
                    avg_amount = (min_amount + max_amount) / 2
                    total_needed = avg_amount * len(wallets)
                else:
                    total_needed = min_amount * len(wallets)
                
                # Ana cüzdanda yeterli bakiye var mı kontrol et
                if main_balance < total_needed + 0.01:  # İşlem ücretleri için 0.01 SOL tut
                    error_msg = f"Ana cüzdanda yetersiz bakiye: {main_balance} SOL, ihtiyaç: {total_needed + 0.01} SOL"
                    logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                # Dağıtım detaylarını hazırla
                distribution_details = []
                
                # Miktarları hesapla
                if randomize and max_amount is not None:
                    amounts = [round(random.uniform(min_amount, max_amount), 4) for _ in wallets]
                else:
                    amounts = [min_amount] * len(wallets)
                
                # Dağıtım detaylarını kaydet
                for i, wallet in enumerate(wallets):
                    distribution_details.append({
                        "wallet_id": wallet.id,
                        "public_key": wallet.public_key,
                        "amount": amounts[i]
                    })
                
                # Rust ile SOL transferlerini gerçekleştir (toplu transfer metodunu kullan)
                amount_per_wallet = amounts[0] if min_amount == max_amount or max_amount is None else None
                
                successful_transfers = []
                failed_transfers = []
                
                if amount_per_wallet is not None:
                    # Sabit miktar - toplu transfer kullan
                    try:
                        signatures = washbot.distribute_sol(main_private_key, addresses, amount_per_wallet)
                        
                        # Başarılı sonuçları işle
                        for i, signature in enumerate(signatures):
                            if i < len(distribution_details):
                                successful_transfers.append({
                                    **distribution_details[i],
                                    "txid": signature
                                })
                        
                        # Başarısız transferleri kontrol et
                        for i in range(len(signatures), len(distribution_details)):
                            failed_transfers.append({
                                **distribution_details[i],
                                "error": "Transaction not processed by Rust module"
                            })
                        
                        logger.info(f"Rust SOL dağıtımı tamamlandı: {len(signatures)} başarılı, {len(distribution_details) - len(signatures)} başarısız transfer")
                        
                    except Exception as bulk_err:
                        logger.warning(f"Rust toplu transfer hatası: {bulk_err}, tek tek işlemlere geçiliyor")
                        # Tek tek transfer işlemlerine geçilecek
                        amount_per_wallet = None
                
                # Eğer toplu transfer başarısız olduysa veya farklı miktarlar varsa, tek tek transfer et
                if amount_per_wallet is None and not successful_transfers:
                    for i, wallet in enumerate(wallets):
                        try:
                            amount = distribution_details[i]['amount']
                            signature = washbot.transfer_sol(main_private_key, wallet.public_key, amount)
                            
                            successful_transfers.append({
                                **distribution_details[i],
                                "txid": signature
                            })
                        except Exception as transfer_err:
                            failed_transfers.append({
                                **distribution_details[i],
                                "error": str(transfer_err)
                            })
                    
                    logger.info(f"Rust SOL dağıtımı tamamlandı: {len(successful_transfers)} başarılı, {len(failed_transfers)} başarısız transfer")
                
                success_count = len(successful_transfers)
                
                # Return detailed results
                if success_count == len(wallets):
                    logger.info(f"Rust: Successfully distributed SOL to {success_count} wallets")
                    return {
                        "success": True,
                        "message": f"Successfully distributed SOL to {success_count} wallets",
                        "from_wallet": main_wallet.id,
                        "successful_transfers": successful_transfers,
                        "failed_transfers": failed_transfers,
                        "total_distributed": sum(t['amount'] for t in successful_transfers)
                    }
                elif success_count > 0:
                    logger.warning(f"Rust: Partially distributed SOL to {success_count}/{len(wallets)} wallets")
                    return {
                        "success": True,
                        "message": f"Partially distributed SOL to {success_count}/{len(wallets)} wallets",
                        "from_wallet": main_wallet.id,
                        "successful_transfers": successful_transfers,
                        "failed_transfers": failed_transfers,
                        "total_distributed": sum(t['amount'] for t in successful_transfers)
                    }
                elif not success_count:
                    logger.error(f"Rust: Failed to distribute SOL to any wallet. Falling back to Python.")
                else:
                    # Devam et ve Python'a geri dön
                    logger.warning(f"Rust entegrasyonu ile SOL dağıtımı başarısız oldu. Python'a dönülüyor.")
                
            except Exception as rust_err:
                logger.warning(f"Rust entegrasyonu ile SOL dağıtımı başarısız oldu: {rust_err}. Python'a dönülüyor.")
                # Python'a dön
        
        # Python ile SOL dağıtımı
        logger.info(f"Python entegrasyonu ile SOL dağıtımı başlatılıyor: {len(wallets)} cüzdana")
        
        # Get main wallet balance
        balance_result = await solana_utils.get_balance(main_wallet.public_key, main_wallet.network)
        
        if not balance_result.get('success', False):
            error_msg = f"Failed to get main wallet balance: {balance_result.get('error')}"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
        
        main_balance = balance_result['balance_sol']
        
        # Calculate total amount needed
        if randomize and max_amount is not None:
            # Estimate average amount
            avg_amount = (min_amount + max_amount) / 2
            total_needed = avg_amount * len(wallets)
        else:
            total_needed = min_amount * len(wallets)
        
        # Check if main wallet has enough balance
        if main_balance < total_needed + 0.01:  # Keep 0.01 SOL for fees
            error_msg = f"Main wallet has insufficient balance: {main_balance} SOL, need {total_needed + 0.01} SOL"
            logger.error(error_msg)
            return {
                "success": False,
                "error": error_msg
            }
        
        # Prepare distribution details
        distribution_details = []
        tasks = []
        
        for wallet in wallets:
            # Calculate amount to send
            if randomize and max_amount is not None:
                amount = round(random.uniform(min_amount, max_amount), 4)
            else:
                amount = min_amount
            
            # Store distribution details
            distribution_details.append({
                "wallet_id": wallet.id,
                "public_key": wallet.public_key,
                "amount": amount
            })
            
            # Create transfer task
            tasks.append(solana_utils.transfer_sol(
                from_private_key=main_wallet.private_key,
                to_public_key=wallet.public_key,
                amount_sol=amount,
                network=main_wallet.network
            ))
        
        # Execute transfers in parallel
        transfer_results = await asyncio.gather(*tasks)
        
        # Process results
        successful_transfers = []
        failed_transfers = []
        
        for i, result in enumerate(transfer_results):
            if result.get('success', False):
                successful_transfers.append({
                    **distribution_details[i],
                    "txid": result.get('txid', '')
                })
            else:
                failed_transfers.append({
                    **distribution_details[i],
                    "error": result.get('error', 'Unknown error')
                })
        
        success_count = len(successful_transfers)
        
        # Return detailed results
        if success_count == len(wallets):
            logger.info(f"Successfully distributed SOL to {success_count} wallets")
            return {
                "success": True,
                "message": f"Successfully distributed SOL to {success_count} wallets",
                "from_wallet": main_wallet.id,
                "successful_transfers": successful_transfers,
                "failed_transfers": failed_transfers,
                "total_distributed": sum(t['amount'] for t in successful_transfers)
            }
        elif success_count > 0:
            logger.warning(f"Partially distributed SOL to {success_count}/{len(wallets)} wallets")
            return {
                "success": True,
                "message": f"Partially distributed SOL to {success_count}/{len(wallets)} wallets",
                "from_wallet": main_wallet.id,
                "successful_transfers": successful_transfers,
                "failed_transfers": failed_transfers,
                "total_distributed": sum(t['amount'] for t in successful_transfers)
            }
        else:
            logger.error(f"Failed to distribute SOL to any wallet")
            return {
                "success": False,
                "error": "Failed to distribute SOL to any wallet",
                "from_wallet": main_wallet.id,
                "failed_transfers": failed_transfers
            }
        
    except Exception as e:
        logger.error(f"Error distributing SOL: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# ===== GELIŞMIŞ USDT-TABANLΙ MULTI-WALLET TRADING SİSTEMİ =====
# solana_token_bot'dan entegre edildi - Enterprise seviyesi çok-cüzdan trading

async def execute_multi_wallet_usdt_buy(
    token_mint_address: str,
    total_usdt_amount: float,
    wallet_ids: List[str],
    encryption_key: str,
    slippage: float = 1.0,
    priority_fee_usdt: float = 0.01
) -> Dict[str, Any]:
    """
    USDT kullanarak çoklu cüzdan token alım işlemi
    
    Args:
        token_mint_address: Satın alınacak token mint adresi
        total_usdt_amount: Toplam USDT miktarı
        wallet_ids: Kullanılacak cüzdan ID'leri
        encryption_key: Şifreleme anahtarı
        slippage: Slippage toleransı
        priority_fee_usdt: Priority fee USDT cinsinden
        
    Returns:
        Dict: Multi-wallet işlem sonucu
    """
    try:
        from utils import get_solana_price_usd, usdt_to_lamports
        from raydium_client import dex_buy_with_usdt
        
        # Wallet'ları yükle
        wallets = await load_wallets(encryption_key)
        target_wallets = [w for w in wallets if w.id in wallet_ids]
        
        if not target_wallets:
            return {
                "success": False,
                "error": "Geçerli cüzdan bulunamadı"
            }
        
        # USDT'yi wallet'lara dağıt
        usdt_per_wallet = total_usdt_amount / len(target_wallets)
        
        logger.info(f"💰 Multi-wallet USDT buy: ${total_usdt_amount} across {len(target_wallets)} wallets")
        
        # Paralel alım işlemleri
        buy_tasks = []
        for wallet in target_wallets:
            buy_tasks.append(dex_buy_with_usdt(
                token_mint_address=token_mint_address,
                amount_usdt=usdt_per_wallet,
                wallet_private_key=wallet.private_key,
                slippage=slippage,
                priority_fee_usdt=priority_fee_usdt
            ))
        
        # İşlemleri paralel olarak çalıştır
        buy_results = await asyncio.gather(*buy_tasks, return_exceptions=True)
        
        # Sonuçları işle
        successful_buys = []
        failed_buys = []
        
        for i, result in enumerate(buy_results):
            if isinstance(result, Exception):
                failed_buys.append({
                    "wallet_id": target_wallets[i].id,
                    "error": str(result)
                })
            elif result.get("success", False):
                successful_buys.append({
                    "wallet_id": target_wallets[i].id,
                    "usdt_amount": usdt_per_wallet,
                    "expected_tokens": result.get("expected_tokens", 0),
                    "sol_amount": result.get("input_amount_sol", 0)
                })
            else:
                failed_buys.append({
                    "wallet_id": target_wallets[i].id,
                    "error": result.get("error", "Unknown error")
                })
        
        success_count = len(successful_buys)
        total_expected_tokens = sum(buy.get("expected_tokens", 0) for buy in successful_buys)
        
        return {
            "success": True,
            "transaction_type": "multi_wallet_buy",
            "token_mint": token_mint_address,
            "total_usdt_spent": total_usdt_amount,
            "wallets_used": len(target_wallets),
            "successful_purchases": success_count,
            "failed_purchases": len(failed_buys),
            "total_expected_tokens": total_expected_tokens,
            "successful_buys": successful_buys,
            "failed_buys": failed_buys,
            "usdt_per_wallet": usdt_per_wallet,
            "slippage": slippage
        }
        
    except Exception as e:
        logger.error(f"Multi-wallet USDT buy error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def execute_multi_wallet_usdt_sell(
    token_mint_address: str,
    sell_percentage: float,
    wallet_ids: List[str],
    encryption_key: str,
    min_usdt_per_wallet: float = 0.0,
    slippage: float = 1.0,
    priority_fee_usdt: float = 0.01
) -> Dict[str, Any]:
    """
    USDT karşılığında çoklu cüzdan token satış işlemi
    
    Args:
        token_mint_address: Satılacak token mint adresi
        sell_percentage: Satılacak yüzde (0-100)
        wallet_ids: Kullanılacak cüzdan ID'leri
        encryption_key: Şifreleme anahtarı
        min_usdt_per_wallet: Cüzdan başına minimum USDT çıktısı
        slippage: Slippage toleransı
        priority_fee_usdt: Priority fee USDT cinsinden
        
    Returns:
        Dict: Multi-wallet satış sonucu
    """
    try:
        from utils import get_solana_price_usd
        from raydium_client import dex_sell_with_usdt
        from solana_utils import fetch_token_balance_enhanced
        
        # Wallet'ları yükle
        wallets = await load_wallets(encryption_key)
        target_wallets = [w for w in wallets if w.id in wallet_ids]
        
        if not target_wallets:
            return {
                "success": False,
                "error": "Geçerli cüzdan bulunamadı"
            }
        
        logger.info(f"💸 Multi-wallet USDT sell: {sell_percentage}% across {len(target_wallets)} wallets")
        
        # Her cüzdan için token bakiyesi kontrolü ve satış işlemi
        sell_tasks = []
        wallet_balances = []
        
        for wallet in target_wallets:
            # Token bakiyesini al
            balance_result = await fetch_token_balance_enhanced(
                token_mint_address, 
                wallet.public_key,
                "https://api.mainnet-beta.solana.com"
            )
            
            if balance_result.get("success", False):
                token_balance = balance_result.get("balance", 0)
                
                if token_balance > 0:
                    # Satılacak miktarı hesapla
                    sell_amount = int(token_balance * (sell_percentage / 100))
                    
                    if sell_amount > 0:
                        wallet_balances.append({
                            "wallet_id": wallet.id,
                            "total_balance": token_balance,
                            "sell_amount": sell_amount
                        })
                        
                        sell_tasks.append(dex_sell_with_usdt(
                            token_mint_address=token_mint_address,
                            token_amount=sell_amount,
                            min_usdt_output=min_usdt_per_wallet,
                            wallet_private_key=wallet.private_key,
                            slippage=slippage,
                            priority_fee_usdt=priority_fee_usdt
                        ))
        
        if not sell_tasks:
            return {
                "success": False,
                "error": "Satılacak token bulunamadı"
            }
        
        # Satış işlemlerini paralel olarak çalıştır
        sell_results = await asyncio.gather(*sell_tasks, return_exceptions=True)
        
        # Sonuçları işle
        successful_sells = []
        failed_sells = []
        
        for i, result in enumerate(sell_results):
            wallet_balance = wallet_balances[i]
            
            if isinstance(result, Exception):
                failed_sells.append({
                    **wallet_balance,
                    "error": str(result)
                })
            elif result.get("success", False):
                successful_sells.append({
                    **wallet_balance,
                    "expected_usdt": result.get("expected_usdt", 0),
                    "price_impact": result.get("price_impact", 0)
                })
            else:
                failed_sells.append({
                    **wallet_balance,
                    "error": result.get("error", "Unknown error")
                })
        
        success_count = len(successful_sells)
        total_expected_usdt = sum(sell.get("expected_usdt", 0) for sell in successful_sells)
        total_tokens_sold = sum(sell.get("sell_amount", 0) for sell in successful_sells)
        
        return {
            "success": True,
            "transaction_type": "multi_wallet_sell",
            "token_mint": token_mint_address,
            "sell_percentage": sell_percentage,
            "wallets_processed": len(target_wallets),
            "successful_sales": success_count,
            "failed_sales": len(failed_sells),
            "total_tokens_sold": total_tokens_sold,
            "total_expected_usdt": total_expected_usdt,
            "successful_sells": successful_sells,
            "failed_sells": failed_sells,
            "slippage": slippage
        }
        
    except Exception as e:
        logger.error(f"Multi-wallet USDT sell error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def calculate_multi_wallet_portfolio_value(
    wallet_ids: List[str],
    encryption_key: str,
    target_tokens: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Multi-wallet portfolio değerini USDT cinsinden hesaplar
    
    Args:
        wallet_ids: Cüzdan ID'leri
        encryption_key: Şifreleme anahtarı
        target_tokens: Hedef token'lar (None ise tüm token'lar)
        
    Returns:
        Dict: Portfolio değeri bilgileri
    """
    try:
        from utils import get_solana_price_usd, lamports_to_usdt
        from solana_utils import fetch_token_balance_enhanced, fetch_wallet_balance_sol
        
        # Wallet'ları yükle
        wallets = await load_wallets(encryption_key)
        target_wallets = [w for w in wallets if w.id in wallet_ids]
        
        if not target_wallets:
            return {
                "success": False,
                "error": "Geçerli cüzdan bulunamadı"
            }
        
        sol_price = Decimal(await get_solana_price_usd())
        portfolio_data = {
            "total_sol_value_usdt": 0.0,
            "total_token_value_usdt": 0.0,
            "wallet_details": []
        }
        
        # Her cüzdan için değer hesaplama
        for wallet in target_wallets:
            # SOL bakiyesi
            sol_balance = await fetch_wallet_balance_sol(
                wallet.public_key,
                "https://api.mainnet-beta.solana.com"
            )
            
            sol_value_usdt = await lamports_to_usdt(
                int(sol_balance * 1000000000), sol_price
            )
            
            wallet_detail = {
                "wallet_id": wallet.id,
                "wallet_name": wallet.name,
                "sol_balance": sol_balance,
                "sol_value_usdt": sol_value_usdt,
                "token_balances": [],
                "total_value_usdt": sol_value_usdt
            }
            
            # Token bakiyeleri (eğer target_tokens belirtilmişse)
            if target_tokens:
                for token_mint in target_tokens:
                    token_balance_result = await fetch_token_balance_enhanced(
                        token_mint,
                        wallet.public_key,
                        "https://api.mainnet-beta.solana.com"
                    )
                    
                    if token_balance_result.get("success", False):
                        token_balance = token_balance_result.get("formatted_balance", 0)
                        
                        if token_balance > 0:
                            # Bu noktada token fiyatını almak için DexScreener API kullanılabilir
                            # Şimdilik placeholder değer
                            estimated_usdt_value = 0.0
                            
                            wallet_detail["token_balances"].append({
                                "token_mint": token_mint,
                                "balance": token_balance,
                                "estimated_usdt_value": estimated_usdt_value
                            })
                            
                            wallet_detail["total_value_usdt"] += estimated_usdt_value
            
            portfolio_data["wallet_details"].append(wallet_detail)
            portfolio_data["total_sol_value_usdt"] += sol_value_usdt
        
        portfolio_data["total_portfolio_value_usdt"] = (
            portfolio_data["total_sol_value_usdt"] + 
            portfolio_data["total_token_value_usdt"]
        )
        
        return {
            "success": True,
            "portfolio_data": portfolio_data,
            "wallets_analyzed": len(target_wallets),
            "sol_price_usd": float(sol_price)
        }
        
    except Exception as e:
        logger.error(f"Portfolio value calculation error: {e}")
        return {
            "success": False,
            "error": str(e)
        }
