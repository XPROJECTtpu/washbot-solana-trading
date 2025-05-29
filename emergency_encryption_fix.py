#!/usr/bin/env python3
"""
EMERGENCY ENCRYPTION FIX
Critical system repair for wallet decryption issues
"""

import os
import logging
import base64
from cryptography.fernet import Fernet
from database import db_session
from models import Wallet
from security import SecurityManager
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EmergencyEncryptionFix:
    """Emergency fix for encryption key mismatch"""
    
    def __init__(self):
        self.old_keys = [
            "WashBot2025ProductionEncryptionKey_SecureMainnet_7f8a9b2c3d4e5f6g7h8i9j0k",
            "washbot_development_key",
            "deployment-ready-washbot-solana-2024",
            "washbot-secure-session-key-2024"
        ]
        self.current_key = os.environ.get('ENCRYPTION_KEY', 'washbot_development_key')
        
    def try_decrypt_with_keys(self, encrypted_data: str):
        """Try to decrypt with multiple possible keys"""
        for key in self.old_keys:
            try:
                security = SecurityManager(key)
                decrypted = security.decrypt_data(encrypted_data)
                return decrypted, key
            except Exception:
                continue
        return None, None
        
    def generate_new_keypair(self):
        """Generate new Solana keypair"""
        from solders.keypair import Keypair
        keypair = Keypair()
        return {
            'public_key': str(keypair.pubkey()),
            'private_key': str(keypair)
        }
        
    def fix_wallet_encryption(self):
        """Fix all wallet encryption issues"""
        logger.info("🚨 Starting emergency encryption fix...")
        
        try:
            # Get all wallets
            wallets = db_session.query(Wallet).all()
            logger.info(f"Found {len(wallets)} wallets to check")
            
            current_security = SecurityManager(self.current_key)
            fixed_count = 0
            regenerated_count = 0
            
            for wallet in wallets:
                try:
                    if not wallet.encrypted_private_key:
                        # Generate new keypair if no private key exists
                        keypair = self.generate_new_keypair()
                        wallet.address = keypair['public_key']
                        wallet.encrypted_private_key = current_security.encrypt_data(keypair['private_key'])
                        regenerated_count += 1
                        logger.info(f"Generated new keypair for wallet {wallet.id}")
                        continue
                    
                    # Try to decrypt with current key first
                    try:
                        current_security.decrypt_data(wallet.encrypted_private_key)
                        # Already works with current key
                        continue
                    except Exception:
                        pass
                    
                    # Try to decrypt with old keys
                    decrypted_key, working_key = self.try_decrypt_with_keys(wallet.encrypted_private_key)
                    
                    if decrypted_key:
                        # Re-encrypt with current key
                        wallet.encrypted_private_key = current_security.encrypt_data(decrypted_key)
                        fixed_count += 1
                        logger.info(f"Fixed encryption for wallet {wallet.id} (was using key: {working_key[:20]}...)")
                    else:
                        # Cannot decrypt, generate new keypair
                        keypair = self.generate_new_keypair()
                        wallet.address = keypair['public_key']
                        wallet.encrypted_private_key = current_security.encrypt_data(keypair['private_key'])
                        regenerated_count += 1
                        logger.warning(f"Regenerated keypair for wallet {wallet.id} (could not decrypt)")
                        
                except Exception as e:
                    logger.error(f"Error processing wallet {wallet.id}: {e}")
                    continue
            
            # Commit changes
            db_session.commit()
            logger.info(f"✅ Encryption fix complete!")
            logger.info(f"✅ Fixed {fixed_count} wallets")
            logger.info(f"🔄 Regenerated {regenerated_count} wallets")
            
            return {
                'success': True,
                'fixed_count': fixed_count,
                'regenerated_count': regenerated_count,
                'total_wallets': len(wallets)
            }
            
        except Exception as e:
            logger.error(f"Emergency fix failed: {e}")
            db_session.rollback()
            return {
                'success': False,
                'error': str(e)
            }
        finally:
            db_session.close()

def main():
    """Run emergency encryption fix"""
    fixer = EmergencyEncryptionFix()
    result = fixer.fix_wallet_encryption()
    
    if result['success']:
        print(f"\n🚀 EMERGENCY FIX SUCCESSFUL!")
        print(f"Fixed: {result['fixed_count']} wallets")
        print(f"Regenerated: {result['regenerated_count']} wallets")
        print(f"Total: {result['total_wallets']} wallets processed")
    else:
        print(f"\n❌ EMERGENCY FIX FAILED: {result['error']}")

if __name__ == "__main__":
    main()