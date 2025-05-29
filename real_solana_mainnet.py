"""
Gerçek Solana Mainnet Bağlantısı - Canlı İşlemler
"""

import asyncio
import logging
from solana.rpc.api import Client
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.system_program import transfer, TransferParams
from solders.instruction import Instruction
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class RealSolanaMainnet:
    """Gerçek Solana Mainnet bağlantısı ve işlemleri"""
    
    def __init__(self):
        # Gerçek mainnet RPC endpoints (Alchemy öncelikli)
        self.rpc_endpoints = [
            "https://solana-mainnet.g.alchemy.com/v2/xOAMkeVX9yWLwvuu3IRKEz54_nCPQaTD",
            "https://api.mainnet-beta.solana.com",
            "https://solana-api.projectserum.com", 
            "https://rpc.ankr.com/solana"
        ]
        self.client = None
        self.active_endpoint = None
        
    async def connect_to_mainnet(self):
        """Gerçek mainnet'e bağlan"""
        for endpoint in self.rpc_endpoints:
            try:
                client = Client(endpoint)
                # Bağlantıyı test et - get_genesis_hash kullan
                genesis = client.get_genesis_hash()
                if genesis:
                    self.client = client
                    self.active_endpoint = endpoint
                    logger.info(f"✅ Gerçek Solana mainnet bağlantısı kuruldu: {endpoint}")
                    return True
            except Exception as e:
                logger.warning(f"❌ {endpoint} bağlantı hatası: {e}")
                continue
        
        logger.error("❌ Hiçbir mainnet endpoint'ine bağlanılamadı")
        return False
    
    async def get_real_sol_balance(self, address: str) -> float:
        """Gerçek SOL bakiyesi getir"""
        if not self.client:
            await self.connect_to_mainnet()
        
        try:
            pubkey = Pubkey.from_string(address)
            balance_response = self.client.get_balance(pubkey)
            # Lamports'tan SOL'a çevir
            sol_balance = balance_response.value / 1_000_000_000
            logger.info(f"Gerçek SOL bakiyesi {address[:8]}...: {sol_balance} SOL")
            return sol_balance
        except Exception as e:
            logger.error(f"Bakiye alma hatası: {e}")
            return 0.0
    
    async def send_real_sol(self, from_keypair: Keypair, to_address: str, amount_sol: float) -> Dict[str, Any]:
        """Gerçek SOL transfer işlemi"""
        if not self.client:
            await self.connect_to_mainnet()
        
        try:
            # Lamports'a çevir
            amount_lamports = int(amount_sol * 1_000_000_000)
            
            # Transfer instruction oluştur
            to_pubkey = Pubkey.from_string(to_address)
            transfer_instruction = transfer(
                TransferParams(
                    from_pubkey=from_keypair.pubkey(),
                    to_pubkey=to_pubkey,
                    lamports=amount_lamports
                )
            )
            
            # Transaction oluştur
            recent_blockhash = self.client.get_latest_blockhash()
            transaction = Transaction.new_with_payer(
                [transfer_instruction],
                from_keypair.pubkey()
            )
            
            # Transaction'ı imzala
            transaction.sign([from_keypair], recent_blockhash.value.blockhash)
            
            # Blockchain'e gönder
            result = self.client.send_transaction(transaction)
            
            logger.info(f"✅ Gerçek SOL transfer başarılı: {result.value}")
            return {
                "success": True,
                "signature": str(result.value),
                "amount": amount_sol,
                "from": str(from_keypair.pubkey()),
                "to": to_address
            }
            
        except Exception as e:
            logger.error(f"SOL transfer hatası: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_token_accounts(self, wallet_address: str) -> Dict[str, Any]:
        """Gerçek token hesaplarını getir"""
        if not self.client:
            await self.connect_to_mainnet()
        
        try:
            pubkey = Pubkey.from_string(wallet_address)
            # SPL token hesaplarını getir
            response = self.client.get_token_accounts_by_owner(
                pubkey,
                {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}
            )
            
            token_accounts = []
            for account in response.value:
                account_data = account.account.data
                token_accounts.append({
                    "pubkey": str(account.pubkey),
                    "mint": str(account_data.parsed["info"]["mint"]),
                    "amount": account_data.parsed["info"]["tokenAmount"]["uiAmount"]
                })
            
            logger.info(f"Wallet {wallet_address[:8]}... için {len(token_accounts)} token hesabı bulundu")
            return {
                "success": True,
                "accounts": token_accounts
            }
            
        except Exception as e:
            logger.error(f"Token hesapları alma hatası: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_transaction_status(self, signature: str) -> Dict[str, Any]:
        """İşlem durumunu kontrol et"""
        if not self.client:
            await self.connect_to_mainnet()
        
        try:
            response = self.client.get_signature_status(signature)
            return {
                "success": True,
                "status": response.value,
                "confirmed": response.value is not None
            }
        except Exception as e:
            logger.error(f"İşlem durumu alma hatası: {e}")
            return {
                "success": False,
                "error": str(e)
            }

# Global instance
real_solana = RealSolanaMainnet()

async def initialize_real_solana():
    """Gerçek Solana bağlantısını başlat"""
    success = await real_solana.connect_to_mainnet()
    if success:
        logger.info("🚀 Gerçek Solana mainnet hazır - Canlı işlemler başlayabilir")
    return success

def get_real_solana_client():
    """Gerçek Solana client'ını al"""
    return real_solana