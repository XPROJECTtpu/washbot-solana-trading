"""
Real Solana Transaction Processor
Production-ready transaction handling with full blockchain integration
"""

import asyncio
import json
import base64
from typing import Dict, List, Optional, Any
from decimal import Decimal
import logging

from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction
from solders.message import Message
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.rpc.responses import GetBalanceResp

from solana.rpc.async_api import AsyncClient
from solana.rpc.commitment import Confirmed, Finalized
from solana.rpc.types import TxOpts

from config import get_solana_rpc_url

logger = logging.getLogger(__name__)

class SolanaTransactionProcessor:
    """
    Production-grade Solana transaction processor
    Handles all blockchain interactions with proper error handling
    """
    
    def __init__(self, rpc_url: str = None):
        self.rpc_url = rpc_url or get_solana_rpc_url()
        self.client = AsyncClient(self.rpc_url)
        self.max_retries = 5
        self.retry_delay = 2.0
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.close()
        
    async def get_wallet_balance(self, public_key: str) -> float:
        """Get SOL balance for a wallet"""
        try:
            pubkey = Pubkey.from_string(public_key)
            
            for attempt in range(self.max_retries):
                try:
                    response = await self.client.get_balance(
                        pubkey, 
                        commitment=Confirmed
                    )
                    
                    if response.value is not None:
                        # Convert lamports to SOL
                        balance_sol = response.value / 1_000_000_000
                        logger.info(f"Balance for {public_key}: {balance_sol} SOL")
                        return balance_sol
                    else:
                        logger.warning(f"No balance data for {public_key}")
                        return 0.0
                        
                except Exception as e:
                    logger.warning(f"Balance check attempt {attempt + 1} failed: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    else:
                        raise
                        
        except Exception as e:
            logger.error(f"Failed to get balance for {public_key}: {e}")
            return 0.0
            
    async def send_sol_transaction(
        self, 
        from_private_key: str, 
        to_public_key: str, 
        amount_sol: float,
        priority_fee: int = 5000
    ) -> Dict[str, Any]:
        """
        Send SOL from one wallet to another
        Returns transaction signature and status
        """
        try:
            # Parse keys
            from_keypair = Keypair.from_base58_string(from_private_key)
            to_pubkey = Pubkey.from_string(to_public_key)
            
            # Convert SOL to lamports
            lamports = int(amount_sol * 1_000_000_000)
            
            logger.info(f"Sending {amount_sol} SOL ({lamports} lamports) to {to_public_key}")
            
            # Get recent blockhash
            blockhash_resp = await self.client.get_latest_blockhash(commitment=Finalized)
            recent_blockhash = blockhash_resp.value.blockhash
            
            # Create transfer instruction
            transfer_instruction = transfer(
                TransferParams(
                    from_pubkey=from_keypair.pubkey(),
                    to_pubkey=to_pubkey,
                    lamports=lamports
                )
            )
            
            # Add compute budget instructions for priority
            compute_limit_instruction = set_compute_unit_limit(200_000)
            compute_price_instruction = set_compute_unit_price(priority_fee)
            
            # Create transaction
            message = Message.new_with_blockhash(
                [compute_limit_instruction, compute_price_instruction, transfer_instruction],
                from_keypair.pubkey(),
                recent_blockhash
            )
            
            transaction = Transaction.new_unsigned(message)
            transaction.sign([from_keypair], recent_blockhash)
            
            # Send transaction with retries
            for attempt in range(self.max_retries):
                try:
                    response = await self.client.send_transaction(
                        transaction,
                        opts=TxOpts(
                            skip_preflight=False,
                            preflight_commitment=Confirmed,
                            max_retries=3
                        )
                    )
                    
                    if response.value:
                        signature = str(response.value)
                        logger.info(f"Transaction sent successfully: {signature}")
                        
                        # Wait for confirmation
                        confirmation = await self._wait_for_confirmation(signature)
                        
                        return {
                            "success": True,
                            "signature": signature,
                            "confirmed": confirmation,
                            "amount_sol": amount_sol,
                            "from": str(from_keypair.pubkey()),
                            "to": to_public_key
                        }
                    else:
                        logger.error("Transaction failed - no signature returned")
                        
                except Exception as e:
                    logger.warning(f"Send attempt {attempt + 1} failed: {e}")
                    if attempt < self.max_retries - 1:
                        await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    else:
                        raise
                        
            return {
                "success": False,
                "error": "Max retries exceeded",
                "amount_sol": amount_sol,
                "from": str(from_keypair.pubkey()),
                "to": to_public_key
            }
            
        except Exception as e:
            logger.error(f"SOL transaction failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "amount_sol": amount_sol,
                "from": from_private_key[:8] + "...",
                "to": to_public_key
            }
            
    async def _wait_for_confirmation(self, signature: str, timeout: int = 60) -> bool:
        """Wait for transaction confirmation"""
        try:
            start_time = asyncio.get_event_loop().time()
            
            while (asyncio.get_event_loop().time() - start_time) < timeout:
                try:
                    response = await self.client.get_signature_statuses([signature])
                    
                    if response.value and len(response.value) > 0:
                        status = response.value[0]
                        if status and status.confirmation_status:
                            if status.confirmation_status in [Confirmed, Finalized]:
                                if status.err is None:
                                    logger.info(f"Transaction {signature} confirmed successfully")
                                    return True
                                else:
                                    logger.error(f"Transaction {signature} failed: {status.err}")
                                    return False
                                    
                    await asyncio.sleep(2)
                    
                except Exception as e:
                    logger.warning(f"Confirmation check failed: {e}")
                    await asyncio.sleep(2)
                    
            logger.warning(f"Transaction {signature} confirmation timeout")
            return False
            
        except Exception as e:
            logger.error(f"Confirmation wait failed: {e}")
            return False
            
    async def batch_transfer_sol(
        self, 
        from_private_key: str, 
        recipients: List[Dict[str, Any]],
        priority_fee: int = 5000
    ) -> List[Dict[str, Any]]:
        """
        Batch transfer SOL to multiple recipients
        recipients format: [{"address": "...", "amount": 0.1}, ...]
        """
        results = []
        
        try:
            # Process transfers in parallel with rate limiting
            semaphore = asyncio.Semaphore(10)  # Max 10 concurrent transfers
            
            async def limited_transfer(recipient):
                async with semaphore:
                    return await self.send_sol_transaction(
                        from_private_key,
                        recipient["address"],
                        recipient["amount"],
                        priority_fee
                    )
                    
            tasks = [limited_transfer(recipient) for recipient in recipients]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        "success": False,
                        "error": str(result),
                        "recipient": recipients[i]
                    })
                else:
                    processed_results.append(result)
                    
            success_count = sum(1 for r in processed_results if r.get("success"))
            logger.info(f"Batch transfer completed: {success_count}/{len(recipients)} successful")
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Batch transfer failed: {e}")
            return [{"success": False, "error": str(e)} for _ in recipients]
            
    async def get_transaction_history(
        self, 
        public_key: str, 
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get recent transaction history for a wallet"""
        try:
            pubkey = Pubkey.from_string(public_key)
            
            response = await self.client.get_signatures_for_address(
                pubkey,
                limit=limit,
                commitment=Confirmed
            )
            
            transactions = []
            if response.value:
                for sig_info in response.value:
                    transactions.append({
                        "signature": str(sig_info.signature),
                        "slot": sig_info.slot,
                        "block_time": sig_info.block_time,
                        "confirmation_status": str(sig_info.confirmation_status) if sig_info.confirmation_status else "unknown",
                        "err": str(sig_info.err) if sig_info.err else None
                    })
                    
            logger.info(f"Retrieved {len(transactions)} transactions for {public_key}")
            return transactions
            
        except Exception as e:
            logger.error(f"Failed to get transaction history: {e}")
            return []
            
    async def estimate_transaction_fee(
        self, 
        from_public_key: str, 
        to_public_key: str, 
        amount_sol: float
    ) -> Dict[str, Any]:
        """Estimate transaction fee"""
        try:
            # Basic fee estimation
            base_fee = 0.000005  # 5000 lamports
            priority_fee = 0.000005  # 5000 lamports
            total_fee = base_fee + priority_fee
            
            return {
                "base_fee_sol": base_fee,
                "priority_fee_sol": priority_fee,
                "total_fee_sol": total_fee,
                "amount_with_fee_sol": amount_sol + total_fee
            }
            
        except Exception as e:
            logger.error(f"Fee estimation failed: {e}")
            return {
                "base_fee_sol": 0.00001,
                "priority_fee_sol": 0.00001,
                "total_fee_sol": 0.00002,
                "amount_with_fee_sol": amount_sol + 0.00002
            }

# Global transaction processor instance
_transaction_processor = None

async def get_transaction_processor() -> SolanaTransactionProcessor:
    """Get shared transaction processor instance"""
    global _transaction_processor
    if _transaction_processor is None:
        _transaction_processor = SolanaTransactionProcessor()
    return _transaction_processor

# Utility functions for easy access
async def send_sol(from_private_key: str, to_address: str, amount: float) -> Dict[str, Any]:
    """Simple SOL transfer function"""
    async with SolanaTransactionProcessor() as processor:
        return await processor.send_sol_transaction(from_private_key, to_address, amount)

async def get_balance(public_key: str) -> float:
    """Simple balance check function"""
    async with SolanaTransactionProcessor() as processor:
        return await processor.get_wallet_balance(public_key)

async def batch_send_sol(from_private_key: str, recipients: List[Dict]) -> List[Dict]:
    """Simple batch transfer function"""
    async with SolanaTransactionProcessor() as processor:
        return await processor.batch_transfer_sol(from_private_key, recipients)