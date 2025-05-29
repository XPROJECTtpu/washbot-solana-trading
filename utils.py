import os
import json
import logging
import uuid
import base64
import re
import hashlib
import time
import aiohttp
import asyncio
from decimal import Decimal
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
import random

logger = logging.getLogger(__name__)

# Solana Program Addresses (Critical for trading)
SOLANA_PROGRAMS = {
    "SPL_TOKEN": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "ASSOCIATED_TOKEN": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 
    "SYSTEM": "11111111111111111111111111111111",
    "WRAPPED_SOL": "So11111111111111111111111111111111111111112",
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"  # Tether USDT
}

def generate_id() -> str:
    """Generate unique ID"""
    return str(uuid.uuid4())

def encrypt_data(data: Union[str, bytes], key: str) -> str:
    """
    Encrypt data using provided key
    
    Args:
        data: Data to encrypt (string or bytes)
        key: Encryption key
        
    Returns:
        Base64 encoded encrypted data
    """
    from security import SecurityManager
    security = SecurityManager(key)
    return security.encrypt_data(data)

def decrypt_data(encrypted_data: str, key: str) -> str:
    """
    Decrypt data using provided key
    
    Args:
        encrypted_data: Base64 encoded encrypted data
        key: Encryption key
        
    Returns:
        Decrypted data
    """
    from security import SecurityManager
    security = SecurityManager(key)
    return security.decrypt_data(encrypted_data)

def format_amount(amount: float, decimals: int = 4) -> str:
    """
    Format number with appropriate decimals
    
    Args:
        amount: Number to format
        decimals: Number of decimal places
        
    Returns:
        Formatted string
    """
    if amount is None:
        return "0"
        
    if amount == 0:
        return "0"
        
    if amount < 0.0001:
        return f"{amount:.8f}".rstrip('0').rstrip('.')
        
    return f"{amount:.{decimals}f}".rstrip('0').rstrip('.')

def format_percentage(percentage: float, decimals: int = 2) -> str:
    """
    Format percentage with appropriate decimals
    
    Args:
        percentage: Percentage to format
        decimals: Number of decimal places
        
    Returns:
        Formatted string
    """
    if percentage is None:
        return "0%"
        
    return f"{percentage:.{decimals}f}%".rstrip('0').rstrip('.')

def format_price_usd(amount: float, decimals: int = 4) -> str:
    """
    Format price in USD
    
    Args:
        amount: Price to format
        decimals: Number of decimal places
        
    Returns:
        Formatted string
    """
    if amount is None:
        return "$0.00"
        
    if amount == 0:
        return "$0.00"
        
    if amount < 0.0001:
        return f"${amount:.8f}".rstrip('0').rstrip('.')
        
    if amount < 0.01:
        return f"${amount:.6f}".rstrip('0').rstrip('.')
        
    if amount < 1:
        return f"${amount:.4f}".rstrip('0').rstrip('.')
        
    if amount < 1000:
        return f"${amount:.2f}".rstrip('0').rstrip('.')
        
    if amount < 1000000:
        return f"${amount/1000:.2f}K".rstrip('0').rstrip('.') + "K"
        
    return f"${amount/1000000:.2f}M".rstrip('0').rstrip('.') + "M"

def format_timestamp(timestamp: Union[str, datetime]) -> str:
    """
    Format timestamp for display
    
    Args:
        timestamp: Timestamp to format
        
    Returns:
        Formatted string
    """
    if timestamp is None:
        return ""
        
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            return timestamp
    
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")

def truncate_address(address: str, length: int = 8) -> str:
    """
    Truncate blockchain address for display
    
    Args:
        address: Address to truncate
        length: Number of characters to show on each end
        
    Returns:
        Truncated address
    """
    if not address or len(address) <= length * 2:
        return address
        
    return f"{address[:length]}...{address[-length:]}"

def sanitize_input(text: str) -> str:
    """
    Sanitize user input
    
    Args:
        text: Text to sanitize
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
        
    # Remove any potential script tags
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.DOTALL)
    
    # Remove other HTML tags
    text = re.sub(r'<.*?>', '', text)
    
    # Escape special characters
    text = text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    text = text.replace('"', '&quot;').replace("'", '&#39;')
    
    return text

def validate_solana_address(address: str) -> bool:
    """
    Validate Solana address format
    
    Args:
        address: Address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not address:
        return False
        
    # Check length (base58 encoded public keys are 32-44 characters)
    if len(address) < 32 or len(address) > 44:
        return False
        
    # Check for valid base58 characters
    if not re.match(r'^[1-9A-HJ-NP-Za-km-z]+$', address):
        return False
        
    return True

def calculate_token_distribution(amount: float, count: int, variance: float = 0.2) -> List[float]:
    """
    Calculate distribution amounts with some variance
    
    Args:
        amount: Total amount to distribute
        count: Number of distributions
        variance: Variance factor (0-1)
        
    Returns:
        List of distribution amounts
    """
    if count <= 0:
        return []
        
    if count == 1:
        return [amount]
        
    base_amount = amount / count
    min_amount = base_amount * (1 - variance)
    max_amount = base_amount * (1 + variance)
    
    # Generate random amounts within variance
    amounts = [random.uniform(min_amount, max_amount) for _ in range(count - 1)]
    
    # Calculate the last amount to ensure sum equals total amount
    amounts.append(amount - sum(amounts))
    
    return amounts

def calculate_risk_score(price_change_24h: float, liquidity_usd: float, volume_24h: float) -> int:
    """
    Calculate risk score for a token (0-100)
    
    Args:
        price_change_24h: 24-hour price change percentage
        liquidity_usd: Liquidity in USD
        volume_24h: 24-hour volume in USD
        
    Returns:
        Risk score (0-100, higher is riskier)
    """
    # Volatility risk (0-40)
    volatility_risk = min(40, abs(price_change_24h) / 2)
    
    # Liquidity risk (0-40)
    liquidity_risk = 0
    if liquidity_usd > 1000000:
        liquidity_risk = 0
    elif liquidity_usd > 500000:
        liquidity_risk = 10
    elif liquidity_usd > 100000:
        liquidity_risk = 20
    elif liquidity_usd > 50000:
        liquidity_risk = 30
    else:
        liquidity_risk = 40
    
    # Volume risk (0-20)
    volume_risk = 0
    volume_to_liquidity = 0 if liquidity_usd == 0 else volume_24h / liquidity_usd
    
    if volume_to_liquidity < 0.1:
        volume_risk = 20
    elif volume_to_liquidity < 0.5:
        volume_risk = 15
    elif volume_to_liquidity < 1:
        volume_risk = 10
    elif volume_to_liquidity < 2:
        volume_risk = 5
    
    return int(volatility_risk + liquidity_risk + volume_risk)

# ===== GELIŞMIŞ SOL/USDT DÖNÜŞÜM FONKSİYONLARI =====
# solana_token_bot'dan entegre edildi

async def get_solana_price_usd() -> float:
    """
    CoinGecko API'den güncel SOL fiyatını USD cinsinden alır.
    Fallback fiyatı ile robust error handling.
    
    Returns:
        float: SOL/USD fiyatı
    """
    try:
        async with aiohttp.ClientSession() as session:
            url = "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd"
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    return float(data["solana"]["usd"])
                else:
                    logger.warning(f"CoinGecko API error: {response.status}")
                    return 247.61  # Fallback price
    except Exception as e:
        logger.error(f"Failed to fetch SOL price: {e}")
        return 247.61  # Fallback price

async def usdt_to_lamports(usdt_amount: float, sol_price_usd: Decimal) -> int:
    """
    USDT miktarını güncel SOL fiyatına göre lamports'a çevirir.
    USD yerine USDT kullanımı - daha güvenilir ve pratik.

    Args:
        usdt_amount (float): Çevrilecek USDT miktarı.
        sol_price_usd (Decimal): 1 SOL'un USD cinsinden fiyatı.

    Returns:
        int: Lamports cinsinden eşdeğer miktar.
    """
    sol_per_usdt = Decimal(usdt_amount) / sol_price_usd
    lamports = int(sol_per_usdt * Decimal(1000000000))  # SOL'u lamports'a çevir
    return lamports

async def lamports_to_usdt(lamports: int, sol_price_usd: Decimal) -> float:
    """
    Lamports miktarını güncel SOL fiyatına göre USDT'ye çevirir.

    Args:
        lamports (int): Çevrilecek lamports miktarı.
        sol_price_usd (Decimal): 1 SOL'un USD cinsinden fiyatı.

    Returns:
        float: USDT cinsinden eşdeğer miktar.
    """
    sol_amount = Decimal(lamports) / Decimal(1000000000)
    usdt_amount = sol_amount * sol_price_usd
    return float(usdt_amount)

async def usdt_to_microlamports(usdt_fee: float, sol_price_usd: Decimal, compute_units: int) -> int:
    """
    USDT cinsinden öncelik ücretini microlamport/CU'ya dönüştürür.
    
    Args:
        usdt_fee: USDT cinsinden öncelik ücreti
        sol_price_usd: SOL/USD fiyatı
        compute_units: İşlem için tahmin edilen compute units
        
    Returns:
        int: Compute unit başına micro-lamports (SetComputeUnitPrice için).
    """
    sol_fee = Decimal(usdt_fee) / sol_price_usd
    lamports_total = sol_fee * Decimal("1e9")
    micro_total = lamports_total * Decimal("1e-3")  # Convert to micro-lamports
    if compute_units > 0:
        base_per_unit = micro_total / Decimal(compute_units)
        return int(base_per_unit)
    return 0

async def fetch_wallet_balance_sol(wallet_address: str, rpc_endpoint: str = None) -> float:
    """
    Cüzdan SOL bakiyesini sorgular - gelişmiş error handling ile.
    
    Args:
        wallet_address: Cüzdan adresi
        rpc_endpoint: RPC endpoint (opsiyonel)
        
    Returns:
        float: SOL cinsinden bakiye
    """
    if not rpc_endpoint:
        rpc_endpoint = "https://api.mainnet-beta.solana.com"
    
    try:
        async with aiohttp.ClientSession() as session:
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [wallet_address]
            }
            
            async with session.post(rpc_endpoint, json=payload, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'result' in data and 'value' in data['result']:
                        lamports = data['result']['value']
                        return lamports / 1000000000  # Convert to SOL
                    else:
                        logger.error(f"Invalid response format: {data}")
                        return 0.0
                else:
                    logger.error(f"HTTP Error {response.status}")
                    return 0.0
                    
    except Exception as e:
        logger.error(f"Failed to fetch wallet balance: {e}")
        return 0.0

def calculate_slippage_amount(amount: float, slippage_percentage: float) -> float:
    """
    Slippage miktarını hesaplar.
    
    Args:
        amount: Ana miktar
        slippage_percentage: Slippage yüzdesi (örn: 1.0 = %1)
        
    Returns:
        float: Minimum alınacak miktar
    """
    slippage_factor = (100 - slippage_percentage) / 100
    return amount * slippage_factor

def validate_transaction_params(amount: float, slippage: float, wallet_address: str) -> Dict[str, Any]:
    """
    İşlem parametrelerini doğrular.
    
    Args:
        amount: İşlem miktarı
        slippage: Slippage yüzdesi
        wallet_address: Cüzdan adresi
        
    Returns:
        Dict: Doğrulama sonucu
    """
    errors = []
    
    if amount <= 0:
        errors.append("İşlem miktarı 0'dan büyük olmalıdır")
        
    if slippage < 0.1 or slippage > 10.0:
        errors.append("Slippage %0.1 - %10 arasında olmalıdır")
        
    if not validate_solana_address(wallet_address):
        errors.append("Geçersiz cüzdan adresi")
    
    return {
        "valid": len(errors) == 0,
        "errors": errors
    }

def log_operation(operation_type: str, details: Dict[str, Any] = None, level: str = "INFO") -> None:
    """
    Log operation to database
    
    Args:
        operation_type: Type of operation
        details: Operation details
        level: Log level
    """
    from database import get_db_connection
    from models import OperationLog
    
    try:
        db = get_db_connection()
        
        log_entry = OperationLog(
            level=level,
            operation=operation_type,
            message=f"{operation_type} operation",
            details=json.dumps(details) if details else None
        )
        
        db.add(log_entry)
        db.commit()
        
    except Exception as e:
        logger.error(f"Failed to log operation: {e}")
