import aiohttp
import logging
import json
import time
from decimal import Decimal
from typing import Dict, Any, List, Optional
import asyncio

logger = logging.getLogger(__name__)

# API endpoints - Updated to v3 API
RAYDIUM_API_URL = "https://api-v3.raydium.io/main"

# Enhanced Solana Program Addresses for DEX operations
SOLANA_PROGRAMS = {
    "SPL_TOKEN": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "ASSOCIATED_TOKEN": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 
    "SYSTEM": "11111111111111111111111111111111",
    "WRAPPED_SOL": "So11111111111111111111111111111111111111112",
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
}

async def get_token_info(token_address: str) -> Dict[str, Any]:
    """
    Get token information from Raydium API
    
    Args:
        token_address: Token address to query
        
    Returns:
        Token information
    """
    try:
        # Sanitize token address
        token_address = token_address.strip()
        
        # API URL for v3
        url = f"{RAYDIUM_API_URL}/tokens/{token_address}"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Raydium API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("success", False):
                    error_msg = data.get("message", "Token not found")
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                token_data = data.get("data", {})
                
                # Extract relevant information
                token_info = {
                    "success": True,
                    "token_address": token_address,
                    "name": token_data.get("name", "Unknown"),
                    "symbol": token_data.get("symbol", ""),
                    "decimals": int(token_data.get("decimals", 9)),
                    "price_usd": float(token_data.get("price", 0)),
                    "liquidity": float(token_data.get("liquidity", 0)),
                    "volume_24h": float(token_data.get("volume24h", 0)),
                    "holders": int(token_data.get("holders", 0)),
                    "market_cap": float(token_data.get("marketCap", 0)),
                    "supply": float(token_data.get("supply", 0)),
                    "is_verified": token_data.get("isVerified", False),
                    "data_source": "raydium"
                }
                
                return token_info
                
    except Exception as e:
        logger.error(f"Error getting token info from Raydium: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def get_pools(token_address: str = None) -> Dict[str, Any]:
    """
    Get liquidity pools from Raydium
    
    Args:
        token_address: Optional token address to filter pools
        
    Returns:
        Liquidity pools information
    """
    try:
        # API URL for v3 - Using the pools endpoint
        url = f"{RAYDIUM_API_URL}/pools"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Raydium API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("success", False):
                    error_msg = data.get("message", "No pools data available")
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                # Extract pools
                all_pools = data.get("data", [])
                
                # Filter by token if needed
                if token_address:
                    filtered_pools = []
                    for pool in all_pools:
                        if (pool.get("baseMint") == token_address or 
                            pool.get("quoteMint") == token_address):
                            filtered_pools.append(pool)
                    pools = filtered_pools
                else:
                    pools = all_pools
                
                # Format results
                results = []
                
                for pool in pools:
                    # API v3 has slightly different field names
                    pool_result = {
                        "pool_id": pool.get("id", ""),
                        "pool_address": pool.get("address", ""),
                        "base_token": {
                            "address": pool.get("baseMint", ""),
                            "name": pool.get("baseName", ""),
                            "symbol": pool.get("baseSymbol", ""),
                            "decimals": pool.get("baseDecimals", 9)
                        },
                        "quote_token": {
                            "address": pool.get("quoteMint", ""),
                            "name": pool.get("quoteName", ""),
                            "symbol": pool.get("quoteSymbol", ""),
                            "decimals": pool.get("quoteDecimals", 9)
                        },
                        "liquidity": float(pool.get("liquidity", 0)),
                        "volume_24h": float(pool.get("volume24h", 0)),
                        "apy": float(pool.get("apr", 0)) * 100,  # Convert to percentage
                        "price": float(pool.get("price", 0)),
                        "price_change_24h": float(pool.get("priceChange24h", 0))
                    }
                    
                    results.append(pool_result)
                
                # Sort by liquidity
                results.sort(key=lambda x: x["liquidity"], reverse=True)
                
                return {
                    "success": True,
                    "token_address": token_address,
                    "count": len(results),
                    "pools": results,
                    "data_source": "raydium"
                }
                
    except Exception as e:
        logger.error(f"Error getting pools from Raydium: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def get_swap_quote(input_mint: str, output_mint: str, amount: float) -> Dict[str, Any]:
    """
    Get swap quote from Raydium
    
    Args:
        input_mint: Input token address
        output_mint: Output token address
        amount: Amount to swap (in input token units)
        
    Returns:
        Swap quote information
    """
    try:
        # API URL for v3
        url = f"{RAYDIUM_API_URL}/quote"
        
        # Request payload
        payload = {
            "inToken": input_mint,
            "outToken": output_mint,
            "amount": str(amount),
            "slippage": 0.5  # Default slippage (0.5%)
        }
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    logger.error(f"Raydium API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("success", False):
                    error_msg = data.get("message", "Failed to get quote")
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                quote_data = data.get("data", {})
                
                # Format result
                quote_result = {
                    "success": True,
                    "input_mint": input_mint,
                    "output_mint": output_mint,
                    "in_amount": float(payload["amount"]),
                    "out_amount": float(quote_data.get("outAmount", 0)),
                    "price": float(quote_data.get("price", 0)),
                    "price_impact": float(quote_data.get("priceImpact", 0)),
                    "route": quote_data.get("route", []),
                    "data_source": "raydium"
                }
                
                return quote_result
                
    except Exception as e:
        logger.error(f"Error getting swap quote from Raydium: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# ===== GELIŞMIŞ USDT-TABANLΙ TRADING SİSTEMİ =====
# solana_token_bot'dan entegre edildi - Enterprise seviyesi trading

async def dex_buy_with_usdt(
    token_mint_address: str,
    amount_usdt: float,
    wallet_private_key: str,
    slippage: float = 1.0,
    priority_fee_usdt: float = 0.01,
    simulate_first: bool = True
) -> Dict[str, Any]:
    """
    USDT değeri kullanarak token satın alma - solana_token_bot entegrasyonu
    
    Args:
        token_mint_address: Satın alınacak token mint adresi
        amount_usdt: Satın alınacak USDT miktarı
        wallet_private_key: Cüzdan private key
        slippage: Slippage toleransı (%)
        priority_fee_usdt: Priority fee USDT cinsinden
        simulate_first: İşlem öncesi simülasyon
        
    Returns:
        Dict: İşlem sonucu
    """
    try:
        from utils import get_solana_price_usd, usdt_to_lamports, usdt_to_microlamports
        
        # Güncel SOL fiyatını al
        sol_price = Decimal(await get_solana_price_usd())
        
        # USDT'yi SOL lamports'a çevir
        sol_lamports = await usdt_to_lamports(amount_usdt, sol_price)
        sol_amount = sol_lamports / 1000000000
        
        # Priority fee hesapla
        priority_micro_lamports = await usdt_to_microlamports(
            priority_fee_usdt, sol_price, 200_000
        )
        
        logger.info(f"💰 USDT Buy: ${amount_usdt} → {sol_amount:.6f} SOL for {token_mint_address}")
        
        # Swap quote al
        quote_result = await get_swap_quote(
            SOLANA_PROGRAMS["WRAPPED_SOL"],  # SOL'dan
            token_mint_address,              # Token'a
            sol_lamports,
            slippage
        )
        
        if not quote_result.get("success", False):
            return {
                "success": False,
                "error": f"Quote alınamadı: {quote_result.get('error', 'Unknown error')}"
            }
        
        expected_tokens = quote_result.get("out_amount", 0)
        price_impact = quote_result.get("price_impact", 0)
        
        # Yüksek price impact kontrolü
        if price_impact > 5.0:  # %5'ten fazla price impact
            logger.warning(f"⚠️ Yüksek price impact: %{price_impact:.2f}")
        
        return {
            "success": True,
            "transaction_type": "buy",
            "input_amount_usdt": amount_usdt,
            "input_amount_sol": sol_amount,
            "expected_tokens": expected_tokens,
            "token_mint": token_mint_address,
            "price_impact": price_impact,
            "slippage": slippage,
            "priority_fee_usdt": priority_fee_usdt,
            "sol_price_usd": float(sol_price),
            "simulated": simulate_first,
            "status": "ready_to_execute"
        }
        
    except Exception as e:
        logger.error(f"USDT buy error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def dex_sell_with_usdt(
    token_mint_address: str,
    token_amount: int,
    min_usdt_output: float,
    wallet_private_key: str,
    slippage: float = 1.0,
    priority_fee_usdt: float = 0.01,
    output_to_sol: bool = True
) -> Dict[str, Any]:
    """
    Token'ları satıp USDT karşılığı alma - solana_token_bot entegrasyonu
    
    Args:
        token_mint_address: Satılacak token mint adresi
        token_amount: Satılacak token miktarı (raw amount)
        min_usdt_output: Minimum USDT çıktısı
        wallet_private_key: Cüzdan private key
        slippage: Slippage toleransı (%)
        priority_fee_usdt: Priority fee USDT cinsinden
        output_to_sol: SOL'a mı çevir (true) yoksa USDT'ye mi (false)
        
    Returns:
        Dict: İşlem sonucu
    """
    try:
        from utils import get_solana_price_usd, lamports_to_usdt, usdt_to_microlamports
        
        # Güncel SOL fiyatını al
        sol_price = Decimal(await get_solana_price_usd())
        
        # Output token belirleme
        output_token = SOLANA_PROGRAMS["WRAPPED_SOL"] if output_to_sol else SOLANA_PROGRAMS["USDT"]
        
        logger.info(f"💸 USDT Sell: {token_amount} tokens → Min ${min_usdt_output}")
        
        # Swap quote al
        quote_result = await get_swap_quote(
            token_mint_address,  # Token'dan
            output_token,        # SOL/USDT'ye
            token_amount,
            slippage
        )
        
        if not quote_result.get("success", False):
            return {
                "success": False,
                "error": f"Quote alınamadı: {quote_result.get('error', 'Unknown error')}"
            }
        
        expected_output = quote_result.get("out_amount", 0)
        price_impact = quote_result.get("price_impact", 0)
        
        # SOL çıktısını USDT'ye çevir
        if output_to_sol:
            expected_usdt = await lamports_to_usdt(expected_output, sol_price)
        else:
            expected_usdt = expected_output / 1000000  # USDT decimals = 6
        
        # Minimum output kontrolü
        if expected_usdt < min_usdt_output:
            return {
                "success": False,
                "error": f"Minimum output karşılanmıyor: ${expected_usdt:.2f} < ${min_usdt_output:.2f}"
            }
        
        # Priority fee hesapla
        priority_micro_lamports = await usdt_to_microlamports(
            priority_fee_usdt, sol_price, 200_000
        )
        
        return {
            "success": True,
            "transaction_type": "sell",
            "token_amount": token_amount,
            "token_mint": token_mint_address,
            "expected_usdt": expected_usdt,
            "min_usdt_output": min_usdt_output,
            "price_impact": price_impact,
            "slippage": slippage,
            "priority_fee_usdt": priority_fee_usdt,
            "sol_price_usd": float(sol_price),
            "output_to_sol": output_to_sol,
            "status": "ready_to_execute"
        }
        
    except Exception as e:
        logger.error(f"USDT sell error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def calculate_usdt_trading_metrics(
    token_mint: str,
    buy_amount_usdt: float,
    target_profit_percentage: float = 50.0
) -> Dict[str, Any]:
    """
    USDT tabanlı trading metrikleri hesaplama
    
    Args:
        token_mint: Token mint adresi
        buy_amount_usdt: Satın alma miktarı USDT
        target_profit_percentage: Hedef kar yüzdesi
        
    Returns:
        Dict: Trading metrikleri
    """
    try:
        from utils import get_solana_price_usd
        
        sol_price = await get_solana_price_usd()
        
        # Hedef satış tutarı
        target_sell_usdt = buy_amount_usdt * (1 + target_profit_percentage / 100)
        
        # Stop-loss tutarı (%20 zarar)
        stop_loss_usdt = buy_amount_usdt * 0.8
        
        return {
            "success": True,
            "token_mint": token_mint,
            "buy_amount_usdt": buy_amount_usdt,
            "target_sell_usdt": target_sell_usdt,
            "stop_loss_usdt": stop_loss_usdt,
            "target_profit_percentage": target_profit_percentage,
            "expected_profit_usdt": target_sell_usdt - buy_amount_usdt,
            "max_loss_usdt": buy_amount_usdt - stop_loss_usdt,
            "sol_price_usd": sol_price,
            "risk_reward_ratio": (target_sell_usdt - buy_amount_usdt) / (buy_amount_usdt - stop_loss_usdt)
        }
        
    except Exception as e:
        logger.error(f"Trading metrics calculation error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def enhanced_swap_instruction_builder(
    input_mint: str,
    output_mint: str,
    amount: int,
    slippage: float,
    wallet_address: str,
    priority_micro_lamports: int = 0
) -> Dict[str, Any]:
    """
    Gelişmiş swap instruction builder - versioned transaction desteği
    
    Args:
        input_mint: Input token mint
        output_mint: Output token mint  
        amount: Swap miktarı
        slippage: Slippage toleransı
        wallet_address: Cüzdan adresi
        priority_micro_lamports: Priority fee
        
    Returns:
        Dict: Swap instruction bilgileri
    """
    try:
        # Minimum output hesapla
        quote_result = await get_swap_quote(input_mint, output_mint, amount, slippage)
        
        if not quote_result.get("success", False):
            return {
                "success": False,
                "error": "Quote alınamadı"
            }
        
        min_output = int(quote_result.get("out_amount", 0) * (1 - slippage / 100))
        
        # Instruction metadata
        instruction_data = {
            "success": True,
            "instruction_type": "swap",
            "input_mint": input_mint,
            "output_mint": output_mint,
            "amount_in": amount,
            "min_amount_out": min_output,
            "slippage": slippage,
            "wallet_address": wallet_address,
            "priority_fee": priority_micro_lamports,
            "estimated_compute_units": 200_000,
            "supports_versioned_tx": True,
            "route": quote_result.get("route", [])
        }
        
        return instruction_data
        
    except Exception as e:
        logger.error(f"Swap instruction builder error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def get_top_tokens() -> Dict[str, Any]:
    """
    Get top tokens from Raydium
    
    Returns:
        Top tokens information
    """
    try:
        # API URL for v3
        url = f"{RAYDIUM_API_URL}/tokens"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Raydium API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("success", False):
                    error_msg = data.get("message", "No tokens data available")
                    return {
                        "success": False,
                        "error": error_msg
                    }
                
                # Extract tokens
                tokens = data.get("data", [])
                
                # Format results
                results = []
                
                for token in tokens:
                    token_result = {
                        "token_address": token.get("address", ""),
                        "name": token.get("name", ""),
                        "symbol": token.get("symbol", ""),
                        "decimals": token.get("decimals", 9),
                        "price_usd": float(token.get("price", 0)),
                        "market_cap": float(token.get("marketCap", 0)),
                        "liquidity": float(token.get("liquidity", 0)),
                        "volume_24h": float(token.get("volume24h", 0)),
                        "price_change_24h": float(token.get("priceChange24h", 0)),
                        "holders": int(token.get("holders", 0)),
                        "is_verified": token.get("isVerified", False)
                    }
                    
                    results.append(token_result)
                
                return {
                    "success": True,
                    "count": len(results),
                    "tokens": results,
                    "data_source": "raydium"
                }
                
    except Exception as e:
        logger.error(f"Error getting top tokens from Raydium: {e}")
        return {
            "success": False,
            "error": str(e)
        }
