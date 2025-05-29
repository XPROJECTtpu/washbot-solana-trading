import aiohttp
import logging
import json
from typing import Dict, Any, List, Optional
import asyncio

logger = logging.getLogger(__name__)

# API endpoints
DEXSCREENER_API_URL = "https://api.dexscreener.com/latest/dex"

async def get_token_info(token_address: str) -> Dict[str, Any]:
    """
    Get token information from DexScreener
    
    Args:
        token_address: Token address to query
        
    Returns:
        Token information
    """
    try:
        # Sanitize token address
        token_address = token_address.strip()
        
        # API URL
        url = f"{DEXSCREENER_API_URL}/tokens/{token_address}"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"DexScreener API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("pairs", []):
                    return {
                        "success": False,
                        "error": "Token not found or no liquidity pools available"
                    }
                
                # Get the first pair (usually the most relevant)
                pairs = data.get("pairs", [])
                pair = pairs[0]
                
                # Extract relevant information
                token_info = {
                    "success": True,
                    "token_address": token_address,
                    "name": pair.get("baseToken", {}).get("name", "Unknown"),
                    "symbol": pair.get("baseToken", {}).get("symbol", ""),
                    "price": float(pair.get("priceUsd", 0)),
                    "price_change_24h": float(pair.get("priceChange", {}).get("h24", 0)),
                    "volume_24h": float(pair.get("volume", {}).get("h24", 0)),
                    "liquidity_usd": float(pair.get("liquidity", {}).get("usd", 0)),
                    "fdv": float(pair.get("fdv", 0)),
                    "pair_address": pair.get("pairAddress", ""),
                    "dex_id": pair.get("dexId", ""),
                    "chain_id": pair.get("chainId", ""),
                    "all_pairs": len(pairs),
                    "created_at": pair.get("pairCreatedAt", ""),
                    "data_source": "dexscreener"
                }
                
                return token_info
                
    except Exception as e:
        logger.error(f"Error getting token info from DexScreener: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def search_tokens(query: str) -> Dict[str, Any]:
    """
    Search tokens on DexScreener
    
    Args:
        query: Search query (name, symbol)
        
    Returns:
        Search results
    """
    try:
        # Sanitize query
        query = query.strip()
        
        if len(query) < 2:
            return {
                "success": False,
                "error": "Search query too short (min 2 characters)"
            }
        
        # API URL
        url = f"{DEXSCREENER_API_URL}/search?q={query}"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"DexScreener API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("pairs", []):
                    return {
                        "success": False,
                        "error": "No tokens found matching query"
                    }
                
                # Extract pairs
                pairs = data.get("pairs", [])
                
                # Format results
                results = []
                
                # Group pairs by token
                token_pairs = {}
                
                for pair in pairs:
                    base_token = pair.get("baseToken", {})
                    token_address = base_token.get("address", "")
                    
                    if token_address:
                        if token_address not in token_pairs:
                            token_pairs[token_address] = {
                                "token_address": token_address,
                                "name": base_token.get("name", "Unknown"),
                                "symbol": base_token.get("symbol", ""),
                                "pairs": []
                            }
                        
                        token_pairs[token_address]["pairs"].append({
                            "pair_address": pair.get("pairAddress", ""),
                            "dex_id": pair.get("dexId", ""),
                            "chain_id": pair.get("chainId", ""),
                            "price_usd": float(pair.get("priceUsd", 0)),
                            "liquidity_usd": float(pair.get("liquidity", {}).get("usd", 0)),
                            "volume_24h": float(pair.get("volume", {}).get("h24", 0))
                        })
                
                # Convert to list and add derived fields
                for token_address, token_data in token_pairs.items():
                    # Find pair with highest liquidity
                    best_pair = max(token_data["pairs"], key=lambda p: p["liquidity_usd"]) if token_data["pairs"] else {}
                    
                    token_result = {
                        "token_address": token_data["token_address"],
                        "name": token_data["name"],
                        "symbol": token_data["symbol"],
                        "price_usd": best_pair.get("price_usd", 0),
                        "liquidity_usd": best_pair.get("liquidity_usd", 0),
                        "volume_24h": sum(p["volume_24h"] for p in token_data["pairs"]),
                        "pair_count": len(token_data["pairs"]),
                        "best_dex": best_pair.get("dex_id", ""),
                        "chain_id": best_pair.get("chain_id", "")
                    }
                    
                    results.append(token_result)
                
                # Sort by liquidity
                results.sort(key=lambda x: x["liquidity_usd"], reverse=True)
                
                return {
                    "success": True,
                    "query": query,
                    "count": len(results),
                    "results": results,
                    "data_source": "dexscreener"
                }
                
    except Exception as e:
        logger.error(f"Error searching tokens on DexScreener: {e}")
        return {
            "success": False,
            "error": str(e)
        }

async def get_chain_pairs(chain_id: str, page: int = 1) -> Dict[str, Any]:
    """
    Get top pairs for a chain
    
    Args:
        chain_id: Chain ID (solana, ethereum, etc.)
        page: Page number
        
    Returns:
        Top pairs
    """
    try:
        # API URL
        url = f"{DEXSCREENER_API_URL}/pairs/{chain_id}/{page}"
        
        # Make request
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    logger.error(f"DexScreener API error: {response.status} - {await response.text()}")
                    return {
                        "success": False,
                        "error": f"API error: {response.status}"
                    }
                
                data = await response.json()
                
                # Check if valid response
                if not data or not data.get("pairs", []):
                    return {
                        "success": False,
                        "error": "No pairs found for chain"
                    }
                
                # Extract pairs
                pairs = data.get("pairs", [])
                
                # Format results
                results = []
                
                for pair in pairs:
                    pair_result = {
                        "pair_address": pair.get("pairAddress", ""),
                        "dex_id": pair.get("dexId", ""),
                        "base_token": {
                            "address": pair.get("baseToken", {}).get("address", ""),
                            "name": pair.get("baseToken", {}).get("name", ""),
                            "symbol": pair.get("baseToken", {}).get("symbol", "")
                        },
                        "quote_token": {
                            "address": pair.get("quoteToken", {}).get("address", ""),
                            "name": pair.get("quoteToken", {}).get("name", ""),
                            "symbol": pair.get("quoteToken", {}).get("symbol", "")
                        },
                        "price_usd": float(pair.get("priceUsd", 0)),
                        "price_change_24h": float(pair.get("priceChange", {}).get("h24", 0)),
                        "liquidity_usd": float(pair.get("liquidity", {}).get("usd", 0)),
                        "volume_24h": float(pair.get("volume", {}).get("h24", 0)),
                        "created_at": pair.get("pairCreatedAt", "")
                    }
                    
                    results.append(pair_result)
                
                return {
                    "success": True,
                    "chain_id": chain_id,
                    "page": page,
                    "count": len(results),
                    "pairs": results,
                    "data_source": "dexscreener"
                }
                
    except Exception as e:
        logger.error(f"Error getting chain pairs from DexScreener: {e}")
        return {
            "success": False,
            "error": str(e)
        }
