"""
Solana Tracker Swap API Client
Unified DEX access for optimal token swaps across multiple Solana DEXs
"""

import aiohttp
import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SolanaTrackerClient:
    """
    Solana Tracker Swap API Client
    Unified access to Raydium, Orca, Meteora and other DEXs
    """
    
    def __init__(self):
        self.base_url = "https://public-api.solanatracker.io"
        self.swap_endpoint = f"{self.base_url}/swap"
        self.quotes_endpoint = f"{self.base_url}/swap/quotes"
        
        # Token mappings for easier use
        self.common_tokens = {
            "SOL": "So11111111111111111111111111111111111111112",
            "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "BONK": "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
            "RAY": "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R",
            "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        }
        
        logger.info("🚀 Solana Tracker Client initialized - Multi-DEX access ready")
    
    def get_token_address(self, token: str) -> str:
        """Get token address from symbol or return address if already valid"""
        if token in self.common_tokens:
            return self.common_tokens[token]
        return token
    
    async def get_swap_quote(self, from_token: str, to_token: str, amount: float, slippage: float = 0.5) -> Dict[str, Any]:
        """
        Get best swap quote across multiple DEXs
        
        Args:
            from_token: Source token symbol or address
            to_token: Destination token symbol or address
            amount: Amount to swap (in token units)
            slippage: Allowed slippage percentage (0.5 = 0.5%)
            
        Returns:
            Best quote with route information
        """
        try:
            from_mint = self.get_token_address(from_token)
            to_mint = self.get_token_address(to_token)
            
            # Convert amount to smallest unit (usually 9 decimals for SOL tokens)
            amount_lamports = int(amount * 10**9)
            
            params = {
                "fromMint": from_mint,
                "toMint": to_mint,
                "amount": amount_lamports,
                "slippage": slippage
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.quotes_endpoint, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data and len(data) > 0:
                            best_quote = data[0]  # First result is usually the best
                            
                            return {
                                "success": True,
                                "from_token": from_token,
                                "to_token": to_token,
                                "input_amount": amount,
                                "output_amount": float(best_quote.get("outAmount", 0)) / 10**9,
                                "estimated_fee": float(best_quote.get("fee", 0)) / 10**9,
                                "dex": best_quote.get("dex", "unknown"),
                                "route": best_quote.get("route", []),
                                "impact": best_quote.get("priceImpact", 0),
                                "quote_data": best_quote,
                                "source": "solana_tracker"
                            }
                        else:
                            return {
                                "success": False,
                                "error": "No quotes available for this pair"
                            }
                    else:
                        error_text = await response.text()
                        logger.error(f"Solana Tracker API error: {response.status} - {error_text}")
                        return {
                            "success": False,
                            "error": f"API error: {response.status}"
                        }
                        
        except Exception as e:
            logger.error(f"Error getting swap quote: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_multiple_quotes(self, from_token: str, to_token: str, amount: float, slippage: float = 0.5) -> Dict[str, Any]:
        """
        Get quotes from multiple DEXs for comparison
        
        Returns:
            All available quotes sorted by best output
        """
        try:
            from_mint = self.get_token_address(from_token)
            to_mint = self.get_token_address(to_token)
            amount_lamports = int(amount * 10**9)
            
            params = {
                "fromMint": from_mint,
                "toMint": to_mint,
                "amount": amount_lamports,
                "slippage": slippage
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.quotes_endpoint, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        quotes = []
                        for quote in data:
                            processed_quote = {
                                "dex": quote.get("dex", "unknown"),
                                "output_amount": float(quote.get("outAmount", 0)) / 10**9,
                                "fee": float(quote.get("fee", 0)) / 10**9,
                                "price_impact": quote.get("priceImpact", 0),
                                "route_length": len(quote.get("route", [])),
                                "raw_data": quote
                            }
                            quotes.append(processed_quote)
                        
                        # Sort by output amount (best first)
                        quotes.sort(key=lambda x: x["output_amount"], reverse=True)
                        
                        return {
                            "success": True,
                            "total_quotes": len(quotes),
                            "best_dex": quotes[0]["dex"] if quotes else "none",
                            "quotes": quotes,
                            "comparison": {
                                "best_output": quotes[0]["output_amount"] if quotes else 0,
                                "worst_output": quotes[-1]["output_amount"] if quotes else 0,
                                "output_range": quotes[0]["output_amount"] - quotes[-1]["output_amount"] if len(quotes) > 1 else 0
                            }
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"API error: {response.status}"
                        }
                        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def simulate_swap(self, from_token: str, to_token: str, amount: float, wallet_address: str) -> Dict[str, Any]:
        """
        Simulate a swap transaction before execution
        
        Args:
            from_token: Source token
            to_token: Destination token  
            amount: Amount to swap
            wallet_address: Wallet public key
            
        Returns:
            Simulation result
        """
        try:
            quote = await self.get_swap_quote(from_token, to_token, amount)
            
            if not quote.get("success"):
                return quote
            
            # Prepare simulation request
            simulation_data = {
                "wallet": wallet_address,
                "fromMint": self.get_token_address(from_token),
                "toMint": self.get_token_address(to_token),
                "amount": int(amount * 10**9),
                "slippage": 0.5,
                "simulate": True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.swap_endpoint, json=simulation_data) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "success": True,
                            "simulation": data,
                            "quote": quote,
                            "estimated_gas": data.get("fee", 0),
                            "can_execute": True
                        }
                    else:
                        return {
                            "success": False,
                            "error": f"Simulation failed: {response.status}"
                        }
                        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute_swap(self, from_token: str, to_token: str, amount: float, wallet_address: str, private_key: str = None) -> Dict[str, Any]:
        """
        Execute actual swap transaction
        
        Args:
            from_token: Source token
            to_token: Destination token
            amount: Amount to swap
            wallet_address: Wallet public key
            private_key: Wallet private key for signing
            
        Returns:
            Transaction result
        """
        try:
            # First get quote
            quote = await self.get_swap_quote(from_token, to_token, amount)
            
            if not quote.get("success"):
                return quote
            
            # Prepare swap request
            swap_data = {
                "wallet": wallet_address,
                "fromMint": self.get_token_address(from_token),
                "toMint": self.get_token_address(to_token),
                "amount": int(amount * 10**9),
                "slippage": 0.5,
                "priorityFee": 0.001  # SOL
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.swap_endpoint, json=swap_data) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # The API returns transaction data that needs to be signed
                        return {
                            "success": True,
                            "transaction_data": data,
                            "quote": quote,
                            "next_step": "sign_and_submit",
                            "instructions": "Use returned transaction data with Solana Web3.js to sign and submit"
                        }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "error": f"Swap failed: {response.status} - {error_text}"
                        }
                        
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_supported_tokens(self) -> Dict[str, Any]:
        """
        Get list of supported tokens
        
        Returns:
            List of supported tokens with metadata
        """
        try:
            # This endpoint might not exist, but we'll provide our known tokens
            supported = {
                "success": True,
                "tokens": self.common_tokens,
                "total_count": len(self.common_tokens),
                "note": "Common tokens - API supports any valid Solana token address"
            }
            return supported
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

# Global client instance
solana_tracker = SolanaTrackerClient()

# Convenience functions for easy access
async def get_best_swap_quote(from_token: str, to_token: str, amount: float) -> Dict[str, Any]:
    """Get best swap quote - simple interface"""
    return await solana_tracker.get_swap_quote(from_token, to_token, amount)

async def compare_dex_quotes(from_token: str, to_token: str, amount: float) -> Dict[str, Any]:
    """Compare quotes across DEXs"""
    return await solana_tracker.get_multiple_quotes(from_token, to_token, amount)

async def execute_best_swap(from_token: str, to_token: str, amount: float, wallet_address: str) -> Dict[str, Any]:
    """Execute swap with best available route"""
    return await solana_tracker.execute_swap(from_token, to_token, amount, wallet_address)