"""
Real-Time Price Feed Manager
Fetches live token prices from multiple DEX sources for chart display
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict, deque
import time

logger = logging.getLogger(__name__)

class RealTimePriceFeed:
    """
    Real-time price feed manager for token price tracking
    Fetches from DexScreener, Jupiter, and other DEX APIs
    """
    
    def __init__(self):
        self.price_history = defaultdict(lambda: deque(maxlen=3600))  # Keep 1 hour of second data
        self.minute_history = defaultdict(lambda: deque(maxlen=1440))  # Keep 24 hours of minute data
        self.active_tokens = set()
        self.is_running = False
        
        # API endpoints
        self.dexscreener_api = "https://api.dexscreener.com/latest/dex"
        self.jupiter_price_api = "https://price.jup.ag/v4/price"
        
        # Update intervals
        self.second_interval = 1  # Update every second
        self.minute_interval = 60  # Aggregate every minute
        
    async def add_token_to_track(self, token_address: str) -> bool:
        """Add token to real-time tracking"""
        try:
            token_address = token_address.strip()
            if token_address and token_address not in self.active_tokens:
                self.active_tokens.add(token_address)
                logger.info(f"🎯 Added token {token_address} to real-time tracking")
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding token to tracking: {e}")
            return False
    
    async def remove_token_from_track(self, token_address: str) -> bool:
        """Remove token from tracking"""
        try:
            self.active_tokens.discard(token_address)
            logger.info(f"🗑️ Removed token {token_address} from tracking")
            return True
        except Exception as e:
            logger.error(f"Error removing token from tracking: {e}")
            return False
    
    async def get_live_price_dexscreener(self, token_address: str) -> Optional[float]:
        """Get live price from DexScreener"""
        try:
            # Use the correct DexScreener API endpoint
            url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        pairs = data.get('pairs', [])
                        
                        if pairs:
                            # Get highest liquidity pair for most accurate price
                            best_pair = max(pairs, key=lambda p: float(p.get('liquidity', {}).get('usd', 0) or 0))
                            price = float(best_pair.get('priceUsd', 0))
                            
                            if price > 0:
                                logger.info(f"DexScreener price for {token_address}: ${price}")
                                return price
                                
        except Exception as e:
            logger.debug(f"DexScreener price fetch error for {token_address}: {e}")
        
        return None
    
    async def get_live_price_jupiter(self, token_address: str) -> Optional[float]:
        """Get live price from Jupiter"""
        try:
            # Use the correct Jupiter API endpoint
            url = f"https://price.jup.ag/v4/price?ids={token_address}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        price_data = data.get('data', {}).get(token_address, {})
                        price = float(price_data.get('price', 0))
                        
                        if price > 0:
                            logger.info(f"Jupiter price for {token_address}: ${price}")
                            return price
                            
        except Exception as e:
            logger.debug(f"Jupiter price fetch error for {token_address}: {e}")
        
        return None
    
    async def fetch_token_price(self, token_address: str) -> Optional[Dict[str, Any]]:
        """Fetch current price from multiple sources"""
        try:
            # Try multiple sources for best accuracy
            price_dex = await self.get_live_price_dexscreener(token_address)
            price_jupiter = await self.get_live_price_jupiter(token_address)
            
            # Use DexScreener as primary, Jupiter as fallback
            final_price = price_dex or price_jupiter
            
            if final_price:
                timestamp = datetime.utcnow()
                return {
                    'token': token_address,
                    'price': final_price,
                    'timestamp': timestamp.isoformat(),
                    'unix_timestamp': int(timestamp.timestamp()),
                    'source': 'dexscreener' if price_dex else 'jupiter'
                }
                
        except Exception as e:
            logger.error(f"Error fetching price for {token_address}: {e}")
        
        return None
    
    async def update_price_histories(self):
        """Update price histories for all tracked tokens"""
        current_time = datetime.utcnow()
        
        for token_address in list(self.active_tokens):
            try:
                price_data = await self.fetch_token_price(token_address)
                
                if price_data:
                    # Add to second-by-second history
                    self.price_history[token_address].append(price_data)
                    
                    # Check if we need to add a minute aggregate
                    minute_key = current_time.replace(second=0, microsecond=0)
                    
                    # Create minute aggregate if needed
                    minute_prices = [
                        p['price'] for p in list(self.price_history[token_address])
                        if datetime.fromisoformat(p['timestamp']).replace(second=0, microsecond=0) == minute_key
                    ]
                    
                    if minute_prices:
                        minute_data = {
                            'token': token_address,
                            'price': sum(minute_prices) / len(minute_prices),  # Average price for the minute
                            'high': max(minute_prices),
                            'low': min(minute_prices),
                            'timestamp': minute_key.isoformat(),
                            'unix_timestamp': int(minute_key.timestamp()),
                            'volume': len(minute_prices)  # Number of updates in that minute
                        }
                        
                        # Only add if we don't already have this minute
                        if not self.minute_history[token_address] or \
                           self.minute_history[token_address][-1]['unix_timestamp'] != minute_data['unix_timestamp']:
                            self.minute_history[token_address].append(minute_data)
                    
            except Exception as e:
                logger.error(f"Error updating price history for {token_address}: {e}")
    
    async def start_price_feed(self):
        """Start the real-time price feed"""
        if self.is_running:
            return
        
        self.is_running = True
        logger.info("🚀 Starting real-time price feed...")
        
        while self.is_running:
            try:
                if self.active_tokens:
                    await self.update_price_histories()
                
                # Wait for next update
                await asyncio.sleep(self.second_interval)
                
            except Exception as e:
                logger.error(f"Error in price feed loop: {e}")
                await asyncio.sleep(5)  # Wait 5 seconds on error
    
    def stop_price_feed(self):
        """Stop the real-time price feed"""
        self.is_running = False
        logger.info("🛑 Stopped real-time price feed")
    
    def get_price_data(self, token_address: str, timeframe: str = 'seconds', limit: int = 100) -> List[Dict[str, Any]]:
        """Get price data for chart display"""
        try:
            if timeframe == 'minutes':
                data = list(self.minute_history[token_address])
            else:
                data = list(self.price_history[token_address])
            
            # Return last N data points
            return data[-limit:] if len(data) > limit else data
            
        except Exception as e:
            logger.error(f"Error getting price data: {e}")
            return []
    
    def get_current_price(self, token_address: str) -> Optional[Dict[str, Any]]:
        """Get current price for a token"""
        try:
            if token_address in self.price_history and self.price_history[token_address]:
                return self.price_history[token_address][-1]
        except Exception as e:
            logger.error(f"Error getting current price: {e}")
        
        return None

# Global price feed manager
price_feed_manager = RealTimePriceFeed()

async def start_price_tracking():
    """Start price tracking in background"""
    try:
        await price_feed_manager.start_price_feed()
    except Exception as e:
        logger.error(f"Error starting price tracking: {e}")

def track_strategy_token(token_address: str):
    """Track token used in strategy"""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(price_feed_manager.add_token_to_track(token_address))
        loop.close()
    except Exception as e:
        logger.error(f"Error tracking strategy token: {e}")