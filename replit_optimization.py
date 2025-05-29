"""
Replit Deploy Optimization Module
Optimizes WashBot for Replit's cloud infrastructure
"""

import asyncio
import logging
import time
from functools import lru_cache, wraps
from typing import Dict, Any, Optional
import os

logger = logging.getLogger(__name__)

# =================================================================
# CACHING LAYER FOR PERFORMANCE
# =================================================================

@lru_cache(maxsize=100)
def get_token_price_cached(token_address: str) -> Dict[str, Any]:
    """
    Cached token price retrieval
    Reduces API calls and improves response times
    """
    try:
        import dexscreener
        result = asyncio.run(dexscreener.get_token_info(token_address))
        return result or {"price": 0, "cached": True}
    except Exception as e:
        logger.warning(f"Cache miss for token {token_address}: {e}")
        return {"price": 0, "error": str(e), "cached": True}

@lru_cache(maxsize=50)
def get_wallet_balance_cached(wallet_address: str) -> float:
    """
    Cached wallet balance retrieval
    Prevents excessive RPC calls
    """
    try:
        # Implement actual balance check here
        return 0.0  # Placeholder
    except Exception as e:
        logger.warning(f"Balance cache miss for {wallet_address}: {e}")
        return 0.0

# =================================================================
# CONNECTION POOL OPTIMIZATION
# =================================================================

class ConnectionManager:
    """
    Manages database and API connections efficiently
    Optimized for Replit's infrastructure
    """
    
    def __init__(self):
        self.db_pool = None
        self.connection_cache = {}
        self.last_health_check = 0
        
    def get_optimized_db_config(self) -> Dict[str, Any]:
        """Get optimized database configuration for Replit"""
        return {
            'pool_size': 15,  # Reduced for Replit limits
            'max_overflow': 25,
            'pool_pre_ping': True,
            'pool_recycle': 300,
            'pool_timeout': 20,
            'echo': False,  # Disable SQL logging in production
            'connect_args': {
                'connect_timeout': 10,
                'command_timeout': 30,
                'sslmode': 'prefer'
            }
        }
    
    async def health_check(self) -> bool:
        """Periodic health check for connections"""
        current_time = time.time()
        if current_time - self.last_health_check < 60:  # Check every minute
            return True
            
        try:
            # Test database connection
            from database import db_session
            from sqlalchemy import text
            db_session.execute(text("SELECT 1"))
            
            self.last_health_check = current_time
            logger.info("✅ Connection health check passed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Connection health check failed: {e}")
            return False

# =================================================================
# BACKGROUND TASK OPTIMIZATION
# =================================================================

class BackgroundTaskManager:
    """
    Manages background tasks optimized for Replit Deploy
    """
    
    def __init__(self):
        self.active_tasks = {}
        self.task_queue = asyncio.Queue()
        self.is_running = False
        
    async def start_background_worker(self):
        """Start background task worker - disabled for deployment"""
        # Disable background worker to prevent async task issues during deploy
        logger.info("Background task worker disabled for deployment stability")
        return
                
    async def process_task(self, task: Dict[str, Any]):
        """Process individual background task - disabled for deployment"""
        return
            
            if task_type == 'balance_update':
                await self.update_wallet_balances()
            elif task_type == 'price_refresh':
                await self.refresh_token_prices()
            elif task_type == 'health_check':
                await self.system_health_check()
                
        except Exception as e:
            logger.error(f"Task processing error: {e}")
    
    async def update_wallet_balances(self):
        """Update wallet balances in background"""
        try:
            from wallet_manager import update_wallet_balances
            await update_wallet_balances()
            logger.info("✅ Wallet balances updated")
        except Exception as e:
            logger.warning(f"Balance update failed: {e}")
    
    async def refresh_token_prices(self):
        """Refresh token prices in background"""
        try:
            # Clear cache periodically
            get_token_price_cached.cache_clear()
            logger.info("✅ Token price cache refreshed")
        except Exception as e:
            logger.warning(f"Price refresh failed: {e}")
    
    async def system_health_check(self):
        """Perform system health check"""
        try:
            connection_manager = ConnectionManager()
            is_healthy = await connection_manager.health_check()
            
            if not is_healthy:
                logger.warning("⚠️ System health check failed")
            
        except Exception as e:
            logger.error(f"Health check error: {e}")

# =================================================================
# REPLIT DEPLOY SPECIFIC OPTIMIZATIONS
# =================================================================

def optimize_for_replit():
    """
    Apply Replit-specific optimizations
    """
    
    # Set optimal logging level
    logging.getLogger().setLevel(logging.INFO)
    
    # Optimize asyncio for Replit
    if hasattr(asyncio, 'set_event_loop_policy'):
        if os.name == 'posix':
            asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    
    # Environment-specific configurations
    os.environ.setdefault('PYTHONUNBUFFERED', '1')
    os.environ.setdefault('FLASK_ENV', 'production')
    
    logger.info("✅ Replit Deploy optimizations applied")

def rate_limit(max_calls_per_minute: int = 60):
    """
    Rate limiting decorator for API endpoints
    Prevents hitting Replit resource limits
    """
    call_times = []
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            now = time.time()
            
            # Remove calls older than 1 minute
            call_times[:] = [t for t in call_times if now - t < 60]
            
            # Check rate limit
            if len(call_times) >= max_calls_per_minute:
                logger.warning(f"Rate limit exceeded for {func.__name__}")
                await asyncio.sleep(1)  # Brief delay
            
            call_times.append(now)
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator

# =================================================================
# STARTUP OPTIMIZATION
# =================================================================

async def replit_startup_sequence():
    """
    Optimized startup sequence for Replit Deploy
    """
    logger.info("🚀 Starting Replit Deploy optimization sequence...")
    
    try:
        # Apply optimizations
        optimize_for_replit()
        
        # Initialize connection manager
        connection_manager = ConnectionManager()
        
        # Start background task manager
        task_manager = BackgroundTaskManager()
        asyncio.create_task(task_manager.start_background_worker())
        
        # Initial health check
        await connection_manager.health_check()
        
        logger.info("✅ Replit Deploy optimization complete!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Replit optimization failed: {e}")
        return False

# =================================================================
# KEEP-ALIVE MECHANISM
# =================================================================

class KeepAliveManager:
    """
    Prevents Replit from putting the app to sleep
    """
    
    def __init__(self):
        self.last_ping = time.time()
        self.ping_interval = 300  # 5 minutes
        
    async def start_keep_alive(self):
        """Start keep-alive pinging"""
        while True:
            try:
                await asyncio.sleep(self.ping_interval)
                await self.ping_self()
            except Exception as e:
                logger.warning(f"Keep-alive ping failed: {e}")
    
    async def ping_self(self):
        """Send self-ping to prevent sleeping"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get('http://localhost:5000/health') as response:
                    if response.status == 200:
                        logger.debug("✅ Keep-alive ping successful")
                        self.last_ping = time.time()
        except Exception as e:
            logger.debug(f"Keep-alive ping error: {e}")

# =================================================================
# GLOBAL INSTANCES
# =================================================================

# Create global instances
connection_manager = ConnectionManager()
task_manager = BackgroundTaskManager()
keep_alive_manager = KeepAliveManager()

# Export for use in main app
__all__ = [
    'get_token_price_cached',
    'get_wallet_balance_cached', 
    'connection_manager',
    'task_manager',
    'keep_alive_manager',
    'replit_startup_sequence',
    'optimize_for_replit',
    'rate_limit'
]