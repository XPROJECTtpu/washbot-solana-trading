"""
🚀 WashBot Main Entry Point - Live Solana Mainnet Trading
"""
import os
import logging
import asyncio
import atexit

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize real Solana mainnet connection
logger.info("🔥 Initializing live Solana mainnet connection...")

try:
    from real_solana_mainnet import initialize_real_solana
    
    # Create async loop for initialization
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    mainnet_success = loop.run_until_complete(initialize_real_solana())
    
    if mainnet_success:
        logger.info("✅ Live Solana mainnet connected - Real trading enabled!")
    else:
        logger.error("❌ Mainnet connection failed - Check RPC endpoints")
        
except Exception as e:
    logger.error(f"Mainnet initialization error: {e}")

# Import app
from app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)