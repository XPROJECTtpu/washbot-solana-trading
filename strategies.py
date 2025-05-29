import logging
import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
import time
import json
from decimal import Decimal

from database import get_db_connection
from models import Strategy, Wallet, Token, TokenPrice
import wallet_manager
import solana_utils
import raydium_client
import dexscreener
# Jupiter client removed - using Raydium instead
from real_solana_client import real_solana_client, execute_real_strategy

# Enhanced Solana Program Addresses for strategies
SOLANA_PROGRAMS = {
    "SPL_TOKEN": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "ASSOCIATED_TOKEN": "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", 
    "SYSTEM": "11111111111111111111111111111111",
    "WRAPPED_SOL": "So11111111111111111111111111111111111111112",
    "USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
}

logger = logging.getLogger(__name__)

class BaseStrategy:
    """Base class for all trading strategies"""
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        """
        Initialize strategy
        
        Args:
            token_address: Token address to trade
            parameters: Strategy parameters
        """
        self.token_address = token_address
        self.parameters = parameters or {}
        self.strategy_id = str(uuid.uuid4())
        self.is_running = False
        self.start_time = None
        self.end_time = None
        self.results = {}
        
        # Default SOL token address
        self.sol_token = "So11111111111111111111111111111111111111112"
        
    async def execute(self):
        """
        Execute the strategy
        
        Returns:
            Strategy results
        """
        # Record start time
        self.start_time = datetime.now()
        self.is_running = True
        
        try:
            # Save strategy in database
            db = get_db_connection()
            db_strategy = Strategy(
                id=self.strategy_id,
                type=self.__class__.__name__,
                token_address=self.token_address,
                parameters=json.dumps(self.parameters),
                status="running",
                created_at=self.start_time
            )
            db.add(db_strategy)
            db.commit()
            
            # Execute strategy logic (to be implemented by subclasses)
            result = await self._execute_impl()
            
            # Record end time
            self.end_time = datetime.now()
            self.is_running = False
            
            # Save results
            self.results = result
            
            # Update database
            db_strategy.status = "completed"
            db_strategy.results = json.dumps(result)
            db_strategy.updated_at = datetime.now()
            db.commit()
            
            return {
                "success": True,
                "strategy_id": self.strategy_id,
                "token_address": self.token_address,
                "type": self.__class__.__name__,
                "parameters": self.parameters,
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "end_time": self.end_time.isoformat() if self.end_time else None,
                "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else None,
                "results": result
            }
            
        except Exception as e:
            logger.error(f"Error executing strategy {self.__class__.__name__}: {e}")
            self.is_running = False
            self.end_time = datetime.now()
            
            # Update database with error
            db = get_db_connection()
            db_strategy = db.query(Strategy).filter_by(id=self.strategy_id).first()
            if db_strategy:
                db_strategy.status = "failed"
                db_strategy.results = json.dumps({"success": False, "error": str(e)})
                db_strategy.updated_at = datetime.now()
                db.commit()
            
            return {
                "success": False,
                "strategy_id": self.strategy_id,
                "token_address": self.token_address,
                "type": self.__class__.__name__,
                "error": str(e)
            }
    
    async def _execute_impl(self):
        """
        Execute strategy implementation
        
        To be implemented by subclasses
        
        Returns:
            Strategy results
        """
        raise NotImplementedError("Subclasses must implement _execute_impl()")
    
    async def check_token_price(self):
        """
        Check current token price
        
        Returns:
            Token price information
        """
        # Try DexScreener first
        token_info = await dexscreener.get_token_info(self.token_address)
        
        if not token_info.get('success', False):
            # Fallback to Raydium
            token_info = await raydium_client.get_token_info(self.token_address)
        
        return token_info
    
    async def track_price_changes(self, duration_seconds=300, interval_seconds=30):
        """
        Track price changes over time
        
        Args:
            duration_seconds: Tracking duration
            interval_seconds: Interval between price checks
            
        Returns:
            Price tracking data
        """
        tracking_data = {
            "start_time": datetime.now().isoformat(),
            "token_address": self.token_address,
            "duration_seconds": duration_seconds,
            "interval_seconds": interval_seconds,
            "price_points": [],
            "initial_price": 0,
            "final_price": 0,
            "max_price": 0,
            "min_price": float('inf'),
            "price_change_pct": 0
        }
        
        # Initial price check
        price_info = await self.check_token_price()
        
        if not price_info.get('success', False):
            logger.error(f"Failed to get initial price for {self.token_address}")
            tracking_data["error"] = "Failed to get initial price"
            return tracking_data
        
        initial_price = price_info.get('price', 0)
        tracking_data["initial_price"] = initial_price
        tracking_data["min_price"] = initial_price
        tracking_data["max_price"] = initial_price
        
        # Add first price point
        tracking_data["price_points"].append({
            "timestamp": datetime.now().isoformat(),
            "price": initial_price,
            "liquidity_usd": price_info.get('liquidity_usd', 0),
            "volume_24h": price_info.get('volume_24h', 0)
        })
        
        # Calculate end time
        end_time = datetime.now() + timedelta(seconds=duration_seconds)
        
        # Track prices at intervals
        while datetime.now() < end_time:
            # Wait for interval
            await asyncio.sleep(interval_seconds)
            
            # Check price
            price_info = await self.check_token_price()
            
            if price_info.get('success', False):
                current_price = price_info.get('price', 0)
                
                # Update min/max prices
                tracking_data["min_price"] = min(tracking_data["min_price"], current_price)
                tracking_data["max_price"] = max(tracking_data["max_price"], current_price)
                
                # Add price point
                tracking_data["price_points"].append({
                    "timestamp": datetime.now().isoformat(),
                    "price": current_price,
                    "liquidity_usd": price_info.get('liquidity_usd', 0),
                    "volume_24h": price_info.get('volume_24h', 0)
                })
            else:
                logger.warning(f"Failed to get price for {self.token_address} during tracking")
        
        # Final price check
        price_info = await self.check_token_price()
        
        if price_info.get('success', False):
            final_price = price_info.get('price', 0)
            tracking_data["final_price"] = final_price
            
            # Calculate price change
            if initial_price > 0:
                tracking_data["price_change_pct"] = (final_price / initial_price - 1) * 100
            
            # Add final price point
            tracking_data["price_points"].append({
                "timestamp": datetime.now().isoformat(),
                "price": final_price,
                "liquidity_usd": price_info.get('liquidity_usd', 0),
                "volume_24h": price_info.get('volume_24h', 0)
            })
        
        return tracking_data

class PumpStrategy(BaseStrategy):
    """Pump It strategy implementation"""
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        """
        Initialize Pump It strategy
        
        Args:
            token_address: Token address to pump
            parameters: Strategy parameters
        """
        super().__init__(token_address, parameters)
        
        # Set default parameters if not provided
        if not self.parameters:
            self.parameters = {
                'target_price_increase': 20.0,  # Target price increase (%)
                'volume_factor': 2.0,           # Target volume increase factor
                'wallet_count': 5,              # Number of wallets to use
                'time_period_minutes': 10,      # Time period for the operation
                'interval_seconds': 30,         # Interval between buys
                'initial_buy_percentage': 10.0, # Initial buy percentage
                'enable_periodic_sells': False, # Enable periodic sell operations
                'sell_after_n_buys': 5,        # Sell after every N buy operations
                'sell_percentage': 50.0,       # Percentage of tokens to sell each time
                'use_rate_limiting': True       # Use rate limiting to avoid RPC errors
            }
    
    async def _execute_impl(self):
        """
        Execute Pump It strategy
        
        Returns:
            Strategy results
        """
        # Get parameters
        target_increase = self.parameters.get('target_price_increase', 20.0)
        volume_factor = self.parameters.get('volume_factor', 2.0)
        wallet_count = self.parameters.get('wallet_count', 5)
        time_period_minutes = self.parameters.get('time_period_minutes', 10)
        interval_seconds = self.parameters.get('interval_seconds', 30)
        initial_buy_percentage = self.parameters.get('initial_buy_percentage', 10.0)
        
        # Periodic sell parameters
        enable_periodic_sells = self.parameters.get('enable_periodic_sells', False)
        sell_after_n_buys = self.parameters.get('sell_after_n_buys', 5)
        sell_percentage = self.parameters.get('sell_percentage', 50.0)
        use_rate_limiting = self.parameters.get('use_rate_limiting', True)
        
        # Check initial token price and volume
        initial_price_info = await self.check_token_price()
        
        if not initial_price_info.get('success', False):
            return {
                "success": False,
                "error": f"Failed to get initial price info: {initial_price_info.get('error', 'Unknown error')}"
            }
        
        initial_price = initial_price_info.get('price', 0)
        initial_volume = initial_price_info.get('volume_24h', 0)
        initial_liquidity = initial_price_info.get('liquidity_usd', 0)
        
        logger.info(f"Starting Pump It strategy for {self.token_address}")
        logger.info(f"Initial price: ${initial_price}, volume: ${initial_volume}, liquidity: ${initial_liquidity}")
        
        # Get wallets for the operation
        encryption_key = "washbot_development_key"
        storage_password = "washbot_secure_storage"
        
        all_wallets = await wallet_manager.get_all_wallets(encryption_key, storage_password)
        
        if len(all_wallets) < wallet_count:
            return {
                "success": False,
                "error": f"Not enough wallets available. Need {wallet_count}, have {len(all_wallets)}"
            }
        
        # Select random wallets
        selected_wallets = random.sample(all_wallets, wallet_count)
        
        # Update wallet balances
        selected_wallets = await wallet_manager.update_wallet_balances(selected_wallets)
        
        # Prepare result data
        result = {
            "success": True,
            "token_address": self.token_address,
            "initial_price": initial_price,
            "initial_volume": initial_volume,
            "initial_liquidity": initial_liquidity,
            "wallets_used": wallet_count,
            "target_increase": target_increase,
            "transactions": [],
            "buy_operations": 0,
            "sell_operations": 0,
            "total_bought_tokens": 0.0,
            "total_sold_tokens": 0.0,
            "total_spent_sol": 0.0,
            "total_earned_sol": 0.0,
            "final_price": 0,
            "price_change_pct": 0,
            "volume_change_factor": 0
        }
        
        # Add token balance tracking for all wallets
        for wallet in selected_wallets:
            wallet.token_balance = 0.0
            wallet.token_decimals = 9
            wallet.buy_count = 0
            
            # Check if wallet already has any token balance
            token_balance = await solana_utils.get_token_balance(
                wallet_public_key=wallet.public_key,
                token_address=self.token_address,
                network=wallet.network
            )
            
            if token_balance.get('success', False) and token_balance.get('balance', 0) > 0:
                wallet.token_balance = token_balance.get('balance', 0)
                wallet.token_decimals = token_balance.get('decimals', 9)
        
        # Calculate time distribution
        total_seconds = time_period_minutes * 60
        intervals = max(1, int(total_seconds / interval_seconds))
        
        # Execute buys with increasing size
        for i in range(intervals):
            # Skip some intervals randomly to create natural pattern
            if random.random() < 0.3:  # 30% chance to skip
                await asyncio.sleep(interval_seconds)
                continue
            
            # Select a wallet for this buy
            wallet = random.choice(selected_wallets)
            
            # Calculate buy amount (increasing over time)
            progress = (i + 1) / intervals
            buy_percentage = initial_buy_percentage + (100 - initial_buy_percentage) * (progress ** 2)
            
            # Buy amount in SOL - using wallet balance * percentage
            buy_amount_sol = wallet.balance * (buy_percentage / 100)
            
            # Ensure minimum amount
            buy_amount_sol = max(0.01, min(buy_amount_sol, wallet.balance * 0.9))
            
            # Execute swap
            swap_result = await jupiter_client.execute_jupiter_swap(
                wallet=wallet,
                input_mint=self.sol_token,
                output_mint=self.token_address,
                amount=buy_amount_sol,
                slippage_bps=500  # Higher slippage for pump
            )
            
            # Record transaction
            tx_info = {
                "type": "buy",
                "wallet_id": wallet.id,
                "wallet_public_key": wallet.public_key,
                "amount_sol": buy_amount_sol,
                "timestamp": datetime.now().isoformat(),
                "success": swap_result.get('success', False)
            }
            
            if swap_result.get('success', False):
                tx_info["txid"] = swap_result.get('txid', '')
                received_tokens = swap_result.get('out_amount', 0)
                tx_info["tokens_received"] = received_tokens
                tx_info["price_impact_pct"] = swap_result.get('price_impact_pct', 0)
                
                # Update wallet token balance
                wallet.token_balance += received_tokens
                wallet.buy_count += 1
                
                # Update global counters
                result["buy_operations"] += 1
                result["total_bought_tokens"] += received_tokens
                result["total_spent_sol"] += buy_amount_sol
                
                logger.info(f"Buy executed: {buy_amount_sol} SOL -> {received_tokens} tokens, tx: {swap_result.get('txid', '')}")
            else:
                tx_info["error"] = swap_result.get('error', 'Unknown error')
                logger.warning(f"Buy failed: {swap_result.get('error', 'Unknown error')}")
            
            result["transactions"].append(tx_info)
            
            # Check if we should execute a sell operation (if periodic sells are enabled)
            if (enable_periodic_sells and 
                wallet.buy_count > 0 and 
                wallet.buy_count % sell_after_n_buys == 0 and
                wallet.token_balance > 0):
                
                # Calculate sell amount
                sell_amount = wallet.token_balance * (sell_percentage / 100)
                
                # Only sell if we have enough tokens
                if sell_amount > 0.000001:
                    logger.info(f"Executing periodic sell after {wallet.buy_count} buys for wallet {wallet.id}")
                    
                    # Execute sell
                    sell_result = await jupiter_client.execute_jupiter_swap(
                        wallet=wallet,
                        input_mint=self.token_address,
                        output_mint=self.sol_token,
                        amount=sell_amount,
                        slippage_bps=1000  # 10% slippage for sells
                    )
                    
                    # Record sell transaction
                    sell_tx_info = {
                        "type": "sell",
                        "wallet_id": wallet.id,
                        "wallet_public_key": wallet.public_key,
                        "amount_tokens": sell_amount,
                        "timestamp": datetime.now().isoformat(),
                        "success": sell_result.get('success', False)
                    }
                    
                    if sell_result.get('success', False):
                        sell_tx_info["txid"] = sell_result.get('txid', '')
                        received_sol = sell_result.get('out_amount', 0) / 1e9  # Convert lamports to SOL
                        sell_tx_info["sol_received"] = received_sol
                        sell_tx_info["price_impact_pct"] = sell_result.get('price_impact_pct', 0)
                        
                        # Update wallet data
                        wallet.token_balance -= sell_amount
                        
                        # Update global counters
                        result["sell_operations"] += 1
                        result["total_sold_tokens"] += sell_amount
                        result["total_earned_sol"] += received_sol
                        
                        logger.info(f"Sell executed: {sell_amount} tokens -> {received_sol} SOL, tx: {sell_result.get('txid', '')}")
                    else:
                        sell_tx_info["error"] = sell_result.get('error', 'Unknown error')
                        logger.warning(f"Sell failed: {sell_result.get('error', 'Unknown error')}")
                    
                    result["transactions"].append(sell_tx_info)
            
            # Wait for next interval
            await asyncio.sleep(interval_seconds)
            
            # Check current price occasionally
            if i % 5 == 0 or i == intervals - 1:
                current_price_info = await self.check_token_price()
                
                if current_price_info.get('success', False):
                    current_price = current_price_info.get('price', 0)
                    price_change = (current_price / initial_price - 1) * 100
                    
                    logger.info(f"Current price: ${current_price} ({price_change:.2f}% change)")
                    
                    # If target increase reached, we can stop early
                    if price_change >= target_increase:
                        logger.info(f"Target price increase of {target_increase}% reached, stopping early")
                        break
        
        # Get final price
        final_price_info = await self.check_token_price()
        
        if final_price_info.get('success', False):
            final_price = final_price_info.get('price', 0)
            final_volume = final_price_info.get('volume_24h', 0)
            final_liquidity = final_price_info.get('liquidity_usd', 0)
            
            result["final_price"] = final_price
            result["final_volume"] = final_volume
            result["final_liquidity"] = final_liquidity
            
            if initial_price > 0:
                result["price_change_pct"] = (final_price / initial_price - 1) * 100
            
            if initial_volume > 0:
                result["volume_change_factor"] = final_volume / initial_volume
        
        logger.info(f"Pump It strategy completed for {self.token_address}")
        logger.info(f"Price change: {result.get('price_change_pct', 0):.2f}%")
        
        return result

class HybridTradingStrategy(BaseStrategy):
    """
    Hybrid Trading Strategy - Allows simultaneous buying and periodic selling
    This strategy creates a buy pressure while maintaining SOL liquidity through periodic sells
    """
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        """
        Initialize Hybrid Trading Strategy
        
        Args:
            token_address: Token address to trade
            parameters: Strategy parameters
        """
        super().__init__(token_address, parameters)
        
        # Set default parameters if not provided
        if not self.parameters:
            self.parameters = {
                'duration_hours': 1.0,         # Total duration in hours
                'wallet_count': 50,            # Number of wallets to use
                'buy_interval_seconds': 30,    # Interval between buys
                'sell_frequency': 5,           # Sell after every X buys
                'sell_percentage': 50.0,       # Percentage of tokens to sell each time
                'initial_buy_amount': 0.01,    # Initial buy amount in SOL
                'max_buy_amount': 0.05,        # Maximum buy amount in SOL
                'min_sol_reserve': 0.02,       # Minimum SOL to keep in wallet
                'randomize_timing': True,      # Randomize timing between operations
                'randomize_amounts': True,     # Randomize buy/sell amounts
                'use_rate_limiting': True      # Use rate limiting to avoid RPC errors
            }
    
    async def _execute_impl(self):
        """
        Execute Hybrid Trading Strategy
        
        Returns:
            Strategy results
        """
        # Get parameters
        duration_hours = self.parameters.get('duration_hours', 1.0)
        wallet_count = self.parameters.get('wallet_count', 50)
        buy_interval_seconds = self.parameters.get('buy_interval_seconds', 30)
        sell_frequency = self.parameters.get('sell_frequency', 5)
        sell_percentage = self.parameters.get('sell_percentage', 50.0)
        initial_buy_amount = self.parameters.get('initial_buy_amount', 0.01)
        max_buy_amount = self.parameters.get('max_buy_amount', 0.05)
        min_sol_reserve = self.parameters.get('min_sol_reserve', 0.02)
        randomize_timing = self.parameters.get('randomize_timing', True)
        randomize_amounts = self.parameters.get('randomize_amounts', True)
        use_rate_limiting = self.parameters.get('use_rate_limiting', True)
        
        # Check initial token price
        initial_price_info = await self.check_token_price()
        
        if not initial_price_info.get('success', False):
            return {
                "success": False,
                "error": f"Failed to get initial price info: {initial_price_info.get('error', 'Unknown error')}"
            }
        
        initial_price = initial_price_info.get('price', 0)
        initial_volume = initial_price_info.get('volume_24h', 0)
        initial_liquidity = initial_price_info.get('liquidity_usd', 0)
        
        logger.info(f"Starting Hybrid Trading Strategy for {self.token_address}")
        logger.info(f"Initial price: ${initial_price}, volume: ${initial_volume}, liquidity: ${initial_liquidity}")
        
        # Get wallets for the operation
        encryption_key = "washbot_development_key"
        storage_password = "washbot_secure_storage"
        
        all_wallets = await wallet_manager.get_all_wallets(encryption_key, storage_password)
        
        if len(all_wallets) < wallet_count:
            return {
                "success": False,
                "error": f"Not enough wallets available. Required: {wallet_count}, Available: {len(all_wallets)}"
            }
        
        # Select wallets with SOL balance
        wallets_with_sol = []
        
        for wallet in all_wallets:
            # Check if wallet has enough SOL
            sol_balance = await solana_utils.get_sol_balance(wallet.public_key, wallet.network)
            
            if sol_balance.get('success', False) and sol_balance.get('balance', 0) >= initial_buy_amount + min_sol_reserve:
                wallet.sol_balance = sol_balance.get('balance', 0)
                wallet.used_for_buys = 0  # Counter for buy operations
                wallet.used_for_sells = 0  # Counter for sell operations
                wallet.total_spent = 0.0  # Total SOL spent
                wallet.total_bought = 0.0  # Total tokens bought
                wallet.total_sold = 0.0  # Total tokens sold
                wallet.total_earned = 0.0  # Total SOL earned
                wallet.token_balance = 0.0  # Current token balance
                
                # Get token balance if any
                token_balance = await solana_utils.get_token_balance(
                    wallet_public_key=wallet.public_key,
                    token_address=self.token_address,
                    network=wallet.network
                )
                
                if token_balance.get('success', False) and token_balance.get('balance', 0) > 0:
                    wallet.token_balance = token_balance.get('balance', 0)
                    wallet.token_decimals = token_balance.get('decimals', 9)
                
                wallets_with_sol.append(wallet)
                
                if len(wallets_with_sol) >= wallet_count:
                    break
        
        if len(wallets_with_sol) < wallet_count:
            return {
                "success": False,
                "error": f"Not enough wallets with SOL balance. Required: {wallet_count}, Available: {len(wallets_with_sol)}"
            }
        
        # Rate limiter for RPC calls to prevent rate limiting
        class RateLimiter:
            def __init__(self, requests_per_minute=45):
                self.rate = requests_per_minute
                self.last_check = time.time()
                self.allowance = self.rate
            
            async def wait_if_needed(self):
                if not use_rate_limiting:
                    return
                    
                current = time.time()
                time_passed = current - self.last_check
                self.last_check = current
                self.allowance += time_passed * (self.rate / 60.0)
                
                if self.allowance > self.rate:
                    self.allowance = self.rate
                    
                if self.allowance < 1.0:
                    # Wait to comply with rate limit
                    await asyncio.sleep((1.0 - self.allowance) * 60.0 / self.rate)
                    self.allowance = 0.0
                else:
                    self.allowance -= 1.0
        
        rate_limiter = RateLimiter()
        
        # Calculate total operations and timing
        total_duration_seconds = duration_hours * 3600
        total_operations = int(total_duration_seconds / buy_interval_seconds)
        
        # Result tracking
        result = {
            "success": True,
            "initial_price": initial_price,
            "initial_volume": initial_volume,
            "initial_liquidity": initial_liquidity,
            "total_operations": total_operations,
            "buy_operations": 0,
            "sell_operations": 0,
            "successful_buys": 0,
            "successful_sells": 0,
            "total_spent_sol": 0.0,
            "total_earned_sol": 0.0,
            "total_bought_tokens": 0.0,
            "total_sold_tokens": 0.0,
            "wallets_used": len(wallets_with_sol),
            "price_tracking": [],
            "transactions": []
        }
        
        # Execute operations
        operations_counter = 0
        buy_counter = 0
        sell_counter = 0
        start_time = time.time()
        
        while operations_counter < total_operations and (time.time() - start_time) < total_duration_seconds:
            # Randomize sleep time if enabled
            current_interval = buy_interval_seconds
            if randomize_timing:
                current_interval = buy_interval_seconds * random.uniform(0.7, 1.3)
            
            # Wait between operations
            await asyncio.sleep(current_interval)
            operations_counter += 1
            
            # Track price every 5 operations
            if operations_counter % 5 == 0 or operations_counter == 1 or operations_counter == total_operations:
                await rate_limiter.wait_if_needed()
                current_price_info = await self.check_token_price()
                
                if current_price_info.get('success', False):
                    current_price = current_price_info.get('price', 0)
                    price_change = (current_price / initial_price - 1) * 100 if initial_price > 0 else 0
                    
                    logger.info(f"Current price: ${current_price} ({price_change:.2f}% change)")
                    
                    # Add to price tracking
                    result["price_tracking"].append({
                        "time": time.time() - start_time,
                        "price": current_price,
                        "operations": operations_counter,
                        "buys": buy_counter,
                        "sells": sell_counter
                    })
            
            # Decide if this is a buy or sell operation
            # Every sell_frequency buys, we do a sell
            is_buy_operation = True
            if buy_counter > 0 and buy_counter % sell_frequency == 0:
                is_buy_operation = False
            
            if is_buy_operation:
                # Perform buy operation
                # Select a wallet for this buy
                available_wallets = [w for w in wallets_with_sol if w.sol_balance >= initial_buy_amount + min_sol_reserve]
                
                if not available_wallets:
                    logger.warning("No wallets with sufficient SOL balance for buy operation")
                    continue
                
                wallet = random.choice(available_wallets)
                
                # Calculate buy amount (may increase over time)
                progress = min(1.0, operations_counter / (total_operations * 0.8))
                base_buy_amount = initial_buy_amount + (max_buy_amount - initial_buy_amount) * progress
                
                # Randomize amount if enabled
                buy_amount = base_buy_amount
                if randomize_amounts:
                    buy_amount = base_buy_amount * random.uniform(0.8, 1.2)
                
                # Ensure amount doesn't exceed wallet balance minus reserve
                max_possible = wallet.sol_balance - min_sol_reserve
                buy_amount = min(buy_amount, max_possible)
                
                # Skip if amount is too small
                if buy_amount < 0.001:
                    continue
                
                # Execute swap
                await rate_limiter.wait_if_needed()
                swap_result = await jupiter_client.execute_jupiter_swap(
                    wallet=wallet,
                    input_mint=self.sol_token,
                    output_mint=self.token_address,
                    amount=buy_amount,
                    slippage_bps=500  # 5% slippage
                )
                
                # Record transaction
                buy_counter += 1
                tx_info = {
                    "type": "buy",
                    "wallet_id": wallet.id,
                    "wallet_public_key": wallet.public_key,
                    "amount_sol": buy_amount,
                    "timestamp": datetime.now().isoformat(),
                    "success": swap_result.get('success', False)
                }
                
                if swap_result.get('success', False):
                    tx_info["txid"] = swap_result.get('txid', '')
                    tx_info["tokens_received"] = swap_result.get('out_amount', 0)
                    tx_info["price_impact_pct"] = swap_result.get('price_impact_pct', 0)
                    logger.info(f"Buy executed: {buy_amount} SOL -> tokens, tx: {swap_result.get('txid', '')}")
                    
                    # Update wallet data
                    wallet.sol_balance -= buy_amount
                    received_tokens = swap_result.get('out_amount', 0)
                    wallet.token_balance += received_tokens
                    wallet.used_for_buys += 1
                    wallet.total_spent += buy_amount
                    wallet.total_bought += received_tokens
                    
                    # Update global counters
                    result["successful_buys"] += 1
                    result["total_spent_sol"] += buy_amount
                    result["total_bought_tokens"] += received_tokens
                else:
                    error_msg = swap_result.get('error', 'Unknown error')
                    tx_info["error"] = error_msg
                    logger.warning(f"Buy failed: {error_msg}")
                
                result["transactions"].append(tx_info)
                result["buy_operations"] += 1
            else:
                # Perform sell operation
                # Find wallets with token balance
                wallets_with_token = [w for w in wallets_with_sol if w.token_balance > 0]
                
                if not wallets_with_token:
                    logger.warning("No wallets with token balance for sell operation")
                    # Continue with buys if no tokens to sell
                    continue
                
                # Select a wallet with tokens
                wallet = random.choice(wallets_with_token)
                
                # Calculate sell amount
                sell_amount = wallet.token_balance * (sell_percentage / 100)
                
                # Randomize amount if enabled
                if randomize_amounts:
                    variation = random.uniform(0.8, 1.2)
                    sell_amount = sell_amount * variation
                
                # Ensure amount doesn't exceed wallet balance
                sell_amount = min(sell_amount, wallet.token_balance)
                
                # Skip if amount is too small
                if sell_amount < 0.000001:
                    continue
                
                # Execute swap
                await rate_limiter.wait_if_needed()
                swap_result = await jupiter_client.execute_jupiter_swap(
                    wallet=wallet,
                    input_mint=self.token_address,
                    output_mint=self.sol_token,
                    amount=sell_amount,
                    slippage_bps=1000  # 10% slippage for sells
                )
                
                # Record transaction
                sell_counter += 1
                tx_info = {
                    "type": "sell",
                    "wallet_id": wallet.id,
                    "wallet_public_key": wallet.public_key,
                    "amount_tokens": sell_amount,
                    "timestamp": datetime.now().isoformat(),
                    "success": swap_result.get('success', False)
                }
                
                if swap_result.get('success', False):
                    tx_info["txid"] = swap_result.get('txid', '')
                    received_sol = swap_result.get('out_amount', 0) / 1e9  # Convert lamports to SOL
                    tx_info["sol_received"] = received_sol
                    tx_info["price_impact_pct"] = swap_result.get('price_impact_pct', 0)
                    logger.info(f"Sell executed: {sell_amount} tokens -> {received_sol} SOL, tx: {swap_result.get('txid', '')}")
                    
                    # Update wallet data
                    wallet.token_balance -= sell_amount
                    wallet.sol_balance += received_sol
                    wallet.used_for_sells += 1
                    wallet.total_sold += sell_amount
                    wallet.total_earned += received_sol
                    
                    # Update global counters
                    result["successful_sells"] += 1
                    result["total_earned_sol"] += received_sol
                    result["total_sold_tokens"] += sell_amount
                else:
                    error_msg = swap_result.get('error', 'Unknown error')
                    tx_info["error"] = error_msg
                    logger.warning(f"Sell failed: {error_msg}")
                
                result["transactions"].append(tx_info)
                result["sell_operations"] += 1
        
        # Get final price and update statistics
        await rate_limiter.wait_if_needed()
        final_price_info = await self.check_token_price()
        
        if final_price_info.get('success', False):
            final_price = final_price_info.get('price', 0)
            final_volume = final_price_info.get('volume_24h', 0)
            final_liquidity = final_price_info.get('liquidity_usd', 0)
            
            result["final_price"] = final_price
            result["final_volume"] = final_volume
            result["final_liquidity"] = final_liquidity
            
            if initial_price > 0:
                result["price_change_pct"] = (final_price / initial_price - 1) * 100
            
            if initial_volume > 0:
                result["volume_change_factor"] = final_volume / initial_volume
        
        # Calculate profit/loss statistics
        result["net_sol_profit"] = result["total_earned_sol"] - result["total_spent_sol"]
        result["roi_percentage"] = (result["net_sol_profit"] / result["total_spent_sol"] * 100) if result["total_spent_sol"] > 0 else 0
        
        # Calculate wallet-specific statistics
        wallet_stats = []
        for wallet in wallets_with_sol:
            if wallet.used_for_buys > 0 or wallet.used_for_sells > 0:
                profit = wallet.total_earned - wallet.total_spent
                roi = (profit / wallet.total_spent * 100) if wallet.total_spent > 0 else 0
                
                wallet_stats.append({
                    "wallet_id": wallet.id,
                    "buys": wallet.used_for_buys,
                    "sells": wallet.used_for_sells,
                    "spent_sol": wallet.total_spent,
                    "earned_sol": wallet.total_earned,
                    "profit_sol": profit,
                    "roi_pct": roi,
                    "remaining_tokens": wallet.token_balance,
                    "sol_balance": wallet.sol_balance
                })
        
        result["wallet_stats"] = wallet_stats
        
        # Log completion
        duration = time.time() - start_time
        logger.info(f"Hybrid Trading Strategy completed for {self.token_address}")
        logger.info(f"Executed {buy_counter} buys and {sell_counter} sells in {duration:.2f} seconds")
        logger.info(f"Price change: {result.get('price_change_pct', 0):.2f}%")
        logger.info(f"Net profit: {result.get('net_sol_profit', 0):.6f} SOL ({result.get('roi_percentage', 0):.2f}% ROI)")
        
        return result

# ===== GELIŞMIŞ USDT-TABANLΙ TRADING STRATEJİLERİ =====
# solana_token_bot'dan entegre edildi - Enterprise seviyesi trading

class USDTEnhancedPumpStrategy(BaseStrategy):
    """
    USDT tabanlı gelişmiş pump stratejisi
    Multi-wallet koordineli token satın alma ve price pump işlemleri
    """
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        super().__init__(token_address, parameters)
        self.strategy_type = "usdt_enhanced_pump"
        
    async def execute(self, 
                     total_usdt_budget: float = 100.0,
                     pump_phases: int = 3,
                     wallet_count: int = 10,
                     time_delay_minutes: int = 5,
                     target_price_increase_pct: float = 50.0,
                     slippage: float = 1.0,
                     encryption_key: str = None) -> Dict[str, Any]:
        """
        USDT tabanlı pump stratejisi çalıştırır
        
        Args:
            total_usdt_budget: Toplam USDT bütçesi
            pump_phases: Pump fazları sayısı
            wallet_count: Kullanılacak wallet sayısı
            time_delay_minutes: Fazlar arası bekleme süresi
            target_price_increase_pct: Hedef fiyat artış yüzdesi
            slippage: Slippage toleransı
            encryption_key: Wallet şifreleme anahtarı
            
        Returns:
            Dict: Strateji sonuçları
        """
        try:
            from wallet_manager import execute_multi_wallet_usdt_buy, get_all_wallets
            from utils import get_solana_price_usd
            from raydium_client import calculate_usdt_trading_metrics
            
            logger.info(f"🚀 USDT Enhanced Pump Strategy başlatılıyor: {self.token_address}")
            
            # Başlangıç metriklerini al
            initial_metrics = await calculate_usdt_trading_metrics(
                self.token_address,
                total_usdt_budget,
                target_price_increase_pct
            )
            
            if not initial_metrics.get("success", False):
                return {
                    "success": False,
                    "error": "Başlangıç metrikleri alınamadı"
                }
            
            # Wallet'ları hazırla
            all_wallets = await get_all_wallets(encryption_key, "default_password")
            if len(all_wallets) < wallet_count:
                return {
                    "success": False,
                    "error": f"Yetersiz wallet: {len(all_wallets)}/{wallet_count}"
                }
            
            selected_wallets = all_wallets[:wallet_count]
            wallet_ids = [w.id for w in selected_wallets]
            
            # Faz başına USDT miktarı
            usdt_per_phase = total_usdt_budget / pump_phases
            
            # Strateji sonuçları
            strategy_results = {
                "success": True,
                "strategy_type": self.strategy_type,
                "token_address": self.token_address,
                "total_usdt_budget": total_usdt_budget,
                "pump_phases": pump_phases,
                "wallet_count": wallet_count,
                "phases_executed": 0,
                "total_tokens_bought": 0,
                "total_usdt_spent": 0,
                "price_tracking": [],
                "phase_results": []
            }
            
            # Pump fazlarını çalıştır
            for phase in range(pump_phases):
                logger.info(f"💰 Pump Phase {phase + 1}/{pump_phases} başlatılıyor...")
                
                # Multi-wallet USDT satın alma
                buy_result = await execute_multi_wallet_usdt_buy(
                    token_mint_address=self.token_address,
                    total_usdt_amount=usdt_per_phase,
                    wallet_ids=wallet_ids,
                    encryption_key=encryption_key,
                    slippage=slippage
                )
                
                phase_result = {
                    "phase": phase + 1,
                    "usdt_allocated": usdt_per_phase,
                    "success": buy_result.get("success", False),
                    "timestamp": datetime.now().isoformat()
                }
                
                if buy_result.get("success", False):
                    phase_result.update({
                        "successful_purchases": buy_result.get("successful_purchases", 0),
                        "total_tokens_bought": buy_result.get("total_expected_tokens", 0),
                        "usdt_spent": buy_result.get("total_usdt_spent", 0)
                    })
                    
                    # Global sayaçları güncelle
                    strategy_results["total_tokens_bought"] += phase_result["total_tokens_bought"]
                    strategy_results["total_usdt_spent"] += phase_result["usdt_spent"]
                    strategy_results["phases_executed"] += 1
                    
                    logger.info(f"✅ Phase {phase + 1} başarılı: {phase_result['total_tokens_bought']} token satın alındı")
                else:
                    phase_result["error"] = buy_result.get("error", "Unknown error")
                    logger.error(f"❌ Phase {phase + 1} başarısız: {phase_result['error']}")
                
                strategy_results["phase_results"].append(phase_result)
                
                # Fazlar arası bekleme (son faz hariç)
                if phase < pump_phases - 1:
                    logger.info(f"⏰ Sonraki faz için {time_delay_minutes} dakika bekleniyor...")
                    await asyncio.sleep(time_delay_minutes * 60)
            
            # Başarı oranını hesapla
            success_rate = (strategy_results["phases_executed"] / pump_phases) * 100
            strategy_results["success_rate"] = success_rate
            
            # ROI tahmini
            if strategy_results["total_usdt_spent"] > 0:
                strategy_results["estimated_roi_pct"] = (
                    (strategy_results["total_tokens_bought"] * 0.001) / 
                    strategy_results["total_usdt_spent"] * 100
                )  # Basit tahmin
            
            logger.info(f"🎯 USDT Enhanced Pump Strategy tamamlandı!")
            logger.info(f"📊 Başarı oranı: %{success_rate:.1f}")
            logger.info(f"💰 Toplam harcanan: ${strategy_results['total_usdt_spent']:.2f}")
            logger.info(f"🪙 Toplam token: {strategy_results['total_tokens_bought']:.6f}")
            
            return strategy_results
            
        except Exception as e:
            logger.error(f"USDT Enhanced Pump Strategy error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

class USDTSmartSellStrategy(BaseStrategy):
    """
    USDT tabanlı akıllı satış stratejisi
    Stop-loss ve take-profit mekanizmaları ile koordineli satış
    """
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        super().__init__(token_address, parameters)
        self.strategy_type = "usdt_smart_sell"
        
    async def execute(self,
                     sell_percentage: float = 50.0,
                     take_profit_pct: float = 100.0,
                     stop_loss_pct: float = 20.0,
                     wallet_count: int = 10,
                     gradual_sell_phases: int = 3,
                     phase_delay_minutes: int = 10,
                     min_usdt_per_wallet: float = 1.0,
                     encryption_key: str = None) -> Dict[str, Any]:
        """
        USDT tabanlı akıllı satış stratejisi
        
        Args:
            sell_percentage: Satılacak token yüzdesi
            take_profit_pct: Take profit seviyesi
            stop_loss_pct: Stop loss seviyesi  
            wallet_count: Kullanılacak wallet sayısı
            gradual_sell_phases: Kademeli satış fazları
            phase_delay_minutes: Fazlar arası bekleme
            min_usdt_per_wallet: Wallet başına min USDT
            encryption_key: Wallet şifreleme anahtarı
            
        Returns:
            Dict: Satış stratejisi sonuçları
        """
        try:
            from wallet_manager import execute_multi_wallet_usdt_sell, get_all_wallets
            from utils import get_solana_price_usd
            
            logger.info(f"💸 USDT Smart Sell Strategy başlatılıyor: {self.token_address}")
            
            # Wallet'ları hazırla
            all_wallets = await get_all_wallets(encryption_key, "default_password")
            if len(all_wallets) < wallet_count:
                return {
                    "success": False,
                    "error": f"Yetersiz wallet: {len(all_wallets)}/{wallet_count}"
                }
            
            selected_wallets = all_wallets[:wallet_count]
            wallet_ids = [w.id for w in selected_wallets]
            
            # Faz başına satış yüzdesi
            sell_pct_per_phase = sell_percentage / gradual_sell_phases
            
            # Strateji sonuçları
            strategy_results = {
                "success": True,
                "strategy_type": self.strategy_type,
                "token_address": self.token_address,
                "total_sell_percentage": sell_percentage,
                "gradual_sell_phases": gradual_sell_phases,
                "wallet_count": wallet_count,
                "phases_executed": 0,
                "total_tokens_sold": 0,
                "total_usdt_received": 0,
                "phase_results": []
            }
            
            # Kademeli satış fazlarını çalıştır
            for phase in range(gradual_sell_phases):
                logger.info(f"💰 Sell Phase {phase + 1}/{gradual_sell_phases} başlatılıyor...")
                
                # Multi-wallet USDT satış
                sell_result = await execute_multi_wallet_usdt_sell(
                    token_mint_address=self.token_address,
                    sell_percentage=sell_pct_per_phase,
                    wallet_ids=wallet_ids,
                    encryption_key=encryption_key,
                    min_usdt_per_wallet=min_usdt_per_wallet,
                    slippage=1.0
                )
                
                phase_result = {
                    "phase": phase + 1,
                    "sell_percentage": sell_pct_per_phase,
                    "success": sell_result.get("success", False),
                    "timestamp": datetime.now().isoformat()
                }
                
                if sell_result.get("success", False):
                    phase_result.update({
                        "successful_sales": sell_result.get("successful_sales", 0),
                        "total_tokens_sold": sell_result.get("total_tokens_sold", 0),
                        "total_usdt_received": sell_result.get("total_expected_usdt", 0)
                    })
                    
                    # Global sayaçları güncelle
                    strategy_results["total_tokens_sold"] += phase_result["total_tokens_sold"]
                    strategy_results["total_usdt_received"] += phase_result["total_usdt_received"]
                    strategy_results["phases_executed"] += 1
                    
                    logger.info(f"✅ Phase {phase + 1} başarılı: ${phase_result['total_usdt_received']:.2f} USDT alındı")
                else:
                    phase_result["error"] = sell_result.get("error", "Unknown error")
                    logger.error(f"❌ Phase {phase + 1} başarısız: {phase_result['error']}")
                
                strategy_results["phase_results"].append(phase_result)
                
                # Fazlar arası bekleme (son faz hariç)
                if phase < gradual_sell_phases - 1:
                    logger.info(f"⏰ Sonraki satış fazı için {phase_delay_minutes} dakika bekleniyor...")
                    await asyncio.sleep(phase_delay_minutes * 60)
            
            # Başarı oranını hesapla
            success_rate = (strategy_results["phases_executed"] / gradual_sell_phases) * 100
            strategy_results["success_rate"] = success_rate
            
            logger.info(f"🎯 USDT Smart Sell Strategy tamamlandı!")
            logger.info(f"📊 Başarı oranı: %{success_rate:.1f}")
            logger.info(f"💰 Toplam USDT: ${strategy_results['total_usdt_received']:.2f}")
            logger.info(f"🪙 Satılan token: {strategy_results['total_tokens_sold']:.6f}")
            
            return strategy_results
            
        except Exception as e:
            logger.error(f"USDT Smart Sell Strategy error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

class USDTPortfolioRebalanceStrategy(BaseStrategy):
    """
    USDT tabanlı portfolio dengeleme stratejisi
    Çoklu token'lar arasında optimal dağılım
    """
    
    def __init__(self, parameters: Dict[str, Any] = None):
        super().__init__("portfolio_rebalance", parameters)
        self.strategy_type = "usdt_portfolio_rebalance"
        
    async def execute(self,
                     target_allocations: Dict[str, float],
                     total_usdt_budget: float = 500.0,
                     wallet_count: int = 15,
                     rebalance_threshold_pct: float = 10.0,
                     encryption_key: str = None) -> Dict[str, Any]:
        """
        USDT tabanlı portfolio dengeleme
        
        Args:
            target_allocations: Token allocation'ları {"token_mint": percentage}
            total_usdt_budget: Toplam USDT bütçesi
            wallet_count: Kullanılacak wallet sayısı
            rebalance_threshold_pct: Dengeleme eşiği
            encryption_key: Wallet şifreleme anahtarı
            
        Returns:
            Dict: Portfolio dengeleme sonuçları
        """
        try:
            from wallet_manager import (
                execute_multi_wallet_usdt_buy,
                execute_multi_wallet_usdt_sell,
                calculate_multi_wallet_portfolio_value,
                get_all_wallets
            )
            
            logger.info(f"⚖️ USDT Portfolio Rebalance Strategy başlatılıyor")
            
            # Allocation'ları doğrula
            total_allocation = sum(target_allocations.values())
            if abs(total_allocation - 100.0) > 0.1:
                return {
                    "success": False,
                    "error": f"Toplam allocation %100 olmalı, şu an: %{total_allocation:.1f}"
                }
            
            # Wallet'ları hazırla
            all_wallets = await get_all_wallets(encryption_key, "default_password")
            if len(all_wallets) < wallet_count:
                return {
                    "success": False,
                    "error": f"Yetersiz wallet: {len(all_wallets)}/{wallet_count}"
                }
            
            selected_wallets = all_wallets[:wallet_count]
            wallet_ids = [w.id for w in selected_wallets]
            
            # Mevcut portfolio değerini hesapla
            portfolio_value = await calculate_multi_wallet_portfolio_value(
                wallet_ids,
                encryption_key,
                list(target_allocations.keys())
            )
            
            if not portfolio_value.get("success", False):
                return {
                    "success": False,
                    "error": "Portfolio değeri hesaplanamadı"
                }
            
            # Strateji sonuçları
            strategy_results = {
                "success": True,
                "strategy_type": self.strategy_type,
                "total_usdt_budget": total_usdt_budget,
                "wallet_count": wallet_count,
                "target_allocations": target_allocations,
                "current_portfolio_value": portfolio_value["portfolio_data"],
                "rebalance_actions": [],
                "total_rebalanced_usdt": 0
            }
            
            # Her token için hedef tutarı hesapla
            for token_mint, target_pct in target_allocations.items():
                target_usdt = total_usdt_budget * (target_pct / 100)
                
                # Bu token için satın alma işlemi
                buy_result = await execute_multi_wallet_usdt_buy(
                    token_mint_address=token_mint,
                    total_usdt_amount=target_usdt,
                    wallet_ids=wallet_ids,
                    encryption_key=encryption_key,
                    slippage=1.0
                )
                
                rebalance_action = {
                    "token_mint": token_mint,
                    "target_allocation_pct": target_pct,
                    "target_usdt": target_usdt,
                    "action": "buy",
                    "success": buy_result.get("success", False)
                }
                
                if buy_result.get("success", False):
                    rebalance_action.update({
                        "successful_purchases": buy_result.get("successful_purchases", 0),
                        "tokens_bought": buy_result.get("total_expected_tokens", 0),
                        "usdt_spent": buy_result.get("total_usdt_spent", 0)
                    })
                    
                    strategy_results["total_rebalanced_usdt"] += rebalance_action["usdt_spent"]
                    logger.info(f"✅ {token_mint}: ${rebalance_action['usdt_spent']:.2f} USDT harcandı")
                else:
                    rebalance_action["error"] = buy_result.get("error", "Unknown error")
                    logger.error(f"❌ {token_mint}: {rebalance_action['error']}")
                
                strategy_results["rebalance_actions"].append(rebalance_action)
            
            # Başarı oranını hesapla
            successful_actions = len([a for a in strategy_results["rebalance_actions"] if a["success"]])
            success_rate = (successful_actions / len(target_allocations)) * 100
            strategy_results["success_rate"] = success_rate
            
            logger.info(f"🎯 USDT Portfolio Rebalance Strategy tamamlandı!")
            logger.info(f"📊 Başarı oranı: %{success_rate:.1f}")
            logger.info(f"💰 Toplam rebalanced: ${strategy_results['total_rebalanced_usdt']:.2f}")
            
            return strategy_results
            
        except Exception as e:
            logger.error(f"USDT Portfolio Rebalance Strategy error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

class DumpStrategy(BaseStrategy):
    """Dump It strategy implementation"""
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        """
        Initialize Dump It strategy
        
        Args:
            token_address: Token address to dump
            parameters: Strategy parameters
        """
        super().__init__(token_address, parameters)
        
        # Set default parameters if not provided
        if not self.parameters:
            self.parameters = {
                'target_price_decrease': 15.0,   # Target price decrease (%)
                'wallet_count': 5,               # Number of wallets to use
                'time_period_minutes': 10,       # Time period for the operation
                'interval_seconds': 30,          # Interval between sells
                'initial_sell_percentage': 10.0  # Initial sell percentage
            }
    
    async def _execute_impl(self):
        """
        Execute Dump It strategy
        
        Returns:
            Strategy results
        """
        # Get parameters
        target_decrease = self.parameters.get('target_price_decrease', 15.0)
        wallet_count = self.parameters.get('wallet_count', 5)
        time_period_minutes = self.parameters.get('time_period_minutes', 10)
        interval_seconds = self.parameters.get('interval_seconds', 30)
        initial_sell_percentage = self.parameters.get('initial_sell_percentage', 10.0)
        
        # Check initial token price and volume
        initial_price_info = await self.check_token_price()
        
        if not initial_price_info.get('success', False):
            return {
                "success": False,
                "error": f"Failed to get initial price info: {initial_price_info.get('error', 'Unknown error')}"
            }
        
        initial_price = initial_price_info.get('price', 0)
        initial_volume = initial_price_info.get('volume_24h', 0)
        initial_liquidity = initial_price_info.get('liquidity_usd', 0)
        
        logger.info(f"Starting Dump It strategy for {self.token_address}")
        logger.info(f"Initial price: ${initial_price}, volume: ${initial_volume}, liquidity: ${initial_liquidity}")
        
        # Get wallets for the operation
        encryption_key = "washbot_development_key"
        storage_password = "washbot_secure_storage"
        
        all_wallets = await wallet_manager.get_all_wallets(encryption_key, storage_password)
        
        # Find wallets with token balance
        wallets_with_token = []
        
        for wallet in all_wallets:
            token_balance = await solana_utils.get_token_balance(
                wallet_public_key=wallet.public_key,
                token_address=self.token_address,
                network=wallet.network
            )
            
            if token_balance.get('success', False) and token_balance.get('balance', 0) > 0:
                wallet.token_balance = token_balance.get('balance', 0)
                wallet.token_decimals = token_balance.get('decimals', 0)
                wallets_with_token.append(wallet)
        
        if len(wallets_with_token) < 1:
            return {
                "success": False,
                "error": f"No wallets with {self.token_address} balance found"
            }
        
        # Use up to wallet_count wallets
        selected_wallets = wallets_with_token[:wallet_count]
        actual_wallet_count = len(selected_wallets)
        
        # Prepare result data
        result = {
            "success": True,
            "token_address": self.token_address,
            "initial_price": initial_price,
            "initial_volume": initial_volume,
            "initial_liquidity": initial_liquidity,
            "wallets_used": actual_wallet_count,
            "target_decrease": target_decrease,
            "transactions": [],
            "final_price": 0,
            "price_change_pct": 0
        }
        
        # Calculate time distribution
        total_seconds = time_period_minutes * 60
        intervals = max(1, min(20, int(total_seconds / interval_seconds)))
        
        # Execute sells with increasing size
        for i in range(intervals):
            # Skip some intervals randomly to create natural pattern
            if random.random() < 0.2:  # 20% chance to skip
                await asyncio.sleep(interval_seconds)
                continue
            
            # Select a wallet for this sell
            wallet = random.choice(selected_wallets)
            
            # Skip if no balance
            if not hasattr(wallet, 'token_balance') or wallet.token_balance <= 0:
                continue
            
            # Calculate sell amount (increasing over time)
            progress = (i + 1) / intervals
            sell_percentage = initial_sell_percentage + (100 - initial_sell_percentage) * (progress ** 2)
            
            # Sell amount - using wallet token balance * percentage
            sell_amount = wallet.token_balance * (sell_percentage / 100)
            
            # Ensure minimum amount
            sell_amount = max(0.000001, min(sell_amount, wallet.token_balance))
            
            # Execute swap
            swap_result = await jupiter_client.execute_jupiter_swap(
                wallet=wallet,
                input_mint=self.token_address,
                output_mint=self.sol_token,
                amount=sell_amount,
                slippage_bps=1000  # Higher slippage for dump
            )
            
            # Record transaction
            tx_info = {
                "wallet_id": wallet.id,
                "wallet_public_key": wallet.public_key,
                "amount_token": sell_amount,
                "timestamp": datetime.now().isoformat(),
                "success": swap_result.get('success', False)
            }
            
            if swap_result.get('success', False):
                tx_info["txid"] = swap_result.get('txid', '')
                tx_info["out_amount_sol"] = swap_result.get('out_amount', 0) / 1e9  # Convert lamports to SOL
                tx_info["price_impact_pct"] = swap_result.get('price_impact_pct', 0)
                logger.info(f"Sell executed: {sell_amount} tokens -> SOL, tx: {swap_result.get('txid', '')}")
                
                # Update wallet token balance
                wallet.token_balance -= sell_amount
            else:
                tx_info["error"] = swap_result.get('error', 'Unknown error')
                logger.warning(f"Sell failed: {swap_result.get('error', 'Unknown error')}")
            
            result["transactions"].append(tx_info)
            
            # Wait for next interval
            await asyncio.sleep(interval_seconds)
            
            # Check current price occasionally
            if i % 3 == 0 or i == intervals - 1:
                current_price_info = await self.check_token_price()
                
                if current_price_info.get('success', False):
                    current_price = current_price_info.get('price', 0)
                    price_change = (current_price / initial_price - 1) * 100
                    
                    logger.info(f"Current price: ${current_price} ({price_change:.2f}% change)")
                    
                    # If target decrease reached, we can stop early
                    if price_change <= -target_decrease:
                        logger.info(f"Target price decrease of {target_decrease}% reached, stopping early")
                        break
        
        # Get final price
        final_price_info = await self.check_token_price()
        
        if final_price_info.get('success', False):
            final_price = final_price_info.get('price', 0)
            final_volume = final_price_info.get('volume_24h', 0)
            final_liquidity = final_price_info.get('liquidity_usd', 0)
            
            result["final_price"] = final_price
            result["final_volume"] = final_volume
            result["final_liquidity"] = final_liquidity
            
            if initial_price > 0:
                result["price_change_pct"] = (final_price / initial_price - 1) * 100
        
        logger.info(f"Dump It strategy completed for {self.token_address}")
        logger.info(f"Price change: {result.get('price_change_pct', 0):.2f}%")
        
        return result

class GradualSellStrategy(BaseStrategy):
    """Gradual Sell strategy implementation"""
    
    def __init__(self, token_address: str, parameters: Dict[str, Any] = None):
        """
        Initialize Gradual Sell strategy
        
        Args:
            token_address: Token address to sell
            parameters: Strategy parameters
        """
        super().__init__(token_address, parameters)
        
        # Set default parameters if not provided
        if not self.parameters:
            self.parameters = {
                'sell_stage1_pct': 30.0,        # Percentage to sell at stage 1
                'sell_stage1_target': 10.0,     # Price increase target for stage 1 (%)
                'sell_stage2_pct': 30.0,        # Percentage to sell at stage 2
                'sell_stage2_target': 20.0,     # Price increase target for stage 2 (%)
                'sell_stage3_pct': 40.0,        # Percentage to sell at stage 3
                'sell_stage3_target': 30.0,     # Price increase target for stage 3 (%)
                'stop_loss': 5.0,               # Stop loss (% below entry)
                'max_duration_hours': 24        # Maximum duration to wait
            }
    
    async def _execute_impl(self):
        """
        Execute Gradual Sell strategy
        
        Returns:
            Strategy results
        """
        # Get parameters
        sell_stage1_pct = self.parameters.get('sell_stage1_pct', 30.0)
        sell_stage1_target = self.parameters.get('sell_stage1_target', 10.0)
        sell_stage2_pct = self.parameters.get('sell_stage2_pct', 30.0)
        sell_stage2_target = self.parameters.get('sell_stage2_target', 20.0)
        sell_stage3_pct = self.parameters.get('sell_stage3_pct', 40.0)
        sell_stage3_target = self.parameters.get('sell_stage3_target', 30.0)
        stop_loss = self.parameters.get('stop_loss', 5.0)
        max_duration_hours = self.parameters.get('max_duration_hours', 24)
        
        # Check initial token price
        initial_price_info = await self.check_token_price()
        
        if not initial_price_info.get('success', False):
            return {
                "success": False,
                "error": f"Failed to get initial price info: {initial_price_info.get('error', 'Unknown error')}"
            }
        
        initial_price = initial_price_info.get('price', 0)
        
        logger.info(f"Starting Gradual Sell strategy for {self.token_address}")
        logger.info(f"Initial price: ${initial_price}")
        
        # Get wallets with token balance
        encryption_key = "washbot_development_key"
        storage_password = "washbot_secure_storage"
        
        all_wallets = await wallet_manager.get_all_wallets(encryption_key, storage_password)
        
        # Find wallets with token balance
        wallets_with_token = []
        
        for wallet in all_wallets:
            token_balance = await solana_utils.get_token_balance(
                wallet_public_key=wallet.public_key,
                token_address=self.token_address,
                network=wallet.network
            )
            
            if token_balance.get('success', False) and token_balance.get('balance', 0) > 0:
                wallet.token_balance = token_balance.get('balance', 0)
                wallet.token_decimals = token_balance.get('decimals', 0)
                wallet.initial_token_balance = token_balance.get('balance', 0)
                wallets_with_token.append(wallet)
        
        if len(wallets_with_token) < 1:
            return {
                "success": False,
                "error": f"No wallets with {self.token_address} balance found"
            }
        
        # Prepare result data
        result = {
            "success": True,
            "token_address": self.token_address,
            "initial_price": initial_price,
            "wallets_used": len(wallets_with_token),
            "total_tokens": sum(w.token_balance for w in wallets_with_token),
            "transactions": [],
            "stages_completed": {},
            "final_price": 0,
            "price_change_pct": 0,
            "total_sol_received": 0
        }
        
        # Set end time
        end_time = datetime.now() + timedelta(hours=max_duration_hours)
        
        # Track stages
        stage1_completed = False
        stage2_completed = False
        stage3_completed = False
        stop_loss_triggered = False
        
        # Main monitoring loop
        check_interval = 60  # Check price every minute
        while datetime.now() < end_time:
            # Check current price
            current_price_info = await self.check_token_price()
            
            if not current_price_info.get('success', False):
                logger.warning(f"Failed to get current price, retrying...")
                await asyncio.sleep(check_interval)
                continue
            
            current_price = current_price_info.get('price', 0)
            price_change = (current_price / initial_price - 1) * 100
            
            logger.info(f"Current price: ${current_price} ({price_change:.2f}% change)")
            
            # Check stop loss
            if price_change < -stop_loss:
                logger.warning(f"Stop loss triggered at {price_change:.2f}% below entry")
                stop_loss_triggered = True
                
                # Sell all remaining tokens
                for wallet in wallets_with_token:
                    if wallet.token_balance > 0:
                        await self._sell_tokens(
                            wallet=wallet,
                            percentage=100.0,
                            result=result,
                            reason="stop_loss"
                        )
                
                result["stages_completed"]["stop_loss"] = {
                    "timestamp": datetime.now().isoformat(),
                    "price": current_price,
                    "price_change_pct": price_change
                }
                
                break
            
            # Check sell targets
            if not stage1_completed and price_change >= sell_stage1_target:
                logger.info(f"Stage 1 target reached: {price_change:.2f}% above entry")
                stage1_completed = True
                
                # Sell stage 1 percentage from all wallets
                for wallet in wallets_with_token:
                    if wallet.token_balance > 0:
                        await self._sell_tokens(
                            wallet=wallet,
                            percentage=sell_stage1_pct,
                            result=result,
                            reason="stage1"
                        )
                
                result["stages_completed"]["stage1"] = {
                    "timestamp": datetime.now().isoformat(),
                    "price": current_price,
                    "price_change_pct": price_change,
                    "percentage_sold": sell_stage1_pct
                }
            
            if not stage2_completed and price_change >= sell_stage2_target:
                logger.info(f"Stage 2 target reached: {price_change:.2f}% above entry")
                stage2_completed = True
                
                # Sell stage 2 percentage from all wallets
                for wallet in wallets_with_token:
                    if wallet.token_balance > 0:
                        await self._sell_tokens(
                            wallet=wallet,
                            percentage=sell_stage2_pct,
                            result=result,
                            reason="stage2"
                        )
                
                result["stages_completed"]["stage2"] = {
                    "timestamp": datetime.now().isoformat(),
                    "price": current_price,
                    "price_change_pct": price_change,
                    "percentage_sold": sell_stage2_pct
                }
            
            if not stage3_completed and price_change >= sell_stage3_target:
                logger.info(f"Stage 3 target reached: {price_change:.2f}% above entry")
                stage3_completed = True
                
                # Sell stage 3 percentage (remaining tokens) from all wallets
                for wallet in wallets_with_token:
                    if wallet.token_balance > 0:
                        await self._sell_tokens(
                            wallet=wallet,
                            percentage=100.0,  # Sell all remaining
                            result=result,
                            reason="stage3"
                        )
                
                result["stages_completed"]["stage3"] = {
                    "timestamp": datetime.now().isoformat(),
                    "price": current_price,
                    "price_change_pct": price_change,
                    "percentage_sold": sell_stage3_pct
                }
                
                # All stages completed, exit loop
                break
            
            # Check if all tokens sold
            if all(w.token_balance <= 0 for w in wallets_with_token):
                logger.info("All tokens sold, ending strategy")
                break
            
            # Wait for next check
            await asyncio.sleep(check_interval)
        
        # If time expired, sell remaining tokens
        if datetime.now() >= end_time and not all(w.token_balance <= 0 for w in wallets_with_token):
            logger.info("Maximum duration reached, selling remaining tokens")
            
            # Sell all remaining tokens
            for wallet in wallets_with_token:
                if wallet.token_balance > 0:
                    await self._sell_tokens(
                        wallet=wallet,
                        percentage=100.0,
                        result=result,
                        reason="time_expired"
                    )
            
            result["stages_completed"]["time_expired"] = {
                "timestamp": datetime.now().isoformat(),
                "price": current_price if 'current_price' in locals() else 0,
                "price_change_pct": price_change if 'price_change' in locals() else 0
            }
        
        # Get final price
        final_price_info = await self.check_token_price()
        
        if final_price_info.get('success', False):
            final_price = final_price_info.get('price', 0)
            
            result["final_price"] = final_price
            
            if initial_price > 0:
                result["price_change_pct"] = (final_price / initial_price - 1) * 100
        
        # Calculate wallet results
        wallet_results = []
        for wallet in wallets_with_token:
            wallet_result = {
                "wallet_id": wallet.id,
                "wallet_public_key": wallet.public_key,
                "initial_balance": wallet.initial_token_balance,
                "remaining_balance": wallet.token_balance,
                "sold_percentage": 100 * (1 - wallet.token_balance / wallet.initial_token_balance) if wallet.initial_token_balance > 0 else 0
            }
            wallet_results.append(wallet_result)
        
        result["wallet_results"] = wallet_results
        
        logger.info(f"Gradual Sell strategy completed for {self.token_address}")
        logger.info(f"Price change: {result.get('price_change_pct', 0):.2f}%")
        logger.info(f"Total SOL received: {result.get('total_sol_received', 0):.4f} SOL")
        
        return result
    
    async def _sell_tokens(self, wallet, percentage, result, reason=""):
        """
        Sell tokens from a wallet
        
        Args:
            wallet: Wallet to sell from
            percentage: Percentage of tokens to sell
            result: Result dictionary to update
            reason: Reason for selling
            
        Returns:
            Success status
        """
        try:
            # Calculate sell amount
            sell_amount = wallet.token_balance * (percentage / 100)
            
            # Skip if amount too small
            if sell_amount <= 0:
                return False
            
            # Execute swap
            swap_result = await jupiter_client.execute_jupiter_swap(
                wallet=wallet,
                input_mint=self.token_address,
                output_mint=self.sol_token,
                amount=sell_amount,
                slippage_bps=300
            )
            
            # Record transaction
            tx_info = {
                "wallet_id": wallet.id,
                "wallet_public_key": wallet.public_key,
                "amount_token": sell_amount,
                "percentage": percentage,
                "timestamp": datetime.now().isoformat(),
                "success": swap_result.get('success', False),
                "reason": reason
            }
            
            if swap_result.get('success', False):
                tx_info["txid"] = swap_result.get('txid', '')
                sol_received = swap_result.get('out_amount', 0) / 1e9  # Convert lamports to SOL
                tx_info["sol_received"] = sol_received
                tx_info["price_impact_pct"] = swap_result.get('price_impact_pct', 0)
                
                logger.info(f"Sell executed: {sell_amount} tokens -> {sol_received} SOL, tx: {swap_result.get('txid', '')}")
                
                # Update wallet token balance
                wallet.token_balance -= sell_amount
                
                # Update total SOL received
                result["total_sol_received"] = result.get("total_sol_received", 0) + sol_received
            else:
                tx_info["error"] = swap_result.get('error', 'Unknown error')
                logger.warning(f"Sell failed: {swap_result.get('error', 'Unknown error')}")
            
            result["transactions"].append(tx_info)
            
            return swap_result.get('success', False)
            
        except Exception as e:
            logger.error(f"Error selling tokens: {e}")
            return False
