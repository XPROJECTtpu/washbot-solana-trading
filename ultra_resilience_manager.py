"""
WashBot Ultra-Resilience Manager
200+ Wallet High-Volume Operations with 3-Second Auto-Recovery
"""

import asyncio
import time
import threading
import logging
import psutil
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict, deque
import weakref
import gc

from models import Strategy, Wallet, Token
from database import db_session
from sqlalchemy import text

logger = logging.getLogger(__name__)

@dataclass
class StrategyPerformance:
    """Strategy performance tracking"""
    strategy_id: str
    wallet_id: str
    start_time: float
    last_heartbeat: float
    restart_count: int = 0
    total_transactions: int = 0
    avg_response_time: float = 0.0
    memory_usage: float = 0.0
    status: str = "running"
    last_error: Optional[str] = None

@dataclass
class SystemMetrics:
    """System-wide performance metrics"""
    active_strategies: int = 0
    total_wallets: int = 0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    transactions_per_second: float = 0.0
    restart_events_last_hour: int = 0
    avg_recovery_time: float = 0.0

class UltraResilienceManager:
    """
    Ultra-Resilient WashBot Manager
    Handles 200+ wallets with 3-second auto-recovery
    """
    
    def __init__(self):
        # Performance tracking
        self.strategy_performance: Dict[str, StrategyPerformance] = {}
        self.system_metrics = SystemMetrics()
        self.restart_events = deque(maxlen=1000)  # Keep last 1000 restart events
        
        # Configuration
        self.MAX_WALLETS = 200
        self.RECOVERY_TIMEOUT = 3.0  # 3 seconds max recovery time
        self.HEARTBEAT_INTERVAL = 1.0  # 1 second heartbeat
        self.PERFORMANCE_CHECK_INTERVAL = 5.0  # 5 second performance checks
        self.MEMORY_THRESHOLD_MB = 2048  # 2GB memory threshold
        self.CPU_THRESHOLD_PERCENT = 80  # 80% CPU threshold
        
        # Async management
        self.executor = None
        self.watchdog_tasks: Dict[str, asyncio.Task] = {}
        self.performance_monitor_task: Optional[asyncio.Task] = None
        self.recovery_lock = asyncio.Lock()
        
        # Database-driven config cache
        self.config_cache = {}
        self.config_last_updated = 0
        
        logger.info("🚀 Ultra-Resilience Manager initialized - 200+ wallet capacity")
    
    async def start_ultra_resilience_system(self):
        """Start the ultra-resilience monitoring system"""
        try:
            logger.info("🔥 Starting Ultra-Resilience System")
            
            # Start performance monitor
            self.performance_monitor_task = asyncio.create_task(
                self._performance_monitor_loop()
            )
            
            # Load initial configuration from database
            await self._refresh_database_config()
            
            # Start strategy monitoring for existing strategies
            await self._bootstrap_existing_strategies()
            
            logger.info("✅ Ultra-Resilience System ACTIVE - Ready for 200+ wallets")
            
        except Exception as e:
            logger.error(f"❌ Failed to start ultra-resilience system: {e}")
            raise
    
    async def _refresh_database_config(self):
        """Extract live configuration from database"""
        try:
            current_time = time.time()
            
            # Update config cache every 30 seconds
            if current_time - self.config_last_updated < 30:
                return
            
            # Get active strategies with wallet info
            query = text("""
                SELECT s.id, s.strategy_type, s.wallet_id, s.target_token, 
                       s.parameters, s.status, s.created_at,
                       w.public_key, w.network, w.name as wallet_name
                FROM strategies s
                JOIN wallets w ON s.wallet_id = w.id
                WHERE s.status IN ('running', 'pending', 'paused')
                ORDER BY s.created_at DESC
            """)
            
            with db_session() as session:
                result = session.execute(query)
                strategies = result.fetchall()
                
                # Update config cache
                self.config_cache = {
                    "strategies": [dict(row._mapping) for row in strategies],
                    "total_strategies": len(strategies),
                    "updated_at": current_time
                }
                
                # Get wallet count
                wallet_count_query = text("SELECT COUNT(*) as count FROM wallets")
                wallet_result = session.execute(wallet_count_query)
                wallet_count = wallet_result.fetchone()[0]
            
            self.config_cache["total_wallets"] = wallet_count
            self.config_last_updated = current_time
            
            logger.info(f"📊 Config refreshed: {len(strategies)} strategies, {wallet_count} wallets")
            
        except Exception as e:
            logger.error(f"❌ Failed to refresh database config: {e}")
    
    async def _bootstrap_existing_strategies(self):
        """Bootstrap monitoring for existing active strategies"""
        try:
            await self._refresh_database_config()
            
            active_strategies = self.config_cache.get("strategies", [])
            
            for strategy in active_strategies:
                if strategy["status"] == "running":
                    await self.register_strategy_monitoring(
                        strategy["id"],
                        strategy["wallet_id"],
                        strategy["strategy_type"]
                    )
            
            logger.info(f"🔄 Bootstrapped monitoring for {len(active_strategies)} strategies")
            
        except Exception as e:
            logger.error(f"❌ Failed to bootstrap existing strategies: {e}")
    
    async def register_strategy_monitoring(self, strategy_id: str, wallet_id: str, strategy_type: str):
        """Register a strategy for ultra-resilient monitoring"""
        try:
            current_time = time.time()
            
            # Create performance tracker
            performance = StrategyPerformance(
                strategy_id=strategy_id,
                wallet_id=wallet_id,
                start_time=current_time,
                last_heartbeat=current_time
            )
            
            self.strategy_performance[strategy_id] = performance
            
            # Start watchdog task
            watchdog_task = asyncio.create_task(
                self._strategy_watchdog(strategy_id)
            )
            self.watchdog_tasks[strategy_id] = watchdog_task
            
            logger.info(f"🐕 Watchdog registered for strategy {strategy_id} (wallet: {wallet_id})")
            
        except Exception as e:
            logger.error(f"❌ Failed to register strategy monitoring: {e}")
    
    async def _strategy_watchdog(self, strategy_id: str):
        """Watchdog monitoring for individual strategy"""
        try:
            while strategy_id in self.strategy_performance:
                performance = self.strategy_performance[strategy_id]
                current_time = time.time()
                
                # Check if strategy is responsive
                time_since_heartbeat = current_time - performance.last_heartbeat
                
                if time_since_heartbeat > (self.RECOVERY_TIMEOUT * 2):  # 6 seconds unresponsive
                    logger.warning(f"🚨 Strategy {strategy_id} unresponsive for {time_since_heartbeat:.1f}s")
                    
                    # Trigger auto-recovery
                    await self._auto_recover_strategy(strategy_id)
                
                # Update system metrics
                self._update_system_metrics()
                
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                
        except asyncio.CancelledError:
            logger.info(f"🛑 Watchdog cancelled for strategy {strategy_id}")
        except Exception as e:
            logger.error(f"❌ Watchdog error for strategy {strategy_id}: {e}")
    
    async def _auto_recover_strategy(self, strategy_id: str):
        """Auto-recover a failed strategy within 3 seconds"""
        recovery_start = time.time()
        
        try:
            async with self.recovery_lock:
                logger.info(f"🔄 AUTO-RECOVERY: Starting for strategy {strategy_id}")
                
                performance = self.strategy_performance.get(strategy_id)
                if not performance:
                    return
                
                # Step 1: Get strategy from database (0.5s max)
                strategy_query = text("""
                    SELECT s.*, w.public_key, w.network 
                    FROM strategies s 
                    JOIN wallets w ON s.wallet_id = w.id 
                    WHERE s.id = :strategy_id
                """)
                
                result = db.session.execute(strategy_query, {"strategy_id": strategy_id})
                strategy_data = result.fetchone()
                
                if not strategy_data:
                    logger.error(f"❌ Strategy {strategy_id} not found in database")
                    return
                
                # Step 2: Restore last known state (1.0s max)
                last_state = await self._get_strategy_last_state(strategy_id)
                
                # Step 3: Restart strategy execution (1.5s max)
                restart_success = await self._restart_strategy_execution(
                    strategy_id, 
                    dict(strategy_data._mapping), 
                    last_state
                )
                
                # Update performance tracking
                recovery_time = time.time() - recovery_start
                performance.restart_count += 1
                performance.last_heartbeat = time.time()
                performance.status = "recovered" if restart_success else "failed_recovery"
                
                # Log restart event
                restart_event = {
                    "strategy_id": strategy_id,
                    "wallet_id": performance.wallet_id,
                    "timestamp": datetime.now().isoformat(),
                    "recovery_time": recovery_time,
                    "success": restart_success,
                    "restart_count": performance.restart_count
                }
                
                self.restart_events.append(restart_event)
                
                if restart_success and recovery_time <= self.RECOVERY_TIMEOUT:
                    logger.info(f"✅ AUTO-RECOVERY SUCCESS: Strategy {strategy_id} recovered in {recovery_time:.2f}s")
                else:
                    logger.error(f"❌ AUTO-RECOVERY FAILED: Strategy {strategy_id} - Time: {recovery_time:.2f}s")
                
        except Exception as e:
            logger.error(f"❌ Auto-recovery failed for strategy {strategy_id}: {e}")
    
    async def _get_strategy_last_state(self, strategy_id: str) -> Dict[str, Any]:
        """Get last known state of strategy for recovery"""
        try:
            # Check strategy results for last state
            query = text("""
                SELECT results, updated_at 
                FROM strategies 
                WHERE id = :strategy_id
            """)
            
            result = db.session.execute(query, {"strategy_id": strategy_id})
            row = result.fetchone()
            
            if row and row[0]:  # results column
                try:
                    return json.loads(row[0])
                except json.JSONDecodeError:
                    return {}
            
            return {}
            
        except Exception as e:
            logger.error(f"❌ Failed to get last state for {strategy_id}: {e}")
            return {}
    
    async def _restart_strategy_execution(self, strategy_id: str, strategy_data: Dict[str, Any], last_state: Dict[str, Any]) -> bool:
        """Restart strategy execution from last known state"""
        try:
            # Import strategy execution functions
            from strategies import execute_pump_strategy, execute_gradual_sell_strategy
            
            strategy_type = strategy_data["strategy_type"]
            parameters = json.loads(strategy_data["parameters"]) if strategy_data["parameters"] else {}
            
            # Merge last state with parameters
            parameters.update(last_state.get("parameters", {}))
            
            # Execute strategy based on type
            if strategy_type == "pump":
                result = await execute_pump_strategy(parameters)
            elif strategy_type == "gradual_sell":
                result = await execute_gradual_sell_strategy(parameters)
            else:
                logger.error(f"❌ Unknown strategy type: {strategy_type}")
                return False
            
            return result.get("success", False)
            
        except Exception as e:
            logger.error(f"❌ Failed to restart strategy execution: {e}")
            return False
    
    async def _performance_monitor_loop(self):
        """Monitor system performance continuously"""
        try:
            while True:
                # Update system metrics
                self._update_system_metrics()
                
                # Check for performance issues
                await self._check_performance_thresholds()
                
                # Refresh database config periodically
                await self._refresh_database_config()
                
                # Cleanup completed strategies
                await self._cleanup_completed_strategies()
                
                await asyncio.sleep(self.PERFORMANCE_CHECK_INTERVAL)
                
        except asyncio.CancelledError:
            logger.info("🛑 Performance monitor stopped")
        except Exception as e:
            logger.error(f"❌ Performance monitor error: {e}")
    
    def _update_system_metrics(self):
        """Update system-wide performance metrics"""
        try:
            # Memory usage
            process = psutil.Process()
            self.system_metrics.memory_usage_mb = process.memory_info().rss / 1024 / 1024
            
            # CPU usage
            self.system_metrics.cpu_usage_percent = process.cpu_percent()
            
            # Active strategies
            self.system_metrics.active_strategies = len(self.strategy_performance)
            
            # Total wallets from config
            self.system_metrics.total_wallets = self.config_cache.get("total_wallets", 0)
            
            # Restart events in last hour
            one_hour_ago = datetime.now() - timedelta(hours=1)
            recent_restarts = [
                event for event in self.restart_events 
                if datetime.fromisoformat(event["timestamp"]) > one_hour_ago
            ]
            self.system_metrics.restart_events_last_hour = len(recent_restarts)
            
            # Average recovery time
            if recent_restarts:
                avg_recovery = sum(event["recovery_time"] for event in recent_restarts) / len(recent_restarts)
                self.system_metrics.avg_recovery_time = avg_recovery
            
        except Exception as e:
            logger.error(f"❌ Failed to update system metrics: {e}")
    
    async def _check_performance_thresholds(self):
        """Check if system is exceeding performance thresholds"""
        try:
            metrics = self.system_metrics
            
            # Memory threshold check
            if metrics.memory_usage_mb > self.MEMORY_THRESHOLD_MB:
                logger.warning(f"🚨 Memory usage high: {metrics.memory_usage_mb:.1f}MB")
                await self._apply_memory_optimization()
            
            # CPU threshold check
            if metrics.cpu_usage_percent > self.CPU_THRESHOLD_PERCENT:
                logger.warning(f"🚨 CPU usage high: {metrics.cpu_usage_percent:.1f}%")
                await self._apply_cpu_throttling()
            
            # Too many restarts check
            if metrics.restart_events_last_hour > 50:  # More than 50 restarts per hour
                logger.warning(f"🚨 High restart frequency: {metrics.restart_events_last_hour} restarts/hour")
                
        except Exception as e:
            logger.error(f"❌ Performance threshold check failed: {e}")
    
    async def _apply_memory_optimization(self):
        """Apply memory optimization when threshold exceeded"""
        try:
            # Force garbage collection
            gc.collect()
            
            # Clear old restart events
            if len(self.restart_events) > 500:
                # Keep only last 500 events
                self.restart_events = deque(list(self.restart_events)[-500:], maxlen=1000)
            
            logger.info("🧹 Memory optimization applied")
            
        except Exception as e:
            logger.error(f"❌ Memory optimization failed: {e}")
    
    async def _apply_cpu_throttling(self):
        """Apply CPU throttling when threshold exceeded"""
        try:
            # Increase heartbeat interval to reduce CPU load
            original_interval = self.HEARTBEAT_INTERVAL
            self.HEARTBEAT_INTERVAL = min(self.HEARTBEAT_INTERVAL * 1.5, 5.0)
            
            if self.HEARTBEAT_INTERVAL != original_interval:
                logger.info(f"🐌 CPU throttling: Heartbeat interval increased to {self.HEARTBEAT_INTERVAL}s")
            
            # Small delay to let system recover
            await asyncio.sleep(1.0)
            
        except Exception as e:
            logger.error(f"❌ CPU throttling failed: {e}")
    
    async def _cleanup_completed_strategies(self):
        """Cleanup monitoring for completed strategies"""
        try:
            completed_strategies = []
            
            for strategy_id, performance in self.strategy_performance.items():
                # Check if strategy is still active in database
                query = text("SELECT status FROM strategies WHERE id = :strategy_id")
                result = db.session.execute(query, {"strategy_id": strategy_id})
                row = result.fetchone()
                
                if not row or row[0] in ["completed", "failed", "cancelled"]:
                    completed_strategies.append(strategy_id)
            
            # Remove completed strategies
            for strategy_id in completed_strategies:
                await self.unregister_strategy_monitoring(strategy_id)
            
            if completed_strategies:
                logger.info(f"🧹 Cleaned up {len(completed_strategies)} completed strategies")
                
        except Exception as e:
            logger.error(f"❌ Strategy cleanup failed: {e}")
    
    async def unregister_strategy_monitoring(self, strategy_id: str):
        """Unregister strategy from monitoring"""
        try:
            # Cancel watchdog task
            if strategy_id in self.watchdog_tasks:
                self.watchdog_tasks[strategy_id].cancel()
                del self.watchdog_tasks[strategy_id]
            
            # Remove performance tracking
            if strategy_id in self.strategy_performance:
                del self.strategy_performance[strategy_id]
            
            logger.info(f"🗑️ Strategy {strategy_id} unregistered from monitoring")
            
        except Exception as e:
            logger.error(f"❌ Failed to unregister strategy {strategy_id}: {e}")
    
    def update_strategy_heartbeat(self, strategy_id: str):
        """Update strategy heartbeat (called by active strategies)"""
        if strategy_id in self.strategy_performance:
            self.strategy_performance[strategy_id].last_heartbeat = time.time()
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "system_metrics": {
                "active_strategies": self.system_metrics.active_strategies,
                "total_wallets": self.system_metrics.total_wallets,
                "memory_usage_mb": round(self.system_metrics.memory_usage_mb, 2),
                "cpu_usage_percent": round(self.system_metrics.cpu_usage_percent, 2),
                "restart_events_last_hour": self.system_metrics.restart_events_last_hour,
                "avg_recovery_time": round(self.system_metrics.avg_recovery_time, 3)
            },
            "performance_thresholds": {
                "max_wallets": self.MAX_WALLETS,
                "recovery_timeout": self.RECOVERY_TIMEOUT,
                "memory_threshold_mb": self.MEMORY_THRESHOLD_MB,
                "cpu_threshold_percent": self.CPU_THRESHOLD_PERCENT
            },
            "recent_restarts": list(self.restart_events)[-10:],  # Last 10 restart events
            "strategy_performance": {
                strategy_id: {
                    "wallet_id": perf.wallet_id,
                    "uptime": time.time() - perf.start_time,
                    "restart_count": perf.restart_count,
                    "status": perf.status,
                    "last_heartbeat_ago": time.time() - perf.last_heartbeat
                }
                for strategy_id, perf in self.strategy_performance.items()
            }
        }

# Global ultra-resilience manager
ultra_resilience_manager = UltraResilienceManager()

# Export functions
async def start_ultra_resilience():
    """Start the ultra-resilience system"""
    await ultra_resilience_manager.start_ultra_resilience_system()

async def register_strategy_for_monitoring(strategy_id: str, wallet_id: str, strategy_type: str):
    """Register a strategy for monitoring"""
    await ultra_resilience_manager.register_strategy_monitoring(strategy_id, wallet_id, strategy_type)

def update_strategy_heartbeat(strategy_id: str):
    """Update strategy heartbeat"""
    ultra_resilience_manager.update_strategy_heartbeat(strategy_id)

def get_ultra_system_status():
    """Get ultra system status"""
    return ultra_resilience_manager.get_system_status()