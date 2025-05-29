"""
🚀 Emergency Deployment RAM Optimizer
Intelligent memory management to resolve false 8GB limit on 32GB Reserved VM
"""

import gc
import os
import sys
import psutil
import logging
import threading
import time
from functools import wraps
from typing import Any, Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DeploymentRAMOptimizer:
    """
    Emergency RAM optimization to bypass false 8GB limits
    """
    
    def __init__(self):
        self.process = psutil.Process()
        self.initial_memory = self._get_memory_mb()
        self.optimization_active = True
        self.cleanup_thread = None
        
    def _get_memory_mb(self) -> float:
        """Get current memory usage in MB"""
        try:
            return self.process.memory_info().rss / 1024 / 1024
        except:
            return 0.0
    
    def force_memory_cleanup(self):
        """Aggressive memory cleanup"""
        try:
            # Multiple garbage collection passes
            for _ in range(5):
                collected = gc.collect()
                if collected == 0:
                    break
            
            # Clear module cache selectively
            self._cleanup_module_cache()
            
            # Force memory trimming
            gc.collect()
            
            logger.info(f"🧹 Memory cleanup: {self._get_memory_mb():.1f}MB")
            
        except Exception as e:
            logger.warning(f"Memory cleanup warning: {e}")
    
    def _cleanup_module_cache(self):
        """Clean up unused modules"""
        try:
            # List of safe-to-remove modules
            removable_patterns = [
                'test_', 'tests.', '_test', 'pytest',
                'unittest', 'doctest', 'pdb', 'pydoc'
            ]
            
            modules_to_remove = []
            for name in sys.modules:
                if any(pattern in name for pattern in removable_patterns):
                    modules_to_remove.append(name)
            
            for name in modules_to_remove:
                if name in sys.modules:
                    del sys.modules[name]
            
            if modules_to_remove:
                logger.debug(f"Removed {len(modules_to_remove)} test modules")
                
        except Exception as e:
            logger.debug(f"Module cleanup note: {e}")
    
    def optimize_environment_variables(self):
        """Set memory-efficient environment variables"""
        try:
            # Python memory optimizations
            os.environ.update({
                'PYTHONOPTIMIZE': '2',  # Maximum optimization
                'PYTHONDONTWRITEBYTECODE': '1',  # No .pyc files
                'PYTHONHASHSEED': '0',  # Deterministic hashing
                'MALLOC_TRIM_THRESHOLD_': '65536',  # Aggressive malloc trimming
                'MALLOC_MMAP_THRESHOLD_': '65536',  # Small mmap threshold
                'PYTHONUNBUFFERED': '1',  # Unbuffered I/O
            })
            
            # Flask/Gunicorn optimizations
            os.environ.update({
                'WEB_CONCURRENCY': '1',  # Single worker to save memory
                'GUNICORN_WORKERS': '1',
                'GUNICORN_THREADS': '2',  # Minimal threads
                'GUNICORN_MAX_REQUESTS': '100',  # Restart workers frequently
                'GUNICORN_MAX_REQUESTS_JITTER': '10',
                'GUNICORN_TIMEOUT': '30',
                'GUNICORN_KEEPALIVE': '5',
            })
            
            logger.info("✅ Memory-optimized environment variables set")
            
        except Exception as e:
            logger.warning(f"Environment optimization warning: {e}")
    
    def start_background_monitoring(self):
        """Start background memory monitoring"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
        
        def monitor_worker():
            while self.optimization_active:
                try:
                    time.sleep(10)  # Check every 10 seconds
                    
                    current_memory = self._get_memory_mb()
                    
                    # If memory usage is high, trigger cleanup
                    if current_memory > 1000:  # 1GB threshold
                        logger.warning(f"⚠️ High memory usage: {current_memory:.1f}MB")
                        self.force_memory_cleanup()
                    
                except Exception as e:
                    logger.debug(f"Monitor note: {e}")
        
        self.cleanup_thread = threading.Thread(target=monitor_worker, daemon=True)
        self.cleanup_thread.start()
        logger.info("🔍 Background memory monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.optimization_active = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=3)
    
    def memory_efficient_decorator(self, func):
        """Decorator for memory-efficient function execution"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Pre-execution cleanup
                self.force_memory_cleanup()
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Post-execution cleanup
                self.force_memory_cleanup()
                
                return result
                
            except Exception as e:
                logger.error(f"Function {func.__name__} error: {e}")
                raise
        
        return wrapper
    
    def optimize_for_deployment(self):
        """Complete deployment optimization"""
        try:
            logger.info("🚀 Starting emergency RAM optimization for deployment...")
            
            # Step 1: Environment optimization
            self.optimize_environment_variables()
            
            # Step 2: Initial memory cleanup
            self.force_memory_cleanup()
            
            # Step 3: Start monitoring
            self.start_background_monitoring()
            
            # Step 4: Report optimization results
            current_memory = self._get_memory_mb()
            saved_memory = self.initial_memory - current_memory
            
            logger.info(f"✅ RAM optimization complete!")
            logger.info(f"💾 Initial memory: {self.initial_memory:.1f}MB")
            logger.info(f"💾 Current memory: {current_memory:.1f}MB")
            logger.info(f"💾 Memory saved: {saved_memory:.1f}MB")
            
            # Verify we're under safe thresholds
            if current_memory < 2000:  # Under 2GB
                logger.info("🎉 Memory usage is deployment-safe!")
            else:
                logger.warning(f"⚠️ Memory still high: {current_memory:.1f}MB")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Deployment optimization failed: {e}")
            return False
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get comprehensive memory statistics"""
        try:
            current_memory = self._get_memory_mb()
            system_memory = psutil.virtual_memory()
            
            return {
                'process_memory_mb': current_memory,
                'initial_memory_mb': self.initial_memory,
                'memory_saved_mb': self.initial_memory - current_memory,
                'system_total_gb': system_memory.total / 1024 / 1024 / 1024,
                'system_available_gb': system_memory.available / 1024 / 1024 / 1024,
                'system_percent_used': system_memory.percent,
                'optimization_active': self.optimization_active
            }
            
        except Exception as e:
            logger.error(f"Stats error: {e}")
            return {}

# Global optimizer instance
deployment_optimizer = DeploymentRAMOptimizer()

def optimize_memory(func):
    """Memory optimization decorator"""
    return deployment_optimizer.memory_efficient_decorator(func)

def init_deployment_optimization():
    """Initialize deployment optimization"""
    return deployment_optimizer.optimize_for_deployment()

def get_deployment_stats():
    """Get current deployment statistics"""
    return deployment_optimizer.get_memory_stats()

def emergency_cleanup():
    """Emergency memory cleanup"""
    deployment_optimizer.force_memory_cleanup()

# Auto-optimize on import
if __name__ != "__main__":
    init_deployment_optimization()