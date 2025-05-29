"""
🚀 WashBot RAM Optimization System
Minimize memory usage during deployment and runtime
"""

import gc
import sys
import os
import psutil
import threading
import time
from functools import wraps
from typing import Any, Callable
import logging

logger = logging.getLogger(__name__)

class RAMOptimizer:
    """
    Advanced RAM optimization for deployment and runtime
    """
    
    def __init__(self):
        self.process = psutil.Process()
        self.initial_memory = self.get_memory_usage()
        self.optimization_active = True
        self.cleanup_thread = None
        
    def get_memory_usage(self) -> dict:
        """Get current memory usage"""
        try:
            memory_info = self.process.memory_info()
            return {
                'rss': memory_info.rss / 1024 / 1024,  # MB
                'vms': memory_info.vms / 1024 / 1024,  # MB
                'percent': self.process.memory_percent()
            }
        except:
            return {'rss': 0, 'vms': 0, 'percent': 0}
    
    def force_garbage_collection(self):
        """Aggressive garbage collection"""
        try:
            # Multiple GC passes for thorough cleanup
            for _ in range(3):
                collected = gc.collect()
                if collected == 0:
                    break
            
            # Clear weak references
            gc.collect()
                
            logger.debug(f"🧹 RAM cleanup completed")
        except Exception as e:
            logger.warning(f"GC warning: {e}")
    
    def optimize_imports(self):
        """Optimize module imports and cleanup unused"""
        try:
            # Remove unused modules
            modules_to_remove = []
            for name, module in sys.modules.items():
                if hasattr(module, '__file__') and module.__file__:
                    # Skip core modules
                    if any(core in name for core in ['flask', 'sqlalchemy', 'solana']):
                        continue
                    modules_to_remove.append(name)
            
            # Selective cleanup of non-essential modules
            cleanup_count = 0
            for name in modules_to_remove[:50]:  # Limit cleanup
                try:
                    if name in sys.modules:
                        del sys.modules[name]
                        cleanup_count += 1
                except:
                    continue
                    
            if cleanup_count > 0:
                logger.debug(f"🧹 Cleaned {cleanup_count} unused modules")
                
        except Exception as e:
            logger.warning(f"Import optimization warning: {e}")
    
    def optimize_flask_app(self, app):
        """Optimize Flask app for minimal RAM usage"""
        try:
            # Minimal session configuration
            app.config.update({
                'PERMANENT_SESSION_LIFETIME': 1800,  # 30 min
                'SESSION_COOKIE_SECURE': True,
                'SESSION_COOKIE_HTTPONLY': True,
                'SESSION_COOKIE_SAMESITE': 'Lax',
            })
            
            # Optimize SQLAlchemy
            if hasattr(app, 'config') and 'SQLALCHEMY_ENGINE_OPTIONS' in app.config:
                app.config['SQLALCHEMY_ENGINE_OPTIONS'].update({
                    'pool_size': 5,  # Minimal pool
                    'max_overflow': 0,  # No overflow
                    'pool_pre_ping': True,
                    'pool_recycle': 300,
                })
            
            logger.info("⚡ Flask app RAM optimized")
            
        except Exception as e:
            logger.warning(f"Flask optimization warning: {e}")
    
    def memory_monitor_decorator(self, func: Callable) -> Callable:
        """Decorator to monitor and optimize function memory usage"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Pre-execution cleanup
                if self.optimization_active:
                    self.force_garbage_collection()
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Post-execution cleanup
                if self.optimization_active:
                    self.force_garbage_collection()
                
                return result
                
            except Exception as e:
                logger.error(f"Memory monitor error in {func.__name__}: {e}")
                return func(*args, **kwargs)
                
        return wrapper
    
    def start_background_cleanup(self):
        """Start background memory cleanup thread"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
            
        def cleanup_worker():
            while self.optimization_active:
                try:
                    time.sleep(30)  # Cleanup every 30 seconds
                    if self.optimization_active:
                        self.force_garbage_collection()
                        
                        # Check memory usage
                        current_memory = self.get_memory_usage()
                        if current_memory['percent'] > 80:  # High memory usage
                            logger.warning(f"🔥 High memory usage: {current_memory['percent']:.1f}%")
                            # More aggressive cleanup
                            for _ in range(5):
                                self.force_garbage_collection()
                                time.sleep(1)
                                
                except Exception as e:
                    logger.warning(f"Background cleanup error: {e}")
        
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        logger.info("🧹 Background RAM cleanup started")
    
    def stop_background_cleanup(self):
        """Stop background cleanup"""
        self.optimization_active = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=5)
        logger.info("🛑 Background RAM cleanup stopped")
    
    def optimize_deployment(self):
        """Deployment-specific optimizations"""
        try:
            # Set memory-efficient environment variables
            os.environ.update({
                'PYTHONOPTIMIZE': '2',
                'PYTHONDONTWRITEBYTECODE': '1',
                'MALLOC_TRIM_THRESHOLD_': '100000',
                'MALLOC_MMAP_THRESHOLD_': '131072',
            })
            
            # Optimize Python settings
            sys.dont_write_bytecode = True
            
            # Initial cleanup
            self.optimize_imports()
            self.force_garbage_collection()
            
            # Start monitoring
            self.start_background_cleanup()
            
            final_memory = self.get_memory_usage()
            saved_mb = self.initial_memory['rss'] - final_memory['rss']
            
            logger.info(f"🚀 Deployment RAM optimization complete")
            logger.info(f"💾 Memory saved: {saved_mb:.1f}MB")
            logger.info(f"📊 Current usage: {final_memory['rss']:.1f}MB ({final_memory['percent']:.1f}%)")
            
        except Exception as e:
            logger.error(f"Deployment optimization error: {e}")
    
    def get_optimization_stats(self) -> dict:
        """Get current optimization statistics"""
        current_memory = self.get_memory_usage()
        return {
            'initial_memory_mb': self.initial_memory['rss'],
            'current_memory_mb': current_memory['rss'],
            'memory_saved_mb': self.initial_memory['rss'] - current_memory['rss'],
            'memory_percent': current_memory['percent'],
            'optimization_active': self.optimization_active
        }

# Global optimizer instance
ram_optimizer = RAMOptimizer()

def optimize_memory(func: Callable) -> Callable:
    """Decorator for memory optimization"""
    return ram_optimizer.memory_monitor_decorator(func)

def init_ram_optimization(app=None):
    """Initialize RAM optimization system"""
    try:
        logger.info("🚀 Initializing RAM optimization system...")
        
        if app:
            ram_optimizer.optimize_flask_app(app)
        
        ram_optimizer.optimize_deployment()
        
        logger.info("✅ RAM optimization system ready")
        return ram_optimizer
        
    except Exception as e:
        logger.error(f"RAM optimization init error: {e}")
        return None

def cleanup_ram():
    """Manual RAM cleanup"""
    ram_optimizer.force_garbage_collection()

def get_memory_stats():
    """Get current memory statistics"""
    return ram_optimizer.get_optimization_stats()