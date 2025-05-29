"""
🚨 Emergency Deploy Fix - Async Task Cleanup & Memory Leak Resolution
"""

import asyncio
import gc
import logging
import signal
import sys
import threading
import weakref
from typing import Set, Any

logger = logging.getLogger(__name__)

class EmergencyDeployFix:
    """
    Emergency fix for deploy issues:
    1. Async task cleanup
    2. Memory leak prevention
    3. Graceful shutdown
    """
    
    def __init__(self):
        self.active_tasks: Set[asyncio.Task] = set()
        self.background_threads: Set[threading.Thread] = set()
        self.cleanup_registered = False
        
    def register_task(self, task: asyncio.Task):
        """Register task for cleanup"""
        self.active_tasks.add(task)
        # Use weak reference to avoid circular references
        task.add_done_callback(lambda t: self.active_tasks.discard(t))
    
    def register_thread(self, thread: threading.Thread):
        """Register background thread"""
        self.background_threads.add(thread)
    
    def cleanup_async_tasks(self):
        """Cleanup all pending async tasks"""
        try:
            # Cancel all pending tasks
            for task in self.active_tasks.copy():
                if not task.done():
                    task.cancel()
                    logger.debug(f"Cancelled task: {task}")
            
            # Wait for tasks to finish
            if self.active_tasks:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(
                        asyncio.gather(*self.active_tasks, return_exceptions=True)
                    )
                except Exception as e:
                    logger.debug(f"Task cleanup exception: {e}")
                finally:
                    loop.close()
            
            self.active_tasks.clear()
            logger.info("✅ Async tasks cleaned up")
            
        except Exception as e:
            logger.warning(f"Async cleanup warning: {e}")
    
    def cleanup_threads(self):
        """Cleanup background threads"""
        try:
            for thread in self.background_threads.copy():
                if thread.is_alive():
                    # Give threads time to finish gracefully
                    thread.join(timeout=2.0)
                    if thread.is_alive():
                        logger.warning(f"Thread still alive: {thread.name}")
            
            self.background_threads.clear()
            logger.info("✅ Background threads cleaned up")
            
        except Exception as e:
            logger.warning(f"Thread cleanup warning: {e}")
    
    def force_memory_cleanup(self):
        """Force aggressive memory cleanup"""
        try:
            # Multiple garbage collection passes
            for _ in range(5):
                collected = gc.collect()
                if collected == 0:
                    break
            
            # Clear weak references
            gc.collect()
            
            logger.info("✅ Memory forcefully cleaned")
            
        except Exception as e:
            logger.warning(f"Memory cleanup warning: {e}")
    
    def register_cleanup_handlers(self):
        """Register cleanup handlers for graceful shutdown"""
        if self.cleanup_registered:
            return
        
        def cleanup_handler(signum, frame):
            logger.info(f"🛑 Received signal {signum}, cleaning up...")
            self.emergency_cleanup()
            sys.exit(0)
        
        # Register signal handlers
        try:
            signal.signal(signal.SIGTERM, cleanup_handler)
            signal.signal(signal.SIGINT, cleanup_handler)
            self.cleanup_registered = True
            logger.info("✅ Cleanup handlers registered")
        except Exception as e:
            logger.warning(f"Signal handler registration warning: {e}")
    
    def emergency_cleanup(self):
        """Emergency cleanup for deployment"""
        logger.info("🚨 Emergency cleanup starting...")
        
        # 1. Cleanup async tasks
        self.cleanup_async_tasks()
        
        # 2. Cleanup threads
        self.cleanup_threads()
        
        # 3. Force memory cleanup
        self.force_memory_cleanup()
        
        logger.info("✅ Emergency cleanup complete")
    
    def optimize_for_deploy(self):
        """Optimize application for deployment"""
        try:
            # Register cleanup handlers
            self.register_cleanup_handlers()
            
            # Initial cleanup
            self.emergency_cleanup()
            
            # Disable debug mode for deployment
            import os
            os.environ['FLASK_DEBUG'] = '0'
            os.environ['PYTHONOPTIMIZE'] = '2'
            
            logger.info("✅ Deploy optimization complete")
            return True
            
        except Exception as e:
            logger.error(f"Deploy optimization failed: {e}")
            return False

# Global emergency fix instance
emergency_fix = EmergencyDeployFix()

def init_emergency_deploy_fix():
    """Initialize emergency deploy fix"""
    return emergency_fix.optimize_for_deploy()

def register_async_task(task: asyncio.Task):
    """Register async task for cleanup"""
    emergency_fix.register_task(task)

def register_background_thread(thread: threading.Thread):
    """Register background thread for cleanup"""
    emergency_fix.register_thread(thread)

def emergency_cleanup():
    """Trigger emergency cleanup"""
    emergency_fix.emergency_cleanup()

# Auto-initialize on import
if __name__ != "__main__":
    init_emergency_deploy_fix()