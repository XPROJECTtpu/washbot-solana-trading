"""
WashBot Background Process Manager
Prevents bot from sleeping and provides auto-restart capabilities
"""

import time
import threading
import logging
import requests
import subprocess
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class BackgroundManager:
    """
    Background process manager that keeps the bot alive and monitors system health
    """
    
    def __init__(self, app, health_check_interval=30, heartbeat_interval=10):
        self.app = app
        self.health_check_interval = health_check_interval
        self.heartbeat_interval = heartbeat_interval
        self.is_running = False
        self.last_heartbeat = datetime.now()
        self.health_stats = {
            "uptime_start": datetime.now(),
            "total_heartbeats": 0,
            "last_health_check": None,
            "system_status": "healthy"
        }
        self.threads = []
        
    def start(self):
        """Start background monitoring processes"""
        if self.is_running:
            logger.warning("Background manager already running")
            return
            
        self.is_running = True
        logger.info("🚀 Starting WashBot Background Manager")
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        self.threads.append(heartbeat_thread)
        
        # Start health check thread  
        health_thread = threading.Thread(target=self._health_check_loop, daemon=True)
        health_thread.start()
        self.threads.append(health_thread)
        
        # Start keep-alive thread
        keepalive_thread = threading.Thread(target=self._keep_alive_loop, daemon=True)
        keepalive_thread.start()
        self.threads.append(keepalive_thread)
        
        logger.info("✅ Background manager started successfully")
        
    def stop(self):
        """Stop background monitoring"""
        self.is_running = False
        logger.info("🛑 Stopping background manager")
        
    def _heartbeat_loop(self):
        """Send regular heartbeat signals"""
        while self.is_running:
            try:
                self.last_heartbeat = datetime.now()
                self.health_stats["total_heartbeats"] += 1
                
                # Log heartbeat every 100 beats to avoid spam
                if self.health_stats["total_heartbeats"] % 100 == 0:
                    logger.info(f"💓 Heartbeat #{self.health_stats['total_heartbeats']}")
                    
                time.sleep(self.heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                time.sleep(5)
                
    def _health_check_loop(self):
        """Perform periodic system health checks"""
        while self.is_running:
            try:
                self._perform_health_check()
                time.sleep(self.health_check_interval)
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
                time.sleep(10)
                
    def _keep_alive_loop(self):
        """Keep the system active to prevent sleeping"""
        while self.is_running:
            try:
                # Make internal request to keep Flask alive
                with self.app.test_client() as client:
                    response = client.get('/health')
                    if response.status_code != 200:
                        logger.warning("Health endpoint returned non-200 status")
                        
                # Keep database connection alive
                from database import get_db_connection
                db = get_db_connection()
                result = db.execute("SELECT 1").fetchone()
                
                time.sleep(60)  # Keep alive every minute
                
            except Exception as e:
                logger.error(f"Keep-alive error: {e}")
                time.sleep(30)
                
    def _perform_health_check(self):
        """Perform comprehensive health check"""
        try:
            self.health_stats["last_health_check"] = datetime.now()
            
            # Check database connectivity
            from database import get_db_connection
            db = get_db_connection()
            db.execute("SELECT 1")
            
            # Check memory usage
            import psutil
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 90:
                logger.warning(f"High memory usage: {memory_percent}%")
                
            # Check disk space
            disk_percent = psutil.disk_usage('/').percent
            if disk_percent > 90:
                logger.warning(f"Low disk space: {disk_percent}% used")
                
            # Update status
            self.health_stats["system_status"] = "healthy"
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.health_stats["system_status"] = "unhealthy"
            
    def get_health_stats(self) -> Dict[str, Any]:
        """Get current health statistics"""
        uptime = datetime.now() - self.health_stats["uptime_start"]
        
        return {
            "is_running": self.is_running,
            "uptime_seconds": int(uptime.total_seconds()),
            "uptime_formatted": str(uptime),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "total_heartbeats": self.health_stats["total_heartbeats"],
            "last_health_check": self.health_stats["last_health_check"].isoformat() if self.health_stats["last_health_check"] else None,
            "system_status": self.health_stats["system_status"],
            "active_threads": len(self.threads)
        }

# Global background manager instance
background_manager = None

def initialize_background_manager(app):
    """Initialize and start the background manager"""
    global background_manager
    
    if background_manager is None:
        background_manager = BackgroundManager(app)
        background_manager.start()
        logger.info("🌟 Background manager initialized and started")
    
    return background_manager

def get_background_manager():
    """Get the global background manager instance"""
    return background_manager