"""
🚀 Gunicorn Configuration - Optimized for 32GB Reserved VM
Emergency memory optimization to bypass false 8GB limits
"""

import os
import multiprocessing

# Memory-optimized settings for deployment
bind = "0.0.0.0:5000"
workers = 1  # Single worker to minimize memory usage
threads = 2  # Minimal threads
worker_class = "sync"
worker_connections = 100
max_requests = 200  # Restart workers frequently to prevent memory leaks
max_requests_jitter = 20
timeout = 300  # 5 minute timeout
keepalive = 5
preload_app = True  # Load app before forking workers
reload = False  # Disable reload in production

# Memory optimization
worker_tmp_dir = "/dev/shm"  # Use shared memory for temporary files
tmp_upload_dir = "/tmp"

# Security and performance
user = None
group = None
umask = 0o077
daemon = False

# Logging
accesslog = "-"  # Log to stdout
errorlog = "-"   # Log to stderr
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = "washbot-gunicorn"

# Environment variables for memory optimization
raw_env = [
    "WEB_CONCURRENCY=1",
    "GUNICORN_WORKERS=1",
    "PYTHONOPTIMIZE=2",
    "PYTHONDONTWRITEBYTECODE=1",
    "MALLOC_TRIM_THRESHOLD_=65536",
    "MALLOC_MMAP_THRESHOLD_=65536",
    "PYTHONUNBUFFERED=1"
]

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("🚀 WashBot server is ready - memory optimized!")

def worker_int(worker):
    """Called just after a worker has been killed."""
    worker.log.info("🧹 Worker killed - cleaning up memory")

def on_exit(server):
    """Called just before the master process is killed."""
    server.log.info("🛑 WashBot server shutting down")

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(f"🚀 Worker {worker.pid} spawned - memory optimized")
    
    # Import and initialize memory optimization in worker
    try:
        from deployment_optimizer import emergency_cleanup
        emergency_cleanup()
        server.log.info(f"✅ Worker {worker.pid} memory optimized")
    except Exception as e:
        server.log.warning(f"⚠️ Worker memory optimization warning: {e}")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("🔄 Preparing to fork worker - optimizing memory")
    
    # Force garbage collection before forking
    import gc
    gc.collect()