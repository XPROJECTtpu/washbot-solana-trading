
"""
🚀 WashBot Deploy Optimization Script - Enhanced
Deployment size reduction and compatibility fixes
"""

import os
import sys
import subprocess
import logging
import shutil
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def cleanup_for_deployment():
    """Remove unnecessary files to reduce deployment size"""
    logging.info("🧹 Starting deployment cleanup...")
    
    # Directories to clean
    dirs_to_clean = [
        "__pycache__",
        ".pytest_cache", 
        "rust-solana/target",
        "node_modules",
        ".git",
        "attached_assets",  # Large asset folder
        "tests",
        ".vscode",
        ".idea"
    ]
    
    total_saved = 0
    
    # Clean directories
    for dir_path in dirs_to_clean:
        if os.path.exists(dir_path):
            try:
                # Get size before deletion
                size_before = sum(
                    os.path.getsize(os.path.join(dirpath, filename))
                    for dirpath, dirnames, filenames in os.walk(dir_path)
                    for filename in filenames
                ) // (1024 * 1024)  # MB
                
                shutil.rmtree(dir_path)
                total_saved += size_before
                logging.info(f"✅ Removed {dir_path} (~{size_before}MB)")
            except Exception as e:
                logging.warning(f"⚠️ Could not remove {dir_path}: {e}")
    
    # Remove temporary and cache files
    extensions_to_remove = [".pyc", ".pyo", ".tmp", ".log", ".png", ".jpeg", ".jpg", ".gif"]
    files_removed = 0
    
    for root, dirs, files in os.walk("."):
        for file in files:
            if any(file.endswith(ext) for ext in extensions_to_remove):
                try:
                    file_path = os.path.join(root, file)
                    os.remove(file_path)
                    files_removed += 1
                except Exception:
                    pass
    
    logging.info(f"🗑️ Removed {files_removed} temporary files")
    logging.info(f"💾 Total space saved: ~{total_saved}MB")
    return total_saved

def optimize_for_deployment():
    """Deploy için sistemi optimize et"""
    logging.info("🚀 Enhanced deploy optimization starting...")
    
    # 1. Clean up files to reduce size
    saved_space = cleanup_for_deployment()
    
    # 2. Rust build bypass - production'da gerekli değil
    logging.info("✅ Rust build bypassed for RAM optimization")
    
    # 3. Python dependencies verify (only critical ones)
    critical_deps = ['flask', 'solana', 'psycopg2', 'gunicorn']
    missing_deps = []
    
    for dep in critical_deps:
        try:
            __import__(dep)
            logging.info(f"✅ {dep} verified")
        except ImportError:
            missing_deps.append(dep)
            logging.warning(f"⚠️ {dep} not found")
    
    # 4. Environment optimize for production
    os.environ.update({
        'PYTHONOPTIMIZE': '2',
        'PYTHONDONTWRITEBYTECODE': '1',
        'PYTHONUNBUFFERED': '1',
        'GUNICORN_CMD_ARGS': '--max-requests 1000 --timeout 30 --keep-alive 5 --worker-connections 100'
    })
    
    # 5. Verify deployment readiness
    if saved_space > 500:  # If we saved more than 500MB
        logging.info(f"✅ Deployment size optimized - saved {saved_space}MB")
    
    if not missing_deps:
        logging.info("✅ All critical dependencies verified")
    else:
        logging.warning(f"⚠️ Missing dependencies: {missing_deps}")
    
    logging.info("✅ Enhanced deploy optimization complete!")
    return len(missing_deps) == 0

if __name__ == "__main__":
    success = optimize_for_deployment()
    
    # Additional check for Rust compatibility
    try:
        subprocess.run(["rustc", "--version"], check=True, capture_output=True)
        logging.info("✅ Rust available but bypassed for deployment")
    except:
        logging.info("ℹ️ Rust not available - continuing with Python-only mode")
    
    sys.exit(0 if success else 1)
