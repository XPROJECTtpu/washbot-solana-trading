"""
Minimal WashBot Entry Point - Deploy Ready
"""
import os
import gc
import logging

# Minimal logging
logging.basicConfig(level=logging.ERROR)

# Force memory optimization
os.environ.update({
    'PYTHONOPTIMIZE': '2',
    'PYTHONDONTWRITEBYTECODE': '1',
    'WEB_CONCURRENCY': '1',
    'GUNICORN_WORKERS': '1'
})

# Aggressive memory cleanup
gc.set_threshold(100, 10, 10)
gc.collect()

# Import Flask app
from flask import Flask

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fallback-key-for-deploy")

@app.route('/')
def index():
    return "WashBot Deploy Test - Memory Optimized"

@app.route('/health')
def health():
    return {"status": "healthy", "memory": "optimized"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)