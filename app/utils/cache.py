import os
import json
import time
from app.utils.logger import get_logger   # fixed import

logger = get_logger()
CACHE_DIR = '/tmp/deepbug_cache'
DEFAULT_TTL = 3600

def ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)

def get_cache_key(target, step):
    safe_target = target.replace('.', '_').replace(':', '_')
    return os.path.join(CACHE_DIR, f"{safe_target}_{step}.json")

def save_cache(target, step, data, ttl=DEFAULT_TTL):
    ensure_cache_dir()
    path = get_cache_key(target, step)
    payload = {
        'timestamp': time.time(),
        'ttl': ttl,
        'data': data
    }
    try:
        with open(path, 'w') as f:
            json.dump(payload, f)
        logger.debug(f"Cached {step} for {target}")
    except Exception as e:
        logger.warning(f"Failed to save cache for {step}: {e}")

def load_cache(target, step):
    path = get_cache_key(target, step)
    if not os.path.exists(path):
        return None
    try:
        with open(path, 'r') as f:
            payload = json.load(f)
        if time.time() - payload['timestamp'] > payload.get('ttl', DEFAULT_TTL):
            logger.debug(f"Cache expired for {step}")
            os.remove(path)
            return None
        return payload['data']
    except Exception as e:
        logger.warning(f"Failed to load cache for {step}: {e}")
        return None

def clear_cache(target=None, step=None):
    if target is None:
        ensure_cache_dir()
        for f in os.listdir(CACHE_DIR):
            os.remove(os.path.join(CACHE_DIR, f))
        logger.info("Cleared all cache")
    else:
        prefix = target.replace('.', '_').replace(':', '_')
        for f in os.listdir(CACHE_DIR):
            if f.startswith(prefix):
                os.remove(os.path.join(CACHE_DIR, f))
        logger.info(f"Cleared cache for {target}")