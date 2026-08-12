import asyncio
import os
import json
import time
import threading
import subprocess
from app.utils.logger import get_logger

logger = get_logger()

# Subprocess spawns are wrapped in a lock so concurrent calls from multiple
# threads (and/or multiple event loops) never spawn processes simultaneously.
# asyncio/uvloop raise "Racing with another loop to spawn a process" when two
# loops spawn subprocesses at the same time - the lock makes the sync runner
# fully immune and keeps async callers safe too.
_SPAWN_LOCK = threading.Lock()

def load_timeout() -> int:
    """Loads default timeout settings from the configuration."""
    config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'app', 'modules', 'config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            return config.get('experimental', {}).get('subprocess_timeout', 600)
    except Exception:
        return 600

async def run_command_async(cmd, timeout=None, cwd=None, env=None):
    """
    Asynchronously runs a system command using asyncio.
    Streams back (stdout, stderr, returncode) without blocking the parent process.
    """
    if timeout is None:
        timeout = load_timeout()
    
    logger.debug(f"Running command async: {' '.join(cmd)}")
    start_time = time.time()
    
    try:
        # Create subprocess (spawn serialized under _SPAWN_LOCK to avoid the
        # uvloop cross-loop subprocess race; execution itself is not locked).
        with _SPAWN_LOCK:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env
            )
        
        # Wait for execution with explicit timeout
        stdout_data, stderr_data = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout
        )
        
        elapsed = time.time() - start_time
        stdout_str = stdout_data.decode('utf-8', errors='ignore')
        stderr_str = stderr_data.decode('utf-8', errors='ignore')
        
        logger.debug(f"Command finished in {elapsed:.2f}s, returncode={process.returncode}")
        
        if process.returncode != 0:
            logger.error(f"Command failed with code {process.returncode}: {stderr_str[:200]}")
            
        return stdout_str, stderr_str, process.returncode

    except asyncio.TimeoutError:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        try:
            process.kill()
            await process.wait()
        except Exception as kill_err:
            logger.debug(f"Process kill error or already dead: {kill_err}")
        return '', f"Timeout after {timeout}s", -1
        
    except Exception as e:
        logger.exception(f"Command execution error: {' '.join(cmd)}")
        return '', str(e), -1

def run_command(cmd, timeout=None, cwd=None, env=None, check=False):
    """
    Synchronous subprocess runner.
    Uses subprocess.Popen instead of an asyncio event loop so that concurrent
    calls from multiple threads never touch shared loop/child-watcher state
    (uvloop raises 'Racing with another loop to spawn a process' otherwise).
    Returns (stdout, stderr, returncode); on timeout or spawn error returns
    ('', message, -1) to mirror the previous contract.
    """
    if timeout is None:
        timeout = load_timeout()

    logger.debug(f"Running command: {' '.join(cmd)}")
    start_time = time.time()

    try:
        # Only the spawn is serialized - long-running processes run in parallel.
        with _SPAWN_LOCK:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env
            )
    except (FileNotFoundError, OSError) as e:
        logger.error(f"Command not found / failed to spawn: {' '.join(cmd)}: {e}")
        return '', str(e), -1
    except Exception as e:
        logger.exception(f"Command spawn error: {' '.join(cmd)}")
        return '', str(e), -1

    try:
        stdout_data, stderr_data = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        proc.kill()
        try:
            proc.communicate()
        except Exception:
            pass
        return '', f"Timeout after {timeout}s", -1

    elapsed = time.time() - start_time
    stdout_str = stdout_data.decode('utf-8', errors='ignore')
    stderr_str = stderr_data.decode('utf-8', errors='ignore')

    logger.debug(f"Command finished in {elapsed:.2f}s, returncode={proc.returncode}")

    if proc.returncode != 0:
        logger.error(f"Command failed with code {proc.returncode}: {stderr_str[:200]}")

    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed with code {proc.returncode}: {stderr_str}")

    return stdout_str, stderr_str, proc.returncode