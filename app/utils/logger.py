# app/utils/logger.py

import logging
import os
import json
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Default values (will be overridden by config)
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_FILE = "logs/deepbug.log"

def load_config():
    """Load config from the standard location."""
    config_path = Path(__file__).parent.parent / "modules" / "config.json"
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def setup_logger(name="deepbug"):
    """Configure and return a logger instance with console + rotating file handlers."""
    config = load_config()
    exp = config.get("experimental", {})
    log_level = exp.get("log_level", DEFAULT_LOG_LEVEL)
    log_file = exp.get("log_file", DEFAULT_LOG_FILE)

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Avoid adding duplicate handlers if already configured
    if logger.handlers:
        return logger

    # Console handler (for Streamlit / terminal)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console.setFormatter(console_format)
    logger.addHandler(console)

    # Rotating file handler (max 10 MB, keep 5 backups)
    try:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(log_file, maxBytes=10_000_000, backupCount=5)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    except Exception as e:
        # If file logging fails, just log to console
        logger.warning(f"Could not set up file logging: {e}")

    return logger

# Singleton instance
_logger = None

def get_logger():
    """Return the singleton logger instance."""
    global _logger
    if _logger is None:
        _logger = setup_logger()
    return _logger