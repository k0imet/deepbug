"""
OOB — first-class out-of-band canary management.

Creates per-run canary tokens via webhook.site (or custom callback URLs),
polls for callbacks, and surfaces results. No API key needed for webhook.site
— the free tier generates a unique UUID per session.

Config keys (under `oob.*`):
  callback_url: override webhook.site with a custom callback URL
  poll_interval: seconds between poll checks (default 3)
  poll_timeout: total polling timeout in seconds (default 60)
  webhook_api_key: optional webhook.site API key for persistent tokens
"""

import asyncio
import time
import json
import uuid
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

_WEBHOOK_SITE_API = 'https://webhook.site'


class OOBCanary:
    """A single out-of-band canary token."""

    def __init__(self, token_id: str, url: str, callback_url: str = '',
                 poll_url: str = '', api_key: str = ''):
        self.token_id = token_id
        self.url = url
        self.callback_url = callback_url or url
        self.poll_url = poll_url
        self.api_key = api_key
        self.callbacks: List[Dict] = []
        self._polled = False

    def __repr__(self):
        return f'OOBCanary({self.token_id[:8]}...)'

    def poll_headers(self) -> Dict:
        if self.api_key:
            return {'api-key': self.api_key}
        return {}


class OOBManager:
    """Manages OOB canary tokens for SSRF, XXE, blind RCE, etc."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get('oob', {}) if isinstance(config, dict) else {}
        self.callback_url = cfg.get('callback_url', '')
        self.poll_interval = float(cfg.get('poll_interval', 3))
        self.poll_timeout = float(cfg.get('poll_timeout', 60))
        self.api_key = cfg.get('webhook_api_key', '')
        self._canaries: List[OOBCanary] = []

    async def create_webhook_token(self) -> Optional[OOBCanary]:
        """Create a new webhook.site token (no API key needed)."""
        try:
            headers = {'Content-Type': 'application/json'}
            if self.api_key:
                headers['api-key'] = self.api_key
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f'{_WEBHOOK_SITE_API}/token',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        uid = data.get('uuid', '')
                        if uid:
                            canary = OOBCanary(
                                token_id=uid,
                                url=f'{_WEBHOOK_SITE_API}/{uid}',
                                callback_url=f'{_WEBHOOK_SITE_API}/{uid}',
                                poll_url=f'{_WEBHOOK_SITE_API}/token/{uid}/requests',
                                api_key=self.api_key,
                            )
                            self._canaries.append(canary)
                            logger.info(f'OOB canary created: {uid}')
                            return canary
        except Exception as e:
            logger.warning(f'webhook.site token creation failed: {e}')
        return None

    def create_custom_canary(self, callback_url: str) -> OOBCanary:
        """Use a pre-existing callback URL as a canary."""
        canary = OOBCanary(
            token_id=callback_url,
            url=callback_url,
            callback_url=callback_url,
        )
        self._canaries.append(canary)
        return canary

    def create_canary(self) -> Optional[OOBCanary]:
        """Create a canary: custom URL if configured, else webhook.site."""
        if self.callback_url:
            return self.create_custom_canary(self.callback_url)
        return asyncio.run(self.create_webhook_token())

    async def poll_canary(self, canary: OOBCanary) -> List[Dict]:
        """Poll for callbacks on a single canary."""
        if not canary.poll_url:
            return []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    canary.poll_url,
                    headers=canary.poll_headers(),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    if r.status == 200:
                        data = await r.json()
                        requests = data.get('data', []) if isinstance(data, dict) else data
                        if not isinstance(requests, list):
                            requests = []
                        new_callbacks = [req for req in requests if not isinstance(req, dict) or
                                         req.get('uuid') not in {c.get('uuid') for c in canary.callbacks}]
                        canary.callbacks.extend(requests)
                        canary._polled = True
                        return new_callbacks
        except Exception as e:
            logger.debug(f'OOB poll failed for {canary.token_id[:8]}: {e}')
        return []

    async def poll_all(self, timeout: Optional[float] = None) -> Dict[str, List[Dict]]:
        """Poll all canaries with a timeout. Returns {token_id: [callbacks]}."""
        timeout = timeout or self.poll_timeout
        deadline = time.time() + timeout
        results: Dict[str, List[Dict]] = {}

        while time.time() < deadline:
            tasks = [self.poll_canary(c) for c in self._canaries]
            batches = await asyncio.gather(*tasks, return_exceptions=True)
            any_new = False
            for canary, batch in zip(self._canaries, batches):
                if isinstance(batch, list) and batch:
                    results.setdefault(canary.token_id, []).extend(batch)
                    any_new = True
            if any_new:
                break
            await asyncio.sleep(self.poll_interval)

        return results

    def canary_payload(self, canary: OOBCanary) -> str:
        """Return the URL payload to inject."""
        return canary.callback_url

    def canary_payloads(self) -> Dict[str, str]:
        """Return {canary_id: url} for all canaries."""
        return {c.token_id: c.callback_url for c in self._canaries}

    def has_callbacks(self) -> bool:
        return any(bool(c.callbacks) for c in self._canaries)

    def summary(self) -> Dict[str, Any]:
        return {
            'total_canaries': len(self._canaries),
            'canaries_with_callbacks': sum(1 for c in self._canaries if c.callbacks),
            'total_callbacks': sum(len(c.callbacks) for c in self._canaries),
            'callback_urls': {c.token_id[:12]: c.callback_url for c in self._canaries},
            'callbacks': [
                {
                    'canary': c.token_id[:12],
                    'requests': [
                        {
                            'method': r.get('method', '') if isinstance(r, dict) else '',
                            'url': (r.get('url', '') if isinstance(r, dict) else str(r))[:200],
                            'ip': r.get('ip', '') if isinstance(r, dict) else '',
                            'user_agent': (r.get('user_agent', '') if isinstance(r, dict) else '')[:120],
                            'created_at': r.get('created_at', '') if isinstance(r, dict) else '',
                        }
                        for r in c.callbacks[:20]
                    ]
                }
                for c in self._canaries if c.callbacks
            ],
        }

    def clear(self):
        self._canaries = []


__all__ = ['OOBCanary', 'OOBManager']