# app/utils/alive_filter.py
# HTTP-alive filtering for candidate confirmation: discard dead URLs
# (404 / 410 / unreachable), retain everything else. Keeps confirmation
# scans (kxss, CSTI, SSRF, open-redirect) focused on live targets.

import asyncio
from typing import Dict, List, Tuple

import aiohttp


async def _probe_url_statuses(urls: List[str], concurrency: int = 20,
                              timeout: int = 8) -> List[Tuple[str, int]]:
    sem = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout)) as session:

        async def one(url: str):
            async with sem:
                try:
                    async with session.get(url, allow_redirects=False) as resp:
                        return url, resp.status
                except Exception:
                    return url, 0

        return await asyncio.gather(*(one(u) for u in urls))


def filter_alive_urls(urls: List[str], concurrency: int = 20,
                      timeout: int = 8) -> Dict[str, List[str]]:
    """Probe URLs and split into `alive` (retained) vs `dead` (discarded).

    Discards 404 / 410 / unreachable (0); retains every other status
    (2xx, 3xx redirects, other 4xx/5xx) for confirmation scanning.
    """
    clean = list(dict.fromkeys([u for u in urls if isinstance(u, str) and u.strip()]))
    if not clean:
        return {'alive': [], 'dead': []}
    statuses = asyncio.run(_probe_url_statuses(clean, concurrency, timeout))
    alive, dead = [], []
    for url, status in statuses:
        if status in (0, 404, 410):
            dead.append(url)
        else:
            alive.append(url)
    return {'alive': alive, 'dead': dead}
