# app/modules/integrations/preview_corpus.py
"""Client for the preview.is security-writeup corpus (hybrid search API).

Uses the published preview.is search API as a grounded reference corpus
during analysis: exact-token + semantic search over ~188k indexed chunks of
real web-security write-ups, returning cited article sections.

QUOTA-AWARE BY DESIGN: free tier is 4 requests/min burst, 200/week, 1000/month.
This client enforces a minimum 15s spacing between calls (4/min is the burst
ceiling), caps `k` at 5 (standard accounts are capped at 5 results), caches
responses per (query, k, min_score) in memory, and exposes usage counters so
callers can see their footprint. Never call it in a tight loop.

Usage:
    from app.modules.integrations.preview_corpus import PreviewCorpus
    pc = PreviewCorpus(api_key=os.environ.get('PREVIEW_IS_API_KEY'))
    hits = pc.search("DOM clobbering gadgets in Vite")
    for h in hits: print(h['rank'], round(h['score'],3), h['title'], h['url'])

Config key: `integrations.preview_corpus.api_key` or env PREVIEW_IS_API_KEY.
"""

import os
import time
import hashlib
import logging
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

_BASE = "https://api.preview.is"
_SEARCH = "/search"
_HEALTH = "/health"

_MIN_INTERVAL_S = 15.0          # 4/min burst ceiling -> >=15s spacing
_MAX_K = 5                      # standard account cap
_DEFAULT_TIMEOUT = 25


class PreviewCorpus:
    """Quota-safe client for the preview.is hybrid search corpus."""

    def __init__(self, api_key: str = "", min_interval: float = _MIN_INTERVAL_S,
                 timeout: float = _DEFAULT_TIMEOUT):
        self.api_key = api_key or os.environ.get("PREVIEW_IS_API_KEY", "")
        self.min_interval = min_interval
        self.timeout = timeout
        self._last_call = 0.0
        self._cache: Dict[str, List[Dict]] = {}
        self.calls_made = 0
        self.cache_hits = 0
        self.rate_limited = 0

    # ------------------------------------------------------------------ helpers
    def _throttle(self):
        wait = self.min_interval - (time.time() - self._last_call)
        if wait > 0:
            time.sleep(wait)

    def _cache_key(self, query: str, k: int, min_score: float) -> str:
        return hashlib.sha256(f"{query}|{k}|{min_score}".encode()).hexdigest()[:24]

    def _headers(self) -> Dict[str, str]:
        return {"Content-Type": "application/json",
                "X-API-Key": self.api_key,
                "User-Agent": "DeepBug-Corpus/1.0"}

    # ------------------------------------------------------------------ public
    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def health(self) -> Optional[Dict]:
        """Liveness + indexed chunk count (no auth, no quota cost)."""
        try:
            r = httpx.get(f"{_BASE}{_HEALTH}", timeout=self.timeout)
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.debug("preview.is health check failed: %s", e)
        return None

    def search(self, query: str, k: int = 3, min_score: float = 0.1,
               full_content: bool = False) -> List[Dict]:
        """Search the corpus. Returns ranked hits with title/url/sections.

        Quota-safe: throttled to >=15s spacing, k capped at 5, cached by
        (query, k, min_score). Returns [] on quota/network failure.
        """
        if not self.available:
            logger.warning("No PREVIEW_IS_API_KEY configured - corpus lookup skipped.")
            return []
        k = max(1, min(int(k), _MAX_K))
        key = self._cache_key(query, k, min_score)
        if key in self._cache:
            self.cache_hits += 1
            return self._cache[key]

        self._throttle()
        self._last_call = time.time()
        self.calls_made += 1
        payload = {"query": query, "k": k, "min_score": min_score,
                   "full_content": bool(full_content)}
        try:
            r = httpx.post(f"{_BASE}{_SEARCH}", json=payload,
                           headers=self._headers(), timeout=self.timeout)
        except Exception as e:
            logger.warning("preview.is corpus request failed: %s", e)
            return []
        if r.status_code == 429:
            self.rate_limited += 1
            logger.warning("preview.is corpus rate-limited (429) - respecting quota.")
            return []
        if r.status_code != 200:
            logger.warning("preview.is corpus returned %s: %s", r.status_code, r.text[:200])
            return []
        try:
            hits = [h for h in r.json().get("results", []) if isinstance(h, dict)]
        except Exception:
            return []
        self._cache[key] = hits
        return hits

    def compact(self, query: str, k: int = 3, min_score: float = 0.1,
                sections: int = 1) -> List[str]:
        """Return one readable line per hit (title | url | top heading)."""
        out = []
        for h in self.search(query, k=k, min_score=min_score):
            heads = [s.get("heading", "") for s in h.get("matched_sections", [])
                     if s.get("heading")][:sections]
            line = f"[{h.get('score', 0):.3f}] {h.get('title', '')} | {h.get('url', '')}"
            if heads:
                line += f" | §§ {', '.join(heads)}"
            out.append(line)
        return out


# ---------------------------------------------------------------------------
# CLI: python3 -m app.modules.integrations.preview_corpus "query" [k]
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    q = " ".join(sys.argv[1:]) or "prototype pollution exploitation"
    k = 3
    try:
        k = int(sys.argv[-1]) if sys.argv[-1].isdigit() else k
    except (IndexError, ValueError):
        pass
    pc = PreviewCorpus()
    if not pc.available:
        print("Set PREVIEW_IS_API_KEY or integrations.preview_corpus.api_key")
        sys.exit(1)
    h = pc.health()
    print(f"corpus: {h.get('indexed_chunks', '?')} chunks, {h.get('embed_dim', '?')}d" if h else "corpus: health N/A")
    for line in pc.compact(q, k=k):
        print("-", line)
    print(f"(calls={pc.calls_made} cache_hits={pc.cache_hits} rate_limited={pc.rate_limited})")
