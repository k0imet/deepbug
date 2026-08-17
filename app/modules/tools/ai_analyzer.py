# modules/tools/ai_analyzer.py
# AI-assisted result analysis (OpenAI-compatible chat completions, no vendor
# SDK - plain aiohttp POST). Modes: summary / triage / prioritize /
# suggest_next / verify / exploit_chain.
#
# Falls back to deterministic local heuristics when AI is unavailable.
#
# Resilience: exponential-backoff retries (429/5xx/connection), LRU cache with
# TTL, token-aware truncation, per-call cost tracking, multi-provider payloads
# (OpenAI / Anthropic / DeepSeek / Groq / Ollama / Azure - auto-detected from
# `api_base` or explicit `provider`).
#
# Config keys (under `ai.*`):
#   enable, provider, api_base, api_key, model, timeout, max_context,
#   max_tokens, temperature, top_p, retries, retry_delay, cache_ttl,
#   json_mode, streaming, cost_tracking

import os
import json
import asyncio
import hashlib
import time
import aiohttp
from typing import Dict, List, Optional, Any, AsyncIterator, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from app.utils.logger import get_logger

logger = get_logger()

_DEFAULT_BASE = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o-mini"

_SYSTEM = (
    "You are a senior offensive-security analyst assistant. Be concise, "
    "technical and actionable. Prefer short bullet lists over prose. "
    "Never hallucinate findings that are not in the data."
)


# ---------------------------------------------------------------------------
# Severity / keyword constants (heuristic fallback)
# ---------------------------------------------------------------------------
_HIGH = frozenset((
    "password", "secret", "token", "api_key", "accesskey", "private",
    "credential", "aws", "github token", "bearer", "authorization",
    "stripe", "cloudflare", "openai", "anthropic", "gcp", "azure",
    "ssh", "private key", "jwt", "service account", "vault",
    "rce", "sql injection", "sqli", "xss", "ssrf", "lfi", "rfi",
    "command injection", "deserialization", "path traversal", "traversal",
    "auth bypass", "authentication bypass", "privilege escalation",
    "idor", "mass assignment", "insecure deserialization",
    "hardcoded", "exposed admin", "debug mode", "stack trace",
    "internal ip", "metadata", "169.254", "localhost", "127.0.0",
    "s3 bucket", "gcs bucket", "azure blob", "firebase", "database url",
    "mongodb", "redis", "elasticsearch", "kibana", "grafana", "jenkins",
    "docker", "kubernetes", "kubeconfig", "etcd", "consul", "vault token",
))
_MED = frozenset((
    "vuln", "ssrf", "open redirect", "takeover", "misconfig", "exposed",
    "leak", "interesting", "bypass", "401", "403", "cors", "csp",
    "clickjacking", "cache poisoning", "host header", "subdomain",
    "wildcard", "cname", "mx", "txt", "spf", "dmarc", "dns",
    "version disclosure", "technology", "framework", "server header",
    "waf", "rate limit", "throttling", "brute force", "enumeration",
    "information disclosure", "verbose error", "error message",
    "backup", "old", "staging", "dev", "test", "uat", "preprod",
    "swagger", "api docs", "graphql", "introspection", "soap",
    "wsdl", "sitemap", "robots", "crossdomain", "clientaccesspolicy",
))
_LOW = frozenset((
    "info", "note", "low", "minor", "cosmetic", "best practice",
    "recommendation", "suggestion", "observation", "finding",
))


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------
class Provider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    GROQ = "groq"
    OLLAMA = "ollama"
    AZURE = "azure"
    GENERIC = "generic"


@dataclass
class AIConfig:
    enable: bool = False
    provider: Provider = Provider.OPENAI
    api_base: str = _DEFAULT_BASE
    api_key: str = field(default_factory=lambda: os.environ.get("OPENAI_API_KEY", ""))
    model: str = _DEFAULT_MODEL
    timeout: int = 60
    max_context: int = 6000
    max_tokens: int = 1200
    temperature: float = 0.2
    top_p: float = 1.0
    retries: int = 3
    retry_delay: float = 1.0
    cache_ttl: int = 3600
    json_mode: bool = True
    streaming: bool = False
    cost_tracking: bool = True

    @classmethod
    def from_dict(cls, cfg: Dict) -> "AIConfig":
        if not isinstance(cfg, dict):
            cfg = {}
        provider_str = str(cfg.get("provider", "openai")).lower()
        try:
            provider = Provider(provider_str)
        except ValueError:
            provider = Provider.GENERIC
        return cls(
            enable=bool(cfg.get("enable", False)),
            provider=provider,
            api_base=str(cfg.get("api_base", _DEFAULT_BASE)).rstrip("/"),
            api_key=str(cfg.get("api_key", "") or os.environ.get("OPENAI_API_KEY", "")),
            model=str(cfg.get("model", _DEFAULT_MODEL)),
            timeout=int(cfg.get("timeout", 60)),
            max_context=int(cfg.get("max_context", 6000)),
            max_tokens=int(cfg.get("max_tokens", 1200)),
            temperature=float(cfg.get("temperature", 0.2)),
            top_p=float(cfg.get("top_p", 1.0)),
            retries=int(cfg.get("retries", 3)),
            retry_delay=float(cfg.get("retry_delay", 1.0)),
            cache_ttl=int(cfg.get("cache_ttl", 3600)),
            json_mode=bool(cfg.get("json_mode", True)),
            streaming=bool(cfg.get("streaming", False)),
            cost_tracking=bool(cfg.get("cost_tracking", True)),
        )


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0


# ---------------------------------------------------------------------------
# Token helpers
# ---------------------------------------------------------------------------
def _approx_tokens(text: str) -> int:
    """Fast approximate token count (~4 chars/token for English/code)."""
    if not text:
        return 0
    return len(text) // 4 + text.count(" ") // 2


def _truncate_to_tokens(text: str, max_tokens: int) -> str:
    if _approx_tokens(text) <= max_tokens:
        return text
    char_limit = max_tokens * 4
    return text[:char_limit] + "\n...[truncated]"


class AIAnalyzer:
    """Analyzes scan result dicts via an OpenAI-compatible API (or Anthropic /
    Azure payloads) with deterministic heuristic fallback when offline."""

    def __init__(self, config: Dict):
        self.cfg = AIConfig.from_dict(config.get('ai', {}) if isinstance(config, dict) else {})
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_loop: Optional[asyncio.AbstractEventLoop] = None
        self._usage_log: List[Usage] = []

    @property
    def available(self) -> bool:
        return bool(self.cfg.enable and self.cfg.api_key)

    async def _get_session(self) -> aiohttp.ClientSession:
        # aiohttp sessions bind to the loop they were created on. scan_sync()
        # runs asyncio.run() per call, so each call may have a NEW loop - a
        # reused session then raises "event loop is closed". Recreate whenever
        # the running loop differs from the one the session belongs to.
        loop = asyncio.get_running_loop()
        if (self._session is None or self._session.closed or self._session_loop is not loop):
            self._close_session()
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.cfg.timeout))
            self._session_loop = loop
        return self._session

    def _close_session(self):
        """Sync teardown: detach (aiohttp >=3.8) or close; never await here."""
        s, self._session = self._session, None
        self._session_loop = None
        if s is not None and not s.closed:
            detach = getattr(s, 'detach', None)
            if detach is not None:
                try:
                    detach()
                except Exception:
                    pass

    async def close(self):
        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None
            self._session_loop = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close_session()
        return False

    # ------------------------------------------------------------------
    # Public API (names kept stable - 5_AI.py calls scan_sync)
    # ------------------------------------------------------------------
    async def scan(self, results: Dict, mode: str = 'summary',
                   target: str = '', streaming: bool = False) -> Dict[str, Any]:
        mode = (mode or 'summary').lower()
        if not isinstance(results, dict):
            results = {}

        cache_key = self._cache_key(results, mode, target)
        cached = self._get_cache(cache_key)
        if cached is not None:
            return {**cached, 'cached': True}

        if not self.available:
            out = self._heuristic(results, mode)
            self._set_cache(cache_key, out)
            return out

        prompt, use_json = self._build_prompt(mode, results, target)
        try:
            if streaming or self.cfg.streaming:
                text_chunks = []
                async for chunk in self._chat_stream(prompt):
                    text_chunks.append(chunk)
                text = "".join(text_chunks)
                if text.startswith('⚠️'):
                    raise RuntimeError(text[:120])
                usage = None
            else:
                text, usage = await self._chat_with_retry(prompt, use_json)
                if usage is not None and self.cfg.cost_tracking:
                    self._usage_log.append(usage)
            out = {'mode': mode, 'source': 'ai', 'text': text,
                   'items': _parse_structured(text, mode), 'cached': False}
            self._set_cache(cache_key, out)
            return out
        except Exception as e:
            logger.warning(f'AI call failed ({type(e).__name__}: {e}); falling back to heuristics')
            out = self._heuristic(results, mode)
            self._set_cache(cache_key, out)
            return out

    def scan_sync(self, results: Dict, mode: str = 'summary',
                  target: str = '', streaming: bool = False) -> Dict[str, Any]:
        try:
            return _run_coro(self.scan(results, mode, target, streaming))
        finally:
            self._close_session()

    def get_usage(self) -> List[Dict]:
        return [asdict(u) for u in self._usage_log]

    def clear_cache(self):
        self._cache.clear()

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------
    def _cache_key(self, results: Dict, mode: str, target: str) -> str:
        blob = json.dumps({'r': results, 'm': mode, 't': target}, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:32]

    def _get_cache(self, key: str) -> Optional[Dict]:
        if key not in self._cache:
            return None
        value, ts = self._cache[key]
        if time.time() - ts > self.cfg.cache_ttl:
            del self._cache[key]
            return None
        return value

    def _set_cache(self, key: str, value: Dict):
        self._cache[key] = (value, time.time())

    # ------------------------------------------------------------------
    # Prompt builder -> returns (prompt, use_json)
    # ------------------------------------------------------------------
    def _build_prompt(self, mode: str, results: Dict, target: str) -> Tuple[str, bool]:
        tgt = target or 'the target'
        context = _compact(results, self.cfg.max_context)
        use_json = self.cfg.json_mode and mode in ('triage', 'prioritize')

        if mode == 'triage':
            return (f'Triage the scan results for {tgt}. Output ONLY a JSON '
                    f'list of items, each {{"severity": "high|medium|low|info", '
                    f'"finding": "...", "confidence": "high|medium|low"}}. Max '
                    f'15 items. Be strict: never invent findings not present '
                    f'in the data.\n\n{context}\n\nExample: '
                    f'[{{"severity": "high", "finding": "Hardcoded AWS key in '
                    f'app.js: AKIA...", "confidence": "high"}}]'), use_json
        if mode == 'prioritize':
            return (f'Prioritize the scan results for {tgt} by business impact '
                    f'and exploitability. Output ONLY a ranked JSON list, each '
                    f'{{"rank": 1, "item": "...", "rationale": "..."}}. Max 10 '
                    f'items.\n\n{context}\n\nExample: [{{"rank": 1, "item": '
                    f'"Hardcoded AWS admin key", "rationale": "cloud takeover"}}]'), use_json
        if mode == 'suggest_next':
            return (f'Suggest the most valuable NEXT steps to validate or '
                    f'exploit these results for {tgt}. Short bullet list, max '
                    f'10, high-impact low-effort wins first.\n\n{context}'), False
        if mode == 'verify':
            return (f'For each high-severity finding against {tgt}, suggest a '
                    f'specific curl / command / payload to verify it manually, '
                    f'with expected vs actual response indicators.\n\n{context}'), False
        if mode == 'exploit_chain':
            return (f'Chain these findings on {tgt} into an exploit path. '
                    f'Step by step, how finding A enables finding B. Include '
                    f'prerequisites and impact at each step.\n\n{context}'), False
        # summary
        return (f'Summarize the scan results for {tgt} in short bullet '
                f'points, highlighting actionable findings. Group by '
                f'severity.\n\n{context}'), False

    # ------------------------------------------------------------------
    # AI path with retries
    # ------------------------------------------------------------------
    async def _chat_with_retry(self, prompt: str, use_json: bool = False) -> Tuple[str, Optional[Usage]]:
        last_err = None
        for attempt in range(1, self.cfg.retries + 1):
            try:
                return await self._chat_once(prompt, use_json)
            except asyncio.TimeoutError:
                last_err = 'timeout'
                logger.warning(f'AI timeout (attempt {attempt}/{self.cfg.retries})')
            except aiohttp.ClientResponseError as e:
                last_err = f'HTTP {e.status}'
                if e.status == 429:
                    delay = self.cfg.retry_delay * (2 ** attempt)
                    logger.warning(f'Rate limited (429); backing off {delay}s')
                    await asyncio.sleep(delay)
                    continue
                if e.status in (401, 403):
                    raise
                if e.status >= 500:
                    logger.warning(f'Server error {e.status} (attempt {attempt})')
                else:
                    raise
            except aiohttp.ClientError as e:
                last_err = f'connection: {e}'
                logger.warning(f'Connection error (attempt {attempt}): {e}')
            except Exception as e:
                last_err = f'{type(e).__name__}: {e}'
                logger.warning(f'AI error (attempt {attempt}): {e}')
            delay = self.cfg.retry_delay * (2 ** (attempt - 1))
            await asyncio.sleep(delay)
        raise RuntimeError(f'AI failed after {self.cfg.retries} attempts: {last_err}')

    async def _chat_once(self, prompt: str, use_json: bool = False) -> Tuple[str, Optional[Usage]]:
        t0 = time.time()
        headers = {'Authorization': f'Bearer {self.cfg.api_key}',
                   'Content-Type': 'application/json'}

        if self.cfg.provider == Provider.ANTHROPIC:
            payload = self._anthropic_payload(prompt)
            endpoint = f"{self._anthropic_base()}/v1/messages"
        elif self.cfg.provider == Provider.AZURE:
            payload = self._openai_payload(prompt, use_json)
            headers = {'api-key': self.cfg.api_key, 'Content-Type': 'application/json'}
            endpoint = f"{self.cfg.api_base}/chat/completions?api-version=2024-02-01"
        else:
            payload = self._openai_payload(prompt, use_json)
            endpoint = f"{self.cfg.api_base}/chat/completions"

        session = await self._get_session()
        async with session.post(endpoint, json=payload, headers=headers) as r:
            r.raise_for_status()
            data = await r.json()

        latency = (time.time() - t0) * 1000

        if self.cfg.provider == Provider.ANTHROPIC:
            text = data.get('content', [{}])[0].get('text', '').strip()
            inp = data.get('usage', {}).get('input_tokens', 0)
            outp = data.get('usage', {}).get('output_tokens', 0)
            usage = Usage(prompt_tokens=inp, completion_tokens=outp,
                          total_tokens=inp + outp, latency_ms=latency)
        else:
            try:
                text = data['choices'][0]['message']['content'].strip()
            except (KeyError, IndexError, TypeError):
                raise RuntimeError(f'Unexpected AI response: {str(data)[:300]}')
            u = data.get('usage', {})
            usage = Usage(prompt_tokens=u.get('prompt_tokens', 0),
                          completion_tokens=u.get('completion_tokens', 0),
                          total_tokens=u.get('total_tokens', 0), latency_ms=latency)
        if self.cfg.cost_tracking:
            usage.cost_usd = self._estimate_cost(usage)
        return text, usage

    def _anthropic_base(self) -> str:
        """Anthropic expects {base}/v1/messages - tolerate a base that already
        ends in /v1 (the natural default most users paste)."""
        base = self.cfg.api_base
        if base.endswith('/v1'):
            return base[:-3].rstrip('/')
        return base

    def _openai_payload(self, prompt: str, use_json: bool) -> Dict:
        payload = {
            'model': self.cfg.model,
            'temperature': self.cfg.temperature,
            'top_p': self.cfg.top_p,
            'max_tokens': self.cfg.max_tokens,
            'messages': [{'role': 'system', 'content': _SYSTEM},
                         {'role': 'user', 'content': prompt}],
        }
        if use_json:
            payload['response_format'] = {'type': 'json_object'}
        return payload

    def _anthropic_payload(self, prompt: str) -> Dict:
        return {
            'model': self.cfg.model,
            'max_tokens': self.cfg.max_tokens,
            'temperature': self.cfg.temperature,
            'system': _SYSTEM,
            'messages': [{'role': 'user', 'content': prompt}],
        }

    def _estimate_cost(self, usage: Usage) -> float:
        """Rough USD estimate per 1M tokens by model prefix."""
        model = self.cfg.model.lower()
        rates = {
            'gpt-4o-mini': (0.15, 0.6),
            'gpt-4o': (5.0, 15.0),
            'gpt-4-turbo': (10.0, 30.0),
            'gpt-4': (30.0, 60.0),
            'claude-3-opus': (15.0, 75.0),
            'claude-3-sonnet': (3.0, 15.0),
            'claude-3-haiku': (0.25, 1.25),
            'deepseek-chat': (0.14, 0.28),
        }
        for prefix, (inp, out) in rates.items():
            if prefix in model:
                return (usage.prompt_tokens * inp + usage.completion_tokens * out) / 1_000_000
        return 0.0

    # ------------------------------------------------------------------
    # Streaming (single call, no retry - chat UX)
    # ------------------------------------------------------------------
    async def _chat_stream(self, prompt: str) -> AsyncIterator[str]:
        headers = {'Authorization': f'Bearer {self.cfg.api_key}',
                   'Content-Type': 'application/json'}
        if self.cfg.provider == Provider.ANTHROPIC:
            payload = self._anthropic_payload(prompt)
            payload['stream'] = True
            endpoint = f"{self._anthropic_base()}/v1/messages"
        else:
            payload = self._openai_payload(prompt, False)
            payload['stream'] = True
            endpoint = f"{self.cfg.api_base}/chat/completions"
        try:
            session = await self._get_session()
            async with session.post(endpoint, json=payload, headers=headers) as r:
                if r.status != 200:
                    body = (await r.text(errors='ignore'))[:400]
                    yield f'⚠️ API error {r.status}: {body}'
                    return
                async for raw in r.content:
                    line = raw.decode('utf-8', 'ignore').strip()
                    if not line or not line.startswith('data:'):
                        continue
                    data = line[5:].strip()
                    if data == '[DONE]':
                        return
                    try:
                        chunk = json.loads(data)
                    except Exception:
                        continue
                    if self.cfg.provider == Provider.ANTHROPIC:
                        text = (chunk.get('delta') or {}).get('text', '')
                    else:
                        choices = chunk.get('choices') or []
                        if not choices:
                            continue
                        text = (choices[0].get('delta') or {}).get('content', '')
                    if text:
                        yield text
        except asyncio.TimeoutError:
            yield f'⚠️ Chat timed out after {self.cfg.timeout}s'
        except aiohttp.ClientError as e:
            yield f'⚠️ Connection error: {e}'
        except Exception as e:
            yield f'⚠️ Chat error: {type(e).__name__}: {e}'

    # ------------------------------------------------------------------
    # Heuristic fallback (deterministic, offline)
    # ------------------------------------------------------------------
    def _heuristic(self, results: Dict, mode: str) -> Dict[str, Any]:
        items = list(_walk_findings(results))
        if mode == 'triage':
            triaged = [{'severity': _severity(i), 'finding': _finding_text(i),
                        'confidence': 'low'} for i in items]
            triaged = sorted(triaged, key=lambda x: _sev_score(x['severity']), reverse=True)[:15]
            return {'mode': mode, 'source': 'heuristic', 'text': _triage_text(triaged),
                    'items': triaged}
        if mode == 'prioritize':
            ranked = sorted(items, key=lambda i: _sev_score(_severity(i)), reverse=True)
            out = [{'rank': n + 1, 'item': _finding_text(i), 'rationale': _auto_rationale(i)}
                   for n, i in enumerate(ranked[:10])]
            return {'mode': mode, 'source': 'heuristic', 'text': _rank_text(out), 'items': out}
        if mode == 'suggest_next':
            return {'mode': mode, 'source': 'heuristic',
                    'text': _suggest_text(results, len(items)), 'items': []}
        if mode == 'verify':
            return {'mode': mode, 'source': 'heuristic',
                    'text': _verify_text(items), 'items': []}
        if mode == 'exploit_chain':
            return {'mode': mode, 'source': 'heuristic',
                    'text': _chain_text(items), 'items': []}
        return {'mode': 'summary', 'source': 'heuristic',
                'text': _summary_text(results), 'items': []}


# ======================================================================
# helpers (shared by both paths)
# ======================================================================

_FINDING_KEYS = frozenset((
    'findings', 'candidates', 'hits', 'secrets', 'leaks',
    'vulnerabilities', 'redirects', 'interesting', 'endpoints',
    'params', 'headers', 'cookies', 'tokens', 'keys',
))


def _walk_findings(results: Dict) -> List[Any]:
    items = []
    if not isinstance(results, dict):
        return items
    for section, value in results.items():
        if section in ('totals', 'scope_zone', 'meta', 'stats'):
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, str)):
                    items.append(item)
        elif isinstance(value, dict):
            for sub in _FINDING_KEYS:
                if isinstance(value.get(sub), list):
                    for item in value[sub]:
                        if isinstance(item, (dict, str)):
                            items.append(item)
    return items


def _finding_text(item: Any) -> str:
    if isinstance(item, str):
        return item[:220]
    for key in ('evidence', 'url', 'message', 'title', 'finding', 'name',
                'description', 'detail', 'payload', 'path'):
        if isinstance(item.get(key), str) and item[key]:
            return f'{item[key][:200]}'
    txt = json.dumps(item, default=str)[:220]
    return txt


def _auto_rationale(item: Any) -> str:
    if isinstance(item, dict):
        sev = str(item.get('severity', 'info')).lower()
        if sev in ('critical', 'high'):
            return 'High impact / likely exploitable'
        if sev == 'medium':
            return 'Moderate impact - verify manually'
        return 'Low impact / informational'
    return 'Unknown severity'


def _severity(item: Any) -> str:
    if isinstance(item, dict):
        s = str(item.get('severity', '')).lower()
        if s in ('critical', 'high', 'medium', 'low', 'info'):
            return s
        blob = ' '.join(str(v) for v in item.values()).lower()
    else:
        blob = str(item).lower()
    if any(h in blob for h in _HIGH):
        return 'high'
    if any(m in blob for m in _MED):
        return 'medium'
    if any(l in blob for l in _LOW):
        return 'low'
    if len(blob) > 200:
        return 'low'
    return 'info'


def _sev_score(sev: str) -> int:
    return {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(sev, 0)


def _compact(results: Dict, limit: int) -> str:
    try:
        text = json.dumps(results, default=str, indent=1)
    except Exception:
        text = str(results)
    return _truncate_to_tokens(text, limit // 4)


def _parse_structured(text: str, mode: str) -> List[Dict]:
    """Best-effort JSON extraction from an AI reply (triage/prioritize)."""
    if mode not in ('triage', 'prioritize'):
        return []
    for start_char in ('[', '{'):
        start = text.find(start_char)
        if start == -1:
            continue
        end = _find_json_end(text, start)
        if end == -1:
            continue
        try:
            parsed = json.loads(text[start:end + 1])
        except Exception:
            continue
        if isinstance(parsed, dict):
            for k in ('findings', 'items', 'results', 'triage'):
                if isinstance(parsed.get(k), list):
                    return parsed[k]
            return [parsed]
        if isinstance(parsed, list):
            return parsed
    return []


def _find_json_end(text: str, start: int) -> int:
    """Find the matching ] or } for a JSON fragment (string/escape aware)."""
    opener = text[start]
    closer = ']' if opener == '[' else '}'
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == '\\':
            escape = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch in ('[', '{'):
            depth += 1
        elif ch in (']', '}'):
            depth -= 1
            if depth == 0 and ch == closer:
                return i
    return -1


def _triage_text(items: List[Dict]) -> str:
    if not items:
        return 'No triageable findings.'
    lines = []
    for it in items[:15]:
        sev = str(it.get('severity', 'info')).upper()
        conf = str(it.get('confidence', 'low'))
        lines.append(f"- [{sev}] ({conf}) {it['finding']}")
    return '\n'.join(lines)


def _rank_text(items: List[Dict]) -> str:
    if not items:
        return 'No items to prioritize.'
    return '\n'.join(f"- {it['rank']}. {it['item']} — {it.get('rationale', '')}"
                     for it in items)


def _summary_text(results: Dict) -> str:
    lines = []
    for section, value in results.items():
        if section in ('totals', 'scope_zone', 'meta', 'stats'):
            continue
        n = 0
        if isinstance(value, list):
            n = len(value)
        elif isinstance(value, dict):
            for sub in _FINDING_KEYS:
                if isinstance(value.get(sub), list):
                    n += len(value[sub])
        lines.append(f"- {section}: {n} item(s)")
    if not lines:
        return 'No findings to summarize.'
    return '\n'.join(lines)


def _suggest_text(results: Dict, n: int) -> str:
    if n == 0:
        return ('- No findings yet - expand the input set and rerun.\n'
                '- Try subdomain enumeration + wayback URLs.\n'
                '- Recon with dorking and JS endpoint extraction.')
    return ('- Manually verify the highest-severity findings before reporting.\n'
            '- Expand the URL pool (wayback + dorking) and rerun the scanners.\n'
            '- Chain findings: use discovered endpoints with param-mining.\n'
            '- Re-check 403 bypasses against any host that returned 403.\n'
            '- Re-run after any scope/asset change.\n'
            '- Look for auth bypasses on admin panels or debug endpoints.\n'
            '- Test SSRF against internal services discovered in JS.\n'
            '- Check for IDOR on numeric IDs found in API responses.')


def _verify_text(items: List[Any]) -> str:
    if not items:
        return 'No findings to verify.'
    lines = ['- For each finding, run the verification curl / command listed.']
    for item in items[:10]:
        if isinstance(item, dict) and item.get('verification'):
            lines.append(f"  • {item['verification']}")
    lines.append('- Compare HTTP status + response body against expected indicators.')
    return '\n'.join(lines)


def _chain_text(items: List[Any]) -> str:
    if len(items) < 2:
        return 'Need at least 2 findings to build an exploit chain.'
    high = [i for i in items if _severity(i) in ('critical', 'high')]
    if len(high) >= 2:
        return (f"- Step 1: Use {_finding_text(high[0])} to gain initial access.\n"
                f"- Step 2: Pivot via {_finding_text(high[1])} to escalate.\n"
                "- Step 3: Exfiltrate data or achieve persistence.")
    return ('- Chain info-leak → auth bypass → privileged action.\n'
            '- Example: exposed .env → JWT secret → forge admin token.')


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


# ======================================================================
# Streaming chat (multi-turn conversation, OpenAI-compatible SSE)
# Keeps the conversation context open across turns: pass the full message
# history each time; the user can paste large code/scan results into the
# conversation (or a pinned context block) and ask follow-ups.
# ======================================================================

_CHAT_SYSTEM = (
    "You are an experienced offensive-security engineer assisting with "
    "scan results, JavaScript code review and bug-hunting. Be concise, "
    "technical and actionable. Prefer short bullet lists over prose."
)


def chat_messages(config: Dict, history: List[Dict], pinned_context: str = '',
                  max_history: int = 20, max_chars: int = 6000) -> List[Dict]:
    """Build the messages payload for a chat turn: system prompt (with the
    pinned code/results context) + the trimmed recent conversation."""
    sys_msg = _CHAT_SYSTEM
    if pinned_context and pinned_context.strip():
        sys_msg += ('\n\nPinned context supplied by the user (scan results, '
                    'JS code, ...) - reference it when answering:\n\n'
                    + pinned_context.strip()[:max_chars])
    messages = [{'role': 'system', 'content': sys_msg}]
    for m in history[-max_history:]:
        role = m.get('role')
        content = str(m.get('content', ''))
        if role not in ('user', 'assistant') or not content:
            continue
        messages.append({'role': role, 'content': content[:max_chars]})
    return messages


async def stream_chat_completion(messages: List[Dict], api_base: str, api_key: str,
                                 model: str, temperature: float = 0.3,
                                 timeout: int = 120, provider: str = 'openai') -> AsyncIterator[str]:
    """Stream an OpenAI-compatible or Anthropic chat completion (SSE).

    Yields content deltas as they arrive (like the openai SDK with
    `stream=True`); the final message is the concatenation of all deltas.
    """
    headers = {'Authorization': f'Bearer {api_key}',
               'Content-Type': 'application/json'}
    provider = provider.lower()

    if provider == 'anthropic':
        base = api_base.rstrip('/')
        if base.endswith('/v1'):
            base = base[:-3].rstrip('/')
        payload = {
            'model': model, 'max_tokens': 1200, 'temperature': temperature,
            'system': _CHAT_SYSTEM, 'messages': messages, 'stream': True,
        }
        endpoint = f'{base}/v1/messages'
    else:
        payload = {'model': model, 'messages': messages, 'stream': True,
                   'stream_options': {'include_usage': True},
                   'temperature': temperature}
        endpoint = f'{api_base.rstrip("/")}/chat/completions'
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.post(endpoint, json=payload, headers=headers) as r:
                if r.status != 200:
                    body = (await r.text(errors='ignore'))[:400]
                    yield f'⚠️ API error {r.status}: {body}'
                    return
                async for raw in r.content:
                    line = raw.decode('utf-8', 'ignore').strip()
                    if not line or not line.startswith('data:'):
                        continue
                    data = line[5:].strip()
                    if data == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data)
                    except Exception:
                        continue
                    if provider == 'anthropic':
                        text = (chunk.get('delta') or {}).get('text', '')
                    else:
                        choices = chunk.get('choices') or []
                        if not choices:
                            continue
                        text = (choices[0].get('delta') or {}).get('content', '')
                    if text:
                        yield text
    except asyncio.TimeoutError:
        yield f'⚠️ Chat timed out after {timeout}s - check the endpoint and try again.'
    except aiohttp.ClientError as e:
        yield f'⚠️ Connection error talking to {api_base}: {e}'
    except Exception as e:
        yield f'⚠️ Chat error: {type(e).__name__}: {e}'


__all__ = ['AIAnalyzer', 'AIConfig', 'Provider', 'Usage', 'chat_messages',
           'stream_chat_completion', '_run_coro']
