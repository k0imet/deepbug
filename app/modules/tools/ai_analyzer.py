# modules/tools/ai_analyzer.py
# AI-assisted result analysis (OpenAI-compatible chat completions, no SDK
# dependency - plain aiohttp POST). Modes: summary / triage / prioritize /
# suggest_next. Config: ai.{enable, api_base, api_key, model, timeout}.
# Falls back to deterministic local heuristics when no key is configured, so
# the feature is always usable and testable offline.

import os
import json
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, AsyncIterator

from app.utils.logger import get_logger

logger = get_logger()

_DEFAULT_BASE = "https://api.openai.com/v1"
_DEFAULT_MODEL = "gpt-4o-mini"

_SYSTEM = (
    "You are a senior offensive-security analyst assistant. Be concise, "
    "technical and actionable. Prefer short bullet lists over prose."
)

_HIGH = ('password', 'secret', 'token', 'api_key', 'accesskey', 'private',
         'credential', 'aws', 'github token', 'bearer', 'authorization')
_MED = ('vuln', 'ssrf', 'open redirect', 'takeover', 'misconfig', 'exposed',
        'leak', 'interesting', 'bypass', '401', '403')


class AIAnalyzer:
    """Analyzes scan result dicts, either via an OpenAI-compatible API or
    with built-in heuristics when the AI is not configured."""

    def __init__(self, config: Dict):
        cfg = config.get('ai', {}) if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get('enable', False))
        self.api_base = str(cfg.get('api_base', _DEFAULT_BASE)).rstrip('/')
        self.api_key = str(cfg.get('api_key', '') or
                           os.environ.get('OPENAI_API_KEY', ''))
        self.model = str(cfg.get('model', _DEFAULT_MODEL))
        self.timeout = int(cfg.get('timeout', 60))
        self.max_context = int(cfg.get('max_context', 6000))

    @property
    def available(self) -> bool:
        return bool(self.enabled and self.api_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, results: Dict, mode: str = 'summary',
                   target: str = '') -> Dict[str, Any]:
        mode = mode or 'summary'
        if not isinstance(results, dict):
            results = {}
        if self.available:
            try:
                text = await self._chat(self._build_prompt(mode, results, target))
                return {'mode': mode, 'source': 'ai', 'text': text,
                        'items': _parse_items(text, mode)}
            except Exception as e:
                logger.warning(f'AI call failed ({e}); falling back to heuristics')
        return self._heuristic(results, mode)

    def scan_sync(self, results: Dict, mode: str = 'summary',
                  target: str = '') -> Dict[str, Any]:
        return _run_coro(self.scan(results, mode, target))

    # ------------------------------------------------------------------
    # Internals: AI path
    # ------------------------------------------------------------------
    async def _chat(self, user_prompt: str) -> str:
        headers = {'Authorization': f'Bearer {self.api_key}',
                   'Content-Type': 'application/json'}
        payload = {
            'model': self.model,
            'temperature': 0.2,
            'max_tokens': 1200,
            'messages': [{'role': 'system', 'content': _SYSTEM},
                         {'role': 'user', 'content': user_prompt}],
        }
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as s:
            async with s.post(f'{self.api_base}/chat/completions',
                              json=payload, headers=headers) as r:
                r.raise_for_status()
                data = await r.json()
                return data['choices'][0]['message']['content'].strip()

    def _build_prompt(self, mode: str, results: Dict, target: str) -> str:
        context = _compact(results, self.max_context)
        tgt = target or 'the target'
        if mode == 'triage':
            return (f'Triage the scan results for {tgt}. Output a JSON list '
                    f'of items, each {{"severity": "high|medium|low|info", '
                    f'"finding": "..."}}. Max 15 items.\n\n{context}')
        if mode == 'prioritize':
            return (f'Prioritize the scan results for {tgt} by business '
                    f'impact and exploitability. Output a ranked JSON list, '
                    f'each {{"rank": 1, "item": "..."}}. Max 10 items.\n\n{context}')
        if mode == 'suggest_next':
            return (f'Suggest the most valuable NEXT steps to validate or '
                    f'exploit these results for {tgt}. Short bullet list, max '
                    f'10.\n\n{context}')
        return (f'Summarize the scan results for {tgt} in short bullet '
                f'points, highlighting actionable findings.\n\n{context}')

    # ------------------------------------------------------------------
    # Internals: heuristic fallback
    # ------------------------------------------------------------------
    def _heuristic(self, results: Dict, mode: str) -> Dict[str, Any]:
        items = list(_walk_findings(results))
        if mode == 'triage':
            triaged = [{'severity': _severity(i), 'finding': _finding_text(i)}
                       for i in items]
            return {'mode': mode, 'source': 'heuristic', 'text': _triage_text(triaged),
                    'items': triaged}
        if mode == 'prioritize':
            ranked = sorted(items, key=lambda i: _sev_score(i), reverse=True)
            out = [{'rank': n + 1, 'item': _finding_text(i)}
                   for n, i in enumerate(ranked[:10])]
            return {'mode': mode, 'source': 'heuristic',
                    'text': _rank_text(out), 'items': out}
        if mode == 'suggest_next':
            text = (_suggest_text(results, len(items)))
            return {'mode': mode, 'source': 'heuristic', 'text': text, 'items': []}
        # summary
        return {'mode': 'summary', 'source': 'heuristic',
                'text': _summary_text(results), 'items': []}

    def _empty_result(self) -> Dict[str, Any]:
        return {'mode': 'summary', 'source': 'heuristic', 'text': '', 'items': []}


# ======================================================================
# helpers (shared by both paths)
# ======================================================================

_FINDING_KEYS = ('findings', 'candidates', 'hits', 'secrets', 'leaks',
                 'vulnerabilities', 'redirects', 'interesting')


def _walk_findings(results: Dict) -> List[Any]:
    items = []
    if not isinstance(results, dict):
        return items
    for section, value in results.items():
        if section in ('totals', 'scope_zone'):
            continue
        if isinstance(value, list):
            for item in value:
                if isinstance(item, (dict, str)):
                    items.append(item)
        elif isinstance(value, dict):
            for sub in ('findings', 'items', 'hits', 'results'):
                if isinstance(value.get(sub), list):
                    for item in value[sub]:
                        if isinstance(item, (dict, str)):
                            items.append(item)
    return items


def _finding_text(item: Any) -> str:
    if isinstance(item, str):
        return item[:200]
    for key in ('evidence', 'url', 'message', 'title', 'finding', 'name'):
        if isinstance(item.get(key), str) and item[key]:
            return f'{item[key][:180]}'
    txt = json.dumps(item, default=str)[:200]
    return txt


def _severity(item: Any) -> str:
    if isinstance(item, dict):
        s = str(item.get('severity', '')).lower()
        if s in ('high', 'medium', 'low', 'info'):
            return s
        blob = ' '.join(str(v) for v in item.values()).lower()
    else:
        blob = str(item).lower()
    if any(h in blob for h in _HIGH):
        return 'high'
    if any(m in blob for m in _MED):
        return 'medium'
    if len(blob) > 200:
        return 'low'
    return 'info'


def _sev_score(item: Any) -> int:
    return {'high': 4, 'medium': 3, 'low': 2, 'info': 1}[_severity(item)]


def _compact(results: Dict, limit: int) -> str:
    try:
        text = json.dumps(results, default=str, indent=1)
    except Exception:
        text = str(results)
    return text[:limit]


def _parse_items(text: str, mode: str) -> List[Dict]:
    """Best-effort JSON extraction from an AI reply (triage/prioritize)."""
    if mode not in ('triage', 'prioritize'):
        return []
    try:
        start = text.find('[')
        end = text.rfind(']')
        if start == -1 or end == -1:
            return []
        return json.loads(text[start:end + 1])
    except Exception:
        return []


def _triage_text(items: List[Dict]) -> str:
    if not items:
        return 'No triageable findings.'
    lines = []
    for it in items[:15]:
        lines.append(f"- [{it['severity'].upper()}] {it['finding']}")
    return '\n'.join(lines)


def _rank_text(items: List[Dict]) -> str:
    if not items:
        return 'No items to prioritize.'
    return '\n'.join(f"- {it['rank']}. {it['item']}" for it in items)


def _summary_text(results: Dict) -> str:
    lines = []
    for section, value in results.items():
        if section in ('totals', 'scope_zone'):
            continue
        n = len(value) if isinstance(value, list) else \
            (len(value.get('findings', [])) if isinstance(value, dict) else 0)
        lines.append(f"- {section}: {n} item(s)")
    if not lines:
        return 'No findings to summarize.'
    return '\n'.join(lines)


def _suggest_text(results: Dict, n: int) -> str:
    if n == 0:
        return 'No findings yet - expand the input set and rerun.'
    return ('- Manually verify the highest-severity findings before reporting.\n'
            '- Expand the URL pool (wayback + dorking) and rerun the scanners.\n'
            '- Chain findings: use discovered endpoints with param-mining.\n'
            '- Re-check 403 bypasses against any host that returned 403.\n'
            '- Re-run after any scope/asset change.')


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
                                 timeout: int = 120) -> AsyncIterator[str]:
    """Stream an OpenAI-compatible chat completion (SSE).

    Yields content deltas as they arrive (like the openai SDK with
    `stream=True`); the final message is the concatenation of all deltas.
    """
    headers = {'Authorization': f'Bearer {api_key}',
               'Content-Type': 'application/json'}
    payload = {
        'model': model,
        'messages': messages,
        'stream': True,
        'stream_options': {'include_usage': True},
        'temperature': temperature,
    }
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as s:
            async with s.post(f'{api_base}/chat/completions', json=payload,
                              headers=headers) as r:
                if r.status != 200:
                    body = (await r.text(errors='ignore'))[:400]
                    yield f'⚠️ API error {r.status}: {body}'
                    return
                async for raw in r.content:
                    line = raw.decode('utf-8', 'ignore').strip()
                    if not line.startswith('data:'):
                        continue
                    data = line[5:].strip()
                    if data == '[DONE]':
                        break
                    try:
                        chunk = json.loads(data)
                    except Exception:
                        continue
                    choices = chunk.get('choices') or []
                    if not choices:
                        continue
                    delta = choices[0].get('delta') or {}
                    content = delta.get('content')
                    if content:
                        yield content
    except asyncio.TimeoutError:
        yield f'⚠️ Chat timed out after {timeout}s - check the endpoint and try again.'
    except aiohttp.ClientError as e:
        yield f'⚠️ Connection error talking to {api_base}: {e}'
    except Exception as e:
        yield f'⚠️ Chat error: {type(e).__name__}: {e}'