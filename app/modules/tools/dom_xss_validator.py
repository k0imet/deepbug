# modules/tools/dom_xss_validator.py
# Active DOM XSS VALIDATION - the "kxss for client-side sinks".
# The JS analyzer finds static sink candidates; this module proves them in a
# headless browser: every candidate URL is loaded with a unique canary injected
# into each query parameter (plus the fragment), then the live DOM is scanned
# and the canary is classified by sink context:
#
#   CONFIRMED  - canary passed through an instrumented executable sink
#                (document.write/eval/Function/setTimeout-str/innerHTML/
#                outerHTML/srcdoc/insertAdjacentHTML), a javascript:/data: URI,
#                an on* event-handler attribute, an iframe srcdoc, or a
#                browser dialog whose message contains the canary.
#   PROBABLE   - canary sits unquoted in script code (first-party), console/
#                pageerror mention, or a code position in a third-party bundle.
#   POTENTIAL  - canary inside a quoted string in script (first-party) or in a
#                DOM attribute / text node (reflection candidate).
#   INFO       - canary in a quoted string inside a known third-party analytics
#                bundle (VWO/GTM/Hotjar/...) or in a comment - classic FP.
#
# The core lesson baked in: "the canary is somewhere inside a <script> element"
# is NOT proof of execution - analytics/tracking scripts routinely read
# location.hash/location.search into strings. Only hooks on actually-executing
# sinks (plus uri/event/srcdoc contexts) get CONFIRMED.
#
# Config (all optional):
#   dom_xss.max_urls        -> cap URLs validated per run (default 40)
#   dom_xss.browser         -> enable browser confirmation (default True)
#   dom_xss.page_timeout_ms -> per-page load budget (default 8000)
#   dom_xss.max_variants    -> parameter+fragment variants per URL (default 6)
#   tools.paths.chromium    -> browser binary (default: auto-detect)

import asyncio
import concurrent.futures
import random
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Callable
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

from app.utils.logger import get_logger

logger = get_logger()

# Known third-party analytics/marketing bundles whose string-context canary hits
# are classic false positives (they read the URL/hash into tracking strings).
_THIRD_PARTY_SRC_RE = re.compile(
    r'(visualwebsiteoptimizer|vwo\.|google-analytics|googletagmanager|gtm\.|'
    r'hotjar|clarity|msclarity|segment\.|amplitude|mixpanel|fullstory|heap\.|'
    r'intercom|zendesk|crisp\.|optimizely|launchdarkly|omniture|tealium|'
    r'qualtrics|surveymonkey|typeform|klaviyo|mailchimp|braze|clevertap|branch\.|'
    r'adjust\.|kochava|connect\.facebook|facebook\.net|twitter\.com|'
    r'googleadservices|doubleclick|tiktok|linkedin\.com|snap\.gg|cdnjs|unpkg|'
    r'jsdelivr|cloudflare|googleapis)', re.I)

# Instrumentation: hook the sinks that actually EXECUTE attacker-controlled
# strings, before any page code runs (add_init_script). Each hook records the
# canary transit into window.__dbxSinkHits for the classifier to read.
_SINK_HOOKS_JS = r"""
(() => {
  if (window.__dbxHooked) return;
  window.__dbxHooked = true;
  const CANARY = '__CANARY__';
  const hits = [];
  window.__dbxSinkHits = hits;
  const hit = (kind, snippet) => {
    const s = String(snippet);
    if (!s.includes(CANARY)) return;
    hits.push(kind + ':' + s.slice(0, 160));
  };

  try {
    const dw = Document.prototype.write;
    Document.prototype.write = function (...args) {
      for (const a of args) hit('document.write', a);
      return dw.apply(this, args);
    };
    Document.prototype.writeln = function (...args) {
      for (const a of args) hit('document.writeln', a);
      return dw.apply(this, args);
    };
  } catch (e) {}

  try {
    const origEval = window.eval;
    window.eval = function (code) { hit('eval', code); return origEval(code); };
  } catch (e) {}

  try {
    const OrigFn = window.Function;
    window.Function = new Proxy(OrigFn, {
      apply(t, th, args) { hit('Function()', args[0]); return Reflect.apply(t, th, args); },
      construct(t, args) { hit('new Function()', args[0]); return Reflect.construct(t, args); }
    });
  } catch (e) {}

  try {
    ['setTimeout', 'setInterval'].forEach(m => {
      const orig = window[m];
      window[m] = function (fn, ms) {
        if (typeof fn === 'string') hit(m, fn);
        return orig.apply(this, arguments);
      };
    });
  } catch (e) {}

  const hijack = (proto, prop) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      Object.defineProperty(proto, prop, {
        configurable: true,
        get() { return desc && desc.get ? desc.get.call(this) : undefined; },
        set(v) {
          hit(prop, v);
          if (desc && desc.set) desc.set.call(this, v);
        }
      });
    } catch (e) {}
  };
  hijack(Element.prototype, 'innerHTML');
  hijack(Element.prototype, 'outerHTML');
  hijack(HTMLIFrameElement.prototype, 'srcdoc');
  hijack(HTMLScriptElement.prototype, 'text');

  try {
    const iAH = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, text) {
      hit('insertAdjacentHTML', text);
      return iAH.call(this, pos, text);
    };
  } catch (e) {}
})();
"""

# Returns { exec: [contexts], dom: [attrib/els], htmlHas: bool } - evaluated in
# the live (post-JS) DOM so innerHTML/document.write sinks surface as real nodes.
# Script matches now carry the canary LINE + a context tag:
#   script[src|inline]/code|str|cmt   (code = unquoted position, str = inside a
#   quoted string, cmt = inside a // or /* */ comment)
_SINK_JS = r"""
(canary) => {
  const out = { exec: [], dom: [], htmlHas: false };
  const c = String(canary);
  const isScriptUri = (v) => v && /^\s*(javascript|vbscript|data)\s*:/i.test(String(v));
  const has = (v) => v && String(v).includes(c);

  document.querySelectorAll('script').forEach(s => {
    const t = s.textContent || '';
    const i = t.indexOf(c);
    if (i < 0) return;
    const src = (s.getAttribute('src') || '').slice(0, 90) || 'inline';
    const ctx = t.slice(Math.max(0, i - 90), Math.min(t.length, i + 130));

    const countUnescaped = (str, q) => {
      let n = 0;
      for (let k = 0; k < str.length; k++) {
        if (str[k] === q && (k === 0 || str[k - 1] !== '\\')) n++;
      }
      return n;
    };
    const inStringAt = (str, pos) => {
      const p = str.slice(0, pos);
      for (const q of ['"', "'", '`']) {
        if (countUnescaped(p, q) % 2 === 1) return true;
      }
      return false;
    };

    let inComment = false;
    const inQuote = inStringAt(t, i);
    const lineStart = t.lastIndexOf('\n', i) + 1;
    if (!inQuote) {
      const lp = t.slice(lineStart, i);
      const idx = lp.indexOf('//');
      if (idx >= 0 && !inStringAt(lp, idx)) inComment = true;
    }
    if (!inComment && !inQuote) {
      const block = t.slice(0, i);
      const lastOpen = block.lastIndexOf('/*');
      if (lastOpen >= 0 && block.indexOf('*/', lastOpen) === -1 &&
          !inStringAt(block, lastOpen)) inComment = true;
    }
    out.exec.push('script[' + src + ']' + (inComment ? '/cmt' : (inQuote ? '/str' : '/code')) + '::' + ctx);
  });

  document.querySelectorAll('iframe').forEach(f => {
    const src = f.getAttribute('src') || '';
    const sd = f.getAttribute('srcdoc') || '';
    if (sd.includes(c)) out.exec.push('iframe-srcdoc::' + sd.slice(0, 120));
    else if (src.includes(c)) out.exec.push((isScriptUri(src) ? 'iframe-uri' : 'iframe-src') + '::' + src.slice(0, 120));
  });

  const el = (document.body || document.documentElement);
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) if (node.nodeValue && node.nodeValue.includes(c)) out.dom.push('text');

  const ALL = el.getElementsByTagName ? el.getElementsByTagName('*') : [];
  for (let i = 0; i < ALL.length; i++) {
    const e = ALL[i];
    for (let j = 0; e.attributes && j < e.attributes.length; j++) {
      const a = e.attributes[j];
      if (!has(a.value)) continue;
      const n = a.name.toLowerCase();
      if (n.startsWith('on')) out.exec.push('event:' + n + '::' + String(a.value).slice(0, 120));
      else if (['href','src','action','formaction','poster','data','background','xlink:href','xmlns'].includes(n)) {
        if (isScriptUri(a.value)) out.exec.push('uri:' + n + '::' + String(a.value).slice(0, 120));
        else out.dom.push(n);
      } else out.dom.push(n);
    }
  }

  const html = document.documentElement.outerHTML || '';
  if (html.includes(c)) out.htmlHas = true;
  return out;
}
"""


class DOMXSSValidator:
    """Headless-Chromium validation of DOM (and reflected-to-DOM) XSS canaries."""

    def __init__(self, config: Dict):
        self.config = config
        cfg = config.get('dom_xss', {})
        self.max_urls = int(cfg.get('max_urls', 40))
        self.enable_browser = bool(cfg.get('browser', True))
        self.page_timeout = int(cfg.get('page_timeout_ms', 8000))
        self.max_variants = int(cfg.get('max_variants', 6))

        self.value = f"dbx{random.randint(100000, 999999)}"

        self.chromium_path = self._resolve_chromium(
            config.get('tools', {}).get('paths', {}).get('chromium'))
        self.has_playwright = False
        if self.enable_browser:
            try:
                import playwright.sync_api  # noqa: F401
                self.has_playwright = self.chromium_path is not None
            except ImportError:
                logger.warning("DOMXSSValidator: playwright not installed - browser validation disabled "
                               "(pip install playwright).")
        self.last_errors: List[str] = []

    @staticmethod
    def _resolve_chromium(configured: Optional[str]) -> Optional[Path]:
        candidates = []
        if configured:
            candidates.append(Path(configured).expanduser())
        for name in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'chrome'):
            hit = shutil.which(name)
            if hit:
                candidates.append(Path(hit))
        candidates += [Path('/usr/bin/chromium'), Path('/usr/bin/chromium-browser'),
                       Path('/usr/bin/google-chrome'), Path('/snap/bin/chromium')]
        for c in candidates:
            try:
                if c.is_file():
                    return c
            except OSError:
                continue
        return None

    # -----------------------------------------------------------------
    # Variant builder
    # -----------------------------------------------------------------
    def build_variants(self, url: str, max_variants: Optional[int] = None) -> List[tuple]:
        """Returns [(vector_label, full_url_with_canary)] - one per param plus the fragment."""
        cap = max_variants or self.max_variants
        parsed = urlparse(url)
        if not (parsed.scheme and parsed.netloc):
            return []

        variants: List[tuple] = []
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for k in dict.fromkeys(k for k, _ in pairs):
            if len(variants) >= max(0, cap - 1):
                break
            replaced = [(kk, self.value if kk == k else vv) for kk, vv in pairs]
            variants.append((f"param:{k}", urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                 urlencode(replaced, doseq=True), parsed.fragment))))

        variants.append(("fragment", urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params,
             parsed.query, self.value))))
        return variants

    # ------------------------------------------------------------------
    # Sink classification
    # ------------------------------------------------------------------
    @staticmethod
    def _classify(exec_hits: List[str], hook_hits: List[str],
                  dom_hits: List[str], html_has: bool) -> Dict:
        """Map raw hits to (Result, Class, evidence). Order matters - first match wins."""
        evidence: List[str] = []

        # 1. Instrumented executable sink - the canary actually flowed through
        #    a sink that executes strings. Strongest signal.
        if hook_hits:
            into_html = [h for h in hook_hits]
            write_hooks = [h for h in hook_hits
                           if h.startswith(('document.write', 'document.writeln'))]
            script_ctx = [h for h in exec_hits if h.startswith('script[')]
            if write_hooks and script_ctx and not [
                    h for h in hook_hits
                    if not h.startswith(('document.write', 'document.writeln'))]:
                # The canary only echoed into a written <script>'s SOURCE TEXT
                # (classic VWO/analytics FP): classify by script context below
                # instead of claiming direct execution. A genuinely dangerous
                # write that also ran eval/innerHTML/... still reports above.
                hook_hits = []
                evidence.append(write_hooks[0][:160])
            else:
                evidence = hook_hits[:5]
                return {'Result': 'CONFIRMED', 'Class': 'exec-hook',
                        'Sink': hook_hits[0][:80], 'Evidence': '; '.join(evidence)}

        for h in exec_hits:
            if h.startswith('dialog:'):
                return {'Result': 'CONFIRMED', 'Class': 'dialog',
                        'Sink': h[:80], 'Evidence': h[:180]}
            if h.startswith('event:'):
                return {'Result': 'CONFIRMED', 'Class': 'event-attr',
                        'Sink': h[:80], 'Evidence': h[:180]}
            if h.startswith('uri:'):
                return {'Result': 'CONFIRMED', 'Class': 'uri-js',
                        'Sink': h[:80], 'Evidence': h[:180]}
            if h.startswith('iframe-srcdoc') or h.startswith('iframe-uri'):
                return {'Result': 'CONFIRMED', 'Class': 'iframe',
                        'Sink': h[:80], 'Evidence': h[:180]}

        # 2. Script matches: context tag decides
        for h in exec_hits:
            if h.startswith('script['):
                third_party = bool(_THIRD_PARTY_SRC_RE.search(h))
                if '/cmt' in h:
                    evidence.append(h)
                    continue
                if '/str' in h:
                    if third_party:
                        evidence.append(h)
                        continue  # classic FP: analytics string
                    return {'Result': 'POTENTIAL', 'Class': 'script-string',
                            'Sink': h[:80], 'Evidence': h[:220]}
                # /code - unquoted script position
                if third_party:
                    return {'Result': 'PROBABLE', 'Class': '3p-script-code',
                            'Sink': h[:80], 'Evidence': h[:220]}
                return {'Result': 'CONFIRMED', 'Class': 'script-code',
                        'Sink': h[:80], 'Evidence': h[:220]}

        for h in exec_hits:
            if h.startswith(('console:', 'pageerror:')):
                return {'Result': 'PROBABLE', 'Class': 'console',
                        'Sink': h[:80], 'Evidence': h[:180]}

        # 3. DOM presence only
        if dom_hits:
            return {'Result': 'POTENTIAL', 'Class': 'dom-attr',
                    'Sink': dom_hits[0][:80],
                    'Evidence': ('DOM hits: ' + '; '.join(dict.fromkeys(dom_hits))[:180])}
        if html_has:
            return {'Result': 'INFO', 'Class': 'html-presence',
                    'Sink': 'dom-html', 'Evidence': 'canary present in page HTML only'}
        if evidence:
            return {'Result': 'INFO', 'Class': 'ignored-context',
                    'Sink': evidence[0][:80],
                    'Evidence': '; '.join(evidence[:4])}
        return {}

    # ------------------------------------------------------------------
    # Headless browser probe (shared harness)
    # ------------------------------------------------------------------
    def _probe_harness(self, full_url: str, deliveries: Optional[List[str]] = None,
                       set_name: bool = False, wait_ms: int = 900) -> Optional[tuple]:
        """Load full_url headless; run optional post-delivery JS (postMessage),
        optionally seed window.name first, then collect canary transit.
        Returns (exec_hits, dom_hits, hook_hits, html_has) or None."""
        from playwright.sync_api import sync_playwright

        canary = self.value
        deliveries = deliveries or []
        exec_hits: List[str] = []
        dom_hits: List[str] = []
        hook_hits: List[str] = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    executable_path=str(self.chromium_path),
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'])
                try:
                    page = browser.new_page()

                    def _on_dialog(dialog):
                        try:
                            if self.value in dialog.message:
                                exec_hits.append(f"dialog:{dialog.message[:120]}")
                            dialog.dismiss()
                        except Exception:
                            pass

                    def _on_console(msg):
                        try:
                            if self.value in msg.text:
                                exec_hits.append(f"console:{msg.type}:{msg.text[:120]}")
                        except Exception:
                            pass

                    def _on_pageerror(err):
                        try:
                            if self.value in str(err):
                                exec_hits.append(f"pageerror:{str(err)[:120]}")
                        except Exception:
                            pass

                    page.on("dialog", _on_dialog)
                    page.on("console", _on_console)
                    page.on("pageerror", _on_pageerror)

                    page.add_init_script(
                        script=_SINK_HOOKS_JS.replace('__CANARY__', canary))

                    if set_name:
                        try:
                            page.goto('about:blank', timeout=self.page_timeout,
                                      wait_until='domcontentloaded')
                            page.evaluate(f"window.name = {canary!r}")
                        except Exception as e:
                            logger.debug(f"DOM XSS window.name seed failed: {e}")

                    try:
                        page.goto(full_url, timeout=self.page_timeout, wait_until='domcontentloaded')
                    except Exception as e:
                        logger.debug(f"DOM XSS goto {full_url}: {e}")
                        return None

                    for snippet in deliveries:
                        try:
                            page.evaluate(snippet)
                        except Exception:
                            pass
                        page.wait_for_timeout(250)
                    page.wait_for_timeout(wait_ms)

                    for frame in page.frames:
                        try:
                            frame_hits = frame.evaluate('window.__dbxSinkHits || []')
                            if frame_hits:
                                hook_hits.extend([str(h) for h in frame_hits])
                        except Exception:
                            pass  # cross-origin frame - skip
                    # Our own postMessage deliveries may surface as 'eval:<delivery>'
                    # hits (the harness evaluates them inside the page realm) - drop
                    # exact self-deliveries so they can't masquerade as page sinks.
                    if deliveries:
                        self_delivery = tuple(d for d in deliveries)
                        hook_hits = [h for h in hook_hits
                                     if not any(h.endswith(d) for d in self_delivery)]

                    result = page.evaluate(_SINK_JS, self.value) or {}
                    exec_hits = list(dict.fromkeys(exec_hits + [str(x) for x in result.get('exec', [])]))
                    dom_hits = [str(x) for x in result.get('dom', [])]
                    html_has = bool(result.get('htmlHas'))
                finally:
                    browser.close()
        except Exception as e:
            logger.debug(f"DOM XSS browser probe failed for {full_url}: {e}")
            self.last_errors.append(f"{full_url}: {str(e)[:150]}")
            return None

        if not (exec_hits or dom_hits or html_has or hook_hits):
            return None  # canary never made it into the page
        return exec_hits, dom_hits, hook_hits, html_has

    def _browser_probe(self, url: str, vector: str, full_url: str) -> Optional[Dict]:
        """Query/fragment variant probe (no post-load delivery)."""
        out = self._probe_harness(full_url)
        if not out:
            return None
        exec_hits, dom_hits, hook_hits, html_has = out

        classified = self._classify(exec_hits, hook_hits, dom_hits, html_has)
        if not classified:
            return None
        return {
            'URL': url,
            'Parameter': vector,
            'Payload': full_url,
            'Result': classified['Result'],
            'Class': classified['Class'],
            'Sink': classified['Sink'],
            'Evidence': classified['Evidence'],
            'Method': 'headless-browser',
        }

    def _postmessage_probe(self, url: str) -> Optional[Dict]:
        """Source vector: post the canary via window.postMessage after load -
        the page's own 'message' handlers receive it and any sink transit is
        caught by the same hooks (string and structured payload variants)."""
        deliveries = [
            f"window.postMessage({self.value!r}, '*')",
            f"window.postMessage({{msg: {self.value!r}}}, '*')",
        ]
        out = self._probe_harness(url, deliveries=deliveries)
        if not out:
            return None
        exec_hits, dom_hits, hook_hits, html_has = out

        classified = self._classify(exec_hits, hook_hits, dom_hits, html_has)
        if not classified:
            return None
        return {
            'URL': url,
            'Parameter': 'postmessage',
            'Payload': f'postMessage("{self.value}", "*") → {url}',
            'Result': classified['Result'],
            'Class': classified['Class'],
            'Sink': classified['Sink'],
            'Evidence': classified['Evidence'],
            'Method': 'headless-browser',
        }

    def _name_probe(self, url: str) -> Optional[Dict]:
        """Source vector: seed window.name (survives navigation), then scan."""
        out = self._probe_harness(url, set_name=True)
        if not out:
            return None
        exec_hits, dom_hits, hook_hits, html_has = out

        classified = self._classify(exec_hits, hook_hits, dom_hits, html_has)
        if not classified:
            return None
        return {
            'URL': url,
            'Parameter': 'window.name',
            'Payload': f'window.name = "{self.value}" (seeded) → {url}',
            'Result': classified['Result'],
            'Class': classified['Class'],
            'Sink': classified['Sink'],
            'Evidence': classified['Evidence'],
            'Method': 'headless-browser',
        }

    # ------------------------------------------------------------------
    # Per-URL validation
    # ------------------------------------------------------------------
    _PRIORITY = {'CONFIRMED': 3, 'PROBABLE': 2, 'POTENTIAL': 1, 'INFO': 0}

    def _validate_url(self, url: str) -> List[Dict]:
        findings: List[Dict] = []
        best: Dict = {}
        probes = [self._browser_probe(url, vector, full_url)
                  for vector, full_url in self.build_variants(url)]
        probes += [self._postmessage_probe(url), self._name_probe(url)]
        for hit in probes:
            if not hit:
                continue
            pr = self._PRIORITY.get(hit.get('Result'), 0)
            best_pr = self._PRIORITY.get(best.get('Result'), -1)
            if pr > best_pr:
                best = hit
                findings = [hit]
            elif pr == best_pr and len(findings) < 3:
                findings.append(hit)
        return findings

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------
    def _scan_all(self, urls: List[str],
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        total = len(urls)
        results: List[Dict] = []
        for idx, url in enumerate(urls):
            if progress_callback:
                progress_callback(idx / total, f"[{idx + 1}/{total}] {url}")
            found = self._validate_url(url)
            results.extend(found)
            if progress_callback:
                progress_callback((idx + 1) / total,
                                  f"[{idx + 1}/{total}] {url} -> {len(found)} hit(s), {len(results)} total")
        confirmed = len([r for r in results if r['Result'] == 'CONFIRMED'])
        if progress_callback:
            progress_callback(1.0, f"Done: {confirmed} confirmed, {len(results) - confirmed} potential")
        return results

    def validate_sync(self, urls: List[str],
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        if not urls:
            return []
        if not self.has_playwright:
            logger.warning("DOMXSSValidator: no headless browser - nothing to validate.")
            return []
        urls = list(dict.fromkeys(urls))[:self.max_urls]

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(self._scan_all, urls, progress_callback).result()
        return self._scan_all(urls, progress_callback)
