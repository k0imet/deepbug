from app.utils.user_agents import PROGRAM_UA_TAG
"""
JSAnalyzer v3.1 - Steroids Edition (performance-hardened)
=========================================================
High-performance async JS analysis for deepbug.

v3.1 FIXES (scan no longer stalls on real-world minified bundles):
- Per-pattern match caps: a 2MB minified bundle produced 30k+ findings for a
  single regex; now capped (js_max_matches, default 30) - kills the memory /
  DataFrame explosion and the O(n*m) scan cost.
- Line numbers via a precomputed offset index + bisect, instead of
  js_content[:match.start()].count('\\n') per match (was quadratic).
- Minified detection: files with huge average line length skip the AST
  entirely (esprima costs ~38 s/MB and yields little on minified code).
- ast_max_bytes lowered 1.5MB -> 250KB (1.5MB permitted ~57s PER FILE).
- Oversized downloads are TRUNCATED, not dropped. Previously the main app
  bundle - the most endpoint-rich file on the target - was discarded whole.
- Bounded the backtracking-prone regexes (event.data lookahead was O(n^2)).
- Per-file watchdog (js_file_timeout) so one pathological file can never
  stall the whole run.

NEW in v3.2 (advanced recon layer - "beyond basic enum"):
- SPA client-side route extraction -> forced-browsing candidates
- Non-prod host / RFC1918 / localhost leakage detection
- Hardcoded JWT harvesting + decode (alg:none, HS256, interesting claims)
- retire.js-lite: detected vendor lib versions matched against CVE ranges

File: app/modules/tools/js_analyzer.py
"""

import re
import json
import bisect
import asyncio
import aiohttp
import itertools
import posixpath
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Union, Set, Tuple
from urllib.parse import urlsplit
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from app.utils.url_utils import urlparse, urljoin, safe_port
from collections import defaultdict
import os
import hashlib

# Dual import keeps both `modules.X` (streamlit pages) and `app.modules.X`
# (headless tests) working.
try:
    from app.modules.tools.js_api_explorer import JSApiExplorer, ApiRequest, EndpointSeverity
    from app.modules.tools.secret_validator import SecretValidator, extract_secrets
    from app.modules.tools.endpoint_validator import sanitize_endpoints, EndpointValidator
    from app.modules.tools.js_gf_secret_scanner import JSGFSecretScanner
    from app.modules.tools.secret_fp_corpus import FalsePositiveCorpus
    from app.modules.tools.api_key_scanner import ApiKeyScanner
    from app.modules.tools.js_semantic import JSSemanticExtractor
    from app.modules.tools import js_security
    from app.modules.tools import js_protocol
    from app.modules.tools import js_taint
    from app.modules.tools.endpoint_engine import (
        EndpointExtractor, SmartEndpointValidator,
        extract_sourcemap_url, unpack_sourcemap, enumerate_webpack_chunks,
        find_swagger_specs, parse_openapi_spec, swagger_probe_candidates,
        merge_endpoints,
    )
except ImportError:  # pragma: no cover - streamlit pages import as `modules.tools`
    from modules.tools.js_api_explorer import JSApiExplorer, ApiRequest, EndpointSeverity
    from modules.tools.secret_validator import SecretValidator, extract_secrets
    from modules.tools.endpoint_validator import sanitize_endpoints, EndpointValidator
    from modules.tools.js_gf_secret_scanner import JSGFSecretScanner
    from modules.tools.secret_fp_corpus import FalsePositiveCorpus
    from modules.tools.api_key_scanner import ApiKeyScanner
    from modules.tools.js_semantic import JSSemanticExtractor
    from modules.tools import js_security
    from modules.tools import js_protocol
    from modules.tools import js_taint
    from modules.tools.endpoint_engine import (
        EndpointExtractor, SmartEndpointValidator,
        extract_sourcemap_url, unpack_sourcemap, enumerate_webpack_chunks,
        find_swagger_specs, parse_openapi_spec, swagger_probe_candidates,
        merge_endpoints,
    )

try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    HAS_ESPRIMA = False

from app.utils.logger import get_logger
logger = get_logger()


def _run_coro_sync(coro):
    """
    Run a coroutine from sync code without ever blocking on abandoned worker
    threads.

    asyncio.run() calls loop.shutdown_default_executor(), which JOINS every
    asyncio.to_thread worker. A file whose analysis blew past the watchdog is
    still churning in such a thread, so asyncio.run would sit there for as
    long as that file takes - the scan reported "Done" and then hung for
    minutes. We manage the loop ourselves and close it without that join.
    """
    def _runner(c):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(c)
        finally:
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            try:
                asyncio.set_event_loop(None)
            except Exception:
                pass
            loop.close()   # deliberately NOT shutdown_default_executor()

    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running and running.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(_runner, coro).result()
    return _runner(coro)


# ---------------------------------------------------------------------
# FRAMEWORK DETECTION PATTERNS
# ---------------------------------------------------------------------
FRAMEWORK_PATTERNS = {
    'react': {
        'patterns': [
            r'React\s*[=:]\s*\{[^}]{0,200}version\s*:\s*["\']([^"\']+)["\']',
            r'react@([^/\s"\']+)',
            r'__REACT_INSPECTOR_RUNTIME__',
            r'createElement\s*\(\s*["\'][^"\']+["\']\s*,',
            r'useState\s*\(',
            r'useEffect\s*\(',
        ],
        'version_extract': r'(?:react|React)[@\s]*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'vue': {
        'patterns': [
            r'Vue\s*\(\s*\{',
            r'vue@([^/\s"\']+)',
            r'__VUE__',
            r'v-if\s*=',
            r'v-for\s*=',
            r'Vue\.config',
        ],
        'version_extract': r'(?:vue|Vue)[@\s]*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'angular': {
        'patterns': [
            r'angular\s*\(\s*\[',
            r'ng-app\s*=',
            r'@angular/core',
            r'angular@([^/\s"\']+)',
        ],
        'version_extract': r'(?:angular|Angular)[@\s]*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'svelte': {
        'patterns': [
            r'svelte@([^/\s"\']+)',
            r'__svelte',
            r'SvelteComponent',
        ],
        'version_extract': r'svelte[@\s]*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'nextjs': {
        'patterns': [
            r'__NEXT_DATA__\s*=',
            r'next@([^/\s"\']+)',
            r'/_next/static/',
        ],
        'version_extract': r'next[@\s]*[=:]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'jquery': {
        'patterns': [
            r'jquery[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'\$\s*\(\s*function\s*\(',
            r'jQuery\s*\(\s*function\s*\(',
        ],
        'version_extract': r'jquery[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'lodash': {
        'patterns': [
            r'lodash[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'_\.\w+\s*\(',
        ],
        'version_extract': r'lodash[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
    'axios': {
        'patterns': [
            r'axios[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'axios\.(get|post|put|delete)\s*\(',
        ],
        'version_extract': r'axios[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    },
}

# ---------------------------------------------------------------------
# PROTOTYPE POLLUTION DETECTION
# v3.1: unbounded [^)]* quantifiers bounded - they backtracked badly on
# single-line minified bundles.
# ---------------------------------------------------------------------
PROTOTYPE_POLLUTION_PATTERNS = [
    r'["\']__proto__["\']\s*:\s*',
    r'\.\s*__proto__\s*[=:]',
    r'\[\s*["\']__proto__["\']\s*\]\s*[=:]',
    r'\.constructor\s*\.prototype',
    r'["\']constructor["\']\s*:\s*\{',
    r'Object\.assign\s*\([^)]{0,200},\s*[^)]{1,200}\)',
    r'\.extend\s*\(\s*true\s*,',
    r'lodash\.merge\s*\(',
    r'\.merge\s*\([^)]{0,200}\{\s*\}',
    r'\$\.extend\s*\(\s*true\s*,',
    r'\.\.\.[A-Za-z_]+\s*\}',
]

# ---------------------------------------------------------------------
# DOM CLOBBING DETECTION
# ---------------------------------------------------------------------
DOM_CLOBBING_PATTERNS = [
    r'document\.getElementById\s*\(\s*[^)]{1,200}\s*\)\.\w+\s*[=:]',
    r'document\.getElementsByName\s*\(',
    r'\.innerHTML\s*[=:]',
    r'\.outerHTML\s*[=:]',
    r'\.insertAdjacentHTML\s*\(',
    r'document\.[A-Za-z_][A-Za-z0-9_]*\s*[=:]',
]

# ---------------------------------------------------------------------
# POSTMESSAGE INSECURITY
# v3.1: `event\.data\s*(?!.*event\.origin)` was O(n^2) on minified code -
# the unbounded `.*` inside the lookahead rescanned the rest of the file at
# EVERY match position. Bounded to a local window.
# ---------------------------------------------------------------------
POSTMESSAGE_PATTERNS = [
    r'window\.addEventListener\s*\(\s*["\']message["\']\s*,\s*function\s*\([^)]{0,120}\)\s*\{[^}]{0,400}\}',
    r'window\.addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:\([^)]{0,120}\)|[A-Za-z_$][\w$]*)\s*=>\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*){0,3}\}',
    r'\.postMessage\s*\([^,]{0,200},\s*["\']\*["\']\s*\)',
    r'\.postMessage\s*\([^,]{0,200},\s*["\']https?://\*["\']\s*\)',
    r'event\.data(?!(?s:.{0,400}?event\.origin))',
]

# ---------------------------------------------------------------------
# DANGEROUS PATTERNS
# ---------------------------------------------------------------------
DANGEROUS_PATTERNS = {
    'eval': r'\beval\s*\(',
    'function_constructor': r'new\s+Function\s*\(',
    'setTimeout_string': r'setTimeout\s*\(\s*["\']',
    'setInterval_string': r'setInterval\s*\(\s*["\']',
    'document_write': r'document\.write\s*\(',
    'document_writeln': r'document\.writeln\s*\(',
    'innerHTML': r'\.innerHTML\s*[=:]',
    'outerHTML': r'\.outerHTML\s*[=:]',
    'insertAdjacentHTML': r'\.insertAdjacentHTML\s*\(',
    'script_src': r'<script[^>]{0,200}src\s*=',
    'iframe_srcdoc': r'iframe[^>]{0,200}srcdoc\s*=',
    'javascript_protocol': r'javascript:',
    'data_protocol': r'data:text/html',
    'webassembly': r'WebAssembly\.(instantiate|compile)',
    'import_scripts': r'importScripts\s*\(',
    'worker': r'new\s+(Worker|SharedWorker)\s*\(',
}

# ---------------------------------------------------------------------
# JSONP DETECTION
# ---------------------------------------------------------------------
JSONP_PATTERNS = [
    r'callback\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
    r'jsonp\s*=\s*([A-Za-z_][A-Za-z0-9_]*)',
    r'\?[^"\'\s]{0,200}callback=',
    r'\?[^"\'\s]{0,200}jsonp=',
]

# ---------------------------------------------------------------------
# DYNAMIC RENDERING DETECTION
# ---------------------------------------------------------------------
DYNAMIC_RENDERING_PATTERNS = [
    r'puppeteer',
    r'playwright',
    r'rendertron',
    r'prerender',
    r'headless',
    r'chrome-launcher',
    r'puppeteer-extra',
    r'stealth',
]

# ---------------------------------------------------------------------
# CSP BYPASS GADGETS
# ---------------------------------------------------------------------
CSP_GADGET_PATTERNS = [
    r'unsafe-inline',
    r'unsafe-eval',
    r'strict-dynamic',
    r'nonce-["\']?\s*[=:]',
    r'sha256-',
    r'sha384-',
    r'javascript:\s*',
    r'eval\s*\(',
    r'Function\s*\(',
]


# ---------------------------------------------------------------------
# VENDOR / THIRD-PARTY LIBRARY SIGNATURES
# ---------------------------------------------------------------------
# Vendor libs (jQuery, bootstrap, webpack runtime, polyfills...) contain
# no app-specific endpoints/secrets -- they are pure analysis noise and
# are usually the largest files. We DETECT them (recording name+version,
# useful for outdated-library/CVE checks) but SKIP the heavy analysis.
VENDOR_LIB_SIGNATURES = [
    # (lib name, filename regex, banner regex (first 3KB), version regex)
    ('jquery',           r'jquery[-.]?(?:ui|migrate|validate|cookie)?[-.]?.*\.js$',
     r'jQuery (?:JavaScript Library|v)\s*v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'jQuery (?:JavaScript Library )?v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('bootstrap',        r'bootstrap(?:\.bundle)?(?:\.min)?\.js$',
     r'Bootstrap v([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Bootstrap v([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('lodash',           r'lodash(?:\.min|\.core)?\.js$',
     r'lodash(?:\.js)?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?\s*\|',
     r'lodash[^\n]{0,40}?([0-9]+\.[0-9]+\.[0-9]+)'),
    ('underscore',       r'underscore(?:\.min)?\.js$',
     r'Underscore\.js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Underscore\.js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('moment',           r'moment(?:\.min|\.with-locales)?\.js$',
     r'Moment\.js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'//!\s*version\s*:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('webpack-runtime',  r'(?:^|/)(?:runtime[~.-]|manifest[.-]).*\.js$',
     r'webpackJsonp|__webpack_require__',
     None),
    ('vendor-chunk',     r'(?:^|/)(?:vendors?[~.-]|chunk-vendors[.-]).*\.js$',
     None,
     None),
    ('polyfills',        r'(?:^|/)polyfills?[.-].*\.js$',
     r'core-js|regeneratorRuntime|zone\.js',
     None),
    ('core-js',          r'core-js(?:\.min)?\.js$',
     r'core-js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'core-js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('zone.js',          r'zone(?:\.min)?\.js$',
     r'Zone\.js|zone\.js',
     None),
    ('modernizr',        r'modernizr[.-].*\.js$',
     r'Modernizr\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Modernizr\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('popper',           r'popper(?:\.min)?\.js$',
     r'Popper\.js|@popperjs',
     None),
    ('select2',          r'select2(?:\.min|\.full)?\.js$',
     r'Select2\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Select2\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('datatables',       r'dataTables(?:\.min)?\.js$|datatables(?:\.min)?\.js$',
     r'DataTables\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'DataTables\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('swiper',           r'swiper(?:\.min|\.bundle)?\.js$',
     r'Swiper\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Swiper\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('gsap',             r'gsap(?:\.min)?\.js$|TweenMax(?:\.min)?\.js$',
     r'GSAP|GreenSock',
     None),
    ('three.js',         r'three(?:\.min|\.module)?\.js$',
     r'three\.js\s+r?([0-9]+)?',
     r'REVISION\s*=\s*["\']?([0-9]+)'),
    ('d3.js',            r'd3(?:\.min|\.v[0-9]+)?\.js$',
     r'd3\.js|D3\.js',
     r'version\s*[:=]\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('chart.js',         r'chart(?:\.min|\.bundle)?\.js$',
     r'Chart\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Chart\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('slick-carousel',   r'slick(?:\.min)?\.js$',
     r'slick\s+(?:carousel\s+)?(?:v|Version)',
     None),
    ('owl-carousel',     r'owl\.carousel(?:\.min)?\.js$',
     r'Owl Carousel',
     None),
    ('hammer.js',        r'hammer(?:\.min)?\.js$',
     r'Hammer\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?',
     r'Hammer\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('axios',            r'(?:^|/)axios(?:\.min)?\.js$',
     r'axios\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)?\s*\|',
     r'axios\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),
    ('font-awesome',     r'all(?:\.min)?\.js$.*font|fontawesome(?:\.min)?\.js$',
     r'Font Awesome',
     None),
]


# ---------------------------------------------------------------------
# ADVANCED RECON LAYER (v3.2) - "beyond basic enum" detectors
# ---------------------------------------------------------------------
# 1) SPA client-side routes -> forced-browsing candidates.
#    All patterns bounded (no unbounded .* / [^)]*) - v3.1 hardening rules.
SPA_ROUTE_PATTERNS = [
    r'\bpath\s*:\s*[\'"](/[^\'"]{1,120})[\'"]',                      # { path: '/admin' } (react-router/vue-router)
    r'<Route[^>]{0,200}?\bpath\s*=\s*[\'"](/[^\'"]{1,120})[\'"]',    # JSX <Route path='/...'>
    r'\b(?:redirectTo|component)\s*:\s*[^,]{0,60}?[\'"](/[^\'"]{1,120})[\'"]\s*,\s*pathMatch',  # angular redirects
    r'`(/[^`$]{1,120})`',                                            # angular/minified template-literal paths (`/score-board`)
    r'\brouterLink[^,]{0,10},\s*(?:wT\()?`(/[^`]{1,120})`',          # minified `routerLink`,wT(`/x`) forms
]
# routes worth probing server-side (authZ gaps hide here)
ROUTE_ADMIN_KEYWORDS = re.compile(
    r'admin|internal|dashboard|manage|config|setting|debug|backup|panel|'
    r'superuser|root|moderator|billing|payment|invoice|token|key|secret|'
    r'user[s]?/|account|profile|export|import|upload|report|audit|log',
    re.IGNORECASE)

# 2) Non-production hosts / internal infrastructure leaked in JS
NONPROD_HOST_PATTERNS = [
    (r'\b((?:dev|staging|stg|stage|test|testing|qa|uat|preprod|pre-prod|'
     r'sandbox|beta|demo|internal|local|alpha|canary)[.-][a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b',
     'nonprod_subdomain'),
    (r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', 'rfc1918_10'),
    (r'\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b', 'rfc1918_172'),
    (r'\b(192\.168\.\d{1,3}\.\d{1,3})\b', 'rfc1918_192'),
    (r'\b(localhost:\d{2,5})\b', 'localhost_port'),
    (r'\b(127\.0\.0\.1:\d{1,5})\b', 'loopback_port'),
]

# 3) JWT tokens hardcoded in JS
JWT_PATTERN = re.compile(r'(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})(?![A-Za-z0-9_-])')

# 4) Vulnerable library versions (retire.js-lite). Ranges are [lo, hi).
#    Only entries with well-established CVEs - no speculative data.
VULNERABLE_LIBRARIES = {
    'jquery': [
        (None, '3.0.0', 'CVE-2015-9251 et al. - XSS via cross-domain ajax / $.parseHTML', 'MEDIUM'),
        ('3.0.0', '3.5.0', 'CVE-2020-11022/11023 - XSS passing HTML to DOM manipulation', 'HIGH'),
    ],
    'lodash': [
        (None, '4.17.12', 'CVE-2019-10744 - Prototype pollution via defaultsDeep', 'HIGH'),
        ('4.17.12', '4.17.21', 'CVE-2021-23337 - Command injection via template', 'HIGH'),
    ],
    'moment': [
        (None, '2.29.2', 'CVE-2022-24785 - Path traversal in locale loading', 'HIGH'),
        ('2.29.2', '2.29.4', 'CVE-2022-31129 - ReDoS in RFC2822 parsing', 'HIGH'),
    ],
    'bootstrap': [
        (None, '3.4.1', 'CVE-2019-8331 - XSS in tooltip/popover data-template', 'MEDIUM'),
        ('4.0.0', '4.3.1', 'CVE-2019-8331 - XSS in tooltip/popover data-template', 'MEDIUM'),
    ],
    'axios': [
        (None, '0.21.1', 'CVE-2020-28168 - SSRF via redirect credential leak', 'MEDIUM'),
        ('1.0.0', '1.6.0', 'CVE-2023-45857 - XSRF token exposure', 'MEDIUM'),
    ],
    'angular': [
        (None, '1.8.0', 'CVE-2020-7676 - XSS via svg/xlink href binding', 'MEDIUM'),
    ],
    'underscore': [
        (None, '1.13.0-0', "CVE-2021-26675 - Prototype pollution in template/interpolation", 'HIGH'),
    ],
}


class JSAnalyzer:
    """
    High-performance async JS analyzer v3.1 (performance-hardened).
    """

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('js_timeout', 15)
        self.max_file_size = config.get('js_max_size', 5 * 1024 * 1024)
        self.max_concurrent_requests = config.get('js_concurrent', 100)

        self.headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36') + PROGRAM_UA_TAG
        }

        self.explorer = JSApiExplorer(config)
        self.extractor = EndpointExtractor()
        self.secret_validator = SecretValidator()
        self.semantic = JSSemanticExtractor(config)
        self.validate_enabled = config.get('js_validate_endpoints', True)
        self.deep_coverage = config.get('js_deep_coverage', True)
        self.probe_swagger = config.get('js_probe_swagger', True)
        self.scope_hosts: Optional[Set[str]] = None
        self.gf_secret_scanner = JSGFSecretScanner(config)
        self._inline_scripts: Dict[str, str] = {}
        self.download_retries = int(config.get('js_download_retries', 2))
        self.store_max_bytes = int(config.get('js_store_max_bytes', 512_000))
        # precompile framework patterns once (500 files -> 1 compile each)
        self._fw_compiled = [
            (name, [re.compile(p, re.I) for p in data.get('patterns', [])],
             re.compile(data['version_extract'], re.I) if data.get('version_extract') else None)
            for name, data in FRAMEWORK_PATTERNS.items()
        ]
        try:
            self.api_key_scanner = ApiKeyScanner(config)
        except Exception as e:
            logger.warning(f"API key scanner unavailable: {e}")
            self.api_key_scanner = None

        # ---- Efficiency guards (anti-hang) ----
        # esprima costs roughly 38 s/MB. The old 1.5MB ceiling therefore
        # allowed ~57s of parsing PER FILE; 250KB caps it near 10s.
        self.ast_max_bytes = int(config.get('js_ast_max_bytes', 250_000))
        # Minified files (huge average line length) skip the AST entirely:
        # esprima is slowest exactly where it adds least.
        self.ast_skip_minified = bool(config.get('js_ast_skip_minified', True))
        # v3.3: when minified/oversized, parse a bounded first window of the
        # bundle instead of skipping the AST outright (structured endpoints
        # from minified code, ~10s worst case per file).
        self.ast_windowed = bool(config.get('js_ast_windowed', True))
        self.minified_line_len = int(config.get('js_minified_line_len', 2000))
        # regex detectors scan at most this many bytes per file
        self.scan_max_bytes = int(config.get('js_scan_max_bytes', 2_000_000))
        # HARD CAP on matches recorded per pattern per file. Without this a
        # single minified bundle yields 30k+ findings for one regex.
        self.max_matches = int(config.get('js_max_matches', 30))
        # CPU analysis runs in worker threads (never blocks the event loop)
        self.analysis_threads = int(config.get('js_analysis_threads', 4))
        # watchdog: no single file may stall the whole scan
        self.file_timeout = int(config.get('js_file_timeout', 90))
        # caps on file intake
        self.max_files = int(config.get('js_max_files', 500))
        # archived JS hunting (wayback) - Marduk-style pipeline
        self.use_archive = bool(config.get('js_use_archive', True))
        # external JS-URL discovery tools (fast Go binaries, run concurrently)
        self.use_subjs = bool(config.get('js_use_subjs', True))
        self.use_getjs = bool(config.get('js_use_getjs', True))
        self.tool_timeout = int(config.get('js_tool_timeout', 180))
        self.tool_threads = int(config.get('js_tool_threads', 20))
        self.max_archive_urls = int(config.get('js_max_archive', 300))
        # vendor libs (jquery, bootstrap, webpack runtime...) carry no
        # app-specific signal -- detect+record them, skip the heavy analysis
        self.skip_vendor = bool(config.get('js_skip_vendor', True))
        # ---- v3.2 advanced recon layer (all pure-additive) ----
        self.detect_routes = bool(config.get('js_detect_routes', True))
        self.detect_nonprod = bool(config.get('js_detect_nonprod', True))
        self.detect_jwts = bool(config.get('js_detect_jwts', True))
        self.check_vuln_libs = bool(config.get('js_check_vuln_libs', True))
        self._compiled_routes = [re.compile(p) for p in SPA_ROUTE_PATTERNS]
        self._compiled_nonprod = [(re.compile(p), k) for p, k in NONPROD_HOST_PATTERNS]

        # Compile regex patterns for performance
        self._compiled_dangerous = {k: re.compile(v, re.IGNORECASE) for k, v in DANGEROUS_PATTERNS.items()}
        self._compiled_proto = [re.compile(p, re.IGNORECASE) for p in PROTOTYPE_POLLUTION_PATTERNS]
        self._compiled_clobbing = [re.compile(p, re.IGNORECASE) for p in DOM_CLOBBING_PATTERNS]
        self._compiled_postmsg = [re.compile(p, re.IGNORECASE) for p in POSTMESSAGE_PATTERNS]
        self._compiled_jsonp = [re.compile(p, re.IGNORECASE) for p in JSONP_PATTERNS]
        self._compiled_rendering = [re.compile(p, re.IGNORECASE) for p in DYNAMIC_RENDERING_PATTERNS]
        self._compiled_csp = [re.compile(p, re.IGNORECASE) for p in CSP_GADGET_PATTERNS]

        # verified-false-positive corpus (fed by prior triage runs)
        fp_path = config.get('false_positive_corpus')
        self.fp_corpus = FalsePositiveCorpus(Path(fp_path) if fp_path else None)

    # =================================================================
    # v3.1 SCAN HELPERS (the anti-hang core)
    # =================================================================

    @staticmethod
    def _line_index(text: str) -> List[int]:
        """
        Precompute the start offset of every line ONCE per file.
        Replaces text[:match.start()].count('\\n') per match, which copied
        the whole prefix for every hit (quadratic on large bundles).
        """
        idx = [0]
        start = text.find('\n')
        while start != -1:
            idx.append(start + 1)
            start = text.find('\n', start + 1)
        return idx

    @staticmethod
    def _line_of(line_index: List[int], pos: int) -> int:
        return bisect.bisect_right(line_index, pos)

    def _capped_finditer(self, pattern, text: str):
        """finditer limited to max_matches - stops scanning early (lazy)."""
        return itertools.islice(pattern.finditer(text), self.max_matches)

    @staticmethod
    def _is_minified(text: str) -> float:
        """Average line length. Minified bundles run into the thousands."""
        newlines = text.count('\n') + 1
        return len(text) / max(newlines, 1)

    # =================================================================
    # ASYNC DOWNLOAD LAYER
    # =================================================================

    def _host_in_scope(self, url: str) -> bool:
        """Gate feeder fetches (source maps / webpack chunks / specs) to in-scope hosts."""
        if not self.scope_hosts:
            return True
        try:
            # hostname, NOT netloc: netloc carries the port, so
            # 'host.example.com:443'.endswith('.example.com') is False and
            # every ported URL silently fell out of scope.
            host = (urlparse(url).hostname or '').lower()
        except Exception:
            return False
        if not host:
            return False
        return any(host == h or host.endswith('.' + h) for h in self.scope_hosts)

    def _host_allowed(self, url: str) -> bool:
        """SSRF guard: refuse IP-literal hosts in private/link-local/reserved
        ranges unless explicitly present in scope_hosts. Hostnames are allowed
        through (DNS resolution to private space isn't attempted here)."""
        try:
            host = (urlsplit(url).hostname or '').strip('[]')
        except Exception:
            return False
        if not host:
            return False
        try:
            ip = ip_address(host)
        except ValueError:
            return True  # hostname
        cgn = (ip_network('100.64.0.0/10') if isinstance(ip, IPv4Address) else None)
        blocked = (ip.is_private or ip.is_loopback or ip.is_link_local or
                   ip.is_reserved or ip.is_multicast or
                   (cgn is not None and ip in cgn))
        if not blocked:
            return True
        if self.scope_hosts and host in self.scope_hosts:
            return True
        return False

    async def _download_js_with_info(self, session: aiohttp.ClientSession, url: str,
                                     semaphore: asyncio.Semaphore) -> Tuple[Optional[str], Dict]:
        """
        v3.5: coverage-aware, hardened downloader.
        - allow_redirects=False (no SSRF via redirect to internal/metadata hosts)
        - private/link-local IP-literal hosts denied unless in scope (SSRF guard)
        - runs from an inline <script> pseudo-url when present
        - transient 5xx/conn-reset retried with backoff
        Returns (content, info) where info feeds the js_coverage report.
        """
        import time as _t
        start = _t.monotonic()
        info = {'url': url, 'kind': 'js', 'outcome': 'error', 'status': '',
                'size': 0, 'ms': 0.0, 'note': ''}

        # inline <script> body staged during HTML extraction (no HTTP fetch)
        inline = self._inline_scripts.get(url)
        if inline is not None:
            info.update({'outcome': 'inline', 'status': 200, 'size': len(inline),
                         'ms': 0.0, 'note': 'inline script'})
            return inline, info

        if not self._host_allowed(url):
            info['outcome'] = 'blocked_private_host'
            info['note'] = 'private/link-local IP literal outside scope'
            info['ms'] = round((_t.monotonic() - start) * 1000, 1)
            return None, info

        async with semaphore:
            attempts = self.download_retries + 1
            for attempt in range(attempts):
                try:
                    async with session.get(url, timeout=self.timeout,
                                           allow_redirects=False) as resp:
                        info['status'] = resp.status
                        if resp.status not in (200, 304):
                            info['outcome'] = f'http_{resp.status}'
                            info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                            # transient upstream errors: retry with backoff
                            if resp.status in (500, 502, 503, 504, 429) and attempt < attempts - 1:
                                await asyncio.sleep(0.4 * (attempt + 1))
                                continue
                            return None, info

                        chunks = []
                        total_bytes = 0
                        truncated = False
                        async for chunk in resp.content.iter_chunked(65536):
                            chunks.append(chunk)
                            total_bytes += len(chunk)
                            if total_bytes >= self.max_file_size:
                                truncated = True
                                break

                        info['size'] = total_bytes
                        info['outcome'] = 'truncated' if truncated else 'ok'
                        info['note'] = (f'truncated at {self.max_file_size} bytes' if truncated else '')
                        info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                        if truncated:
                            logger.info(f"Truncated to {self.max_file_size} bytes (still analyzed): {url}")

                        raw_bytes = b"".join(chunks)[:self.max_file_size]
                        return raw_bytes.decode('utf-8', errors='ignore'), info
                except asyncio.TimeoutError:
                    if attempt < attempts - 1:
                        await asyncio.sleep(0.4 * (attempt + 1))
                        continue
                    info['outcome'] = 'timeout'
                    info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                    logger.warning(f"Download timeout for {url}")
                    return None, info
                except (aiohttp.ClientConnectionError, ConnectionError) as e:
                    if attempt < attempts - 1:
                        await asyncio.sleep(0.4 * (attempt + 1))
                        continue
                    info['outcome'] = 'error'
                    info['note'] = f'{type(e).__name__}: {str(e)[:120]}'
                    info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                    logger.debug(f"Failed async download for {url}: {e}")
                    return None, info
                except Exception as e:
                    info['outcome'] = 'error'
                    info['note'] = f'{type(e).__name__}: {str(e)[:120]}'
                    info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                    logger.debug(f"Failed async download for {url}: {e}")
                    return None, info
        return None, info

    async def _download_js_async(self, session: aiohttp.ClientSession, url: str,
                                  semaphore: asyncio.Semaphore) -> Optional[str]:
        content, _info = await self._download_js_with_info(session, url, semaphore)
        return content

    def _extract_js_from_html(self, html: str, base_url: str) -> Tuple[List[str], List[str]]:
        """Extract JS candidates from HTML: script src, link[rel=modulepreload/
        preload as=script], iframe src - resolved against <base href> when
        present. Returns (js_urls, inline_script_bodies)."""
        js_urls: List[str] = []
        inline: List[str] = []

        base_href = base_url
        m_base = re.search(r'<base\b[^>]*\bhref=["\x27]([^"\x27]+)["\x27]', html, re.I)
        if m_base:
            abs_base = urljoin(base_url, m_base.group(1))
            if abs_base.startswith(('http://', 'https://')):
                base_href = abs_base

        def _abs(src: str):
            full = urljoin(base_href, src)
            return full if full.startswith(('http://', 'https://')) else ''

        # <script src=...>
        for match in re.finditer(r'<script\b[^>]*\bsrc=["\x27]([^"\x27]+)["\x27]', html, re.I):
            u = _abs(match.group(1))
            if u and u not in js_urls:
                js_urls.append(u)
        # <script>...</script> inline bodies (boot configs, secrets, endpoints)
        for match in re.finditer(
                r'<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>', html, re.I | re.S):
            body = match.group(1).strip()
            if body and len(body) > 16 and not body.lstrip().startswith(('<', '<!--')):
                inline.append(body)
        # link rel=modulepreload / preload as=script
        for match in re.finditer(
                r'<link\b[^>]*\brel=["\x27](?:modulepreload|preload)["\x27][^>]*>', html, re.I):
            href = re.search(r'\bhref=["\x27]([^"\x27]+)["\x27]', match.group(0), re.I)
            if href and ('as="script"' in match.group(0) or 'as=script' in match.group(0) or
                         'modulepreload' in match.group(0)):
                u = _abs(href.group(1))
                if u and u not in js_urls:
                    js_urls.append(u)
            elif href:
                u = _abs(href.group(1))
                if u and u not in js_urls:
                    js_urls.append(u)
        # iframe src (often loads the real SPA shell / app JS)
        for match in re.finditer(r'<iframe\b[^>]*\bsrc=["\x27]([^"\x27]+)["\x27]', html, re.I):
            u = _abs(match.group(1))
            if u and u not in js_urls:
                js_urls.append(u)
        return js_urls, inline

    async def _fetch_single_html_and_extract(self, session: aiohttp.ClientSession,
                                              url: str) -> Tuple[List[str], Dict]:
        """Fetch a seed URL's HTML and extract script srcs. Returns (js_urls, info)
        where info feeds the js_coverage report (no silent host drops).
        Inline <script> bodies are staged in self._inline_scripts (fetched as
        pseudo-urls by the downloader, no HTTP round-trip)."""
        import time as _t
        start = _t.monotonic()
        info = {'url': url, 'kind': 'seed', 'outcome': 'html_failed', 'status': '',
                'size': 0, 'ms': 0.0, 'note': ''}
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=False) as resp:
                info['status'] = resp.status
                content_type = resp.headers.get('content-type', '').lower()
                info['note'] = content_type.split(';')[0] or ''
                if 'text/html' in content_type:
                    text = await resp.text()
                    info['size'] = len(text)
                    js_urls, inline = self._extract_js_from_html(text, url)
                    for i, body in enumerate(inline):
                        pseudo = f"{url.rstrip('/')}~inline{i}"
                        self._inline_scripts[pseudo] = body
                        js_urls.append(pseudo)
                    info['outcome'] = f'html_ok:{len(js_urls)}'
                    info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                    return js_urls, info
                elif 'javascript' in content_type or url.endswith('.js'):
                    info['outcome'] = 'js_seed'
                    info['ms'] = round((_t.monotonic() - start) * 1000, 1)
                    return [url], info
        except Exception as e:
            info['outcome'] = 'error'
            info['note'] = f'{type(e).__name__}: {str(e)[:120]}'
            logger.debug(f"Failed pre-fetching url list target {url}: {e}")
        info['ms'] = round((_t.monotonic() - start) * 1000, 1)
        return [], info

    # =================================================================
    # FRAMEWORK FINGERPRINTING
    # =================================================================

    def _detect_frameworks(self, js_content: str, source_url: str) -> List[Dict]:
        findings = []
        for framework, patterns, vext in self._fw_compiled:
            detected = False
            version = None
            for pat in patterns:
                if pat.search(js_content):
                    detected = True
                    if vext:
                        ver_match = vext.search(js_content)
                        if ver_match:
                            version = ver_match.group(1)
                    break

            if detected:
                findings.append({
                    'type': 'framework',
                    'framework': framework,
                    'version': version or 'unknown',
                    'source': source_url,
                    'severity': 'INFO',
                })
        return findings

    # =================================================================
    # PATTERN DETECTORS (all capped + bisect line numbers)
    # =================================================================

    def _detect_prototype_pollution(self, js_content: str, source_url: str,
                                    line_index: List[int]) -> List[Dict]:
        findings = []
        for pattern in self._compiled_proto:
            for match in self._capped_finditer(pattern, js_content):
                findings.append({
                    'type': 'prototype_pollution',
                    'pattern': pattern.pattern[:50],
                    'line': self._line_of(line_index, match.start()),
                    'context': js_content[max(0, match.start()-50):match.end()+50].strip(),
                    'source': source_url,
                    'severity': 'HIGH',
                    'confidence': 'medium',
                })
        return findings

    def _detect_dom_clobbering(self, js_content: str, source_url: str,
                               line_index: List[int]) -> List[Dict]:
        findings = []
        for pattern in self._compiled_clobbing:
            for match in self._capped_finditer(pattern, js_content):
                findings.append({
                    'type': 'dom_clobbering',
                    'pattern': pattern.pattern[:50],
                    'line': self._line_of(line_index, match.start()),
                    'context': js_content[max(0, match.start()-50):match.end()+50].strip(),
                    'source': source_url,
                    'severity': 'MEDIUM',
                    'confidence': 'medium',
                })
        return findings

    def _detect_postmessage_issues(self, js_content: str, source_url: str,
                                   line_index: List[int]) -> List[Dict]:
        findings = []
        for pattern in self._compiled_postmsg:
            for match in self._capped_finditer(pattern, js_content):
                findings.append({
                    'type': 'postmessage_insecure',
                    'pattern': pattern.pattern[:50],
                    'line': self._line_of(line_index, match.start()),
                    'context': js_content[max(0, match.start()-50):match.end()+50].strip(),
                    'source': source_url,
                    'severity': 'HIGH',
                    'confidence': 'medium',
                })
        return findings

    def _detect_dangerous_patterns(self, js_content: str, source_url: str,
                                   line_index: List[int]) -> List[Dict]:
        findings = []
        for name, pattern in self._compiled_dangerous.items():
            for match in self._capped_finditer(pattern, js_content):
                severity = 'HIGH' if name in ('eval', 'function_constructor',
                                              'document_write', 'innerHTML') else 'MEDIUM'
                findings.append({
                    'type': 'dangerous_pattern',
                    'pattern_name': name,
                    'line': self._line_of(line_index, match.start()),
                    'context': js_content[max(0, match.start()-50):match.end()+50].strip(),
                    'source': source_url,
                    'severity': severity,
                    'confidence': 'high',
                })
        return findings

    def _detect_jsonp(self, js_content: str, source_url: str,
                      line_index: List[int]) -> List[Dict]:
        findings = []
        for pattern in self._compiled_jsonp:
            for match in self._capped_finditer(pattern, js_content):
                findings.append({
                    'type': 'jsonp_endpoint',
                    'callback': match.group(1) if match.lastindex else 'unknown',
                    'line': self._line_of(line_index, match.start()),
                    'source': source_url,
                    'severity': 'MEDIUM',
                    'confidence': 'medium',
                })
        return findings

    def _detect_dynamic_rendering(self, js_content: str, source_url: str) -> List[Dict]:
        """One finding per engine keyword - repeats add nothing."""
        findings = []
        for pattern in self._compiled_rendering:
            match = pattern.search(js_content)
            if match:
                findings.append({
                    'type': 'dynamic_rendering',
                    'engine': match.group(0).lower(),
                    'source': source_url,
                    'severity': 'INFO',
                    'confidence': 'high',
                    'note': 'Check for SSRF via dynamic rendering endpoints',
                })
        return findings

    def _detect_csp_gadgets(self, js_content: str, source_url: str,
                            line_index: List[int]) -> List[Dict]:
        findings = []
        for pattern in self._compiled_csp:
            for match in self._capped_finditer(pattern, js_content):
                findings.append({
                    'type': 'csp_gadget',
                    'pattern': pattern.pattern[:50],
                    'line': self._line_of(line_index, match.start()),
                    'context': js_content[max(0, match.start()-50):match.end()+50].strip(),
                    'source': source_url,
                    'severity': 'MEDIUM',
                    'confidence': 'low',
                    'note': 'May be useful for CSP bypass if strict-dynamic or unsafe-inline present',
                })
        return findings

    # =================================================================
    # SECRETS EXTRACTION (DUAL ENGINE)
    # =================================================================

    def _extract_secrets(self, js_content: str, source_url: str = '') -> List[Dict]:
        all_secrets = []
        try:
            validator_secrets = extract_secrets(js_content, source_url, self.secret_validator)
            all_secrets.extend(validator_secrets)
        except Exception as e:
            logger.warning(f"secret_validator failed for {source_url}: {e}")

        try:
            gf_secrets = self.gf_secret_scanner.scan_js_content(js_content, source_url)
            all_secrets.extend(gf_secrets)
        except Exception as e:
            logger.warning(f"GF secret scanner failed for {source_url}: {e}")

        seen = set()
        unique_secrets = []
        for s in all_secrets:
            if self.fp_corpus.is_false_positive(s, source_url):
                continue
            key = (s.get('type', 'unknown'), str(s.get('value', '')))
            if key not in seen:
                seen.add(key)
                unique_secrets.append(s)

        return unique_secrets

    # =================================================================
    # MAIN ANALYSIS PIPELINE
    # =================================================================

    async def analyze_js_urls_async(self, js_urls: List[str],
                                     progress_callback: Optional[Callable] = None,
                                     validate: Optional[bool] = None) -> Dict[str, Any]:
        def _emit(frac, msg):
            # a throwing UI callback (e.g. Streamlit) must never collapse the scan
            if progress_callback:
                try:
                    _emit(frac, msg)
                except Exception:
                    pass

        results = {
            'js_files': [],
            'endpoints': [],
            'secrets': [],
            'api_keys': [],
            'graphql_endpoints': [],
            'websocket_endpoints': [],
            'source_map_flags': [],
            'frameworks': [],
            'prototype_pollution': [],
            'dom_clobbering': [],
            'postmessage_issues': [],
            'dangerous_patterns': [],
            'jsonp_endpoints': [],
            'dynamic_rendering': [],
            'csp_gadgets': [],
            'libraries': [],
            'vendor_skipped': 0,
            'timed_out_files': [],
            'spa_routes': [],
            'nonprod_hosts': [],
            'jwts': [],
            'total_js_analyzed': 0,
            'total_endpoints': 0,
            'critical_endpoints': [],
            'high_endpoints': [],
            'coverage': [],
            'oauth_clients': [],
            'jwt_correlation': [],
            'service_graph': {'hosts': [], 'edges': [], 'auth_relationships': []},
            'oidc_config': [],
            'ws_protocol': [], 'service_workers': [], 'push_keys': [],
            'ssrf_candidates': [], 'error_services': [], 'auth_guards': [],
            'taint': [],
        }

        js_urls = list(dict.fromkeys(js_urls))
        if len(js_urls) > self.max_files:
            logger.warning(f"JS file list capped: {len(js_urls)} -> {self.max_files} (js_max_files)")
            js_urls = js_urls[:self.max_files]
        if not js_urls:
            return results

        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        all_reqs: List[Dict] = []
        discovered_maps: Set[str] = set()
        discovered_chunks: Set[str] = set()
        discovered_specs: Set[str] = set()
        swagger_ui_hosts: Set[str] = set()

        # httpx already accepted these hosts regardless of cert state; aiohttp
        # must not then drop them. Invalid/self-signed certs are routine on
        # dev/staging subdomains and would otherwise silently zero out their JS
        # (the endpoint validator below also uses verify_ssl=False).
        _conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, max_line_size=65536, max_field_size=65536, connector=_conn) as session:
            tasks = [self._download_js_with_info(session, url, semaphore) for url in js_urls]
            downloaded = await asyncio.gather(*tasks)
            downloaded_contents = [c for c, _info in downloaded]
            for _c, info in downloaded:
                results['coverage'].append(info)

            total_files = len(js_urls)

            # CPU-heavy per-file analysis runs in worker threads: the event
            # loop (and progress bar) stays alive. A watchdog guarantees the
            # scan completes even if one file is pathological.
            analysis_sem = asyncio.Semaphore(self.analysis_threads)
            import concurrent.futures
            # Our own pool, not the loop's default one: a wedged file's thread
            # is abandoned at the end instead of being joined during teardown.
            pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=self.analysis_threads, thread_name_prefix='deepbug-js')
            loop = asyncio.get_event_loop()

            async def _analyze_in_thread(u, c):
                if not c:
                    return None
                try:
                    async with analysis_sem:
                        # No shield: a per-file timeout must also cancel the
                        # queued/started future so a pathological file can't
                        # wedge the pool and deadlock the scan (the worker
                        # thread is still bounded by the overall deadline).
                        return await asyncio.wait_for(
                            loop.run_in_executor(pool, self._analyze_single_file, u, c),
                            timeout=self.file_timeout,
                        )
                except asyncio.TimeoutError:
                    logger.warning(f"Analysis timed out after {self.file_timeout}s, skipped: {u}")
                    results['timed_out_files'].append(u)
                    return None
                except Exception as e:
                    logger.warning(f"Analysis failed for {u}: {e}")
                    return None

            # Global analysis deadline: even if a pathological file wedges a
            # worker, the scan completes with partial results instead of hanging.
            try:
                analyses = await asyncio.wait_for(
                    asyncio.gather(
                        *[_analyze_in_thread(u, c) for u, c in zip(js_urls, downloaded_contents)]
                    ),
                    timeout=max(int(self.config.get('js_analysis_budget',
                                                    self.file_timeout * len(js_urls) // max(self.analysis_threads, 1) + 60)), 60),
                )
            except asyncio.TimeoutError:
                logger.warning("Overall JS analysis budget exceeded - continuing with partial results")
                analyses = []
                for u, info in zip(js_urls, results['coverage']):
                    if (u, 'budget') not in results['timed_out_files']:
                        results['timed_out_files'].append(u)

            for idx, per in enumerate(analyses):
                if per is None:
                    continue
                results['js_files'].append(per['file'])
                results['total_js_analyzed'] += 1
                all_reqs.extend(per['endpoints'])
                discovered_maps.update(per['maps'])
                discovered_chunks.update(per['chunks'])
                discovered_specs.update(per['specs'])
                swagger_ui_hosts.update(per['ui'])
                results['secrets'].extend(per['secrets'])
                results['api_keys'].extend(per['api_keys'])
                results['frameworks'].extend(per['frameworks'])
                results['prototype_pollution'].extend(per['proto'])
                results['dom_clobbering'].extend(per['clobbing'])
                results['postmessage_issues'].extend(per['postmsg'])
                results['dangerous_patterns'].extend(per['dangerous'])
                results['jsonp_endpoints'].extend(per['jsonp'])
                results['dynamic_rendering'].extend(per['rendering'])
                results['csp_gadgets'].extend(per['csp'])
                if per.get('library'):
                    results['libraries'].append(per['library'])
                    results['vendor_skipped'] += 1
                results['spa_routes'].extend(per.get('routes', []))
                results['nonprod_hosts'].extend(per.get('nonprod', []))
                results['jwts'].extend(per.get('jwts', []))
                for _pk in ('ws_protocol', 'service_workers', 'push_keys',
                            'ssrf_candidates', 'error_services', 'auth_guards', 'taint'):
                    results[_pk].extend(per.get(_pk, []))
                if progress_callback and ((idx + 1) % 5 == 0 or idx + 1 == total_files):
                    _emit((idx + 1) / total_files,
                                      f"Analyzed {idx + 1}/{total_files} JS files | "
                                      f"{results['vendor_skipped']} vendor skipped | "
                                      f"{len(all_reqs)} endpoints | "
                                      f"{len(results['secrets'])} secrets | "
                                      f"{len(results['api_keys'])} API keys | "
                                      f"{len(results['prototype_pollution'])} proto vectors")

            # ============================================================
            # SECOND PASS: deep-scan coverage feeders (source maps, webpack
            # chunks) - recursive chunk-graph traversal, FULL detector set on
            # every feeder and on unpacked original sources.
            # ============================================================
            if self.deep_coverage:
                if self.probe_swagger:
                    for base in swagger_ui_hosts:
                        for cand in swagger_probe_candidates(base):
                            u = cand.get('url')
                            if u and self._host_in_scope(u):
                                discovered_specs.add(u)

                # per-file out keys -> aggregate results keys (names differ for
                # the legacy pattern detectors; using the raw key for all of
                # them would KeyError the moment a feeder produced a finding)
                _FEEDER_MAP = {
                    'secrets': 'secrets', 'api_keys': 'api_keys',
                    'frameworks': 'frameworks', 'proto': 'prototype_pollution',
                    'clobbing': 'dom_clobbering', 'postmsg': 'postmessage_issues',
                    'dangerous': 'dangerous_patterns', 'jsonp': 'jsonp_endpoints',
                    'rendering': 'dynamic_rendering', 'csp': 'csp_gadgets',
                    'routes': 'spa_routes', 'nonprod': 'nonprod_hosts',
                    'jwts': 'jwts', 'ws_protocol': 'ws_protocol',
                    'service_workers': 'service_workers', 'push_keys': 'push_keys',
                    'ssrf_candidates': 'ssrf_candidates',
                    'error_services': 'error_services', 'auth_guards': 'auth_guards',
                    'taint': 'taint',
                }

                def _extend_feeder_findings(per, original_src=''):
                    for src_key, dst_key in _FEEDER_MAP.items():
                        for f in per.get(src_key, []):
                            if original_src:
                                f['original_src'] = original_src
                            results[dst_key].append(f)

                seen_feeder_urls: Set[str] = set()
                scanned_feeders = 0
                max_feeders = self.max_files  # total feeder budget

                async def _deep_scan_feeders(maps: Set[str], chunks: Set[str], depth: int):
                    nonlocal scanned_feeders
                    to_scan = []  # (kind, url, original_src, content)
                    if maps:
                        # inline data: maps unpacked directly - never fetched
                        entries = []
                        for dm in (m for m in maps if m.startswith('data:')):
                            info = {'url': dm[:100], 'kind': 'source_map', 'outcome': 'inline',
                                    'status': 200, 'size': len(dm), 'ms': 0.0,
                                    'note': 'inline data: map'}
                            entries.append((dm, dm, info))
                        non_data = [m for m in maps if not m.startswith('data:')]
                        if non_data:
                            mt = [self._download_js_with_info(session, m, semaphore) for m in non_data]
                            for m_url, (m_text, m_info) in zip(non_data, await asyncio.gather(*mt)):
                                entries.append((m_url, m_text, m_info))
                        for m_url, m_text, m_info in entries:
                            m_info['kind'] = 'source_map'
                            results['coverage'].append(m_info)
                            if not m_text:
                                continue
                            try:
                                _paths, pairs = unpack_sourcemap(m_text)
                            except Exception:
                                continue
                            for path, content in pairs:
                                if content and content.strip():
                                    to_scan.append(('map_source', m_url, path, content))
                    if chunks:
                        ct = [self._download_js_with_info(session, c, semaphore) for c in chunks]
                        for c_url, (c_text, c_info) in zip(chunks, await asyncio.gather(*ct)):
                            c_info['kind'] = 'chunk'
                            results['coverage'].append(c_info)
                            if c_text and not (self.skip_vendor and self.identify_vendor_lib(c_url)):
                                to_scan.append(('chunk', c_url, '', c_text))
                            else:
                                results['vendor_skipped'] += 1

                    new_maps: Set[str] = set()
                    new_chunks: Set[str] = set()
                    for kind, url, src_path, content in to_scan:
                        if scanned_feeders >= max_feeders:
                            logger.warning(f"Feeder budget exhausted ({max_feeders}) - stopping deep scan")
                            break
                        scanned_feeders += 1
                        try:
                            per = await asyncio.wait_for(
                                loop.run_in_executor(pool, self._analyze_single_file, url, content),
                                timeout=self.file_timeout)
                        except asyncio.TimeoutError:
                            results['timed_out_files'].append(url)
                            continue
                        except Exception as e:
                            logger.warning(f"Feeder analysis failed for {url}: {e}")
                            continue
                        if kind == 'chunk':
                            results['js_files'].append(per['file'])
                            results['total_js_analyzed'] += 1
                            _extend_feeder_findings(per)
                        else:
                            per['file']['url'] = f"{url}#{src_path}"
                            per['file']['kind'] = 'map_source'
                            results['js_files'].append(per['file'])
                            results['total_js_analyzed'] += 1
                            _extend_feeder_findings(per, original_src=src_path)
                        all_reqs.extend(per['endpoints'])
                        for e in per['endpoints']:
                            e['source_url'] = url
                            if kind == 'map_source':
                                e['original_src'] = src_path
                        for m in per['maps']:
                            if self._host_in_scope(m):
                                new_maps.add(m)
                        for c in per['chunks']:
                            if self._host_in_scope(c):
                                new_chunks.add(c)
                        if progress_callback:
                            _emit(min(0.90 + scanned_feeders / (max_feeders + 1) * 0.09, 0.99),
                                              f"Deep scan: {scanned_feeders} feeders | "
                                              f"maps={len(new_maps)} chunks={len(new_chunks)}")

                    if depth < 2 and scanned_feeders < max_feeders:
                        new_maps = {m for m in new_maps if m not in seen_feeder_urls}
                        new_chunks = {c for c in new_chunks if c not in seen_feeder_urls}
                        seen_feeder_urls.update(new_maps | new_chunks)
                        if new_maps or new_chunks:
                            await _deep_scan_feeders(new_maps, new_chunks, depth + 1)

                seen_feeder_urls.update(discovered_maps | discovered_chunks)
                await _deep_scan_feeders(discovered_maps, discovered_chunks, 0)

                # ============================================================
                # OIDC discovery + JWKS (passive reads only)
                # ============================================================
                oidc_cands: Set[str] = set()
                for ep in list(all_reqs):
                    u = ep.get('url') or ''
                    sigs = ep.get('security_signals') or []
                    if ('.well-known/openid-configuration' in u) or \
                       ('.well-known/oauth-authorization-server' in u) or \
                       any(s == 'oidc_discovery' for s in sigs):
                        oidc_cands.add(u)

                oidc_rows = []
                if oidc_cands:
                    if progress_callback:
                        _emit(0.95, f"OIDC discovery: {len(oidc_cands)} config(s)...")
                    for oidc_url in list(oidc_cands)[:5]:
                        try:
                            async with session.get(oidc_url, timeout=15,
                                                   allow_redirects=False) as resp:
                                if resp.status != 200:
                                    continue
                                text = await resp.text(errors='ignore')
                                try:
                                    cfg_doc = json.loads(text)
                                except Exception:
                                    continue
                            jwks_url = cfg_doc.get('jwks_uri') or \
                                urljoin(oidc_url, '.well-known/jwks.json')
                            keys = []
                            try:
                                async with session.get(jwks_url, timeout=15, allow_redirects=False) as jr:
                                    if jr.status == 200:
                                        jd = json.loads(await jr.text(errors='ignore'))
                                        for k in (jd.get('keys') or []):
                                            keys.append({'kid': k.get('kid', ''),
                                                         'alg': k.get('alg', ''),
                                                         'kty': k.get('kty', ''),
                                                         'use': k.get('use', '')})
                            except Exception:
                                pass
                            host = urlsplit(oidc_url).netloc
                            oidc_rows.append({
                                'issuer': cfg_doc.get('issuer', ''),
                                'authorization_endpoint': cfg_doc.get('authorization_endpoint', ''),
                                'token_endpoint': cfg_doc.get('token_endpoint', ''),
                                'userinfo_endpoint': cfg_doc.get('userinfo_endpoint', ''),
                                'jwks_uri': cfg_doc.get('jwks_uri', ''),
                                'host': host,
                                'grant_types_supported': ','.join(cfg_doc.get('grant_types_supported', []) or []),
                                'scopes_supported': ','.join(cfg_doc.get('scopes_supported', []) or [])[:200],
                                'jwks_keys': keys,
                            })
                        except Exception as e:
                            logger.debug(f"OIDC fetch failed {oidc_url}: {e}")
                    results['oidc_config'] = oidc_rows

                if discovered_specs:
                    if progress_callback:
                        _emit(0.94, f"Parsing {len(discovered_specs)} API specs...")
                    spec_urls = list(discovered_specs)
                    spec_tasks = [self._download_js_async(session, s, semaphore) for s in spec_urls]
                    for s_url, s_text in zip(spec_urls, await asyncio.gather(*spec_tasks)):
                        if not s_text:
                            continue
                        try:
                            spec = json.loads(s_text)
                        except Exception:
                            try:
                                import yaml
                                spec = yaml.safe_load(s_text)
                            except Exception:
                                continue
                        all_reqs.extend(sanitize_endpoints(parse_openapi_spec(spec, s_url)))

        # Abandon any still-running analysis threads instead of joining them.
        try:
            pool.shutdown(wait=False)
        except Exception:
            pass

        # Global dedup across the main pass + second pass
        all_reqs = merge_endpoints(all_reqs)

        # Live status validation
        to_probe: List[Dict] = []
        passthrough: List[Dict] = []
        for r in all_reqs:
            if (r.get('websocket') or r.get('graphql_type') or
                    'source_map_available' in (r.get('suspicious_indicators') or [])):
                passthrough.append(r)
            else:
                # Absolutize relative URLs against their source JS - otherwise the
                # validator sees an empty host and drops them as out_of_scope
                if r.get('url') and not r['url'].startswith(('http://', 'https://')):
                    base = r.get('source_url', '')
                    if base:
                        r['url'] = urljoin(base, r['url'])
                to_probe.append(r)

        do_validate = self.validate_enabled if validate is None else bool(validate)
        if do_validate and to_probe:
            max_validate = int(self.config.get('js_max_validate', 300))

            conf_rank = {'high': 0, 'medium': 1, 'low': 2}
            to_probe.sort(key=lambda r: conf_rank.get(r.get('confidence', 'medium'), 1))
            if len(to_probe) > max_validate:
                logger.info(f"Validation capped: {len(to_probe)} -> {max_validate} endpoints")
                overflow = to_probe[max_validate:]
                to_probe = to_probe[:max_validate]
                for r in overflow:
                    r['live_status'] = 'unvalidated_capped'
                passthrough.extend(overflow)

            if progress_callback:
                _emit(0.97, f"Validating {len(to_probe)} endpoints...")
            try:
                budget = int(self.config.get('js_validate_budget', 240))

                def _val_progress(frac, msg):
                    # map validation onto the 0.97 -> 0.99 slice of the bar
                    if progress_callback:
                        try:
                            _emit(0.97 + 0.02 * min(max(frac, 0.0), 1.0), msg)
                        except Exception:
                            pass

                validator = SmartEndpointValidator(
                    allowed_hosts=self.scope_hosts,
                    global_concurrency=self.max_concurrent_requests,
                    per_host_concurrency=self.config.get('js_per_host_concurrency', 8),
                    timeout=int(self.config.get('js_validate_timeout', 8)),
                    verify_ssl=False,
                    drop_dead=True,
                    budget_seconds=budget,
                    progress_callback=_val_progress,
                )
                # Outer guard sits ABOVE the internal budget so the internal one
                # fires first and returns partial results; the outer wait_for is
                # only a last resort (it discards everything validated so far).
                to_probe = await asyncio.wait_for(
                    validator.validate(to_probe),
                    timeout=budget + 30,
                )
            except asyncio.TimeoutError:
                logger.warning("Endpoint validation exceeded its budget - returning unvalidated results")
            except Exception as e:
                logger.warning(f"Endpoint validation failed: {e}")

        if progress_callback:
            _emit(0.99, f"Building results ({len(passthrough) + len(to_probe)} endpoints)...")

        for req in passthrough + to_probe:
            results['total_endpoints'] += 1

            if req.get('websocket'):
                results['websocket_endpoints'].append(req)
            elif req.get('graphql_type'):
                results['graphql_endpoints'].append(req)
            elif 'source_map_available' in (req.get('suspicious_indicators') or []):
                results['source_map_flags'].append(req)
            else:
                results['endpoints'].append(req)

            sev = req.get('severity')
            if sev == 'critical':
                results['critical_endpoints'].append(req)
            elif sev == 'high':
                results['high_endpoints'].append(req)

        # Deduplicate secrets (full-value key so 50-char prefixes can't collide)
        seen_secrets = set()
        unique_secrets = []
        for s in results['secrets']:
            key = (s.get('type', 'unknown'), str(s.get('value', '')))
            if key not in seen_secrets:
                seen_secrets.add(key)
                unique_secrets.append(s)
        results['secrets'] = unique_secrets

        # Deduplicate API keys (mirror of secrets pass; chunk/main dup rows)
        if results['api_keys']:
            seen_ak = set()
            unique_ak = []
            for k in results['api_keys']:
                key = (k.get('type', ''), k.get('service', ''), str(k.get('value', '')))
                if key not in seen_ak:
                    seen_ak.add(key)
                    unique_ak.append(k)
            results['api_keys'] = unique_ak

        # ================================================================
        # v3.4 SECURITY LAYER (aggregate, over the merged endpoint IR)
        # ================================================================
        all_eps = passthrough + to_probe
        try:
            results['oauth_clients'] = js_security.oauth_analysis(all_eps)
        except Exception as e:
            logger.warning(f"OAuth analysis failed: {e}")
            results['oauth_clients'] = []
        try:
            results['jwt_correlation'] = js_security.jwt_correlation(results['jwts'], all_eps)
        except Exception as e:
            logger.warning(f"JWT correlation failed: {e}")
            results['jwt_correlation'] = []
        try:
            results['service_graph'] = js_security.service_graph(
                all_eps, results['jwts'], results['oauth_clients'])
        except Exception as e:
            logger.warning(f"Service graph build failed: {e}")
            results['service_graph'] = {'hosts': [], 'edges': [], 'auth_relationships': []}
        # strip full JWT tokens from the exposed results (correlation already ran)
        for j in results['jwts']:
            j.pop('token', None)

        if progress_callback:
            _emit(1.0, f"Done: {results['total_endpoints']} endpoints, "
                                   f"{len(results['secrets'])} secrets, "
                                   f"{len(results['oauth_clients'])} oauth clients, "
                                   f"{len(results['jwt_correlation'])} jwt correlations")

        logger.info(
            f"JS scan v3.1 complete. Files: {results['total_js_analyzed']}, "
            f"Vendor skipped: {results['vendor_skipped']}, "
            f"Timed out: {len(results['timed_out_files'])}, "
            f"Endpoints: {results['total_endpoints']}, "
            f"Secrets: {len(results['secrets'])}, "
            f"Proto vectors: {len(results['prototype_pollution'])}, "
            f"Dangerous: {len(results['dangerous_patterns'])}"
        )
        return results

    # =================================================================
    # EXTERNAL JS-URL DISCOVERY (subjs + getJS)
    # =================================================================

    @staticmethod
    def _which(binary: str) -> Optional[str]:
        import shutil as _shutil
        return _shutil.which(binary)

    async def _run_subjs(self, urls: List[str]) -> List[str]:
        """subjs: reads URLs/hosts on stdin, prints JS URLs on stdout."""
        binary = self._which('subjs')
        if not binary:
            return []
        payload = "\n".join(urls).encode()
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, '-c', str(self.tool_threads),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(payload),
                                            timeout=self.tool_timeout)
            found = [l.strip() for l in out.decode(errors='ignore').splitlines() if l.strip()]
            logger.info(f"subjs: {len(found)} JS URLs from {len(urls)} inputs")
            return found
        except asyncio.TimeoutError:
            logger.warning(f"subjs timed out after {self.tool_timeout}s")
        except Exception as e:
            logger.warning(f"subjs failed: {e}")
        return []

    async def _run_getjs(self, urls: List[str]) -> List[str]:
        """getJS: --input file, --complete makes relative URLs absolute."""
        binary = self._which('getJS') or self._which('getjs')
        if not binary:
            return []
        import tempfile, os as _os
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix='deepbug_getjs_', suffix='.txt')
            with _os.fdopen(fd, 'w') as fh:
                fh.write("\n".join(urls))
            proc = await asyncio.create_subprocess_exec(
                binary, '--input', tmp, '--complete',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=self.tool_timeout)
            found = [l.strip() for l in out.decode(errors='ignore').splitlines()
                     if l.strip().startswith(('http://', 'https://'))]
            logger.info(f"getJS: {len(found)} JS URLs from {len(urls)} inputs")
            return found
        except asyncio.TimeoutError:
            logger.warning(f"getJS timed out after {self.tool_timeout}s")
        except Exception as e:
            logger.warning(f"getJS failed: {e}")
        finally:
            if tmp:
                try:
                    _os.unlink(tmp)
                except Exception:
                    pass
        return []

    async def _gather_tool_js_urls(self, urls: List[str]) -> List[str]:
        """Run subjs and getJS concurrently - wall time is the slower of the two."""
        jobs = []
        if self.use_subjs:
            jobs.append(self._run_subjs(urls))
        if self.use_getjs:
            jobs.append(self._run_getjs(urls))
        if not jobs:
            return []
        out: List[str] = []
        for res in await asyncio.gather(*jobs, return_exceptions=True):
            if isinstance(res, list):
                out.extend(res)
        return out

    # =================================================================
    # URL CANONICALISATION / DEDUP
    # =================================================================

    @staticmethod
    def _canonical_key(url: str) -> Optional[Tuple[str, str]]:
        """
        Returns ((host[:port], path), scheme) with DEFAULT ports stripped, so
        https://h:443/a.js and http://h:80/a.js collapse to one entry instead
        of being downloaded and analyzed twice.
        """
        try:
            p = urlparse(url)
        except Exception:
            return None
        host = (p.hostname or '').lower()
        if not host:
            return None
        port = safe_port(p)
        if (p.scheme == 'https' and port == 443) or (p.scheme == 'http' and port == 80):
            port = None
        netloc = f"{host}:{port}" if port else host
        # Normalize dot-segments so /./a.js and /a.js are one file (and
        # cache-busted ?v=1 / ?v=2 variants collapse to a single entry).
        path = posixpath.normpath(p.path) if p.path else '/'
        return (f"{netloc}{path}", p.scheme)

    def _dedup_js_urls(self, urls: List[str]) -> List[str]:
        """Scheme/port-aware dedup. https wins when both schemes are present."""
        best: Dict[str, Tuple[str, str]] = {}
        order: List[str] = []
        for u in urls:
            if not u or not u.startswith(('http://', 'https://')):
                continue
            u = u.split('#', 1)[0]
            ck = self._canonical_key(u)
            if ck is None:
                continue
            key, scheme = ck
            cur = best.get(key)
            if cur is None:
                best[key] = (scheme, u)
                order.append(key)
            elif scheme == 'https' and cur[0] == 'http':
                best[key] = (scheme, u)
        return [best[k][1] for k in order]

    # =================================================================
    # STANDALONE VALIDATION (run separately from analysis)
    # =================================================================

    async def validate_endpoints_async(self, endpoints: List[Dict],
                                       progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Validate an already-discovered endpoint list. Kept separate from
        analysis so a slow or wedged validation can never cost you the scan -
        analysis results are complete and saveable before this ever runs.
        """
        if not endpoints:
            return []
        budget = int(self.config.get('js_validate_budget', 240))
        max_validate = int(self.config.get('js_max_validate', 300))

        conf_rank = {'high': 0, 'medium': 1, 'low': 2}
        queue = sorted(endpoints, key=lambda r: conf_rank.get(r.get('confidence', 'medium'), 1))
        overflow: List[Dict] = []
        if len(queue) > max_validate:
            overflow = queue[max_validate:]
            queue = queue[:max_validate]
            for r in overflow:
                r['live_status'] = 'unvalidated_capped'

        validator = SmartEndpointValidator(
            allowed_hosts=self.scope_hosts,
            global_concurrency=self.max_concurrent_requests,
            per_host_concurrency=self.config.get('js_per_host_concurrency', 8),
            timeout=int(self.config.get('js_validate_timeout', 8)),
            verify_ssl=False,
            drop_dead=True,
            budget_seconds=budget,
            progress_callback=progress_callback,
        )
        try:
            done = await asyncio.wait_for(validator.validate(queue), timeout=budget + 30)
        except asyncio.TimeoutError:
            logger.warning("Standalone validation hit its hard guard - returning unvalidated")
            done = queue
        except Exception as e:
            logger.warning(f"Standalone validation failed: {e}")
            done = queue
        return done + overflow

    def validate_endpoints(self, endpoints: List[Dict],
                           progress_callback: Optional[Callable] = None) -> List[Dict]:
        return _run_coro_sync(self.validate_endpoints_async(endpoints, progress_callback))

    async def _gather_archived_js_urls(self, hosts: List[str]) -> List[str]:
        """
        Historical .js URLs per host. Prefers the waybackurls binary if installed;
        falls back to the Wayback CDX API directly (no external tool needed).
        """
        import shutil as _shutil
        collected: List[str] = []

        waybackurls = _shutil.which('waybackurls')
        if waybackurls:
            for host in hosts:
                try:
                    # exec + stdin PIPE (never shell-interpolate host - host is
                    # attacker-influenced and would be a command-injection sink)
                    proc = await asyncio.create_subprocess_exec(
                        waybackurls,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(host.encode() + b'\n'), timeout=60)
                    collected.extend(u.strip() for u in stdout.decode(errors='ignore').splitlines()
                                     if '.js' in u)
                except Exception as e:
                    logger.debug(f"waybackurls failed for {host}: {e}")
        else:
            cdx = ("https://web.archive.org/cdx/search/cdx?url=*.{h}/*"
                   "&output=text&fl=original&collapse=urlkey"
                   "&filter=original:.*\\.js(\\?|$)&limit={lim}")
            async with aiohttp.ClientSession(headers=self.headers, max_line_size=65536, max_field_size=65536) as session:
                for host in hosts:
                    try:
                        async with session.get(cdx.format(h=host, lim=self.max_archive_urls),
                                               timeout=aiohttp.ClientTimeout(total=30)) as resp:
                            if resp.status == 200:
                                text = await resp.text(errors='ignore')
                                collected.extend(u.strip() for u in text.splitlines() if u.strip())
                    except Exception as e:
                        logger.debug(f"CDX query failed for {host}: {e}")

        return list(dict.fromkeys(collected))[:self.max_archive_urls]

    def _extract_endpoints_from_text(self, content: str, source_url: str) -> List[Dict]:
        """
        AST explorer (size- AND minification-guarded) + regex extractor, merged.

        The AST is skipped for minified code: esprima costs ~38 s/MB and a
        minified bundle yields little the regex extractor misses.
        """
        api_requests = []
        avg_line = self._is_minified(content)
        size_guard = len(content) > self.ast_max_bytes
        minified_guard = self.ast_skip_minified and avg_line > self.minified_line_len
        if size_guard or minified_guard:
            if self.ast_windowed:
                # v3.3: minified/oversized bundles no longer skip the AST
                # entirely - a bounded window (first ast_max_bytes) is parsed,
                # so minified code still yields structured endpoint calls.
                window = content[:self.ast_max_bytes]
                if len(window) >= 512:
                    try:
                        api_requests = self.explorer.analyze_js(window, source_url=source_url)
                        logger.debug(f"Windowed AST ({len(window)}B) for "
                                     f"{'minified' if minified_guard else 'oversized'}: {source_url}")
                    except Exception as e:
                        logger.warning(f"Windowed AST explorer failed for {source_url}: {e}")
            else:
                logger.debug(f"AST skipped (size {len(content)}B > {self.ast_max_bytes}B): {source_url}"
                             if size_guard else
                             f"AST skipped (minified, avg line {avg_line:.0f} chars): {source_url}")
        else:
            try:
                api_requests = self.explorer.analyze_js(content, source_url=source_url)
            except Exception as e:
                logger.warning(f"AST explorer failed for {source_url}: {e}")

        extra = self.extractor.extract(content, source_url=source_url)
        merged = merge_endpoints(api_requests, extra, source_url=source_url)
        return sanitize_endpoints(merged)

    # =================================================================
    # v3.2: SPA ROUTES / NON-PROD HOSTS / JWT / VULN LIBS
    # =================================================================

    def _sem_req_to_endpoint(self, req: Dict, source_url: str) -> Optional[Dict]:
        """Convert a js_semantic RequestIR dict into an enriched endpoint record
        carrying security context (auth/params/body/objects/signals)."""
        if not (req.get('url') or req.get('url_template')):
            return None
        url = req.get('url') or ''
        if not url.startswith(('http://', 'https://')):
            if (req.get('url_template') or '').startswith('${'):
                # dynamic root - keep canonical path (e.g. /accounts/{id}/invoices)
                url = req.get('canonical_path') or req.get('url_template') or ''
            else:
                url = urljoin(source_url, req.get('url_template') or req.get('canonical_path') or '')
        auth = req.get('auth') or {}
        ep = {
            'url': url,
            'source_url': source_url,
            'method': (req.get('method') or 'GET').upper(),
            'severity': 'info',
            'confidence': 'medium',
            'extraction_method': 'ast_semantic',
            'url_template': req.get('url_template', ''),
            'canonical_path': req.get('canonical_path', ''),
            'content_type': req.get('content_type'),
            'headers': req.get('headers') or {},
            'body': req.get('body') or {},
            'query_params': req.get('query_params') or {},
            'path_params': req.get('path_params') or [],
            'params': req.get('params') or [],
            'auth': auth,
            'websocket': bool(req.get('websocket')),
            'file_upload': bool(req.get('file_upload')),
            'line': (req.get('source') or {}).get('line', 0),
            'function': (req.get('source') or {}).get('function', ''),
            'raw': req.get('raw', ''),
            'suspicious_indicators': [],
        }
        if auth.get('type'):
            ep['auth'] = auth
        # attach client_secret / oauth material for downstream correlation
        body = ep.get('body') or {}
        for k in ('client_secret', 'client_id', 'grant_type', 'audience', 'scope', 'redirect_uri'):
            if k in body and 'client_secret' not in (ep.get('suspicious_indicators') or []):
                pass
        # object/tenant/ssrf classification + security signals + interest
        ep = js_security.classify_endpoint(ep)
        # websocket endpoint flag consumed by flatten
        if ep.get('websocket'):
            ep['websocket'] = True
        return ep

    def _detect_spa_routes(self, js_content: str, source_url: str) -> List[Dict]:
        """Extract client-side router paths - forced-browsing candidates."""
        findings, seen = [], set()
        for pat in self._compiled_routes:
            for m in self._capped_finditer(pat, js_content):
                route = m.group(1)
                if route in seen or not route.startswith('/') or route == '/':
                    continue
                seen.add(route)
                interesting = bool(ROUTE_ADMIN_KEYWORDS.search(route))
                findings.append({
                    'type': 'spa_route',
                    'route': route,
                    'interesting': interesting,
                    'source': source_url,
                    'severity': 'MEDIUM' if interesting else 'INFO',
                    'note': 'probe server-side: authZ gaps on client-hidden routes'
                    if interesting else '',
                })
        return findings

    def _detect_nonprod_hosts(self, js_content: str, source_url: str) -> List[Dict]:
        """Non-prod subdomains / RFC1918 IPs / localhost ports leaked in JS."""
        findings, seen = [], set()
        for pat, kind in self._compiled_nonprod:
            for m in self._capped_finditer(pat, js_content):
                host = m.group(1)
                if host in seen:
                    continue
                seen.add(host)
                sev = 'MEDIUM' if kind == 'nonprod_subdomain' else 'LOW'
                findings.append({
                    'type': 'nonprod_host',
                    'indicator': kind,
                    'host': host,
                    'source': source_url,
                    'severity': sev,
                    'note': 'scope-expansion lead: check if in program scope / weaker env',
                })
        return findings

    def _detect_jwts(self, js_content: str, source_url: str) -> List[Dict]:
        """Harvest hardcoded JWTs; decode header+payload, flag weak algs/claims."""
        import base64
        findings, seen = [], set()

        def _b64url_decode(seg: str) -> Optional[Dict]:
            try:
                seg += '=' * (-len(seg) % 4)
                return json.loads(base64.urlsafe_b64decode(seg.encode()))
            except Exception:
                return None

        sev_rank = {'INFO': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3}
        for m in self._capped_finditer(JWT_PATTERN, js_content):
            token = m.group(1)
            if token in seen:
                continue
            seen.add(token)
            parts = token.split('.')
            header = _b64url_decode(parts[0]) or {}
            payload = _b64url_decode(parts[1]) if len(parts) > 1 else None
            alg = str(header.get('alg', '')).lower()
            notes, severity = [], 'INFO'
            if alg in ('none', ''):
                notes.append('alg:none/empty - signature bypass territory')
                severity = 'HIGH'
            elif alg == 'hs256':
                notes.append('HS256 - try weak-secret brute / alg confusion if RS256 expected')
                severity = 'MEDIUM'
            if payload:
                for claim in ('admin', 'role', 'is_admin', 'scope'):
                    v = payload.get(claim)
                    if v not in (None, False, '', 'user'):
                        notes.append(f"interesting claim {claim}={v!r}")
                        if sev_rank[severity] < sev_rank['MEDIUM']:
                            severity = 'MEDIUM'
                if payload.get('exp'):
                    notes.append(f"exp={payload['exp']}")
            findings.append({
                'type': 'hardcoded_jwt',
                'token_preview': token[:40] + '...',
                'token': token,
                'alg': header.get('alg', 'unknown'),
                'payload_keys': ', '.join(list(payload.keys())[:8]) if payload else '',
                'notes': '; '.join(notes),
                'source': source_url,
                'severity': severity,
            })
        return findings

    @staticmethod
    def _version_tuple(v: str) -> Tuple[int, ...]:
        try:
            return tuple(int(x) for x in re.findall(r'\d+', v)[:3])
        except Exception:
            return ()

    @classmethod
    def _in_version_range(cls, version: str, lo: Optional[str], hi: Optional[str]) -> bool:
        vt = cls._version_tuple(version)
        if not vt:
            return False
        vt3 = (vt + (0, 0, 0))[:3]
        if lo is not None and vt3 < (cls._version_tuple(lo) + (0, 0, 0))[:3]:
            return False
        if hi is not None and vt3 >= (cls._version_tuple(hi) + (0, 0, 0))[:3]:
            return False
        return True

    def _check_vulnerable_libraries(self, libraries: List[Dict]) -> List[Dict]:
        """retire.js-lite: match detected vendor lib versions against CVE ranges."""
        findings, seen = [], set()
        for lib in libraries:
            name, version = lib.get('library'), lib.get('version', 'unknown')
            if version == 'unknown' or name not in VULNERABLE_LIBRARIES:
                continue
            for lo, hi, cve, sev in VULNERABLE_LIBRARIES[name]:
                if self._in_version_range(version, lo, hi):
                    key = (name, version, cve)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        'type': 'vulnerable_library',
                        'library': name,
                        'version': version,
                        'cve': cve,
                        'severity': sev,
                        'source': lib.get('source', ''),
                    })
        return findings

    @staticmethod
    def identify_vendor_lib(url: str, content: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Return {'library', 'version', 'matched'} if the file is a known
        third-party vendor lib, else None.
        """
        path = urlparse(url).path or url
        fname = path.rsplit('/', 1)[-1].lower()
        head = content[:3072] if content else ''
        for name, fname_re, banner_re, ver_re in VENDOR_LIB_SIGNATURES:
            matched = None
            if re.search(fname_re, fname, re.IGNORECASE):
                matched = 'filename'
            elif head and banner_re and re.search(banner_re, head, re.IGNORECASE):
                matched = 'banner'
            if not matched:
                continue
            version = None
            if ver_re and head:
                vm = re.search(ver_re, head, re.IGNORECASE)
                if vm and vm.groups():
                    version = vm.group(1)
            return {'library': name, 'version': version or 'unknown', 'matched': matched}
        return None

    def _analyze_single_file(self, url: str, js_content: str) -> Dict[str, Any]:
        """ALL per-file CPU analysis in one call - designed to run in a worker thread."""
        out = {'endpoints': [], 'maps': set(), 'chunks': set(), 'specs': set(), 'ui': set(),
               'secrets': [], 'api_keys': [], 'frameworks': [], 'proto': [], 'clobbing': [], 'postmsg': [],
               'dangerous': [], 'jsonp': [], 'rendering': [], 'csp': [], 'library': None,
               'routes': [], 'nonprod': [], 'jwts': [],
               'ws_protocol': [], 'service_workers': [], 'push_keys': [],
               'ssrf_candidates': [], 'error_services': [], 'auth_guards': [], 'taint': [],
               'file': {'url': url, 'size': len(js_content),
                        'size_human': self._human_readable_size(len(js_content))}}

        # Persist the fetched body (capped at a smaller store window so the
        # results dict can't balloon to ~1GB for 500x2MB files). The scan
        # itself always uses the full js_content; only the cached preview is
        # truncated. content_hash lets downstream re-scans key a disk cache.
        out['file']['content'] = js_content[:self.store_max_bytes]
        if js_content:
            try:
                out['file']['content_hash'] = hashlib.sha256(
                    js_content.encode('utf-8', 'ignore')).hexdigest()[:16]
                out['file']['full_size'] = len(js_content)
            except Exception:
                pass

        # ---- Vendor identification (always runs so library vuln-checking and
        # the framework report work even when vendor skipping is disabled) ----
        lib = self.identify_vendor_lib(url, js_content)
        if lib:
            lib.update({'source': url, 'severity': 'INFO', 'type': 'vendor_lib',
                        'size': len(js_content)})
            out['library'] = lib
            out['file']['vendor'] = f"{lib['library']} {lib['version']}"
            if self.skip_vendor:
                logger.info(f"Vendor JS skipped: {url} [{lib['library']} {lib['version']} | {lib['matched']}]")
                return out

        out['endpoints'] = self._extract_endpoints_from_text(js_content, url)

        # v3.4: semantic AST extraction - enriched IR (auth/params/body/objects).
        try:
            sem = self.semantic.extract(js_content[:self.scan_max_bytes], url)
            out['formdata'] = sem['formdata']
            for req in sem['requests']:
                ep = self._sem_req_to_endpoint(req, url)
                if ep:
                    out['endpoints'].append(ep)
        except Exception as e:
            logger.warning(f"Semantic extraction failed for {url}: {e}")
            out['formdata'] = {}

        # Coverage feeders (downloaded in the second pass)
        if self.deep_coverage:
            smap = extract_sourcemap_url(js_content, url)
            if smap and (smap.startswith('data:') or self._host_in_scope(smap)):
                out['maps'].add(smap)
            for chunk in enumerate_webpack_chunks(js_content, url):
                if self._host_in_scope(chunk):
                    out['chunks'].add(chunk)
            specs, ui = find_swagger_specs(js_content, url)
            for spec_url in specs:
                if self._host_in_scope(spec_url):
                    out['specs'].add(spec_url)
            if ui:
                p = urlparse(url)
                out['ui'].add(f"{p.scheme}://{p.netloc}")

        # Pattern detectors scan a capped window with a shared line index.
        scan = js_content[:self.scan_max_bytes]
        line_index = self._line_index(scan)

        out['secrets'] = self._extract_secrets(scan, source_url=url)
        if self.api_key_scanner is not None:
            out['api_keys'] = self.api_key_scanner.scan_js_content(scan, source_url=url)
        else:
            out['api_keys'] = []
        out['frameworks'] = self._detect_frameworks(scan, url)
        out['proto'] = self._detect_prototype_pollution(scan, url, line_index)
        out['clobbing'] = self._detect_dom_clobbering(scan, url, line_index)
        out['postmsg'] = self._detect_postmessage_issues(scan, url, line_index)
        out['dangerous'] = self._detect_dangerous_patterns(scan, url, line_index)
        out['jsonp'] = self._detect_jsonp(scan, url, line_index)
        out['rendering'] = self._detect_dynamic_rendering(scan, url)
        out['csp'] = self._detect_csp_gadgets(scan, url, line_index)
        # v3.2 advanced recon layer (capped like every other detector)
        if self.detect_routes:
            out['routes'] = self._detect_spa_routes(scan, url)
        if self.detect_nonprod:
            out['nonprod'] = self._detect_nonprod_hosts(scan, url)
        if self.detect_jwts:
            out['jwts'] = self._detect_jwts(scan, url)
        # v3.6.1: protocol intel (ws/service-worker/push/ssrf/error-services/
        # client auth guards) + source->sink taint candidates
        try:
            proto = js_protocol.scan_js(scan, url)
            out['ws_protocol'] = proto.get('ws_protocol', [])
            out['service_workers'] = proto.get('service_workers', [])
            out['push_keys'] = proto.get('push_keys', [])
            out['ssrf_candidates'] = proto.get('ssrf_candidates', [])
            out['error_services'] = proto.get('error_services', [])
            out['auth_guards'] = proto.get('auth_guards', [])
        except Exception as e:
            logger.debug(f"js_protocol scan failed for {url}: {e}")
            for k in ('ws_protocol', 'service_workers', 'push_keys',
                      'ssrf_candidates', 'error_services', 'auth_guards'):
                out[k] = []
        try:
            out['taint'] = js_taint.scan_taint(scan, url)
        except Exception as e:
            logger.debug(f"js_taint scan failed for {url}: {e}")
            out['taint'] = []
        return out

    def analyze_js_urls(self, js_urls: List[str],
                        progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        return _run_coro_sync(self.analyze_js_urls_async(js_urls, progress_callback))

    # =================================================================
    # PROJECT WORKFLOW
    # =================================================================

    async def analyze_js_for_project_async(self, urls: List[str],
                                              progress_callback: Optional[Callable] = None,
                                              validate: Optional[bool] = None) -> Dict[str, pd.DataFrame]:
        all_js_urls = []

        _conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, connector=_conn, max_line_size=65536, max_field_size=65536) as session:
            tasks = [self._fetch_single_html_and_extract(session, url) for url in urls]
            gathered = await asyncio.gather(*tasks)
            list_of_lists = [g[0] for g in gathered]
            seed_coverage = [g[1] for g in gathered]
            for lst in list_of_lists:
                all_js_urls.extend(lst)

        # --- external discovery tools (subjs + getJS, concurrent) ---
        if (self.use_subjs or self.use_getjs) and urls:
            if progress_callback:
                progress_callback(0.01, "Discovering JS with subjs + getJS...")
            try:
                tool_urls = await self._gather_tool_js_urls(list(urls))
                if tool_urls:
                    all_js_urls.extend(tool_urls)
            except Exception as e:
                logger.warning(f"External JS discovery failed (continuing): {e}")

        all_js_urls = self._dedup_js_urls(all_js_urls)

        if self.use_archive and self.scope_hosts:
            if progress_callback:
                progress_callback(0.02, "Gathering archived JS URLs (Wayback)...")
            try:
                archived = await self._gather_archived_js_urls(sorted(self.scope_hosts))
                fresh = [u for u in archived if u not in all_js_urls]
                if fresh:
                    logger.info(f"Archived JS: +{len(fresh)} historical .js URLs")
                    all_js_urls.extend(fresh)
            except Exception as e:
                logger.warning(f"Archived JS gathering failed (continuing): {e}")

        all_js_urls = self._dedup_js_urls(all_js_urls)
        if self.scope_hosts:
            all_js_urls = [u for u in all_js_urls if self._host_in_scope(u)]
        logger.info(f"JS discovery: {len(all_js_urls)} unique JS URLs after dedup")
        if not all_js_urls:
            logger.info("No JS targets matched.")
            return self._results_to_dataframes({'coverage': seed_coverage})

        results = await self.analyze_js_urls_async(all_js_urls, progress_callback, validate=validate)
        results.setdefault('coverage', []).extend(seed_coverage)
        return self._results_to_dataframes(results)

    def analyze_js_for_project(self, urls: List[str],
                               progress_callback: Optional[Callable] = None,
                               validate: Optional[bool] = None) -> Dict[str, pd.DataFrame]:
        return _run_coro_sync(self.analyze_js_for_project_async(urls, progress_callback, validate))

    # =================================================================
    # DATAFRAME CONVERSION
    # =================================================================

    def _results_to_dataframes(self, results: Dict[str, Any]) -> Dict[str, pd.DataFrame]:
        js_files_df = pd.DataFrame(results.get('js_files', []))

        endpoints_rows = []
        for req in results.get('endpoints', []):
            endpoints_rows.append(self._flatten_api_request(req))
        for req in results.get('graphql_endpoints', []):
            row = self._flatten_api_request(req)
            row['category'] = 'graphql'
            endpoints_rows.append(row)
        for req in results.get('websocket_endpoints', []):
            row = self._flatten_api_request(req)
            row['category'] = 'websocket'
            endpoints_rows.append(row)

        endpoints_df = pd.DataFrame(endpoints_rows)

        secrets_data = results.get('secrets', [])
        if secrets_data:
            normalized_secrets = []
            for s in secrets_data:
                normalized_secrets.append({
                    'type': s.get('type', 'Unknown'),
                    'provider': s.get('provider', 'Unknown'),
                    'pattern_name': s.get('pattern_name', ''),
                    'value': s.get('value', ''),
                    'severity': s.get('severity', 'MEDIUM'),
                    'line': s.get('line', 0),
                    'context': s.get('context', ''),
                    'source': s.get('source', ''),
                    'confidence': s.get('confidence', 'medium'),
                    'entropy': s.get('entropy', 0),
                })
            secrets_df = pd.DataFrame(normalized_secrets)
        else:
            secrets_df = pd.DataFrame(columns=[
                'type', 'provider', 'pattern_name', 'value', 'severity',
                'line', 'context', 'source', 'confidence', 'entropy'
            ])

        api_keys_data = results.get('api_keys', [])
        if api_keys_data:
            api_keys_df = pd.DataFrame([{
                'type': k.get('type', 'API Key'),
                'service': k.get('service', ''),
                'key_name': k.get('key_name', ''),
                'value': k.get('value', ''),
                'severity': k.get('severity', 'MEDIUM'),
                'line': k.get('line', 0),
                'context': k.get('context', ''),
                'source': k.get('source', ''),
                'confidence': k.get('confidence', 'high'),
                'entropy': k.get('entropy', 0),
                'verification': k.get('verification', ''),
            } for k in api_keys_data])
        else:
            api_keys_df = pd.DataFrame(columns=[
                'type', 'service', 'key_name', 'value', 'severity',
                'line', 'context', 'source', 'confidence', 'entropy', 'verification'
            ])

        sourcemap_rows = []
        for req in results.get('source_map_flags', []):
            sourcemap_rows.append({
                'source_url': req.get('source_url', ''),
                'source_map_url': req.get('url', ''),
                'confidence': req.get('confidence', ''),
            })
        sourcemap_df = pd.DataFrame(sourcemap_rows)

        priority_rows = []
        for req in results.get('critical_endpoints', []):
            row = self._flatten_api_request(req)
            row['priority'] = 'CRITICAL'
            priority_rows.append(row)
        for req in results.get('high_endpoints', []):
            row = self._flatten_api_request(req)
            row['priority'] = 'HIGH'
            priority_rows.append(row)
        priority_df = pd.DataFrame(priority_rows)

        graphql_rows = []
        for req in results.get('graphql_endpoints', []):
            graphql_rows.append({
                'source_url': req.get('source_url', ''),
                'endpoint': req.get('url', ''),
                'graphql_type': req.get('graphql_type', ''),
                'operation_name': req.get('graphql_operation', ''),
                'method': req.get('method', ''),
                'auth': req.get('auth', ''),
                'severity': req.get('severity', ''),
                'suspicious_indicators': ', '.join(req.get('suspicious_indicators', [])),
            })
        graphql_df = pd.DataFrame(graphql_rows)

        ws_rows = []
        for req in results.get('websocket_endpoints', []):
            ws_rows.append({
                'source_url': req.get('source_url', ''),
                'endpoint': req.get('url', ''),
                'protocol': req.get('headers', {}).get('Sec-WebSocket-Protocol', ''),
                'auth': req.get('auth', ''),
                'severity': req.get('severity', ''),
                'suspicious_indicators': ', '.join(req.get('suspicious_indicators', [])),
            })
        websocket_df = pd.DataFrame(ws_rows)

        frameworks_df = pd.DataFrame(results.get('frameworks', []))
        proto_df = pd.DataFrame(results.get('prototype_pollution', []))
        clobber_df = pd.DataFrame(results.get('dom_clobbering', []))
        postmsg_df = pd.DataFrame(results.get('postmessage_issues', []))
        dangerous_df = pd.DataFrame(results.get('dangerous_patterns', []))
        jsonp_df = pd.DataFrame(results.get('jsonp_endpoints', []))
        rendering_df = pd.DataFrame(results.get('dynamic_rendering', []))
        csp_df = pd.DataFrame(results.get('csp_gadgets', []))
        libraries_df = pd.DataFrame(results.get('libraries', []))

        # v3.2 dataframes
        routes_df = pd.DataFrame(results.get('spa_routes', []))
        nonprod_df = pd.DataFrame(results.get('nonprod_hosts', []))
        jwts_df = pd.DataFrame(results.get('jwts', []))
        vuln_libs = (self._check_vulnerable_libraries(results.get('libraries', []))
                     if self.check_vuln_libs else [])
        vuln_libs_df = pd.DataFrame(vuln_libs)

        # v3.3: coverage report - every fetch outcome, no silent drops
        coverage_df = pd.DataFrame(results.get('coverage', []))
        if coverage_df.empty:
            coverage_df = pd.DataFrame(columns=[
                'url', 'kind', 'outcome', 'status', 'size', 'ms', 'note'])

        # v3.4: security frames
        oauth_df = pd.DataFrame(results.get('oauth_clients', []))
        if oauth_df.empty:
            oauth_df = pd.DataFrame(columns=[
                'host', 'endpoint', 'method', 'grant_type', 'client_id',
                'client_secret_exposed', 'secret_component', 'audience',
                'scopes', 'redirect_uri', 'pkce', 'source'])
        jwt_rel_df = pd.DataFrame(results.get('jwt_correlation', []))
        if jwt_rel_df.empty:
            jwt_rel_df = pd.DataFrame(columns=[
                'alg', 'issuer', 'audience', 'subject', 'azp', 'scopes',
                'flags', 'related_hosts', 'source', 'severity_evidence'])
        oidc_df = pd.DataFrame(results.get('oidc_config', []))
        if oidc_df.empty:
            oidc_df = pd.DataFrame(columns=[
                'issuer', 'authorization_endpoint', 'token_endpoint',
                'userinfo_endpoint', 'jwks_uri', 'host',
                'grant_types_supported', 'scopes_supported', 'jwks_keys'])

        # v3.6.1 protocol / taint frames
        ws_proto_df = pd.DataFrame(results.get('ws_protocol', []))
        sw_df = pd.DataFrame(results.get('service_workers', []))
        push_df = pd.DataFrame(results.get('push_keys', []))
        ssrf_df2 = pd.DataFrame(results.get('ssrf_candidates', []))
        errsvc_df = pd.DataFrame(results.get('error_services', []))
        guards_df = pd.DataFrame(results.get('auth_guards', []))
        taint_df = pd.DataFrame(results.get('taint', []))
        for _d in (ws_proto_df, sw_df, push_df, ssrf_df2, errsvc_df, guards_df, taint_df):
            if _d.empty:
                for _c in ('type', 'value', 'line', 'context', 'source', 'severity', 'confidence'):
                    if _c not in _d.columns:
                        _d[_c] = ''
        sg = results.get('service_graph') or {}
        hosts_df = pd.DataFrame(sg.get('hosts', []))
        edges_df = pd.DataFrame(sg.get('edges', []))
        rel_df = pd.DataFrame(sg.get('auth_relationships', []))
        for _df, _cols in ((hosts_df, ['host', 'endpoints', 'oauth', 'accepts', 'referenced_by']),
                           (edges_df, ['from', 'to', 'kind']),
                           (rel_df, ['from', 'to', 'via', 'auth'])):
            if _df.empty:
                _df = pd.DataFrame(columns=_cols)
        host_df = hosts_df if not hosts_df.empty else pd.DataFrame(columns=['host', 'endpoints', 'oauth', 'accepts', 'referenced_by'])
        edge_df = edges_df if not edges_df.empty else pd.DataFrame(columns=['from', 'to', 'kind'])
        authrel_df = rel_df if not rel_df.empty else pd.DataFrame(columns=['from', 'to', 'via', 'auth'])

        return {
            'js_files': js_files_df,
            'js_discovered_endpoints': endpoints_df,
            'js_sensitive_data_findings': secrets_df,
            'js_api_keys': api_keys_df,
            'js_source_maps': sourcemap_df,
            'js_priority_endpoints': priority_df,
            'js_graphql_endpoints': graphql_df,
            'js_websocket_endpoints': websocket_df,
            'js_frameworks': frameworks_df,
            'js_prototype_pollution': proto_df,
            'js_dom_clobbering': clobber_df,
            'js_postmessage_issues': postmsg_df,
            'js_dangerous_patterns': dangerous_df,
            'js_jsonp_endpoints': jsonp_df,
            'js_dynamic_rendering': rendering_df,
            'js_csp_gadgets': csp_df,
            'js_libraries': libraries_df,
            'js_spa_routes': routes_df,
            'js_nonprod_hosts': nonprod_df,
            'js_jwts': jwts_df,
            'js_vulnerable_libs': vuln_libs_df,
            'js_coverage': coverage_df,
            'js_oauth_clients': oauth_df,
            'js_jwt_correlation': jwt_rel_df,
            'js_service_graph_hosts': host_df,
            'js_service_graph_edges': edge_df,
            'js_auth_relationships': authrel_df,
            'js_oidc_config': oidc_df,
            'js_ws_protocol': ws_proto_df,
            'js_service_workers': sw_df,
            'js_push_keys': push_df,
            'js_ssrf_candidates': ssrf_df2,
            'js_error_services': errsvc_df,
            'js_auth_guards': guards_df,
            'js_taint_candidates': taint_df,
        }

    def _flatten_api_request(self, req: Dict) -> Dict:
        return {
            'source_url': req.get('source_url', ''),
            'endpoint': req.get('url', ''),
            'method': req.get('method', ''),
            'auth': req.get('auth', ''),
            'graphql_type': req.get('graphql_type', ''),
            'graphql_operation': req.get('graphql_operation', ''),
            'websocket': req.get('websocket', False),
            'cors_with_credentials': req.get('cors_with_credentials', False),
            'severity': req.get('severity', 'info'),
            'confidence': req.get('confidence', ''),
            'extraction_method': req.get('extraction_method', ''),
            'alive': req.get('alive'),
            'live_status': req.get('live_status', ''),
            'allow_methods': req.get('allow_methods', ''),
            'soft_404': req.get('soft_404', False),
            'suspicious_indicators': ', '.join(req.get('suspicious_indicators', [])),
            'query_params': json.dumps(req.get('query_params', {})),
            'body_schema': json.dumps(req.get('body', req.get('body_schema', {}))),
            'headers': json.dumps(req.get('headers', {})),
            # v3.4 semantic enrichment
            'url_template': req.get('url_template', ''),
            'canonical_path': req.get('canonical_path', ''),
            'original_src': req.get('original_src', ''),
            'content_type': req.get('content_type', ''),
            'auth_type': (req.get('auth') or {}).get('type', '') if isinstance(req.get('auth'), dict) else req.get('auth', ''),
            'auth_source': (req.get('auth') or {}).get('source', '') if isinstance(req.get('auth'), dict) else '',
            'objects': '; '.join(f"{o.get('name')}({o.get('class')})" for o in (req.get('objects') or [])),
            'security_signals': '; '.join(req.get('security_signals') or []),
            'interest_score': req.get('interest_score', 0),
            'line': req.get('line', 0),
            'function': req.get('function', ''),
            'file_upload': req.get('file_upload', False),
        }

    def _empty_results(self) -> Dict[str, pd.DataFrame]:
        return {
            'js_files': pd.DataFrame(columns=['url', 'size', 'size_human']),
            'js_discovered_endpoints': pd.DataFrame(columns=[
                'source_url', 'endpoint', 'method', 'auth', 'graphql_type',
                'graphql_operation', 'websocket', 'cors_with_credentials',
                'severity', 'confidence', 'extraction_method',
                'alive', 'live_status', 'allow_methods', 'soft_404',
                'suspicious_indicators', 'query_params', 'body_schema', 'headers',
                'url_template', 'canonical_path', 'content_type', 'auth_type',
                'auth_source', 'objects', 'security_signals', 'interest_score',
                'line', 'function', 'file_upload'
            ]),
            'js_sensitive_data_findings': pd.DataFrame(columns=[
                'type', 'provider', 'pattern_name', 'value', 'severity',
                'line', 'context', 'source', 'confidence', 'entropy'
            ]),
            'js_api_keys': pd.DataFrame(columns=[
                'type', 'service', 'key_name', 'value', 'severity',
                'line', 'context', 'source', 'confidence', 'entropy', 'verification'
            ]),
            'js_source_maps': pd.DataFrame(columns=['source_url', 'source_map_url', 'confidence']),
            'js_priority_endpoints': pd.DataFrame(columns=[
                'source_url', 'endpoint', 'method', 'auth', 'priority',
                'severity', 'suspicious_indicators', 'confidence'
            ]),
            'js_graphql_endpoints': pd.DataFrame(columns=[
                'source_url', 'endpoint', 'graphql_type', 'operation_name',
                'method', 'auth', 'severity', 'suspicious_indicators'
            ]),
            'js_websocket_endpoints': pd.DataFrame(columns=[
                'source_url', 'endpoint', 'protocol', 'auth',
                'severity', 'suspicious_indicators'
            ]),
            'js_frameworks': pd.DataFrame(columns=['type', 'framework', 'version', 'source', 'severity']),
            'js_prototype_pollution': pd.DataFrame(columns=['type', 'pattern', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_dom_clobbering': pd.DataFrame(columns=['type', 'pattern', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_postmessage_issues': pd.DataFrame(columns=['type', 'pattern', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_dangerous_patterns': pd.DataFrame(columns=['type', 'pattern_name', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_jsonp_endpoints': pd.DataFrame(columns=['type', 'callback', 'line', 'source', 'severity', 'confidence']),
            'js_dynamic_rendering': pd.DataFrame(columns=['type', 'engine', 'source', 'severity', 'confidence', 'note']),
            'js_csp_gadgets': pd.DataFrame(columns=['type', 'pattern', 'line', 'context', 'source', 'severity', 'confidence', 'note']),
            'js_libraries': pd.DataFrame(columns=['type', 'library', 'version', 'matched', 'source', 'severity', 'size']),
            'js_spa_routes': pd.DataFrame(columns=['type', 'route', 'interesting', 'source', 'severity', 'note']),
            'js_nonprod_hosts': pd.DataFrame(columns=['type', 'indicator', 'host', 'source', 'severity', 'note']),
            'js_jwts': pd.DataFrame(columns=['type', 'token_preview', 'alg', 'payload_keys', 'notes', 'source', 'severity']),
            'js_vulnerable_libs': pd.DataFrame(columns=['type', 'library', 'version', 'cve', 'severity', 'source']),
            'js_coverage': pd.DataFrame(columns=['url', 'kind', 'outcome', 'status', 'size', 'ms', 'note']),
            'js_oauth_clients': pd.DataFrame(columns=[
                'host', 'endpoint', 'method', 'grant_type', 'client_id',
                'client_secret_exposed', 'secret_component', 'audience',
                'scopes', 'redirect_uri', 'pkce', 'source']),
            'js_jwt_correlation': pd.DataFrame(columns=[
                'alg', 'issuer', 'audience', 'subject', 'azp', 'scopes',
                'flags', 'related_hosts', 'source', 'severity_evidence']),
            'js_service_graph_hosts': pd.DataFrame(columns=['host', 'endpoints', 'oauth', 'accepts', 'referenced_by']),
            'js_service_graph_edges': pd.DataFrame(columns=['from', 'to', 'kind']),
            'js_auth_relationships': pd.DataFrame(columns=['from', 'to', 'via', 'auth']),
            'js_oidc_config': pd.DataFrame(columns=[
                'issuer', 'authorization_endpoint', 'token_endpoint',
                'userinfo_endpoint', 'jwks_uri', 'host',
                'grant_types_supported', 'scopes_supported', 'jwks_keys']),
            'js_ws_protocol': pd.DataFrame(columns=['type', 'value', 'event', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_service_workers': pd.DataFrame(columns=['type', 'value', 'line', 'context', 'source', 'severity', 'confidence', 'note']),
            'js_push_keys': pd.DataFrame(columns=['type', 'value', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_ssrf_candidates': pd.DataFrame(columns=['type', 'value', 'line', 'context', 'source', 'severity', 'confidence', 'note']),
            'js_error_services': pd.DataFrame(columns=['type', 'service', 'value', 'line', 'context', 'source', 'severity', 'confidence']),
            'js_auth_guards': pd.DataFrame(columns=['type', 'value', 'line', 'context', 'source', 'severity', 'confidence', 'note']),
            'js_taint_candidates': pd.DataFrame(columns=['type', 'sink', 'source', 'function', 'line', 'context', 'source_url', 'severity', 'confidence', 'note']),
        }

    @staticmethod
    def _human_readable_size(size_bytes: int) -> str:
        if size_bytes == 0:
            return "0 B"
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024
            i += 1
        return f"{size_bytes:.1f} {size_names[i]}"