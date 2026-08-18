"""
JSApiExplorer v2.0 - Production-Ready JavaScript API Endpoint Extractor
=======================================================================
A heavily enhanced AST-based JavaScript analyzer for bug bounty recon.
Extracts API endpoints, auth patterns, GraphQL operations, WebSocket URLs,
and suspicious endpoints from JavaScript source code.

Author: k0imet (enhanced by veteran collaboration)
"""

import re
import json
import hashlib
import esprima
from typing import List, Dict, Any, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode
from app.utils.url_utils import urlparse, urljoin
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from enum import Enum

from app.utils.logger import get_logger

logger = get_logger()


class EndpointSeverity(Enum):
    """Severity classification for extracted endpoints."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ApiRequest:
    """Structured API request object with enhanced metadata."""
    source_url: str = ""
    url: str = ""
    method: str = "GET"
    headers: Dict[str, Any] = field(default_factory=dict)
    body: Any = None
    body_schema: Dict[str, Any] = field(default_factory=dict)
    auth: Optional[str] = None
    cookies: List[str] = field(default_factory=list)
    query_params: Dict[str, str] = field(default_factory=dict)
    graphql_operation: Optional[str] = None
    graphql_type: Optional[str] = None  # query, mutation, subscription
    websocket: bool = False
    cors_with_credentials: bool = False
    severity: EndpointSeverity = EndpointSeverity.INFO
    suspicious_indicators: List[str] = field(default_factory=list)
    confidence: str = "high"  # high, medium, low
    extraction_method: str = "ast"  # ast, regex, sourcemap

    def to_dict(self) -> Dict[str, Any]:
        """Convert to plain dict for JSON serialization."""
        d = asdict(self)
        d['severity'] = self.severity.value
        return d


class JSApiExplorer:
    """
    Deeply analyzes JavaScript source to extract structured API request information.

    v2.0 Enhancements:
    - Regex fallback for obfuscated/minified code
    - Source map parsing support
    - Inter-procedural baseURL resolution
    - GraphQL operation extraction
    - WebSocket/Socket.io detection
    - Array.join() and ternary URL resolution
    - Suspicious endpoint scoring
    - URL normalization and deduplication
    - Body schema inference
    - CORS credential detection
    - Fixed superagent chaining (token-based proximity matching)
    - Enhanced error logging with pattern context
    """

    # Regex patterns for fallback extraction (high-signal, low-false-positive)
    REGEX_PATTERNS = {
        'fetch': re.compile(
            r"fetch\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'axios_method': re.compile(
            r"axios\.(get|post|put|patch|delete|head|options)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'axios_request': re.compile(
            r"axios\s*\.\s*request\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'jquery_ajax': re.compile(
            r"\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'xhr_open': re.compile(
            r"\.open\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'websocket': re.compile(
            r"new\s+WebSocket\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'socket_io': re.compile(
            r"io\.(?:connect|)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
        'graphql_endpoint': re.compile(
            r"['\"]([^'\"]*graphql[^'\"]*)['\"]",
            re.IGNORECASE
        ),
        'api_url_literal': re.compile(
            r"['\"]((?:https?://|/)(?:api|v\d+|graphql|rest|admin|internal|debug)[^'\"]*)['\"]",
            re.IGNORECASE
        ),
        'custom_client': re.compile(
            r"\b(api|http|client|service)\.(get|post|put|patch|delete|head|fetch|request)\s*\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE
        ),
    }

    # Suspicious endpoint indicators for scoring
    SUSPICIOUS_PATTERNS = {
        'admin_endpoint': re.compile(r'/admin|/management|/dashboard|/console|/cpanel', re.IGNORECASE),
        'internal_endpoint': re.compile(r'/internal|/private|/_|/debug|/dev|/staging|/test', re.IGNORECASE),
        'sensitive_action': re.compile(r'delete|remove|drop|purge|reset|wipe|disable|ban|suspend', re.IGNORECASE),
        'auth_bypass': re.compile(r'bypass|skip|override|force|impersonate|sudo', re.IGNORECASE),
        'idor_risk': re.compile(r'/\d+|/\{id\}|/\{userId\}|/\{accountId\}', re.IGNORECASE),
        'graphql_introspection': re.compile(r'introspection|__schema|__type', re.IGNORECASE),
        'versioned_api': re.compile(r'/api/v\d+', re.IGNORECASE),
        'debug_params': re.compile(r'debug|test|mock|sandbox|draft', re.IGNORECASE),
        'role_param': re.compile(r'role|permission|isAdmin|is_staff|superuser|privilege', re.IGNORECASE),
        'file_upload': re.compile(r'upload|import|bulk|batch|csv|excel', re.IGNORECASE),
        'export_data': re.compile(r'export|download|backup|dump|archive', re.IGNORECASE),
        'payment_related': re.compile(r'payment|billing|invoice|subscription|pricing|wallet', re.IGNORECASE),
    }

    def __init__(self, config: Dict):
        self.config = config
        self.http_client_patterns = self._build_http_client_patterns()
        # Cache for parsed results: {(source_url, content_hash): [requests]}
        self._parse_cache: Dict[str, List[Dict]] = {}
        self._parse_cache_max = int((config or {}).get('js_ast_cache_max', 256))
        # Instance tracking for inter-procedural analysis
        self._instance_configs: Dict[str, Dict] = {}
        # Token stream for superagent chaining fix
        self._current_tokens: List[Dict] = []
        self._current_js_content: str = ""

    def _build_http_client_patterns(self) -> List[Dict]:
        """Define patterns to recognize common HTTP client libraries."""
        patterns = []

        # Core clients
        patterns.append({'name': 'fetch', 'detect': self._parse_fetch_call})
        patterns.append({'name': 'axios', 'detect': self._parse_axios_call})
        patterns.append({'name': 'jquery_ajax', 'detect': self._parse_jquery_ajax_call})
        patterns.append({'name': 'xhr', 'detect': self._parse_xhr_call})
        patterns.append({'name': 'superagent', 'detect': self._parse_superagent_call})
        patterns.append({'name': 'node_http', 'detect': self._parse_node_http_call})

        # Modern & custom
        patterns.append({'name': 'custom_api_client', 'detect': self._parse_custom_client_call})
        patterns.append({'name': 'tanstack_query', 'detect': self._parse_tanstack_query})
        patterns.append({'name': 'swr', 'detect': self._parse_swr})
        patterns.append({'name': 'apollo', 'detect': self._parse_apollo})

        # WebSocket / Real-time
        patterns.append({'name': 'websocket', 'detect': self._parse_websocket})
        patterns.append({'name': 'socket_io', 'detect': self._parse_socket_io})
        patterns.append({'name': 'grpc_web', 'detect': self._parse_grpc_web})

        return patterns

    # =====================================================================
    # PUBLIC API
    # =====================================================================

    def analyze_js(self, js_content: str, source_url: str = '') -> List[Dict[str, Any]]:
        """
        Entry point: parse the JS and return a list of request objects.

        Flow:
        1. Check cache
        2. Try AST parsing (primary)
        3. Fallback to regex extraction if AST yields little
        4. Source map detection and parsing
        5. Deduplicate and score
        6. Cache and return
        """
        content_hash = hashlib.sha256(js_content.encode()).hexdigest()[:16]
        cache_key = f"{source_url}:{content_hash}"

        if cache_key in self._parse_cache:
            logger.debug(f"Cache hit for {source_url}")
            return self._parse_cache[cache_key]

        all_requests: List[ApiRequest] = []
        self._current_js_content = js_content
        self._instance_configs = {}  # Reset per file

        # === Phase 1: AST Parsing (Primary) ===
        ast_requests = self._analyze_ast(js_content, source_url)
        all_requests.extend(ast_requests)

        # === Phase 2: Regex Fallback ===
        if len(ast_requests) < 3:  # If AST found few, likely obfuscated/minified
            regex_requests = self._analyze_regex(js_content, source_url)
            all_requests.extend(regex_requests)
            logger.info(f"Regex fallback added {len(regex_requests)} requests for {source_url}")

        # === Phase 3: Source Map Detection ===
        source_map_requests = self._analyze_source_map(js_content, source_url)
        if source_map_requests:
            all_requests.extend(source_map_requests)
            logger.info(f"Source map parsing added {len(source_map_requests)} requests")

        # === Phase 4: Post-Processing ===
        # Resolve relative URLs, deduplicate, score, normalize
        processed = self._post_process(all_requests, source_url)

        # Convert to dicts for output
        result = [req.to_dict() for req in processed]

        # Cache - bounded (plain dict with size eviction; large scans would
        # otherwise hold every unique bundle's AST forever)
        self._parse_cache[cache_key] = result
        if len(self._parse_cache) > self._parse_cache_max:
            keep = self._parse_cache_max // 2
            self._parse_cache = dict(list(self._parse_cache.items())[-keep:])
        return result

    def get_source_map_url(self, js_content: str, source_url: str) -> Optional[str]:
        """Extract source map URL from JS content."""
        # Standard source map comment
        match = re.search(r'//#\s*sourceMappingURL=([^\s\n]+)', js_content)
        if match:
            map_url = match.group(1)
            # Resolve relative URLs
            if map_url.startswith('http'):
                return map_url
            elif source_url:
                return urljoin(source_url, map_url)
            return map_url
        return None

    # =====================================================================
    # PHASE 1: AST ANALYSIS
    # =====================================================================

    def _neutralize_modern_syntax(self, js_content: str) -> Optional[str]:
        """Token-level rewrite so esprima 4 (ES2017) can parse ES2020+ code.

        Turbopack / Next.js 15+ chunks are full of optional chaining (?.),
        nullish coalescing (??) and logical assignment (||=, &&=) - esprima's
        parser bails on the FIRST such token and the whole AST phase is lost.
        esprima.tokenize() knows these tokens lexically, so we rewrite only
        the offending Punctuator tokens at their exact ranges; string and
        template literals pass through untouched. Returns None if even
        tokenization fails (e.g. private-field syntax), or the rewritten
        source if anything changed."""
        try:
            tokens = list(esprima.tokenize(js_content, {'range': True}))
        except Exception:
            return None
        out: List[str] = []
        cursor = 0
        changed = False
        i = 0
        n = len(tokens)
        while i < n:
            t = tokens[i]
            start = t.range[0]
            val = t.value
            nxt = tokens[i + 1] if i + 1 < n else None
            nxt2 = tokens[i + 2] if i + 2 < n else None
            contiguous = nxt is not None and nxt.range[0] == t.range[1]
            if t.type == 'Punctuator' and val == '?' and contiguous:
                # esprima 4 tokenizes ?. ?? ?.[ ?.( as '?' + '.' / '?' + '?' /
                # '?' + '.' + '[' / '?' + '.' + '('  (separate tokens)
                if nxt.value == '?':
                    # ?? -> || ; ??= -> =  (replacement - original chars dropped)
                    if nxt2 and nxt2.value == '=' and nxt2.range[0] == nxt.range[1]:
                        out.append(js_content[cursor:start])
                        out.append('=')
                        cursor = nxt2.range[1]
                        i += 3
                    else:
                        out.append(js_content[cursor:start])
                        out.append('||')
                        cursor = nxt.range[1]
                        i += 2
                    changed = True
                    continue
                if nxt.value == '.':
                    # a?.b -> a.b ; a?.[k] -> a[k] ; a?.(b) -> a ? (b) ternary
                    # shape. Only '?' + '.' are rewritten; the identifier or
                    # bracket/paren AFTER them passes through verbatim, so we
                    # advance past exactly two tokens (text of skipped tokens is
                    # replaced by our own output - never silently dropped).
                    nxt2c = nxt2 is not None and nxt2.range[0] == nxt.range[1]
                    if nxt2c and nxt2.type == 'Identifier':
                        out.append(js_content[cursor:start])
                        out.append('.')
                    elif nxt2c and nxt2.value == '[':
                        out.append(js_content[cursor:start])
                        out.append('')
                    elif nxt2c and nxt2.value == '(':
                        # a?.(b) -> a(b): dropping the tokens keeps esprima
                        # parsing (a ? (b) is invalid - missing ': alternate')
                        out.append(js_content[cursor:start])
                        out.append('')
                    else:
                        out.append(js_content[cursor:start])
                        out.append('')          # a ? .5 : ... -> a5 (parses)
                    cursor = nxt.range[1]
                    i += 2
                    changed = True
                    continue
                # plain ternary - leave untouched
                i += 1
                continue
            if t.type == 'Punctuator' and val in ('?.', '?.[', '?.('):
                # single-token spellings (some esprima builds) - optional chains
                out.append(js_content[cursor:start])
                out.append({'?.': '.', '?.[': '[', '?.(': '('}[val])
                cursor = t.range[1]
                changed = True
                i += 1
                continue
            if t.type == 'Punctuator' and val in ('??', '??='):
                out.append(js_content[cursor:start])
                out.append('||' if val == '??' else '=')
                cursor = t.range[1]
                changed = True
                i += 1
                continue
            if t.type == 'Punctuator' and val in ('||', '&&') and contiguous \
                    and nxt.value == '=':
                out.append(js_content[cursor:start])
                out.append('=')                  # ||= / &&= -> =
                cursor = nxt.range[1]
                i += 2
                changed = True
                continue
            if t.type == 'Keyword' and val == 'import' and i + 2 < n \
                    and tokens[i + 1].value == '.' and tokens[i + 2].value == 'meta':
                out.append(js_content[cursor:start])
                out.append('self')               # import.meta -> self
                cursor = tokens[i + 2].range[1]
                i += 3
                changed = True
                continue
            i += 1
        if not changed:
            return None
        out.append(js_content[cursor:])
        return ''.join(out)

    def _analyze_ast(self, js_content: str, source_url: str) -> List[ApiRequest]:
        requests: List[ApiRequest] = []
        tree = None
        try:
            tree = esprima.parseScript(js_content, {'loc': True, 'tolerant': True, 'range': True}).toDict()
        except Exception as e:
            neutralized = self._neutralize_modern_syntax(js_content)
            if neutralized is None:
                logger.warning(f"Esprima parsing failed for {source_url}: {e}")
                return requests
            logger.info(f"Esprima ES2017 parse failed ({e}); modern-syntax "
                        f"neutralization applied for {source_url}")
            try:
                tree = esprima.parseScript(
                    neutralized, {'loc': True, 'tolerant': True, 'range': True}).toDict()
            except Exception as e2:
                logger.warning(f"Esprima parsing failed for {source_url}: {e2}")
                return requests
        try:
            self._current_tokens = [t.toDict() for t in esprima.tokenize(js_content, {'loc': True, 'range': True})]
        except Exception:
            self._current_tokens = []
        constants = self._get_constants(tree)
        self._extract_instance_configs(tree, constants)
        self._walk_node(tree, lambda node: self._inspect_node(node, source_url, requests, constants))
        for req in requests:
            if req.url:
                self._enrich_query_params(req)
                self._resolve_instance_baseurl(req, constants)
                self._infer_body_schema(req)
        return requests

    def _get_constants(self, tree: Dict) -> Dict:
        """Enhanced constant resolution with ternary and join support."""
        constants = {}

        def find_consts(node):
            if not isinstance(node, dict):
                return

            if node.get('type') == 'VariableDeclarator':
                name = node.get('id', {}).get('name')
                if name and node.get('init'):
                    init = node['init']
                    value = self._extract_value(init, constants)
                    if value is not None:
                        constants[name] = value
                    elif str_val := self._extract_string(init, constants):
                        constants[name] = str_val

            elif node.get('type') == 'AssignmentExpression':
                left = node.get('left', {})
                if left.get('type') == 'Identifier':
                    name = left.get('name')
                    if name and node.get('right'):
                        value = self._extract_value(node['right'], constants)
                        if value is not None:
                            constants[name] = value
                        elif str_val := self._extract_string(node['right'], constants):
                            constants[name] = str_val

        # NOTE: the callback runs for EVERY node already - never re-walk a
        # subtree from inside it (that made traversal exponential in tree
        # depth and hung on deep-minified chunks).
        self._walk_node(tree, find_consts)
        return constants

    def _extract_instance_configs(self, tree: Dict, constants: Dict):
        """
        Extract instance configurations for inter-procedural analysis.
        Tracks: new ApiClient({baseURL: '...'}), createClient({...}), etc.
        """
        def find_instances(node):
            if not isinstance(node, dict):
                return

            # Pattern: const api = new SomeClient({ baseURL: '...' })
            if node.get('type') == 'VariableDeclarator':
                name = node.get('id', {}).get('name')
                init = node.get('init', {})
                if init.get('type') == 'NewExpression' and name:
                    args = init.get('arguments', [])
                    if args and args[0].get('type') == 'ObjectExpression':
                        config = self._extract_value(args[0], constants)
                        if isinstance(config, dict):
                            self._instance_configs[name] = config

                # Pattern: const api = createClient({ baseURL: '...' })
                elif init.get('type') == 'CallExpression' and name:
                    callee = init.get('callee', {})
                    callee_name = self._get_callee_name(callee)
                    if callee_name and any(x in callee_name.lower() for x in ['client', 'api', 'http', 'service', 'agent']):
                        args = init.get('arguments', [])
                        if args and args[0].get('type') == 'ObjectExpression':
                            config = self._extract_value(args[0], constants)
                            if isinstance(config, dict):
                                self._instance_configs[name] = config

            # Pattern: api.defaults.baseURL = '...'
            elif node.get('type') == 'AssignmentExpression':
                left = node.get('left', {})
                if left.get('type') == 'MemberExpression':
                    obj_name = self._get_member_chain(left)
                    if obj_name and any(x in obj_name.lower() for x in ['baseurl', 'base_url', 'root', 'host']):
                        # Try to find the instance name
                        parts = obj_name.split('.')
                        if len(parts) >= 1:
                            instance_name = parts[0]
                            value = self._extract_value(node.get('right'), constants)
                            if value:
                                if instance_name not in self._instance_configs:
                                    self._instance_configs[instance_name] = {}
                                # Map common config keys
                                key = parts[-1].lower()
                                if key in ('baseurl', 'base_url'):
                                    self._instance_configs[instance_name]['baseURL'] = value
                                elif key in ('headers',):
                                    self._instance_configs[instance_name]['headers'] = value

        self._walk_node(tree, find_instances)

    def _get_callee_name(self, callee: Dict) -> str:
        """Extract a human-readable name from a callee node."""
        if callee.get('type') == 'Identifier':
            return callee.get('name', '')
        elif callee.get('type') == 'MemberExpression':
            obj = self._get_callee_name(callee.get('object', {}))
            prop = callee.get('property', {}).get('name', '')
            return f"{obj}.{prop}" if obj else prop
        return ''

    def _get_member_chain(self, node: Dict) -> str:
        """Get the full member expression chain as a string."""
        if node.get('type') == 'Identifier':
            return node.get('name', '')
        elif node.get('type') == 'MemberExpression':
            obj = self._get_member_chain(node.get('object', {}))
            prop = node.get('property', {}).get('name', '')
            return f"{obj}.{prop}" if obj else prop
        return ''

    def _walk_node(self, node, callback):
        # Iterative DFS - minified chunks (Turbopack) nest 20k+ levels deep,
        # which would blow Python's recursion limit in a recursive walk.
        stack = [node]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                callback(current)
                stack.extend(v for v in current.values()
                             if isinstance(v, (dict, list)))
            elif isinstance(current, list):
                stack.extend(item for item in current
                             if isinstance(item, (dict, list)))

    def _inspect_node(self, node, source_url: str, requests: List, constants: Dict):
        if node.get('type') in ('CallExpression', 'NewExpression'):
            for pattern in self.http_client_patterns:
                try:
                    result = pattern['detect'](node, source_url, constants)
                    if result:
                        if isinstance(result, list):
                            requests.extend(result)
                        else:
                            requests.append(result)
                except Exception as e:
                    callee_info = self._get_callee_name(node.get('callee', {}))
                    logger.debug(f"Pattern '{pattern['name']}' failed on '{callee_info}': {e}")

    # =====================================================================
    # CORE PARSERS (Enhanced)
    # =====================================================================

    def _parse_fetch_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        callee = node.get('callee', {})
        if callee.get('type') != 'Identifier' or callee.get('name') != 'fetch':
            return None
        args = node.get('arguments', [])
        if len(args) < 1:
            return None

        url = self._extract_string(args[0], constants)
        if not url:
            return None

        request = self._create_base_request(source_url, url, 'GET')

        if len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
            for prop in args[1].get('properties', []):
                key = prop.get('key', {}).get('name')
                value = self._extract_value(prop.get('value'), constants)
                if key == 'method':
                    request.method = (value or 'GET').upper()
                elif key == 'headers' and isinstance(value, dict):
                    request.headers = value
                elif key in ('body', 'data'):
                    request.body = value
                elif key == 'credentials' and value == 'include':
                    request.cookies = ['include']
                    request.cors_with_credentials = True

        self._detect_auth(request)
        return request

    def _parse_axios_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        obj = callee.get('object', {})
        if obj.get('type') != 'Identifier' or obj.get('name') != 'axios':
            return None
        prop = callee.get('property', {})
        if prop.get('type') != 'Identifier':
            return None

        method_name = prop.get('name')
        args = node.get('arguments', [])
        request = self._create_base_request(source_url, '', 'GET')

        if method_name == 'request':
            if len(args) >= 1 and args[0].get('type') == 'ObjectExpression':
                for p in args[0].get('properties', []):
                    key = p.get('key', {}).get('name')
                    value = self._extract_value(p.get('value'), constants)
                    if key == 'method':
                        request.method = str(value).upper()
                    elif key == 'url':
                        request.url = str(value)
                    elif key == 'headers' and isinstance(value, dict):
                        request.headers = value
                    elif key == 'data':
                        request.body = value
                    elif key == 'params' and isinstance(value, dict):
                        request.query_params = value
            if not request.url:
                return None
            self._detect_auth(request)
            return request

        if method_name in ['get', 'delete', 'head', 'options']:
            if len(args) >= 1:
                request.url = self._extract_string(args[0], constants) or ''
                if len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
                    for p in args[1].get('properties', []):
                        key = p.get('key', {}).get('name')
                        value = self._extract_value(p.get('value'), constants)
                        if key == 'headers' and isinstance(value, dict):
                            request.headers = value
                        elif key == 'params' and isinstance(value, dict):
                            request.query_params = value
            request.method = method_name.upper()
            if request.url:
                self._detect_auth(request)
                return request

        elif method_name in ['post', 'put', 'patch']:
            if len(args) >= 1:
                request.url = self._extract_string(args[0], constants) or ''
                if len(args) >= 2:
                    request.body = self._extract_value(args[1], constants)
                if len(args) >= 3 and args[2].get('type') == 'ObjectExpression':
                    for p in args[2].get('properties', []):
                        key = p.get('key', {}).get('name')
                        value = self._extract_value(p.get('value'), constants)
                        if key == 'headers' and isinstance(value, dict):
                            request.headers = value
                        elif key == 'params' and isinstance(value, dict):
                            request.query_params = value
            request.method = method_name.upper()
            if request.url:
                self._detect_auth(request)
                return request
        return None

    def _parse_jquery_ajax_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        if callee.get('object', {}).get('name') != '$' or callee.get('property', {}).get('name') != 'ajax':
            return None

        args = node.get('arguments', [])
        if not args or args[0].get('type') != 'ObjectExpression':
            return None

        request = self._create_base_request(source_url, '', 'GET')
        for prop in args[0].get('properties', []):
            key = prop.get('key', {}).get('name')
            value = self._extract_value(prop.get('value'), constants)
            if key == 'url':
                request.url = str(value)
            elif key in ['type', 'method']:
                request.method = str(value).upper()
            elif key == 'headers' and isinstance(value, dict):
                request.headers = value
            elif key == 'data':
                request.body = value
            elif key == 'beforeSend':
                # jQuery beforeSend often sets auth headers
                request.suspicious_indicators.append('beforeSend_callback')

        if request.url:
            self._detect_auth(request)
            return request
        return None

    def _parse_xhr_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        callee = node.get('callee', {})
        if callee.get('type') == 'MemberExpression' and callee.get('property', {}).get('name') == 'open':
            args = node.get('arguments', [])
            if len(args) >= 2:
                method = self._extract_string(args[0], constants)
                url = self._extract_string(args[1], constants)
                if url:
                    req = self._create_base_request(
                        source_url, url,
                        method.upper() if isinstance(method, str) else 'GET'
                    )
                    # Check for setRequestHeader in nearby code via regex fallback
                    return req
        return None

    def _parse_superagent_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """
        FIXED: Uses token stream proximity matching instead of broken parent walk.
        """
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        if callee.get('object', {}).get('name') != 'request':
            return None
        method_name = callee.get('property', {}).get('name')
        if method_name not in ['get', 'post', 'put', 'patch', 'delete', 'head']:
            return None

        args = node.get('arguments', [])
        if not args:
            return None
        url = self._extract_string(args[0], constants)
        if not url:
            return None

        request = self._create_base_request(source_url, url, method_name.upper())

        # FIXED: Use token stream for chaining detection
        if self._current_tokens and node.get('range'):
            node_start, node_end = node['range']
            # Look for .set() and .send() in tokens after this node
            self._detect_superagent_chain(request, node_end)

        self._detect_auth(request)
        return request

    def _detect_superagent_chain(self, request: ApiRequest, after_pos: int):
        """Detect .set() and .send() chain calls using token stream."""
        if not self._current_tokens:
            return

        # Find tokens after our position
        relevant_tokens = [
            t for t in self._current_tokens
            if t.get('range', [0, 0])[0] > after_pos
        ]

        # Look for .set( or .send( within a reasonable window (next 50 tokens)
        i = 0
        chain_depth = 0
        while i < min(len(relevant_tokens), 50):
            token = relevant_tokens[i]
            token_val = token.get('value', '')

            if token_val == '.':
                # Check next token for method name
                if i + 1 < len(relevant_tokens):
                    next_token = relevant_tokens[i + 1]
                    method = next_token.get('value', '')

                    if method == 'set' and i + 2 < len(relevant_tokens):
                        # Find the argument to .set()
                        # Skip to opening paren
                        j = i + 2
                        while j < len(relevant_tokens) and relevant_tokens[j].get('value') != '(':
                            j += 1
                        if j < len(relevant_tokens):
                            # Extract headers from tokens between parens
                            headers = self._extract_from_token_range(j + 1, relevant_tokens)
                            if isinstance(headers, dict):
                                request.headers.update(headers)

                    elif method == 'send' and i + 2 < len(relevant_tokens):
                        j = i + 2
                        while j < len(relevant_tokens) and relevant_tokens[j].get('value') != '(':
                            j += 1
                        if j < len(relevant_tokens):
                            body = self._extract_from_token_range(j + 1, relevant_tokens)
                            if body:
                                request.body = body

                    elif method in ['get', 'post', 'put', 'patch', 'delete', 'head']:
                        # New request chain started, stop
                        break

                    i += 2
                    continue

            i += 1

    def _extract_from_token_range(self, start_idx: int, tokens: List[Dict]) -> Any:
        """Try to reconstruct a value from token stream."""
        # Simple heuristic: look for string literals or object patterns
        values = []
        paren_depth = 1
        i = start_idx
        while i < len(tokens) and paren_depth > 0:
            token = tokens[i]
            val = token.get('value', '')

            if val == '(':
                paren_depth += 1
            elif val == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    break
            elif token.get('type') == 'String':
                values.append(val.strip("'\""))
            i += 1

        if len(values) == 2:
            return {values[0]: values[1]}
        elif values:
            return values[0]
        return None

    def _parse_node_http_call(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        if callee.get('object', {}).get('name') not in ['http', 'https'] or callee.get('property', {}).get('name') != 'request':
            return None

        args = node.get('arguments', [])
        if not args or args[0].get('type') != 'ObjectExpression':
            return None

        options_node = args[0]
        request = self._create_base_request(source_url, '', 'GET')

        for prop in options_node.get('properties', []):
            key = prop.get('key', {}).get('name')
            value = self._extract_value(prop.get('value'), constants)
            if key == 'method':
                request.method = str(value).upper()
            elif key == 'path':
                hostname = self._extract_value_from_obj(options_node, 'hostname', constants)
                port = self._extract_value_from_obj(options_node, 'port', constants)
                if hostname and value:
                    protocol = 'https' if callee.get('object', {}).get('name') == 'https' else 'http'
                    port_part = f":{port}" if port else ""
                    request.url = f"{protocol}://{hostname}{port_part}{value}"
            elif key == 'headers' and isinstance(value, dict):
                request.headers = value

        if request.url:
            self._detect_auth(request)
            return request
        return None

    # =====================================================================
    # MODERN & CUSTOM PARSERS (Enhanced)
    # =====================================================================

    def _parse_custom_client_call(self, node, source_url, constants):
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        prop = callee.get('property', {})
        if prop.get('type') != 'Identifier':
            return None
        method_name = prop.get('name', '').lower()
        if method_name not in ('get', 'post', 'put', 'patch', 'delete', 'head', 'fetch', 'request'):
            return None
        # Skip libraries that already have dedicated parsers (avoids double-counting
        # e.g. axios.get, which would otherwise inflate the AST count and disable the
        # regex fallback threshold).
        obj = callee.get('object', {})
        if obj.get('type') == 'Identifier' and obj.get('name') in ('axios', '$', 'http', 'https', 'request'):
            return None
        args = node.get('arguments', [])
        url = self._extract_string(args[0], constants) if args else None
        if not url:
            return None
        request = self._create_base_request(source_url, url, method_name.upper())
        obj = callee.get('object', {})
        if obj.get('type') == 'Identifier':
            instance_name = obj.get('name')
            if instance_name in self._instance_configs:
                config = self._instance_configs[instance_name]
                if 'baseURL' in config:
                    request.url = urljoin(str(config['baseURL']), request.url)
                if 'headers' in config and isinstance(config['headers'], dict):
                    request.headers.update(config['headers'])
        if len(args) > 1 and args[1].get('type') == 'ObjectExpression':
            for p in args[1].get('properties', []):
                k = p.get('key', {}).get('name')
                v = self._extract_value(p.get('value'), constants)
                if k == 'headers' and isinstance(v, dict):
                    request.headers = v
                elif k in ('data', 'body'):
                    request.body = v
                elif k == 'params' and isinstance(v, dict):
                    request.query_params = v
        self._detect_auth(request)
        return request

    def _parse_swr(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """SWR: useSWR(key, fetcher) - enhanced to extract from fetcher."""
        callee = node.get('callee', {})
        if callee.get('type') != 'Identifier' or callee.get('name') != 'useSWR':
            return None

        args = node.get('arguments', [])
        if len(args) < 1:
            return None

        key = self._extract_string(args[0], constants)
        request = self._create_base_request(source_url, key or '', 'GET')
        request.confidence = 'medium'  # SWR keys might not be URLs

        # Try to resolve fetcher function for more details
        if len(args) >= 2:
            fetcher = args[1]
            if fetcher.get('type') == 'ArrowFunctionExpression':
                # Walk fetcher body for HTTP calls
                body = fetcher.get('body', {})
                if body.get('type') == 'BlockStatement':
                    for stmt in body.get('body', []):
                        if stmt.get('type') == 'ReturnStatement':
                            arg = stmt.get('argument', {})
                            if arg.get('type') == 'CallExpression':
                                # Try to parse as fetch/axios
                                for pattern in self.http_client_patterns:
                                    if pattern['name'] in ['fetch', 'axios']:
                                        try:
                                            inner_req = pattern['detect'](arg, source_url, constants)
                                            if inner_req:
                                                request.url = inner_req.url or request.url
                                                request.headers.update(inner_req.headers)
                                                request.method = inner_req.method
                                        except Exception:
                                            pass
        return request

    def _parse_apollo(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """
        Apollo Client: Enhanced GraphQL operation extraction.
        Extracts operation type, name, and variables structure.
        """
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        prop_name = callee.get('property', {}).get('name', '')
        if prop_name not in ('query', 'mutate', 'subscribe'):
            return None

        request = self._create_base_request(source_url, '', 'POST')
        request.graphql_type = prop_name
        request.confidence = 'medium'

        args = node.get('arguments', [])
        if args and args[0].get('type') == 'ObjectExpression':
            for p in args[0].get('properties', []):
                key = p.get('key', {}).get('name')
                if key == 'query':
                    # Extract from gql template or string literal
                    gql_content = self._extract_graphql_content(p.get('value'), constants)
                    if gql_content:
                        request.graphql_operation = self._extract_operation_name(gql_content)
                        request.body = {'query': gql_content}
                        # Try to infer endpoint from context or default to /graphql
                        request.url = '/graphql'
                elif key == 'mutation':
                    gql_content = self._extract_graphql_content(p.get('value'), constants)
                    if gql_content:
                        request.graphql_operation = self._extract_operation_name(gql_content)
                        request.body = {'query': gql_content}
                        request.url = '/graphql'
                elif key == 'variables' and p.get('value'):
                    vars_val = self._extract_value(p.get('value'), constants)
                    if isinstance(vars_val, dict):
                        if request.body is None:
                            request.body = {}
                        request.body['variables'] = vars_val
                        request.body_schema = {k: type(v).__name__ for k, v in vars_val.items()}

        # Try to find Apollo Client instance for endpoint
        obj = callee.get('object', {})
        if obj.get('type') == 'Identifier':
            instance_name = obj.get('name')
            if instance_name in self._instance_configs:
                config = self._instance_configs[instance_name]
                if 'uri' in config:
                    request.url = config['uri']
                elif 'link' in config:
                    # Often contains HttpLink with uri
                    request.url = config.get('link', {}).get('uri', '/graphql')

        if request.url:
            self._detect_auth(request)
            return request
        return None

    def _parse_tanstack_query(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """Tanstack (React) Query: useQuery(['users'], fetchUsers) or useMutation(...)"""
        callee = node.get('callee', {})
        name = callee.get('name')
        if not name or name not in ['useQuery', 'useMutation']:
            return None

        args = node.get('arguments', [])
        if not args:
            return None

        url_hint = ""
        if args[0].get('type') == 'ArrayExpression':
            elements = [self._extract_string(el, constants) for el in args[0].get('elements', [])]
            url_hint = "/".join(filter(None, elements))
        elif args[0].get('type') == 'ObjectExpression':
            for p in args[0].get('properties', []):
                if p.get('key', {}).get('name') == 'queryKey':
                    val = self._extract_value(p.get('value'), constants)
                    if isinstance(val, list):
                        url_hint = "/".join([str(v) for v in val if v])
                    elif isinstance(val, str):
                        url_hint = val

        if url_hint:
            method = 'POST' if name == 'useMutation' else 'GET'
            request = self._create_base_request(source_url, url_hint, method)
            request.confidence = 'medium'

            # Try to extract queryFn for actual URL
            if args[0].get('type') == 'ObjectExpression':
                for p in args[0].get('properties', []):
                    if p.get('key', {}).get('name') == 'queryFn':
                        fn = p.get('value', {})
                        if fn.get('type') == 'ArrowFunctionExpression':
                            body = fn.get('body', {})
                            if body.get('type') == 'CallExpression':
                                for pattern in self.http_client_patterns:
                                    if pattern['name'] in ['fetch', 'axios', 'custom_api_client']:
                                        try:
                                            inner_req = pattern['detect'](body, source_url, constants)
                                            if inner_req:
                                                request.url = inner_req.url or request.url
                                                request.method = inner_req.method
                                                request.headers.update(inner_req.headers)
                                        except Exception:
                                            pass
            return request
        return None

    # =====================================================================
    # WEBSOCKET / REAL-TIME PARSERS (New)
    # =====================================================================

    def _parse_websocket(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """Detect WebSocket connections."""
        callee = node.get('callee', {})
        if callee.get('type') != 'Identifier' or callee.get('name') != 'WebSocket':
            return None
        if callee.get('type') == 'MemberExpression':
            # window.WebSocket or global.WebSocket
            if callee.get('property', {}).get('name') != 'WebSocket':
                return None

        args = node.get('arguments', [])
        if not args:
            return None

        url = self._extract_string(args[0], constants)
        if not url:
            return None

        request = self._create_base_request(source_url, url, 'WS')
        request.websocket = True
        request.confidence = 'high'

        # Check for protocols (often auth-related)
        if len(args) >= 2 and args[1].get('type') == 'ArrayExpression':
            protocols = [self._extract_string(el, constants) for el in args[1].get('elements', [])]
            request.headers['Sec-WebSocket-Protocol'] = ', '.join(filter(None, protocols))

        self._detect_auth(request)
        return request

    def _parse_socket_io(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """Detect Socket.io connections."""
        callee = node.get('callee', {})
        if callee.get('type') == 'MemberExpression':
            obj = callee.get('object', {})
            prop = callee.get('property', {})
            if obj.get('name') == 'io' and prop.get('name') in ('connect', ''):
                pass
            else:
                return None
        elif callee.get('type') != 'Identifier' or callee.get('name') != 'io':
            return None

        args = node.get('arguments', [])
        url = self._extract_string(args[0], constants) if args else ''

        request = self._create_base_request(source_url, url or '', 'WS')
        request.websocket = True
        request.confidence = 'medium'

        # Socket.io options often contain auth
        if len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
            for p in args[1].get('properties', []):
                key = p.get('key', {}).get('name')
                value = self._extract_value(p.get('value'), constants)
                if key == 'auth' and isinstance(value, dict):
                    request.headers['Socket-Auth'] = json.dumps(value)
                    request.suspicious_indicators.append('socket_auth_object')
                elif key == 'extraHeaders' and isinstance(value, dict):
                    request.headers.update(value)

        self._detect_auth(request)
        return request

    def _parse_grpc_web(self, node: Dict, source_url: str, constants: Dict) -> Optional[ApiRequest]:
        """Detect gRPC-Web invocations."""
        callee = node.get('callee', {})
        if callee.get('type') != 'MemberExpression':
            return None
        prop = callee.get('property', {})
        if prop.get('name') not in ('invoke', 'unary', 'serverStreaming'):
            return None

        obj = callee.get('object', {})
        if obj.get('type') == 'Identifier' and 'grpc' in obj.get('name', '').lower():
            args = node.get('arguments', [])
            if args and args[0].get('type') == 'ObjectExpression':
                request = self._create_base_request(source_url, '', 'POST')
                request.headers['Content-Type'] = 'application/grpc-web-text'
                request.suspicious_indicators.append('grpc_web')

                for p in args[0].get('properties', []):
                    key = p.get('key', {}).get('name')
                    value = self._extract_value(p.get('value'), constants)
                    if key == 'host':
                        request.url = str(value)
                    elif key == 'method':
                        request.graphql_operation = str(value)  # Reuse field for method name

                if request.url:
                    return request
        return None

    # =====================================================================
    # PHASE 2: REGEX FALLBACK
    # =====================================================================

    def _analyze_regex(self, js_content: str, source_url: str) -> List[ApiRequest]:
        """Regex-based fallback for obfuscated/minified code."""
        requests: List[ApiRequest] = []

        # fetch patterns
        for match in self.REGEX_PATTERNS['fetch'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'GET')
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            self._detect_auth(req)
            requests.append(req)

        # axios method patterns
        for match in self.REGEX_PATTERNS['axios_method'].finditer(js_content):
            method = match.group(1).upper()
            url = match.group(2)
            req = self._create_base_request(source_url, url, method)
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            self._detect_auth(req)
            requests.append(req)

        # axios request pattern
        for match in self.REGEX_PATTERNS['axios_request'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'POST')
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            self._detect_auth(req)
            requests.append(req)

        # jQuery ajax
        for match in self.REGEX_PATTERNS['jquery_ajax'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'GET')
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            self._detect_auth(req)
            requests.append(req)

        # XHR open
        for match in self.REGEX_PATTERNS['xhr_open'].finditer(js_content):
            method = match.group(1).upper()
            url = match.group(2)
            req = self._create_base_request(source_url, url, method)
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            self._detect_auth(req)
            requests.append(req)

        # WebSocket
        for match in self.REGEX_PATTERNS['websocket'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'WS')
            req.websocket = True
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            requests.append(req)

        # Socket.io
        for match in self.REGEX_PATTERNS['socket_io'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'WS')
            req.websocket = True
            req.extraction_method = 'regex'
            req.confidence = 'medium'
            requests.append(req)

        # GraphQL endpoints
        for match in self.REGEX_PATTERNS['graphql_endpoint'].finditer(js_content):
            url = match.group(1)
            req = self._create_base_request(source_url, url, 'POST')
            req.extraction_method = 'regex'
            req.confidence = 'low'
            req.suspicious_indicators.append('graphql_endpoint_regex')
            requests.append(req)

        # Custom client
        for match in self.REGEX_PATTERNS['custom_client'].finditer(js_content):
            method = match.group(2).upper()
            url = match.group(3)
            req = self._create_base_request(source_url, url, method)
            req.extraction_method = 'regex'
            req.confidence = 'low'
            self._detect_auth(req)
            requests.append(req)

        # High-signal API URL literals
        for match in self.REGEX_PATTERNS['api_url_literal'].finditer(js_content):
            url = match.group(1)
            # Skip if already captured by other patterns
            req = self._create_base_request(source_url, url, 'GET')
            req.extraction_method = 'regex'
            req.confidence = 'low'
            req.suspicious_indicators.append('api_url_literal')
            requests.append(req)

        return requests

    # =====================================================================
    # PHASE 3: SOURCE MAP ANALYSIS
    # =====================================================================

    def _analyze_source_map(self, js_content: str, source_url: str) -> List[ApiRequest]:
        """Detect and parse source maps for additional endpoint extraction."""
        map_url = self.get_source_map_url(js_content, source_url)
        if not map_url:
            return []

        requests: List[ApiRequest] = []

        # In a real implementation, you would fetch the source map here
        # For now, we flag that a source map exists and add a marker request
        marker = self._create_base_request(source_url, map_url, 'GET')
        marker.extraction_method = 'sourcemap'
        marker.suspicious_indicators.append('source_map_available')
        marker.confidence = 'high'
        requests.append(marker)

        logger.info(f"Source map detected: {map_url} for {source_url}")
        return requests

    # =====================================================================
    # PHASE 4: POST-PROCESSING
    # =====================================================================

    def _post_process(self, requests: List[ApiRequest], source_url: str) -> List[ApiRequest]:
        """Deduplicate, normalize, resolve, and score all requests."""

        # Step 1: Resolve relative URLs
        for req in requests:
            if req.url and not req.url.startswith('http') and source_url:
                if req.url.startswith('/'):
                    req.url = urljoin(source_url, req.url)
                elif req.url.startswith('./') or req.url.startswith('../'):
                    req.url = urljoin(source_url, req.url)

        # Step 2: Normalize URLs
        for req in requests:
            req.url = self._normalize_url(req.url)

        # Step 3: Deduplicate
        seen: Set[str] = set()
        unique_requests: List[ApiRequest] = []
        for req in requests:
            key = f"{req.method}:{req.url}:{json.dumps(req.query_params, sort_keys=True)}"
            if key not in seen:
                seen.add(key)
                unique_requests.append(req)

        # Step 4: Score suspicious endpoints
        for req in unique_requests:
            self._score_endpoint(req)

        # Step 5: Sort by severity
        severity_order = {
            EndpointSeverity.CRITICAL: 0,
            EndpointSeverity.HIGH: 1,
            EndpointSeverity.MEDIUM: 2,
            EndpointSeverity.LOW: 3,
            EndpointSeverity.INFO: 4,
        }
        unique_requests.sort(key=lambda r: severity_order.get(r.severity, 5))

        return unique_requests

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        if not url:
            return url
        # Remove trailing slash
        url = url.rstrip('/')
        # Sort query params
        try:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                if parsed.query:
                    qs = parse_qs(parsed.query)
                    sorted_qs = sorted(qs.items())
                    new_query = urlencode(sorted_qs, doseq=True)
                    url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                else:
                    url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            # bare-relative ('users/123') stays as-is; absolutized later
        except Exception:
            pass
        return url

    def _score_endpoint(self, request: ApiRequest):
        """Score endpoint for suspicious indicators and assign severity."""
        indicators = []
        url = request.url.lower()
        method = request.method.upper()

        # Check URL patterns
        for name, pattern in self.SUSPICIOUS_PATTERNS.items():
            if pattern.search(url):
                indicators.append(name)

        # Check method sensitivity
        if method in ['DELETE', 'PUT', 'PATCH']:
            indicators.append('state_changing_method')

        # Check auth
        if request.auth:
            indicators.append('authenticated_endpoint')

        # Check CORS with credentials
        if request.cors_with_credentials:
            indicators.append('cors_with_credentials')

        # Check GraphQL
        if request.graphql_type:
            indicators.append('graphql_endpoint')
            if request.graphql_type == 'mutate':
                indicators.append('graphql_mutation')

        # Check body schema for sensitive fields
        if request.body_schema:
            for key in request.body_schema.keys():
                lower_key = key.lower()
                if any(x in lower_key for x in ['role', 'admin', 'permission', 'isadmin']):
                    indicators.append('sensitive_body_field')

        # Check query params
        for key in request.query_params.keys():
            lower_key = key.lower()
            if any(x in lower_key for x in ['debug', 'test', 'role', 'admin', 'token']):
                indicators.append('sensitive_query_param')

        request.suspicious_indicators = list(getattr(request, 'suspicious_indicators', [])) + indicators

        # Assign severity based on indicator count and type
        if any(x in indicators for x in ['admin_endpoint', 'auth_bypass', 'graphql_mutation']):
            request.severity = EndpointSeverity.CRITICAL
        elif len(indicators) >= 3 or any(x in indicators for x in ['internal_endpoint', 'sensitive_action', 'cors_with_credentials']):
            request.severity = EndpointSeverity.HIGH
        elif len(indicators) >= 1:
            request.severity = EndpointSeverity.MEDIUM
        else:
            request.severity = EndpointSeverity.INFO

    # =====================================================================
    # ENHANCED HELPERS
    # =====================================================================

    def _create_base_request(self, source_url: str, url: str, method: str) -> ApiRequest:
        return ApiRequest(
            source_url=source_url,
            url=url or '',
            method=method,
        )

    def _detect_auth(self, request: ApiRequest):
        """Enhanced auth detection with multiple schemes."""
        headers = request.headers
        auth = headers.get('Authorization') or headers.get('authorization')
        if isinstance(auth, str):
            lower = auth.lower()
            if 'bearer' in lower:
                request.auth = 'Bearer Token'
            elif 'basic' in lower:
                request.auth = 'Basic Auth'
            elif 'api-key' in lower or 'apikey' in lower:
                request.auth = 'API Key'
            elif 'digest' in lower:
                request.auth = 'Digest Auth'
            else:
                request.auth = 'Custom Auth'

        # Check for cookie-based auth indicators
        cookie = headers.get('Cookie') or headers.get('cookie')
        if cookie:
            request.suspicious_indicators.append('cookie_auth_header')

        # Check for X-API-Key pattern
        for key in headers.keys():
            lower_key = key.lower()
            if 'api-key' in lower_key or 'x-api-key' in lower_key or 'apikey' in lower_key:
                request.auth = 'API Key (Header)'
                request.suspicious_indicators.append('api_key_header')

    def _extract_string(self, node: Dict, constants: Dict) -> Optional[str]:
        """Enhanced string extraction with array join and ternary support."""
        if not node:
            return None
        t = node.get('type')

        if t == 'Literal':
            return str(node.get('value', ''))
        if t == 'Identifier':
            name = node.get('name')
            val = constants.get(name)
            return str(val) if val is not None else f"${{{name}}}"
        if t == 'BinaryExpression' and node.get('operator') == '+':
            left = self._extract_string(node.get('left'), constants) or ""
            right = self._extract_string(node.get('right'), constants) or ""
            return left + right
        if t == 'TemplateLiteral':
            parts = []
            for q in node.get('quasis', []):
                parts.append(q.get('value', {}).get('raw', ''))
            for e in node.get('expressions', []):
                parts.append(self._extract_string(e, constants) or '')
            return ''.join(parts)

        # NEW: Array.join() support
        if t == 'CallExpression':
            callee = node.get('callee', {})
            if callee.get('type') == 'MemberExpression':
                obj = callee.get('object', {})
                prop = callee.get('property', {})
                if prop.get('name') == 'join' and obj.get('type') == 'ArrayExpression':
                    elements = [self._extract_string(el, constants) or '' for el in obj.get('elements', [])]
                    separator = self._extract_string(node.get('arguments', [{}])[0], constants) or ''
                    return separator.join(elements)

        # NEW: Ternary / ConditionalExpression support - collect all branches
        if t == 'ConditionalExpression':
            branches = []
            true_branch = self._extract_string(node.get('consequent'), constants)
            false_branch = self._extract_string(node.get('alternate'), constants)
            if true_branch:
                branches.append(true_branch)
            if false_branch:
                branches.append(false_branch)
            if branches:
                return branches[0]  # Return first; caller can handle multiple if needed

        return None

    def _extract_value(self, node: Dict, constants: Dict = None) -> Any:
        """Extract objects, arrays, literals with constant resolution."""
        if not node:
            return None
        if constants is None:
            constants = {}

        if node.get('type') == 'Literal':
            return node.get('value')
        if node.get('type') == 'Identifier':
            name = node.get('name')
            return constants.get(name)
        if node.get('type') == 'ObjectExpression':
            obj = {}
            for p in node.get('properties', []):
                key = p.get('key', {}).get('name') or p.get('key', {}).get('value')
                obj[key] = self._extract_value(p.get('value'), constants)
            return obj
        if node.get('type') == 'ArrayExpression':
            return [self._extract_value(el, constants) for el in node.get('elements', [])]
        if node.get('type') == 'TemplateLiteral':
            return self._extract_string(node, constants)
        if node.get('type') == 'BinaryExpression' and node.get('operator') == '+':
            left = self._extract_value(node.get('left'), constants)
            right = self._extract_value(node.get('right'), constants)
            if isinstance(left, str) and isinstance(right, str):
                return left + right
        return None

    def _extract_value_from_obj(self, obj_node: Dict, key_name: str, constants: Dict = None) -> Any:
        """Helper to pluck a specific value directly out of an AST ObjectExpression."""
        if constants is None:
            constants = {}
        if obj_node.get('type') == 'ObjectExpression':
            for prop in obj_node.get('properties', []):
                key = prop.get('key', {}).get('name') or prop.get('key', {}).get('value')
                if key == key_name:
                    return self._extract_value(prop.get('value'), constants)
        return None

    def _enrich_query_params(self, request: ApiRequest):
        """Extract query params from URL."""
        try:
            parsed = urlparse(request.url)
            if parsed.query:
                for k, v in parse_qs(parsed.query).items():
                    request.query_params[k] = v[0] if v else ''
        except Exception:
            pass

    def _resolve_instance_baseurl(self, request: ApiRequest, constants: Dict):
        """Resolve baseURL from instance configs for custom clients."""
        # Already handled in _parse_custom_client_call, but this is a catch-all
        pass

    def _infer_body_schema(self, request: ApiRequest):
        """Infer JSON schema from body object for mass assignment detection."""
        if request.body and isinstance(request.body, dict):
            schema = {}
            for key, value in request.body.items():
                if isinstance(value, dict):
                    schema[key] = 'object'
                elif isinstance(value, list):
                    schema[key] = 'array'
                elif isinstance(value, str):
                    schema[key] = 'string'
                elif isinstance(value, bool):
                    schema[key] = 'boolean'
                elif isinstance(value, (int, float)):
                    schema[key] = 'number'
                else:
                    schema[key] = 'unknown'
            request.body_schema = schema

            # Flag sensitive fields
            sensitive_keys = ['role', 'isAdmin', 'is_staff', 'permissions', 'groups', 
                              'superuser', 'admin', 'owner', 'creator', 'level', 'tier']
            for key in schema.keys():
                if any(sk in key.lower() for sk in sensitive_keys):
                    request.suspicious_indicators.append(f'body_field:{key}')

    def _extract_graphql_content(self, node: Dict, constants: Dict) -> Optional[str]:
        """Extract GraphQL query string from gql template or literal."""
        if not node:
            return None
        t = node.get('type')

        if t == 'TaggedTemplateExpression':
            tag = node.get('tag', {})
            if tag.get('name') in ('gql', 'graphql'):
                quasi = node.get('quasi', {})
                parts = []
                for q in quasi.get('quasis', []):
                    parts.append(q.get('value', {}).get('raw', ''))
                return ''.join(parts)
        elif t == 'TemplateLiteral':
            parts = []
            for q in node.get('quasis', []):
                parts.append(q.get('value', {}).get('raw', ''))
            return ''.join(parts)
        elif t == 'Literal':
            val = node.get('value', '')
            if isinstance(val, str) and ('query' in val or 'mutation' in val):
                return val
        elif t == 'Identifier':
            name = node.get('name')
            val = constants.get(name)
            if isinstance(val, str):
                return val
        return None

    def _extract_operation_name(self, gql_content: str) -> Optional[str]:
        """Extract operation name from GraphQL content."""
        if not gql_content:
            return None
        # Match: query GetUsers, mutation DeleteUser, subscription OnUpdate
        match = re.search(r'(query|mutation|subscription)\s+(\w+)', gql_content)
        if match:
            return match.group(2)
        return None