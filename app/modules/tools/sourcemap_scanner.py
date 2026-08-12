# modules/tools/sourcemap_scanner.py

import re
import json
import io
import gzip
import brotli
import requests
from app.utils.url_utils import urljoin
from typing import List, Dict, Optional, Callable, Any
import concurrent.futures

# We use ijson for streaming JSON parsing; fallback if not available
try:
    import ijson
    HAS_IJSON = True
except ImportError:
    HAS_IJSON = False

from app.utils.logger import get_logger
from app.utils.user_agents import get_user_agent, detect_waf_block

logger = get_logger()


class SourceMapScanner:
    def __init__(self, config: Dict):
        self.config = config

        # Session for large downloads (source maps)
        self.download_session = requests.Session()
        self.download_session.headers.update({'User-Agent': get_user_agent()})
        self.download_session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20))
        self.download_session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20))

        # Session for lightweight probes (JS files)
        self.probe_session = requests.Session()
        self.probe_session.headers.update({'User-Agent': get_user_agent()})
        self.probe_session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=10))
        self.probe_session.mount('http://', requests.adapters.HTTPAdapter(pool_connections=5, pool_maxsize=10))

        self.max_file_size = 50 * 1024 * 1024  # 50 MB

        # Secret patterns (expanded)
        self.secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'gh[pous]_[0-9a-zA-Z]{36,40}', 'GitHub Token'),
            (r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT'),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Key'),
            (r'xox[baprs]-[0-9a-zA-Z-]+', 'Slack Token'),
            (r'(?i)(api[_-]?key|apikey|token|secret|password)[\s:=]+[\'"]?([0-9a-zA-Z\-_]{16,})[\'"]?', 'Generic Secret'),
            (r'-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----', 'Private Key'),
        ]
        self.endpoint_pattern = re.compile(r'https?://[^\s\'"<>]+|/[a-zA-Z0-9_\-/]+')
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.comment_pattern = re.compile(r'(//|/\*).*?(TODO|FIXME|XXX|HACK|WARNING|DEBUG|SECURITY|BUG).*?(?:\*/|$)', re.DOTALL)

    def _extract_sourcemap_url(self, js_content: str, base_url: str) -> Optional[str]:
        match = re.search(r'//# sourceMappingURL=(.+?)$', js_content, re.M)
        if match:
            map_url = match.group(1).strip()
            return urljoin(base_url, map_url)
        return None

    def _stream_decompress(self, resp: requests.Response):
        """
        Return a file-like object that decompresses gzip or brotli on the fly.
        """
        content_encoding = resp.headers.get('content-encoding', '').lower()
        if 'gzip' in content_encoding:
            return gzip.GzipFile(fileobj=resp.raw)
        elif 'br' in content_encoding:
            # Brotli doesn't support streaming; we load the whole payload (bounded by size limit)
            data = resp.raw.read()
            return io.BytesIO(brotli.decompress(data))
        else:
            return resp.raw

    def _iter_source_entries(self, map_url: str):
        """
        Stream the sourcemap JSON using ijson and yield (source_path, source_content) pairs.
        Memory footprint stays flat even for huge sourcemaps.
        """
        with self.download_session.get(map_url, stream=True, timeout=(3, 30)) as resp:
            resp.raise_for_status()
            content_length = int(resp.headers.get('content-length', 0))
            if content_length > self.max_file_size:
                logger.warning(f"Source map too large: {map_url} ({content_length} bytes)")
                return

            raw_stream = self._stream_decompress(resp)
            if not HAS_IJSON:
                # Fallback: load everything (not streaming) – still memory heavy
                try:
                    data = json.load(raw_stream)
                    sources = data.get('sources', [])
                    sources_content = data.get('sourcesContent', [])
                    if len(sources) != len(sources_content):
                        logger.warning("Mismatch between sources and sourcesContent")
                        return
                    for src, content in zip(sources, sources_content):
                        if content:
                            yield src, content
                except Exception as e:
                    logger.error(f"Failed to parse sourcemap: {e}")
                return

            # ijson streaming parsing
            parser = ijson.parse(raw_stream)
            sources = []
            sources_content = []
            current_array = None
            in_sources = False
            in_content = False

            for prefix, event, value in parser:
                if prefix == 'sources' and event == 'start_array':
                    in_sources = True
                elif prefix == 'sources' and event == 'end_array':
                    in_sources = False
                elif prefix == 'sourcesContent' and event == 'start_array':
                    in_content = True
                elif prefix == 'sourcesContent' and event == 'end_array':
                    in_content = False
                elif in_sources and event == 'string':
                    sources.append(value)
                elif in_content and event == 'string':
                    sources_content.append(value)

            if len(sources) != len(sources_content):
                logger.warning("Mismatch between sources and sourcesContent")
                return

            for src, content in zip(sources, sources_content):
                if content:
                    yield src, content

    def _scan_source(self, source_path: str, content: str) -> Dict[str, Any]:
        findings = {
            'path': source_path,
            'secrets': [],
            'endpoints': [],
            'ips': [],
            'comments': [],
        }

        # Secrets
        for pattern, name in self.secret_patterns:
            for match in re.finditer(pattern, content):
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context = content[start:end].replace('\n', ' ')
                findings['secrets'].append({
                    'type': name,
                    'value': match.group(0),
                    'context': context.strip(),
                    'line': content[:match.start()].count('\n') + 1
                })

        # Endpoints (regex)
        for match in self.endpoint_pattern.finditer(content):
            endpoint = match.group(0)
            if len(endpoint) > 2 and not endpoint.startswith(('//', '/*')):
                findings['endpoints'].append({'endpoint': endpoint})

        # IP addresses
        for match in self.ip_pattern.finditer(content):
            findings['ips'].append({'ip': match.group(0)})

        # Comments with keywords
        for match in self.comment_pattern.finditer(content):
            findings['comments'].append({'comment': match.group(0).strip()})

        return findings

    def scan_url(self, js_url: str, progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        result = {
            'url': js_url,
            'has_sourcemap': False,
            'source_files': [],
            'findings': []
        }
        try:
            # Probe JS file – read only enough to find sourceMappingURL
            resp = self.probe_session.get(js_url, timeout=(3, 10), stream=True)
            if resp.status_code != 200:
                return result

            # Check for WAF block
            if detect_waf_block(resp):
                logger.warning(f"Request blocked by WAF for {js_url}")
                return result

            js_head = ''
            for chunk in resp.iter_content(chunk_size=8192):
                js_head += chunk.decode('utf-8', errors='ignore')
                if len(js_head) > 20000 or 'sourceMappingURL' in js_head:
                    break

            map_url = self._extract_sourcemap_url(js_head, js_url)
            if not map_url:
                return result

            result['has_sourcemap'] = True
            # Stream parse the sourcemap
            for src_path, src_content in self._iter_source_entries(map_url):
                result['source_files'].append(src_path)
                findings = self._scan_source(src_path, src_content)
                if findings['secrets'] or findings['endpoints'] or findings['comments']:
                    result['findings'].append(findings)

            if progress_callback:
                progress_callback(1.0, f"Scanned {len(result['source_files'])} source files")
            logger.info(f"Found {len(result['findings'])} source files with findings in {js_url}")
        except Exception as e:
            logger.error(f"Error scanning {js_url}: {e}")
        return result

    def scan_urls(self, js_urls: List[str], progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        results = []
        total = len(js_urls)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in js_urls}
            for idx, future in enumerate(concurrent.futures.as_completed(future_to_url)):
                url = future_to_url[future]
                try:
                    res = future.result()
                    if res['findings']:
                        results.append(res)
                    if progress_callback:
                        progress_callback((idx+1)/total, f"Scanned {idx+1}/{total} JS files")
                except Exception as e:
                    logger.error(f"Error processing {url}: {e}")
        return results