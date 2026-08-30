"""End-to-end fixture (v3.7): a fully local campaign exercising

seed HTML -> iframe HTML -> main bundle -> Next.js _buildManifest.js ->
lazy chunk -> sourceMappingURL -> source map (sourcesContent) -> hidden
endpoint recovered from the ORIGINAL source.

Constraints honoured here:
* localhost only, ephemeral ports (127.0.0.1:0);
* reliable teardown (explicit shutdown + join, asserted);
* no live program scan - the analyzer runs against this fixture only;
* the assertion suite covers every stage plus the no-out-of-scope-fetch
  guarantee (every request the engine makes is logged server-side).
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pandas as pd
import pytest

from app.modules.tools.js_analyzer import JSAnalyzer

BUILD_ID = 'e2ebuild2026a'
HOST = '127.0.0.1'

SEED_HTML = f"""<html><head>
<script id="__NEXT_DATA__" type="application/json">
{{"buildId":"{BUILD_ID}","page":"/","props":{{}}}}</script>
<script src="/static/main.js"></script>
</head><body><iframe src="/app/shell"></iframe></body></html>"""

SHELL_HTML = """<html><head><script src="/static/main.js"></script></head>
<body>embedded shell</body></html>"""

MAIN_JS = (
    '(self.webpackChunk=self.webpackChunk||[]).push([[177],{},function(n){}]);'
    'createServerReference("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",'
    'callServer,void 0,findSourceMapURL,"deleteUserAccount");')

BUILD_MANIFEST_JS = (
    'self.__BUILD_MANIFEST={"/":["static/chunks/lazy-e2e.js"],'
    '"/account/[id]":["static/chunks/lazy-e2e.js"]};'
    'sortedPages:["/","/account/[id]"];')

# The compiled chunk itself contains NO endpoint - the sensitive material
# lives only in the recovered ORIGINAL source below.
LAZY_CHUNK_JS = '(function(){"use strict";var e=1;})();\n' \
                '//# sourceMappingURL=/static/chunks/lazy-e2e.js.map\n'

SOURCE_MAP = {
    "version": 3,
    "file": "lazy-e2e.js",
    "sources": ["webpack:///_/src/admin/export-all.ts"],
    "sourcesContent": [
        "export const EXPORT_ENDPOINT = '/api/internal/v1/export-all';\n"
        "export const LEGACY_PATH = \"/admin/debug/dump-users\";\n"
    ],
    "names": [],
    "mappings": "AAAA",
}

RESPONSES = {
    '/': ('html', SEED_HTML),
    '/app/shell': ('html', SHELL_HTML),
    '/static/main.js': ('js', MAIN_JS),
    f'/_next/static/{BUILD_ID}/_buildManifest.js': ('js', BUILD_MANIFEST_JS),
    f'/_next/static/{BUILD_ID}/static/chunks/lazy-e2e.js':
        ('js', LAZY_CHUNK_JS),
    '/static/chunks/lazy-e2e.js.map': ('json', json.dumps(SOURCE_MAP)),
}
ALLOWED_PATHS = set(RESPONSES) | {
    # routine negative probes the engine is ALLOWED to make in-scope:
    '/static/main.js.map',                       # guessed {bundle}.map
    f'/_next/static/{BUILD_ID}/_buildManifest.js.map',
    f'/_next/static/{BUILD_ID}/static/chunks/lazy-e2e.js.map',
    f'/_next/static/{BUILD_ID}/_ssgManifest.js',
    f'/_next/static/{BUILD_ID}/_middlewareManifest.js',
    f'/_next/static/{BUILD_ID}/_routesManifest.json',
}

CONTENT_TYPES = {'html': 'text/html; charset=utf-8',
                 'js': 'application/javascript',
                 'json': 'application/json'}


class _State:
    requested: list


def _make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split('?')[0]
            state.requested.append(path)
            entry = RESPONSES.get(path)
            if entry is None:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            kind, body = entry
            payload = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPES[kind])
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture(scope='module')
def e2e_results():
    state = _State()
    state.requested = []
    server = ThreadingHTTPServer((HOST, 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True,
                              name='deepbug-e2e-fixture')
    thread.start()
    base = f'http://{HOST}:{server.server_address[1]}'
    try:
        analyzer = JSAnalyzer({
            'js_use_archive': False,
            'js_use_subjs': False,
            'js_use_getjs': False,
            'js_validate_endpoints': False,
        })
        analyzer.scope_hosts = {HOST}
        results = analyzer.analyze_js_for_project(
            [f'{base}/'], validate=False)
        yield {
            'results': results,
            'requested': [p for p in state.requested],
            'base': base,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        assert not thread.is_alive(), 'fixture server did not shut down'


def _frame(results, key):
    df = results.get(key)
    return df if isinstance(df, __import__('pandas').DataFrame) else None


def test_iframe_was_treated_as_html_not_js(e2e_results):
    cov = e2e_results['results']['js_coverage']
    shell = f"{e2e_results['base']}/app/shell"
    frames = cov[(cov.get('kind') == 'frame_seed') & (cov.get('url') == shell)]
    assert not frames.empty
    assert str(frames.iloc[0]['outcome']).startswith('html_ok')
    # the shell document itself was never analyzed as a JavaScript file
    js_files = e2e_results['results']['js_files']
    assert not any(js_files.get('url', pd.Series(dtype=str)).eq(shell))


def test_manifest_and_lazy_chunk_were_fetched(e2e_results):
    cov = e2e_results['results']['js_coverage']
    manifest_url = (f"{e2e_results['base']}/_next/static/"
                    f"{BUILD_ID}/_buildManifest.js")
    mrows = cov[cov.get('url') == manifest_url]
    assert not mrows.empty
    assert mrows.iloc[0].get('kind') == 'nextjs_manifest'
    assert mrows.iloc[0].get('outcome') == 'ok'

    chunk_url = (f"{e2e_results['base']}/_next/static/"
                 f"{BUILD_ID}/static/chunks/lazy-e2e.js")
    crows = cov[(cov.get('kind') == 'chunk') & (cov.get('url') == chunk_url)]
    assert not crows.empty and crows.iloc[0].get('outcome') == 'ok'


def test_map_unpacked_with_sources_content(e2e_results):
    smaps = e2e_results['results']['js_source_maps']
    unpacked = smaps[smaps.get('outcome') == 'unpacked'] \
        if not smaps.empty else smaps
    assert not unpacked.empty
    assert int(unpacked.iloc[0]['sources_content_count']) >= 1
    assert 'lazy-e2e.js.map' in str(unpacked.iloc[0]['source_map_url'])


def test_recovered_endpoint_from_original_source_present(e2e_results):
    eps = e2e_results['results']['js_discovered_endpoints']
    blob = '\n'.join(
        ' '.join(str(v) for v in row) for row in eps.itertuples(index=False)) \
        if not eps.empty else ''
    assert '/api/internal/v1/export-all' in blob
    assert '/admin/debug/dump-users' in blob
    # evidence must point back at the source map that produced the rows
    map_rows = eps[eps.get('original_src', '').astype(str).str.contains(
        'export-all.ts', na=False)] if not eps.empty else eps
    assert not map_rows.empty


def test_coverage_contains_all_stages(e2e_results):
    kinds = set(e2e_results['results']['js_coverage'].get('kind', []))
    assert {'seed', 'frame_seed', 'nextjs_manifest', 'chunk',
            'source_map'} <= kinds


def test_no_out_of_scope_url_was_fetched(e2e_results):
    for path in e2e_results['requested']:
        assert path in ALLOWED_PATHS, f'unexpected fetch: {path}'
    # and the chain really happened end to end
    for required in ('/', '/app/shell', '/static/main.js',
                     f'/_next/static/{BUILD_ID}/_buildManifest.js',
                     f'/_next/static/{BUILD_ID}/static/chunks/'
                     f'lazy-e2e.js',
                     '/static/chunks/lazy-e2e.js.map'):
        assert required in e2e_results['requested']


def test_server_action_inventory_recorded(e2e_results):
    arts = e2e_results['results']['js_nextjs_artifacts']
    actions = arts[arts.get('type') == 'next_server_action'] \
        if not arts.empty else arts
    assert not actions.empty
    row = actions.iloc[0]
    assert row['severity'] == 'INFO'
    assert row['extraction_method']
