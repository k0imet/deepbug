"""Focused tests for proactive Next.js manifest discovery (v3.7)."""
from app.modules.tools.js_analyzer import (
    JSAnalyzer,
    extract_nextjs_build_ids,
    nextjs_manifest_candidates,
    parse_next_build_manifest,
    parse_next_path_set_manifest,
    parse_next_routes_manifest,
)


def analyzer():
    return JSAnalyzer({
        'js_use_archive': False,
        'js_use_subjs': False,
        'js_use_getjs': False,
    })


def test_build_id_from_raw_next_data_json():
    html = ('<script id="__NEXT_DATA__" type="application/json">'
            '{"props":{},"buildId":"build-20260825-x","page":"/"}</script>')
    assert extract_nextjs_build_ids(html) == ['build-20260825-x']


def test_build_id_from_escaped_inline_flight_form():
    inline = r'self.__NEXT_DATA__=JSON.parse("{\"buildId\":\"9xYz_123\"}")'
    assert extract_nextjs_build_ids(inline) == ['9xYz_123']


def test_build_id_from_static_script_reference():
    html = '<script src="/_next/static/AbC123def/_buildManifest.js"></script>'
    assert extract_nextjs_build_ids(html) == ['AbC123def']


def test_build_id_rejects_framework_path_segments_and_garbage():
    assert extract_nextjs_build_ids(
        '/_next/static/chunks/main.js') == []
    assert extract_nextjs_build_ids('<p>no data here</p>') == []
    # charset violation: slashes and spaces are never build IDs
    assert extract_nextjs_build_ids('"buildId":"../etc passwd"') == []


def test_candidates_cover_all_client_manifest_names():
    cands = nextjs_manifest_candidates('https://t.example/', 'b1')
    names = [c.rsplit('/', 1)[-1] for c in cands]
    assert set(names) == {'_buildManifest.js', '_ssgManifest.js',
                          '_middlewareManifest.js', '_routesManifest.json'}
    assert all(c.startswith('https://t.example/_next/static/b1/') for c in cands)
    assert not any('server' in c for c in cands)


def test_parse_build_manifest_routes_and_chunks():
    text = ('self.__BUILD_MANIFEST={"/":["static/chunks/main-abc.js"],'
            '"/about":["static/chunks/about-def.js"]};')
    parsed = parse_next_build_manifest(
        text, 'https://t.example/_next/static/bld1/_buildManifest.js')
    assert parsed['routes'] == ['/', '/about']
    assert parsed['chunks'] == [
        'https://t.example/_next/static/bld1/static/chunks/main-abc.js',
        'https://t.example/_next/static/bld1/static/chunks/about-def.js',
    ]


def test_parse_build_manifest_iife_wrapped_and_sorted_pages():
    text = ('self.__BUILD_MANIFEST=(function(t){return t})({"/docs":[],'
            '"static/chunks/x-1.js":[],"sortedPages":["/docs","/blog/[slug]"]});')
    parsed = parse_next_build_manifest(
        text, 'https://t.example/_next/static/bld1/_buildManifest.js')
    assert '/docs' in parsed['routes']
    assert '/blog/[slug]' in parsed['routes']
    assert any('x-1.js' in c for c in parsed['chunks'])


def test_parse_routes_manifest_json_defensive():
    routes = parse_next_routes_manifest(
        '{"version":3,"dynamicRoutes":[{"page":"/blog/[slug]","regex":"x"}],'
        '"dataRoutes":[{"page":"/ssr-page"}]}')
    assert routes == ['/blog/[slug]', '/ssr-page']
    assert parse_next_routes_manifest('not json at all') == []


def test_parse_ssg_and_middleware_path_sets():
    ssg = parse_next_path_set_manifest('self.__SSG_MANIFEST=new Set(["/pre","/a/b"]);')
    mw = parse_next_path_set_manifest('self.__MIDDLEWARE_MANIFEST=["/edge"];')
    assert ssg == ['/pre', '/a/b']
    assert mw == ['/edge']
    assert parse_next_path_set_manifest('self.__SSG_MANIFEST=void 0') == []


def test_server_only_artifacts_only_when_referenced():
    subject = analyzer()
    subject.scope_hosts = {'t.example'}
    html = ('<script>fetch("/_next/server/app-paths-manifest.json")</script>'
            '<div>hello</div>')
    accepted = subject._collect_nextjs_candidates(html, [], 'https://t.example/')
    assert 'https://t.example/_next/server/app-paths-manifest.json' in accepted

    # no reference -> nothing server-side is probed
    subject2 = analyzer()
    subject2.scope_hosts = {'t.example'}
    accepted2 = subject2._collect_nextjs_candidates(
        '<html><body>plain</body></html>', [], 'https://t.example/')
    assert accepted2 == []
    assert all('/server/' not in row['url'] or row['outcome'].startswith('skipped')
               for row in subject2._candidate_notes)


def test_candidate_generation_is_capped():
    subject = analyzer()
    subject.max_nextjs_manifests = 4
    subject.scope_hosts = None
    subject._collect_nextjs_candidates(
        '{"buildId":"aaaa1111"}', [], 'https://t.example/')
    assert len(subject._nextjs_candidates) <= 4


def test_out_of_scope_candidate_recorded_but_not_fetched():
    subject = analyzer()
    subject.scope_hosts = {'other.example'}
    accepted = subject._collect_nextjs_candidates(
        '{"buildId":"zzzz9999"}', [], 'https://t.example/')
    assert accepted == []
    notes = subject._candidate_notes
    assert notes and all(n['outcome'] == 'skipped_out_of_scope'
                         for n in notes)
    assert all(n['kind'] == 'nextjs_manifest_candidate' for n in notes)


def test_private_ip_candidate_blocked():
    subject = analyzer()
    subject.scope_hosts = None
    accepted = subject._collect_nextjs_candidates(
        '{"buildId":"priv1234"}', [], 'http://10.0.0.5/')
    assert accepted == []
    assert subject._candidate_notes[0]['outcome'] == 'blocked_private_host'


def test_analyzed_manifest_yields_route_rows_and_chunk_feeders():
    subject = analyzer()
    url = 'https://t.example/_next/static/bld1/_buildManifest.js'
    content = ('self.__BUILD_MANIFEST={"/account":["static/chunks/account-a1.js"]};'
               'sortedPages:["/","/account"];')
    out = subject._analyze_single_file(url, content)
    chunk_urls = list(out['chunks'])
    assert 'https://t.example/_next/static/bld1/static/chunks/account-a1.js' \
        in chunk_urls
    route_values = {row['value'] for row in out['nextjs']}
    assert {'/', '/account'} <= route_values
    manifest_rows = [r for r in out['nextjs']
                     if r['extraction_method'] == 'build_manifest']
    assert manifest_rows and all(r['severity'] == 'INFO' for r in manifest_rows)
