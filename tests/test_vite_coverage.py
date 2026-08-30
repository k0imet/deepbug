"""Focused tests for Vite/Rollup runtime + manifest coverage (v3.7)."""
import json

from app.modules.tools.js_analyzer import (
    JSAnalyzer,
    extract_vite_assets,
    has_vite_evidence,
    parse_vite_manifest,
    vite_manifest_candidates,
)


def analyzer():
    return JSAnalyzer({
        'js_use_archive': False,
        'js_use_subjs': False,
        'js_use_getjs': False,
    })


BUNDLE = 'https://t.example/assets/index-A1b2C3.js'


def test_runtime_marker_alone_is_not_strong_evidence():
    assert has_vite_evidence('import.meta.env.MODE') is False
    assert has_vite_evidence('__vite__mapDeps([0])') is True


def test_literal_dynamic_imports_extracted():
    content = ('const m = () => import("./chunk-Ab12.js");\n'
               'const n = () => import("/assets/lazy-Xy9z.mjs?import");')
    assets = extract_vite_assets(content)
    assert sorted(assets['chunks']) == ['./chunk-Ab12.js',
                                        '/assets/lazy-Xy9z.mjs']
    assert assets['other'] == []


def test_mapdeps_and_preload_arrays_extracted_with_css_segregated():
    content = ('const __vite__mapDeps=(i,m=__vite__mapDeps,d=m.f||('
               'm.f=["assets/shared-Dp1.js","assets/style-Qq2.css",'
               '"img/logo.png"]))=>i.map(k=>d[k]);'
               '__vitePreload(()=>import("./view-Zz9.js"),["assets/view-Zz9.css"])')
    assets = extract_vite_assets(content)
    assert 'assets/shared-Dp1.js' in assets['chunks']
    assert './view-Zz9.js' in assets['chunks']
    # CSS/images are recorded, never treated as JS chunks
    assert 'assets/style-Qq2.css' in assets['other']
    assert 'img/logo.png' in assets['other']
    assert not any(c.endswith('.css') for c in assets['chunks'])


def test_manifest_candidates_require_reference_or_strong_evidence():
    # weak content: no reference, no strong evidence -> no probing
    cands, strong = vite_manifest_candidates(BUNDLE, 'console.log(1)')
    assert cands == [] and strong is False
    # referenced manifest -> probed even without runtime markers
    cands, _ = vite_manifest_candidates(BUNDLE, 'fetch("./.vite/manifest.json")')
    assert any(c.endswith('.vite/manifest.json') for c in cands)
    # strong evidence -> bounded default probes
    cands, strong = vite_manifest_candidates(BUNDLE, '__vite__mapDeps([0]);')
    assert strong and 0 < len(cands) <= 6


def test_parse_vite_manifest_entries_imports_and_assets():
    manifest = {
        "_": None,
        "src/main.tsx": {"file": "assets/index-A1.js", "isEntry": True,
                         "imports": ["node_modules/vendor.js"],
                         "dynamicImports": ["src/Lazy.tsx"],
                         "css": ["assets/index-A1.css"]},
        "src/Lazy.tsx": {"file": "assets/lazy-B2.js",
                         "isDynamicEntry": True},
        "src/style.scss": {"file": "assets/style-C3.css"},
        "src/logo.svg": {"file": "assets/logo-D4.svg"},
    }
    parsed = parse_vite_manifest(manifest, BUNDLE.rsplit('/', 1)[0] + '/')
    base = BUNDLE.rsplit('/', 1)[0]
    assert parsed['entries'] == [f'{base}/assets/index-A1.js']
    assert f'{base}/assets/lazy-B2.js' in parsed['chunks']
    assert f'{base}/node_modules/vendor.js' in parsed['chunks']
    assert f'{base}/assets/index-A1.css' in parsed['css']
    assert f'{base}/assets/logo-D4.svg' in parsed['assets']
    assert 'src/main.tsx' in parsed['sources']


def test_analyzed_bundle_feeds_chunks_and_skips_css_as_js():
    subject = analyzer()
    content = ('__vitePreload(()=>import("./lazy-Ef5.js"),[])'
               ';__vite__mapDeps([0])')
    out = subject._analyze_single_file(BUNDLE, content)
    chunk_urls = {u for u in out['chunks']}
    assert 'https://t.example/assets/lazy-Ef5.js' in chunk_urls
    assert all(u.lower().endswith(('.js', '.mjs')) for u in chunk_urls)
    # manifest probe candidates staged (strong evidence present)
    assert any('manifest.json' in u for u in out['vite_manifests'])


def test_css_never_enters_chunk_pipeline():
    subject = analyzer()
    out = subject._analyze_single_file(
        BUNDLE, '__vite__mapDeps([0]);m.f=["style-A1.css"]')
    assert not list(out['chunks'])


def test_vite_manifest_fetch_outcomes_recorded_in_coverage():
    subject = analyzer()
    subject.scope_hosts = {'t.example'}
    url = 'https://t.example/assets/.vite/manifest.json'
    good = json.dumps({
        "src/a.ts": {"file": "a-H1.js", "isEntry": True},
        "src/b.ts": {"file": "b-H2.js", "isDynamicEntry": True,
                     "css": ["../shared.css"]},
    })
    # Vite manifest entry files are relative to the MANIFEST directory
    # (.vite/), so resolution must land inside .vite/, and css is recorded
    # separately - never as JS chunks.
    parsed = parse_vite_manifest(json.loads(good), url.rsplit('/', 1)[0] + '/')
    assert parsed['entries'] == ['https://t.example/assets/.vite/a-H1.js']
    assert 'https://t.example/assets/.vite/b-H2.js' in parsed['chunks']
    assert parsed['css'] == ['https://t.example/assets/shared.css']
    assert parsed['assets'] == []
