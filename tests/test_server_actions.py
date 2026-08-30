"""Focused tests for App Router / flight / server-action extraction (v3.7)."""
from app.modules.tools.js_analyzer import (
    JSAnalyzer,
    decode_flight_payloads,
    dedupe_nextjs_artifacts,
)


def analyzer():
    return JSAnalyzer({
        'js_use_archive': False,
        'js_use_subjs': False,
        'js_use_getjs': False,
    })


ACTION = 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678'


def test_basic_createserverreference_still_detected():
    rows = analyzer()._detect_nextjs_artifacts(
        f'createServerReference("{ACTION}", callServer);', 'https://t/b.js')
    assert any(r['value'] == ACTION and r['type'] == 'next_server_action'
               for r in rows)


def test_interop_paren_variant():
    content = f'(0,l.createServerReference)("{ACTION}",l.callServer)'
    rows = analyzer()._detect_nextjs_artifacts(content, 'https://t/b.js')
    assert rows[0]['value'] == ACTION
    assert rows[0]['extraction_method'] == 'create_server_reference_interop'


def test_minified_alias_form():
    content = f'var s=n.createServerReference;s("{ACTION}",n.callServer,void 0,n.findSourceMapURL,"deleteUserAccount")'
    rows = analyzer()._detect_nextjs_artifacts(content, 'https://t/b.js')
    assert rows[0]['value'] == ACTION
    assert rows[0]['function_name'] in ('deleteUserAccount', '')


def test_register_server_reference_carries_names():
    content = f'registerServerReference(deleteUser,"{ACTION}","deleteUser");'
    rows = analyzer()._detect_nextjs_artifacts(content, 'https://t/b.js')
    assert rows[0]['value'] == ACTION
    assert rows[0]['function_name'] == 'deleteUser'
    assert rows[0]['route_or_module'] == 'deleteUser'
    assert rows[0]['extraction_method'] == 'register_server_reference'


def test_next_action_header_capture():
    content = '{"headers":{"Next-Action":"' + ACTION + '"}}'
    rows = analyzer()._detect_nextjs_artifacts(content, 'https://t/b.js')
    assert rows and rows[0]['extraction_method'] == 'next_action_header'


def test_action_entry_map_in_source_maps():
    content = ('__next_internal_action_entry_do_not_use__='
               f'{{"{ACTION}":"updateProfile"}};')
    rows = analyzer()._detect_nextjs_artifacts(
        content, 'https://t/map-source', is_source_map_source=True)
    assert rows[0]['function_name'] == 'updateProfile'
    assert rows[0]['extraction_method'] == 'source_map_entry_map'
    assert rows[0]['confidence'] == 'high'


def test_flight_payload_decoding_and_marker_gated_ids():
    raw_push = (r'self.__next_f.push([1,"{\"action\":\"$F1\",\"id\":\"'
                + ACTION + r'\",\"bound\":null}"])')
    decoded = decode_flight_payloads(raw_push)
    assert decoded and ACTION in decoded[0]

    # marker present -> id extracted from flight data
    rows = analyzer()._detect_nextjs_artifacts(raw_push, 'https://t/page')
    assert any(r['value'] == ACTION and
               r['extraction_method'].startswith('flight') for r in rows)

    # same ID with NO action marker -> not extracted (no speculative claims)
    plain = r'self.__next_f.push([1,"{\"foo\":\"' + ACTION + r'\"}"])'
    assert analyzer()._detect_nextjs_artifacts(plain, 'https://t/p') == []


def test_dedup_across_bundle_chunk_map_and_flight():
    bundle_row = {'type': 'next_server_action', 'value': ACTION,
                  'function_name': '', 'route_or_module': '',
                  'confidence': 'medium', 'source': 'bundle.js'}
    map_row = {'type': 'next_server_action', 'value': ACTION,
               'function_name': 'deleteUser', 'route_or_module': '',
               'confidence': 'high', 'source': 'map#src'}
    flight_row = dict(map_row)
    flight_row['source'] = 'flight'

    deduped = dedupe_nextjs_artifacts([bundle_row, map_row, flight_row])
    named = [r for r in deduped if r['function_name']]
    bare = [r for r in deduped if not r['function_name']]
    assert len(named) == 1 and len(bare) == 1
    assert named[0]['confidence'] == 'high'


def test_actions_are_inventory_never_vulnerability_labels():
    rows = analyzer()._detect_nextjs_artifacts(
        f'registerServerReference(xferFunds,"{ACTION}","xferFunds");',
        'https://t/b.js')
    assert all(r['severity'] == 'INFO' for r in rows)
    assert all('Inventory only' in r['note'] for r in rows)
    assert all(r['type'] != 'vulnerability' for r in rows)
    assert all(not r.get('severity') or r['severity'] in ('INFO',)
               for r in rows)


def test_rows_carry_required_evidence_fields():
    row = analyzer()._detect_nextjs_artifacts(
        f'registerServerReference(f,"{ACTION}","f");', 'https://t/b.js')[0]
    assert set(row) >= {'type', 'value', 'function_name', 'route_or_module',
                        'source', 'extraction_method', 'severity',
                        'confidence'}
