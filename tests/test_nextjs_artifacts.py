from app.modules.tools.js_analyzer import JSAnalyzer


def analyzer():
    return JSAnalyzer({
        'js_use_archive': False,
        'js_use_subjs': False,
        'js_use_getjs': False,
    })


def test_detects_next_server_action_and_build_routes():
    action = 'a' * 40
    content = f'''createServerReference("{action}", callServer);
                  self.__BUILD_MANIFEST={{sortedPages:["/","/account/[id]"]}};'''

    rows = analyzer()._detect_nextjs_artifacts(content, 'https://example.test/app.js')

    assert {(row['type'], row['value']) for row in rows} == {
        ('next_server_action', action),
        ('next_route', '/'),
        ('next_route', '/account/[id]'),
    }


def test_next_artifacts_are_inventory_not_vulnerability_claims():
    action = 'Z' * 24
    row = analyzer()._detect_nextjs_artifacts(
        f'createServerReference("{action}", callServer)', 'https://example.test/x.js')[0]

    assert row['severity'] == 'INFO'
    assert 'Inventory only' in row['note']
