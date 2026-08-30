from app.modules.tools.js_analyzer import JSAnalyzer


def analyzer():
    return JSAnalyzer({
        'js_use_archive': False,
        'js_use_subjs': False,
        'js_use_getjs': False,
    })


def test_html_asset_parser_handles_real_world_attribute_forms():
    subject = analyzer()
    html = """
      <base href=/assets/>
      <script defer src=main.js></script>
      <link href='lazy.js' as='script' rel='preload stylesheet'>
      <link rel='modulepreload crossorigin' href=module.js>
      <script>window.apiBase = '/api/v2';</script>
    """

    urls, inline = subject._extract_js_from_html(html, 'https://example.test/app/')

    assert urls == [
        'https://example.test/assets/main.js',
        'https://example.test/assets/lazy.js',
        'https://example.test/assets/module.js',
    ]
    assert inline == ["window.apiBase = '/api/v2';"]


def test_frames_are_not_misclassified_as_javascript():
    subject = analyzer()

    urls, _ = subject._extract_js_from_html(
        '<iframe src="/embedded/app"></iframe>', 'https://example.test/')

    assert urls == []
    assert subject._last_frame_urls == ['https://example.test/embedded/app']
