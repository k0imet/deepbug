import asyncio

from app.modules.tools.xxe_scanner import XXEScanner


class _Response:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def text(self, **kwargs):
        return '<root/>'


class _Session:
    def __init__(self):
        self.kwargs = None

    def request(self, *args, **kwargs):
        self.kwargs = kwargs
        return _Response()


def test_xxe_post_applies_xml_content_type():
    session = _Session()
    asyncio.run(XXEScanner()._send(session, 'https://example.test/xml', 'POST', '<root/>'))
    assert session.kwargs['headers']['Content-Type'] == 'application/xml'
