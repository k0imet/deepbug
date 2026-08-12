"""Safe URL parsing helpers (Python 3.13 hardening).

urllib.parse.urlparse() / urlsplit() / urljoin() have raised ValueError
since 3.13 on malformed bracketed netlocs - an unbalanced bracket
('http://[::1') or a bracketed literal that is not an IP address
('http://[zzz]') - where older Pythons returned a lenient parse result.
`.port` also raises ValueError on non-numeric ports.

deepbug feeds attacker-controlled strings (extracted from JS, HTML,
Wayback dumps, third-party tool output) through these parsers, so one
bad string must never abort a whole scan.

The safe_* wrappers never raise on parse: on ValueError they percent-encode
the brackets (always legal in URLs), parse, then decode the affected
components - reproducing the pre-3.13 behaviour for malformed input while
leaving valid URLs byte-for-byte untouched. They are drop-in compatible
(urlparse returns a 6-field ParseResult, urlsplit a 5-field one).
"""

from urllib.parse import ParseResult, urljoin as _urljoin
from urllib.parse import urlparse as _urlparse
from urllib.parse import urlsplit as _urlsplit


def _escape_brackets(url: str) -> str:
    return url.replace('[', '%5B').replace(']', '%5D')


def _unescape_brackets(text: str) -> str:
    return text.replace('%5B', '[').replace('%5D', ']')


def safe_urlsplit(url: str, scheme: str = '', allow_fragments: bool = True) -> ParseResult:
    try:
        return _urlsplit(url, scheme, allow_fragments)
    except ValueError:
        try:
            p = _urlsplit(_escape_brackets(url), scheme, allow_fragments)
        except ValueError:
            return ParseResult('', '', url, '', '')
        return ParseResult(p.scheme, _unescape_brackets(p.netloc),
                           _unescape_brackets(p.path),
                           _unescape_brackets(p.query),
                           _unescape_brackets(p.fragment))


def safe_urlparse(url: str, scheme: str = '', allow_fragments: bool = True) -> ParseResult:
    try:
        return _urlparse(url, scheme, allow_fragments)
    except ValueError:
        try:
            p = _urlparse(_escape_brackets(url), scheme, allow_fragments)
        except ValueError:
            return ParseResult('', '', url, '', '', '')
        return ParseResult(p.scheme, _unescape_brackets(p.netloc),
                           _unescape_brackets(p.path), _unescape_brackets(p.params),
                           _unescape_brackets(p.query), _unescape_brackets(p.fragment))


def safe_urljoin(base: str, url: str) -> str:
    try:
        return _urljoin(base, url)
    except ValueError:
        try:
            return _unescape_brackets(_urljoin(_escape_brackets(base),
                                               _escape_brackets(url)))
        except ValueError:
            if url.startswith(('http://', 'https://', '//')):
                return url
            return base


def safe_port(parsed: ParseResult):
    """parsed.port, but never raises on non-numeric ports."""
    try:
        return parsed.port
    except ValueError:
        return None


# Drop-in aliases: `from app.utils.url_utils import urlparse, urljoin`
urlparse = safe_urlparse
urlsplit = safe_urlsplit
urljoin = safe_urljoin

__all__ = ['safe_urlparse', 'safe_urlsplit', 'safe_urljoin', 'safe_port',
           'urlparse', 'urlsplit', 'urljoin']
