# modules/tools/url_cleaner.py
# URL list de-polluter / dedup -- a local, dependency-free "uro" replacement.
#
# The lesson from the "Recon to Master" checklist + the "5-Minute Workflow":
# crawled / archived / GF-tagged URL lists are 90% noise. Before they feed
# collateral (nuclei, browsers, param miners) they should be reduced to the
# minimal set that can actually carry a finding signal:
#
#   * static / media assets dropped           (css, js, img, woff, ...)
#   * download / export assets dropped        (zip, pdf, docx, apk, ...)
#   * tracking params stripped                (utm_*, fbclid, gclid, ...)
#   * path normalization                      (lowercased host, trailing slash)
#   * blog / news / date-slug noise reduced    (URLs map to a cleaner key)
#   * query de-dup by *parameter key*  -- two URLs that differ only in a
#     value (and the value is not itself signal) collapse to one line
#
#  uro calls this "--pathglot", "--sneaky". Ours does the same using only
#  the standard library, so every pipeline (active crawler, wayback hunter,
#  GF hits) can share the same de-pollution before feeding the validators.

import re
from typing import Dict, List, Iterable, Optional, Any
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)


_STATIC_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.avif',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.webm', '.avi', '.mov', '.wav',
}

_DOWNLOAD_EXT = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.exe', '.dmg', '.msi', '.apk', '.deb', '.rpm',
}

_TRACK_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_cid', 'utm_brand', 'utm_cn', 'utm_ctx',
    'gclid', 'yclid', 'fbclid', 'msclkid', 'dclid', 'olvkw', 'mc_cid',
    'from', 'ref', 'ref_source', 'ref_campaign', 'ref_id',
    '_ga', '_gs', '_gid', 'wbraid', 'gbraid', 'campaign_id', 'subid',
    'PHPSESSID', 'sessionid', 'jsessionid',
}

_BLOG_SEGS = [
    '/blog/', '/blogs/', '/news/', '/press/', '/post/', '/posts/',
    '/article/', '/articles/', '/category/', '/categories/', '/tag/',
    '/author/', '/authors/', '/media/', '/updates/', '/stories/',
]

_DATE_RE = re.compile(r'(?:^|/)\d{4}(?:[-/]\d{1,2}(?:[-/]\d{1,2})?)?(?:/|$)')


class URLCleaner:
    """
    De-pollute URL lists into a signal-carrying core set.

    Usage:
        cleaner = URLCleaner()
        clean_urls  = cleaner.clean_urls(["https://tgt.com/a?utm_source=x&b=1",
                                          "https://tgt.com/a?b=2"])
        # -> ["https://tgt.com/a?b="]  (param set collapses to key)
    """

    def __init__(self, config: Optional[Dict] = None, drop_blog_slugs: bool = True):
        config = config or {}
        uc = config.get("url_clean", config) if isinstance(config, dict) else {}
        # drop_blog_slugs: strip date/news-style path decoration
        self.drop_blog = bool(uc.get("drop_blog_slugs", drop_blog_slugs))
        # keep_values: True keeps query VALUES, otherwise dedupe by path+keys
        self.keep_values = bool(uc.get("keep_values", False))

    # -- single URL ----------------------------------------------------
    def clean_url(self, raw: str) -> Optional[str]:
        """Return cleaned URL, or None when it has no signal to give."""
        try:
            u = raw.strip()
            if not u:
                return None
            if u.startswith('//'):
                u = 'https:' + u
            elif not u.startswith(('http://', 'https://')):
                u = 'https://' + u

            parts = urlsplit(u)
            host = parts.hostname.lower() if parts.hostname else parts.netloc.lower()
            if not host:
                return None
            path = parts.path or '/'
            if len(path) > 1 and path.endswith('/'):
                path = path.rstrip('/')

            if path.lower().endswith(tuple(_STATIC_EXT)):
                return None
            if path.lower().endswith(tuple(_DOWNLOAD_EXT)):
                return None
            if self.drop_blog and _is_decorative(path):
                return None

            # --- build a canonical query string ----------------------
            if self.keep_values:
                kept = []
                for k, v in parse_qsl(parts.query, keep_blank_values=True):
                    if k.lower() not in _TRACK_PARAMS:
                        kept.append((k, v))
                query = urlencode(kept)
                return _url(host, parts, query)

            keys = []
            for k, _v in parse_qsl(parts.query, keep_blank_values=True):
                if k.lower() not in _TRACK_PARAMS:
                    keys.append(k)
            if keys:
                query = urlencode([(k, '') for k in sorted(set(keys))])
            else:
                query = ''
            return _urljoin(host, parts, query)
        except Exception:
            return None

    # ------------------------------------------------------------------
    def clean_urls(self, urls: Iterable[str]) -> List[str]:
        seen = set()
        out: List[str] = []
        for raw in urls:
            c = self.clean_url(raw) if raw else None
            if c is None:
                continue
            key = c
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out

    def summarize(self, urls: Iterable[str]) -> Dict[str, Any]:
        cleaned = self.clean_urls(urls)
        by_host: Dict[str, int] = {}
        for c in cleaned:
            h = urlsplit(c).netloc
            by_host[h] = by_host.get(h, 0) + 1
        return {"cleaned": cleaned, "by_host": by_host}


# ---------------------------------------------------------------------
def _url(host: str, parts, query: str) -> str:
    scheme = "https" if parts.scheme in ("https", "http") else "https"
    h = host.lower()
    if parts.port:
        h = f"{h}:{parts.port}"
    path = parts.path or "/"
    if not path:
        path = "/"
    return urlunsplit((scheme, h, path, query, ""))


def _urljoin(host: str, parts, query: str) -> str:
    return _url(host, parts, query)


def _is_decorative(path: str) -> bool:
    """Path decoration that is unlikely to accept attacker input: blog
    listing, date-tree, or simple content slugs."""
    pl = path.lower()
    if any(s in pl for s in _BLOG_SEGS):
        return True
    if _DATE_RE.search(pl):
        return True
    # numeric-id-ish ending but IS one of the interesting ones we keep.
    # e.g. /post/2021/10/hello -> covered by _BLOG_SEGS above
    return False