# app/modules/integrations/auth_session.py
"""AuthSession — one auth context, injected everywhere.

Bug-hunting reality: most high-value surface is behind a login. This module
captures ONE authenticated context per target (cookies + bearer + refresh
state) via several flows and replays it into every validator:

  * json_login   - POST JSON {"email":..,"password":..} -> extract access token
                   from the response (recursive key scan) or Authorization header
  * form_login   - GET the login page, harvest its CSRF token(s), POST the form
  * oauth2       - grant_type=password against /oauth/token (client_id/secret)
  * manual_cookie / manual_bearer - paste an existing session

Token extraction is defensive: JSON key scan (token/access_token/jwt/...),
Bearer response headers, cookie set on login response. A refresh_token is kept
so expired-token flows can recover.

Auth data is stored per project under projects/<project>/.auth/<target>.json
(projects/ is gitignored - tokens never reach the repo). Never logs tokens.

Config keys (under `auth_session.*`):
  timeout, retries, verify_tls (default False - targets are often self-signed)
"""

import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_TOKEN_KEYS = ('access_token', 'token', 'jwt', 'id_token', 'auth_token', 'accessToken', 'jwtToken')
_REFRESH_KEYS = ('refresh_token', 'refreshToken')
_CSRF_INPUT = ('csrf', 'token', '_token', '__RequestVerificationToken', 'authenticity_token', 'xsrf')


class AuthError(Exception):
    pass


class AuthSession:
    """A single authenticated context for one target."""

    def __init__(self, target: str = '', base_url: str = '',
                 cookies: Optional[Dict[str, str]] = None,
                 bearer: str = '',
                 headers: Optional[Dict[str, str]] = None):
        self.target = target
        self.base_url = base_url.rstrip('/')
        self.cookies: Dict[str, str] = dict(cookies or {})
        self.bearer = bearer
        self.extra_headers: Dict[str, str] = dict(headers or {})
        self.refresh_token = ''
        self.token_expires_at: Optional[float] = None
        self.flow = ''
        self.last_errors: List[str] = []

    # ------------------------------------------------------------------ state
    @property
    def authenticated(self) -> bool:
        return bool(self.bearer) or bool(self.cookies)

    @property
    def expired(self) -> bool:
        return bool(self.token_expires_at and time.time() > self.token_expires_at)

    def auth_headers(self) -> Dict[str, str]:
        """Headers to merge into ANY request (aiohttp/httpx/requests)."""
        h = dict(self.extra_headers)
        if self.bearer:
            h['Authorization'] = f'Bearer {self.bearer}'
        return h

    def to_dict(self) -> Dict:
        return {
            'target': self.target, 'base_url': self.base_url,
            'cookies': self.cookies, 'bearer': self.bearer,
            'extra_headers': self.extra_headers, 'refresh_token': self.refresh_token,
            'token_expires_at': self.token_expires_at, 'flow': self.flow,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "AuthSession":
        s = cls(target=d.get('target', ''), base_url=d.get('base_url', ''),
                cookies=d.get('cookies') or {}, bearer=d.get('bearer', ''),
                headers=d.get('extra_headers') or {})
        s.refresh_token = str(d.get('refresh_token', '') or '')
        s.token_expires_at = d.get('token_expires_at')
        s.flow = str(d.get('flow', '') or '')
        return s

    # ------------------------------------------------------------------ I/O
    def save(self, project_path: Path):
        auth_dir = Path(project_path) / '.auth'
        auth_dir.mkdir(parents=True, exist_ok=True)
        safe = self.target.replace('.', '_').replace('/', '_').replace(':', '_')
        (auth_dir / f'{safe}.json').write_text(json.dumps(self.to_dict(), indent=1))

    @classmethod
    def load(cls, project_path: Path, target: str) -> Optional["AuthSession"]:
        auth_dir = Path(project_path) / '.auth'
        safe = target.replace('.', '_').replace('/', '_').replace(':', '_')
        f = auth_dir / f'{safe}.json'
        if not f.exists():
            return None
        try:
            return cls.from_dict(json.loads(f.read_text()))
        except Exception as e:
            logger.warning('AuthSession load failed: %s', e)
            return None

    # ------------------------------------------------------------------ flows
    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=30, verify=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'},
            follow_redirects=False)

    @staticmethod
    def _scan_token(payload: dict) -> Tuple[str, str]:
        """Recursively find (access_token, refresh_token) in a JSON response."""
        access, refresh = '', ''
        stack = [payload]
        while stack and not access:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for k, v in node.items():
                low = k.lower()
                if not access and low in _TOKEN_KEYS and isinstance(v, str):
                    access = v
                if not refresh and low in _REFRESH_KEYS and isinstance(v, str):
                    refresh = v
                if isinstance(v, dict):
                    stack.append(v)
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    stack.append(v[0])
        return access, refresh

    def json_login(self, url: str, username_field: str, password_field: str,
                   username: str, password: str,
                   extra_fields: Optional[Dict] = None) -> "AuthSession":
        """POST JSON credentials; harvest token from body/headers/cookie."""
        self.flow = 'json_login'
        payload = {username_field: username, password_field: password}
        if extra_fields:
            payload.update(extra_fields)
        with self._client() as c:
            try:
                r = c.post(urljoin(self.base_url, url), json=payload)
            except httpx.HTTPError as e:
                raise AuthError(f'json_login transport error: {e}')
        if r.status_code not in (200, 201):
            raise AuthError(f'json_login HTTP {r.status_code}: {r.text[:200]}')
        try:
            body = r.json()
        except Exception:
            body = {}
        access, refresh = self._scan_token(body)
        if not access:
            # Bearer/Token response header?
            for h in ('Authorization', 'Token', 'X-Auth-Token', 'Set-Cookie'):
                v = r.headers.get(h, '')
                if v.startswith('Bearer '):
                    access = v[7:]
                    break
        if not access and not r.cookies:
            raise AuthError(f'json_login: no token or session cookie in response: {r.text[:200]}')
        if access:
            self.bearer = access
            self.refresh_token = refresh
        # cookie-set session (no token) is valid too
        self.cookies.update(dict(r.cookies))
        self.base_url = self.base_url or urljoin(str(r.url), '/')
        return self

    def form_login(self, url: str, username_field: str, password_field: str,
                   username: str, password: str,
                   csrf_fields: Optional[List[str]] = None) -> "AuthSession":
        """GET login page, harvest CSRF input(s), POST the form (urlencoded)."""
        self.flow = 'form_login'
        import re
        with self._client() as c:
            try:
                page = c.get(urljoin(self.base_url, url))
            except httpx.HTTPError as e:
                raise AuthError(f'form_login transport error: {e}')
            if page.status_code not in (200, 302):
                raise AuthError(f'form_login page HTTP {page.status_code}')
            self.cookies.update(dict(page.cookies))
            data = {username_field: username, password_field: password}
            wanted = [w.lower() for w in (csrf_fields or [])]
            for name, value in re.findall(
                    r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', page.text):
                low = name.lower()
                if not wanted:
                    if any(t in low for t in _CSRF_INPUT):
                        data[name] = value
                elif low in wanted:
                    data[name] = value
            try:
                r = c.post(urljoin(self.base_url, url), data=data)
            except httpx.HTTPError as e:
                raise AuthError(f'form_login post error: {e}')
            self.cookies.update(dict(r.cookies))
            # token in body?
            try:
                access, refresh = self._scan_token(r.json())
            except Exception:
                access, refresh = '', ''
            if access:
                self.bearer = access
                self.refresh_token = refresh
            if r.status_code >= 400 and not self.authenticated:
                raise AuthError(f'form_login HTTP {r.status_code}: {r.text[:200]}')
            if not self.authenticated:
                raise AuthError('form_login: no session cookie or token established '
                                f'(final HTTP {r.status_code})')
        return self

    def oauth2_password(self, token_url: str, client_id: str, client_secret: str,
                        username: str, password: str, scope: str = '',
                        extra: Optional[Dict] = None) -> "AuthSession":
        """grant_type=password against an OAuth token endpoint."""
        self.flow = 'oauth2'
        data = {'grant_type': 'password', 'username': username, 'password': password,
                'client_id': client_id, 'client_secret': client_secret}
        if scope:
            data['scope'] = scope
        if extra:
            data.update(extra)
        with self._client() as c:
            try:
                r = c.post(urljoin(self.base_url, token_url), data=data)
            except httpx.HTTPError as e:
                raise AuthError(f'oauth2 transport error: {e}')
        if r.status_code != 200:
            raise AuthError(f'oauth2 HTTP {r.status_code}: {r.text[:200]}')
        try:
            body = r.json()
        except Exception:
            raise AuthError(f'oauth2: non-JSON response: {r.text[:200]}')
        access, refresh = self._scan_token(body)
        if not access:
            raise AuthError(f'oauth2: no access_token in response: {r.text[:200]}')
        self.bearer = access
        self.refresh_token = refresh
        exp = body.get('expires_in')
        if exp:
            self.token_expires_at = time.time() + int(exp)
        return self

    def manual(self, bearer: str = '', cookie_header: str = '') -> "AuthSession":
        """Paste an existing session: 'Bearer xxx' / 'Cookie a=b; c=d'."""
        self.flow = 'manual'
        if bearer.startswith('Bearer '):
            bearer = bearer[7:]
        if bearer:
            self.bearer = bearer
        if cookie_header:
            for pair in cookie_header.split(';'):
                if '=' in pair:
                    k, v = pair.strip().split('=', 1)
                    self.cookies[k.strip()] = v.strip()
        if not self.authenticated:
            raise AuthError('manual: provide a bearer token or cookie header')
        return self

    def refresh(self, token_url: str) -> bool:
        """Attempt refresh_token grant; True on success."""
        if not self.refresh_token:
            return False
        data = {'grant_type': 'refresh_token', 'refresh_token': self.refresh_token}
        try:
            with self._client() as c:
                r = c.post(urljoin(self.base_url, token_url), data=data)
            body = r.json()
        except Exception as e:
            self.last_errors.append(f'refresh failed: {e}')
            return False
        access, refresh = self._scan_token(body)
        if access:
            self.bearer = access
            if refresh:
                self.refresh_token = refresh
            exp = body.get('expires_in')
            self.token_expires_at = time.time() + int(exp) if exp else None
            return True
        return False

    # ------------------------------------------------------------------ verify
    def verify(self, url: str = '', expect: Tuple[int, ...] = (200, 201, 204)) -> bool:
        """One GET through the session; True if status in expect."""
        probe = url or self.base_url or '/'
        with self._client() as c:
            try:
                r = c.get(urljoin(self.base_url, probe),
                          headers=self.auth_headers(), cookies=self.cookies)
            except httpx.HTTPError:
                return False
        return r.status_code in expect

    def requests_session(self):
        """Return a requests.Session carrying this auth context (cookies +
        bearer). Bridges into legacy tools (idor_scanner) that use requests."""
        import requests
        s = requests.Session()
        s.headers.update(self.auth_headers())
        if self.cookies:
            s.cookies.update(self.cookies)
        return s


def default_project_path(config) -> Path:
    """projects dir for the active project (used by page code)."""
    base = Path(config['project_settings']['base_projects_dir']).expanduser()
    return base / config.get('_current_project', '')
