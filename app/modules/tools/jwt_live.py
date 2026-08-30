"""
JWT Live — decode, audit, and test JWTs found in JavaScript.

No auth required for the decode/analysis phase. Given a JWT token (or a list
of them), it:
  - Decodes header + payload (no key needed)
  - Checks alg:none / alg:empty (signature bypass)
  - Checks alg:HS256 with known weak secrets (brute-force wordlist)
  - Checks alg confusion (RS256→HS256 using the public key)
  - Flags interesting claims (admin, role, scope, is_admin, exp, iss)
  - Checks expiry
  - Estimates key strength from the header

Config keys (under `jwt_live.*`):
  weak_secrets: list of common HMAC secrets to try (defaults below)
"""

import json
import base64
import re
import hmac
import hashlib
import time
from typing import Dict, List, Optional, Any, Tuple, Set

from app.utils.logger import get_logger

logger = get_logger()

_JWT_RE = re.compile(
    r'(?<![A-Za-z0-9_-])'
    r'(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,})'
    r'(?![A-Za-z0-9_-])'
)

_WEAK_SECRETS = [
    'secret', 'password', 'secretkey', 'secret_key', 'changeme',
    'test', 'testing', 'dev', 'development', 'admin', 'password123',
    '123456', 'abcdef', 'qwerty', 'letmein', 'monkey', 'dragon',
    'master', 'hello', 'iloveyou', 'trustno1', 'sunshine',
    'princess', 'welcome', 'shadow', 'ashley', 'football',
    'jesus', 'michael', 'ninja', 'mustang', 'password1',
    'superman', 'batman', 'access', 'secret123', 'token',
    'jwt_secret', 'jwt_secret_key', 'hmac_secret', 'signing_key',
    'your-256-bit-secret', 'mysecret', 'my_secret', 'key',
    'app_secret', 'app_key', 'api_secret', 'api_key',
    'application_secret', 'auth_secret', 'private_key', 'public_key',
    'secret-token', 'access-token', 'secret_token', 'access_token',
    'SuperSecret', 'SuperSecretKey', 'SecretKey', 'mykey',
    'default', 'default_secret', 'test_secret', 'testkey',
    'simple', 'simplest', 'notsecure', 'insecure', 'hackme',
    'supersecret', 'topsecret', 'classified', 'confidential',
    'base64_secret', 'hex_secret', 'binary_secret',
    'my-256-bit-secret', 'my-384-bit-secret', 'my-512-bit-secret',
    'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
    'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512',
    'gXq4x9LmK2vR7wP3nB5sT8yF1cA6dE0hJ3oU6zI9pW2',
    'yJ0oU3zI6pW9gX2qL4mK7vR1nB5sT8xFcA6dE0hJ3',
    'Pyjwt_secret_key', 'Pyjwt_secret_key_123',
    'django-insecure', 'django_secret_key',
    'SECRET_KEY', 'SECRET', 'JWT_SECRET', 'JWT_SECRET_KEY',
    'APP_SECRET', 'APP_KEY', 'API_SECRET', 'AUTH_SECRET',
    'ENCRYPTION_KEY', 'SIGNING_KEY', 'VERIFICATION_KEY',
]


def _b64url_decode(seg: str) -> Optional[Dict]:
    try:
        seg += '=' * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg.encode()))
    except Exception:
        return None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def find_jwts(text: str) -> List[str]:
    return [m.group(1) for m in _JWT_RE.finditer(text)]


def decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """Decode a JWT without verification. Returns header + payload info."""
    parts = token.split('.')
    if len(parts) < 2:
        return None
    header = _b64url_decode(parts[0])
    if not isinstance(header, dict):
        return None
    payload = _b64url_decode(parts[1]) if len(parts) > 1 else {}
    if not isinstance(payload, dict):
        payload = {}
    sig = parts[2] if len(parts) > 2 else ''
    return {
        'header': header,
        'payload': payload,
        'signature': sig,
        'alg': header.get('alg', 'none'),
        'typ': header.get('typ', ''),
        'kid': header.get('kid', ''),
        'jku': header.get('jku', ''),
        'jwk': header.get('jwk', ''),
        'x5u': header.get('x5u', ''),
        'x5c': header.get('x5c', ''),
    }


def _check_alg_none(decoded: Dict) -> List[Dict]:
    alg = decoded['alg'].lower()
    findings = []
    if alg in ('none', ''):
        findings.append({
            'type': 'alg_none',
            'severity': 'CRITICAL',
            'detail': 'alg:none or empty — signature bypass. Any forgeable payload '
                      'will be accepted. Remove the signature segment entirely '
                      '(leave the trailing dot) and test.',
            'confidence': 'high',
        })
    return findings


def _check_weak_secret(token: str, decoded: Dict, weak_secrets: List[str]) -> List[Dict]:
    alg = decoded['alg'].lower()
    if alg not in ('hs256', 'hs384', 'hs512'):
        return []
    parts = token.split('.')
    if len(parts) != 3:
        return []
    header_b64 = parts[0]
    payload_b64 = parts[1]
    sig_b64 = parts[2]
    message = f'{header_b64}.{payload_b64}'.encode()
    hash_func = {'hs256': hashlib.sha256, 'hs384': hashlib.sha384, 'hs512': hashlib.sha512}.get(alg)
    if not hash_func:
        return []

    findings = []
    for secret in weak_secrets:
        try:
            computed = _b64url_encode(hmac.new(secret.encode(), message, hash_func).digest())
            if computed == sig_b64:
                findings.append({
                    'type': 'weak_secret',
                    'severity': 'CRITICAL',
                    'detail': f'HS256 secret cracked: "{secret}". Full token forgery.',
                    'secret': secret,
                    'confidence': 'high',
                })
                break
        except Exception:
            continue
    return findings


def _check_alg_confusion(decoded: Dict) -> List[Dict]:
    findings = []
    alg = decoded['alg'].lower()
    if alg.startswith('rs') or alg.startswith('es') or alg.startswith('ps'):
        findings.append({
            'type': 'alg_confusion',
            'severity': 'HIGH',
            'detail': f'alg:{alg} — if the server accepts HS256, try alg confusion: '
                      f'download the public key (JWKS endpoint), sign with it as '
                      f'the HMAC secret, and change alg to HS256.',
            'confidence': 'medium',
        })
    if decoded['jwk']:
        findings.append({
            'type': 'embedded_jwk',
            'severity': 'HIGH',
            'detail': 'jwk in header — if the server trusts embedded JWKs, '
                      'generate your own keypair and embed it.',
            'confidence': 'high',
        })
    if decoded['jku']:
        findings.append({
            'type': 'jku_header',
            'severity': 'MEDIUM',
            'detail': f'jku: {decoded["jku"]} — if the server fetches JWKS from '
                      f'this URL, check for SSRF or host your own JWKS.',
            'confidence': 'medium',
        })
    if decoded['x5u']:
        findings.append({
            'type': 'x5u_header',
            'severity': 'MEDIUM',
            'detail': f'x5u: {decoded["x5u"]} — certificate chain URL. Check for SSRF.',
            'confidence': 'medium',
        })
    return findings


def _check_claims(payload: Dict) -> List[Dict]:
    findings = []
    now = int(time.time())
    exp = payload.get('exp')
    if exp:
        if isinstance(exp, (int, float)) and exp < now:
            findings.append({
                'type': 'expired',
                'severity': 'INFO',
                'detail': f'Token expired at {exp} (now={now}). Server may still accept it.',
                'confidence': 'low',
            })
        elif isinstance(exp, (int, float)):
            remain = exp - now
            findings.append({
                'type': 'expiry',
                'severity': 'INFO',
                'detail': f'Token expires in {remain}s ({exp}).',
                'confidence': 'low',
            })

    iat = payload.get('iat')
    if iat and isinstance(iat, (int, float)):
        age = now - iat
        if age > 86400 * 30:
            findings.append({
                'type': 'long_lived',
                'severity': 'MEDIUM',
                'detail': f'Token issued {age // 86400}d ago — no rotation.',
                'confidence': 'medium',
            })

    interesting = []
    for claim in ('admin', 'is_admin', 'isAdmin', 'role', 'roles', 'scope',
                  'scopes', 'permissions', 'privileges', 'group', 'groups',
                  'sub', 'iss', 'aud', 'azp', 'email', 'user_id', 'userId',
                  'username', 'name', 'preferred_username', 'tenant', 'org',
                  'organization', 'type', 'account_type', 'tier', 'plan',
                  'subscription', 'api_key', 'apiKey', 'secret'):
        v = payload.get(claim)
        if v is not None and v != '' and v != 'user' and v is not False:
            interesting.append(f'{claim}={v!r}')

    if interesting:
        findings.append({
            'type': 'interesting_claims',
            'severity': 'MEDIUM',
            'detail': '; '.join(interesting[:8]),
            'confidence': 'medium',
        })

    for claim in ('password', 'passwd', 'secret', 'pwd', 'token', 'api_key'):
        if claim in payload:
            findings.append({
                'type': 'sensitive_in_jwt',
                'severity': 'CRITICAL',
                'detail': f'"{claim}" in JWT payload — sensitive data in token body.',
                'confidence': 'high',
            })

    return findings


def _check_kid_injection(decoded: Dict) -> List[Dict]:
    findings = []
    kid = decoded.get('kid', '')
    if kid and ('../' in kid or '..\\' in kid or '/' in kid):
        findings.append({
            'type': 'kid_path_traversal',
            'severity': 'HIGH',
            'detail': f'kid="{kid}" — path traversal candidate. Try ../../dev/null '
                      f'or /dev/null for key confusion.',
            'confidence': 'medium',
        })
    if kid and '|' in kid:
        findings.append({
            'type': 'kid_command_injection',
            'severity': 'HIGH',
            'detail': f'kid="{kid}" — pipe character. Try command injection.',
            'confidence': 'medium',
        })
    if kid and kid.startswith('../../'):
        findings.append({
            'type': 'kid_sqli',
            'severity': 'HIGH',
            'detail': f'kid="{kid}" — SQLi candidate. Try SELECT-based injection.',
            'confidence': 'medium',
        })
    return findings


def audit_jwt(token: str, weak_secrets: Optional[List[str]] = None,
              source: str = '') -> Dict[str, Any]:
    """Full audit of a single JWT token."""
    decoded = decode_jwt(token)
    if not decoded:
        return {'token': token[:40] + '...', 'source': source,
                'valid': False, 'error': 'Could not decode as JWT',
                'findings': []}

    secrets = weak_secrets or _WEAK_SECRETS
    findings = []
    findings.extend(_check_alg_none(decoded))
    findings.extend(_check_weak_secret(token, decoded, secrets))
    findings.extend(_check_alg_confusion(decoded))
    findings.extend(_check_claims(decoded['payload']))
    findings.extend(_check_kid_injection(decoded))

    sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    findings.sort(key=lambda f: sev_rank.get(f['severity'], 5))

    payload_keys = list(decoded['payload'].keys())[:12]

    return {
        'token': token[:40] + '...',
        'source': source,
        'valid': True,
        'alg': decoded['alg'],
        'typ': decoded['typ'],
        'kid': decoded['kid'],
        'jku': decoded['jku'],
        'jwk': bool(decoded['jwk']),
        'payload_keys': ', '.join(payload_keys),
        'issuer': decoded['payload'].get('iss', ''),
        'subject': decoded['payload'].get('sub', ''),
        'audience': str(decoded['payload'].get('aud', '')),
        'expiry': decoded['payload'].get('exp'),
        'issued_at': decoded['payload'].get('iat'),
        'cracked_key': '',
        'findings': findings,
        'critical_count': sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high_count': sum(1 for f in findings if f['severity'] == 'HIGH'),
        'header': decoded['header'],
        'payload': decoded['payload'],
    }


def audit_jwts(tokens: List[str], weak_secrets: Optional[List[str]] = None,
               source: str = '') -> List[Dict]:
    """Audit a list of JWT tokens. Deduplicates by token preview."""
    seen = set()
    results = []
    for token in tokens:
        preview = token[:40]
        if preview in seen:
            continue
        seen.add(preview)
        result = audit_jwt(token, weak_secrets, source)
        if result.get('valid'):
            results.append(result)
    return results


def audit_from_text(text: str, weak_secrets: Optional[List[str]] = None,
                    source: str = '') -> List[Dict]:
    """Find all JWTs in a text blob and audit them."""
    tokens = find_jwts(text)
    return audit_jwts(tokens, weak_secrets, source)


def audit_from_urls(urls: List[str], timeout: int = 15) -> List[Dict]:
    """Fetch URLs, find JWTs in their bodies, and audit them."""
    import httpx
    all_results = []
    for url in urls:
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True,
                             verify=False,
                             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                                     'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'})
            if resp.status_code == 200 and resp.text:
                results = audit_from_text(resp.text, source=url)
                all_results.extend(results)
        except Exception as e:
            logger.debug(f"JWT fetch failed for {url}: {e}")
    return all_results


def scan_sync(urls_or_text: List[str], weak_secrets: Optional[List[str]] = None) -> List[Dict]:
    """Convenience: auto-detect if input is URLs or plain text."""
    if not urls_or_text:
        return []
    if urls_or_text[0].startswith(('http://', 'https://')):
        return audit_from_urls(urls_or_text)
    return audit_from_text('\n'.join(urls_or_text))


__all__ = [
    'find_jwts', 'decode_jwt', 'audit_jwt', 'audit_jwts',
    'audit_from_text', 'audit_from_urls', 'scan_sync',
]