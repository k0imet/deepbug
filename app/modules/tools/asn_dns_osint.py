# modules/tools/asn_dns_osint.py
# Infrastructure-level recon (infosecwriteups "ASN mapping" + "DNS history"
# tricks) using only keyless public APIs:
#
#   * ASN lookup      - resolve domain IPs, map to ASN via BGPView, pull the
#                       ASN's entire prefix list (finds IPs no tool knows)
#   * Reverse lookup  - keyless Hackertarget reverseiplookup over a sample of
#                       the ASN ranges -> subdomains other hunters miss
#   * DNS OSINT       - DoH (dns.google): SPF parse (ip4:/ip6:/include: leaks
#                       origin IPs behind CDNs), MX hosts, DMARC, DKIM probes
#
# Everything scope-filtered; output feeds the subdomain pipeline.
#   {'asns': [...], 'ipv4_ranges': [...], 'origin_ips': [...], 'spf': {...},
#    'dmarc': {...}, 'mx_hosts': [...], 'dkim': [...], 'subdomains': [...],
#    'errors': [...], 'totals': {...}}

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any

from app.utils.logger import get_logger

logger = get_logger()

_DOH = 'https://dns.google/resolve'
_BGPVIEW_IP = 'https://api.bgpview.io/ip/{ip}'
_BGPVIEW_ASN = 'https://api.bgpview.io/asn/{asn}/prefixes'
_REVERSE = 'https://api.hackertarget.com/reverseiplookup/?q={ip}'

_DKIM_SELECTORS = ['default', 's1', 's2', 'k1', 'k2', 'google', 'dkim',
                   'selector1', 'selector2', 'mail', 'mta', 'mandrill', 'pm']

_SPF_INCLUDE_RE = re.compile(r'include:([^\s]+)')
_SPF_IP4_RE = re.compile(r'ip4:([0-9.]+(?:/\d+)?)')
_SPF_IP6_RE = re.compile(r'ip6:([0-9a-fA-F:]+(?:/\d+)?)')
_SPF_A_RE = re.compile(r'\ba:([^\s]+)')


class ASNDNSOsint:
    """
    ASN + DNS OSINT recon. Keyless, passive, scope-filtered.

    Usage:
        scan = ASNDNSOsint(config)
        results = scan.scan_sync('example.com', scope_hosts=['example.com'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('asn_osint', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 20))
        self.max_prefixes = int(cfg.get('max_prefixes', 5))
        self.max_reverse = int(cfg.get('max_reverse', 200))
        self.max_ips_sample = int(cfg.get('max_ip_sample', 10))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, domain: str,
                   progress_callback: Optional[Callable[[float, str], None]] = None,
                   scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain:
            return self._empty_result()
        scope_hosts = [h.lower().rstrip('.') for h in (scope_hosts or [domain]) if h and h != '*']

        def _in_zone(host: str) -> bool:
            host = host.lower().rstrip('.')
            return any(host == s or host.endswith('.' + s) for s in scope_hosts)

        result = self._empty_result()
        result['target'] = domain
        result['scope_zone'] = sorted(scope_hosts)
        errors: List[str] = []
        seen_hosts: set = set()

        def _add_sub(host: str):
            host = (host or '').strip().lower().rstrip('.')
            if host and _in_zone(host) and host not in seen_hosts:
                seen_hosts.add(host)
                result['subdomains'].append(host)

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            # 1) A/AAAA + MX + TXT for the apex
            try:
                a_ips = await self._doh(session, domain, 'A')
                result['origin_ips'].extend(a_ips)
            except Exception as e:
                errors.append(f'A lookup: {e}')
            try:
                mx_hosts = await self._doh(session, domain, 'MX')
                for h in mx_hosts:
                    host = h.split()[1].rstrip('.') if h.split() else ''
                    if host:
                        result['mx_hosts'].append(host)
                        _add_sub(host)
            except Exception as e:
                errors.append(f'MX lookup: {e}')
            try:
                txt_records = await self._doh(session, domain, 'TXT')
                self._parse_spf(txt_records, result, _add_sub)
            except Exception as e:
                errors.append(f'TXT lookup: {e}')

            if progress_callback:
                progress_callback(0.3, f'ASN/SPF/MX done for {domain}')

            # 2) DMARC + DKIM
            try:
                dmarc = await self._doh(session, f'_dmarc.{domain}', 'TXT')
                if dmarc:
                    result['dmarc']['record'] = dmarc[0]
                    result['dmarc']['p'] = _extract_kv(dmarc[0], 'p')
                    result['dmarc']['rua'] = _extract_uris(dmarc[0], 'rua')
                    result['dmarc']['ruf'] = _extract_uris(dmarc[0], 'ruf')
            except Exception as e:
                errors.append(f'DMARC: {e}')
            for selector in _DKIM_SELECTORS:
                try:
                    recs = await self._doh(session, f'{selector}._domainkey.{domain}', 'TXT')
                    if recs:
                        result['dkim'].append({'selector': selector, 'record': recs[0]})
                except Exception:
                    continue

            # 3) ASN mapping
            ip = a_ips[0] if a_ips else None
            if ip:
                try:
                    asn, org = await self._asn_for_ip(session, ip)
                    if asn:
                        result['asns'].append({'asn': asn, 'org': org})
                        v4, v6 = await self._prefixes_for_asn(session, asn)
                        result['ipv4_ranges'].extend(v4[:self.max_prefixes])
                        result['ipv6_ranges'].extend(v6[:self.max_prefixes])
                except Exception as e:
                    errors.append(f'ASN: {e}')

            # 4) reverse lookup over a sample of the ranges
            sample = _sample_ranges(result['ipv4_ranges'] + a_ips, self.max_ips_sample)
            reversed_hosts: List[str] = []
            for ip in sample:
                if len(reversed_hosts) >= self.max_reverse:
                    break
                try:
                    hosts = await self._reverse_lookup(session, ip)
                except Exception as e:
                    errors.append(f'reverse {ip}: {e}')
                    continue
                for h in hosts:
                    if h and h not in reversed_hosts:
                        reversed_hosts.append(h)
            for h in reversed_hosts:
                _add_sub(h)

            if progress_callback:
                progress_callback(1.0, f'ASN/DNS-OSINT done: {len(result["subdomains"])} hosts')

        result['subdomains'] = sorted(set(result['subdomains']))
        result['origin_ips'] = sorted(set(result['origin_ips']))
        result['mx_hosts'] = sorted(set(result['mx_hosts']))
        result['errors'] = errors[:10]
        result['totals'] = {
            'subdomains': len(result['subdomains']),
            'asns': len(result['asns']),
            'ipv4_ranges': len(result['ipv4_ranges']),
            'origin_ips': len(result['origin_ips']),
            'mx_hosts': len(result['mx_hosts']),
            'dkim': len(result['dkim']),
            'dmarc': bool(result['dmarc'].get('record')),
        }
        logger.info(f'ASN/DNS-OSINT done: {result["totals"]}')
        return result

    def scan_sync(self, domain: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(domain, progress_callback, scope_hosts))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    async def _doh(self, session: aiohttp.ClientSession, name: str,
                   rtype: str) -> List[str]:
        params = {'name': name, 'type': rtype}
        async with session.get(_DOH, params=params) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
        answers = data.get('Answer', []) if isinstance(data, dict) else []
        out = []
        for a in answers:
            d = a.get('data', '')
            if isinstance(d, str) and d not in out:
                out.append(d)
        return out

    async def _asn_for_ip(self, session: aiohttp.ClientSession, ip: str) -> tuple:
        async with session.get(_BGPVIEW_IP.format(ip=ip)) as resp:
            if resp.status != 200:
                return None, ''
            data = await resp.json(content_type=None)
        node = (data or {}).get('data', {}) if isinstance(data, dict) else {}
        asn_node = node.get('asn', {}) if isinstance(node, dict) else {}
        asn = asn_node.get('asn') if isinstance(asn_node, dict) else None
        org = asn_node.get('name', '') if isinstance(asn_node, dict) else ''
        return asn, org

    async def _prefixes_for_asn(self, session: aiohttp.ClientSession, asn) -> tuple:
        async with session.get(_BGPVIEW_ASN.format(asn=asn)) as resp:
            if resp.status != 200:
                return [], []
            data = await resp.json(content_type=None)
        node = (data or {}).get('data', {}) if isinstance(data, dict) else {}
        v4 = [p.get('prefix', '') for p in node.get('ipv4_prefixes', []) or [] if isinstance(p, dict)]
        v6 = [p.get('prefix', '') for p in node.get('ipv6_prefixes', []) or [] if isinstance(p, dict)]
        return v4, v6

    async def _reverse_lookup(self, session: aiohttp.ClientSession, ip: str) -> List[str]:
        async with session.get(_REVERSE.format(ip=ip)) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors='ignore')
        hosts = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(('API count', 'error', 'rDNS')):
                hosts.append(line)
        return hosts[:500]

    @staticmethod
    def _parse_spf(records: List[str], result: Dict, add_sub) -> None:
        for rec in records:
            if not rec.startswith('v=spf1'):
                continue
            result['spf']['record'] = rec
            for m in _SPF_INCLUDE_RE.findall(rec):
                if m not in result['spf']['include']:
                    result['spf']['include'].append(m)
            result['spf']['ip4'].extend(_SPF_IP4_RE.findall(rec))
            result['spf']['ip6'].extend(_SPF_IP6_RE.findall(rec))
            for m in _SPF_A_RE.findall(rec):
                add_sub(m)
            for m in re.findall(r'mx(?::([^\s]+))?', rec):
                if m:
                    add_sub(m)
            m = re.search(r'\s(\+|~|-)all$', rec)
            if m:
                result['spf']['all'] = m.group(1)
        result['spf']['ip4'] = sorted(set(result['spf']['ip4']))
        result['spf']['ip6'] = sorted(set(result['spf']['ip6']))

    def _empty_result(self) -> Dict[str, Any]:
        return {
            'asns': [], 'ipv4_ranges': [], 'ipv6_ranges': [], 'origin_ips': [],
            'spf': {'record': '', 'include': [], 'ip4': [], 'ip6': [], 'all': ''},
            'dmarc': {'record': '', 'p': '', 'rua': [], 'ruf': []},
            'mx_hosts': [], 'dkim': [], 'subdomains': [], 'errors': [],
            'totals': {}, 'target': '', 'scope_zone': [],
        }


def _extract_kv(record: str, key: str) -> str:
    for part in record.split(';'):
        k, _, v = part.strip().partition('=')
        if k.strip().lower() == key:
            return v.strip()
    return ''


def _extract_uris(record: str, key: str) -> List[str]:
    v = _extract_kv(record, key)
    if not v:
        return []
    return [u.strip() for u in v.split(',') if u.strip() and 'mailto:' in u]


def _sample_ranges(entries: List[str], max_ips: int) -> List[str]:
    """Turn a few /24-ish CIDRs into sample IPs (deterministic, low-noise)."""
    out = []
    for e in entries:
        e = e.strip()
        if '/' in e:
            prefix, _, size = e.partition('/')
            try:
                size = int(size)
            except ValueError:
                continue
            if size >= 24 and '.' in prefix:
                base = '.'.join(prefix.split('.')[:3])
                out.append(f'{base}.1')
                out.append(f'{base}.2')
                out.append(f'{base}.254')
            else:
                out.append(prefix)
        else:
            out.append(e)
    seen = set()
    result = []
    for ip in out:
        if ip not in seen and len(result) < max_ips:
            seen.add(ip)
            result.append(ip)
    return result


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()