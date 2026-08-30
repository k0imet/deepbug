"""
DisclosureCatalog — query the 11,304-report bug bounty disclosure dataset.

Mined from the Disclosure Index (bug-bounty-disclosures.vercel.app) and cached
locally at `docs/skills/_disclosure_catalog.js`. Provides:

- Statistical summaries by program/vulnerability class/severity
- Similar-finding lookup (given a vulnerability class, find real report titles)
- Payload pattern extraction from report titles
- Weakness-to-CWE mapping
- Program-specific intel (what classes are most reported for a given program)
"""

import json
import os
import re
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional, Any, Set


_CATALOG_PATH = Path(__file__).resolve().parent.parent.parent.parent / 'docs' / 'skills' / '_disclosure_catalog.js'

_reports: Optional[List[Dict]] = None


def _load() -> List[Dict]:
    global _reports
    if _reports is not None:
        return _reports
    if not _CATALOG_PATH.exists():
        _reports = []
        return _reports
    src = _CATALOG_PATH.read_text(encoding='utf-8', errors='replace')
    blob = src.split('window.DISCLOSURE_REPORTS=', 1)[1].strip().rstrip(';')
    _reports = json.loads(blob)
    return _reports


def stats() -> Dict[str, Any]:
    reports = _load()
    if not reports:
        return {}
    classes = Counter(r.get('vulnerabilityClass') or 'Unknown' for r in reports)
    severities = Counter(r.get('severity') or 'Unknown' for r in reports)
    platforms = Counter(r.get('platform') or 'Unknown' for r in reports)
    return {
        'total': len(reports),
        'by_class': classes.most_common(20),
        'by_severity': severities.most_common(10),
        'by_platform': platforms.most_common(10),
    }


def program_intel(program: str) -> Dict[str, Any]:
    """What vuln classes are most reported for a given program."""
    reports = _load()
    hits = [r for r in reports if program.lower() in (r.get('program') or '').lower()]
    if not hits:
        return {'program': program, 'total': 0, 'note': 'No disclosures found for this program.'}
    classes = Counter(r.get('vulnerabilityClass') or 'Unknown' for r in hits)
    severities = Counter(r.get('severity') or 'Unknown' for r in hits)
    return {
        'program': program,
        'total': len(hits),
        'top_classes': classes.most_common(10),
        'severity_distribution': dict(severities),
        'sample_titles': [r.get('title', '')[:150] for r in hits[:5]],
    }


def similar_findings(vuln_class: str, limit: int = 10) -> List[Dict]:
    """Find real report titles for a given vulnerability class."""
    reports = _load()
    hits = [
        r for r in reports
        if vuln_class.lower() in (r.get('vulnerabilityClass') or '').lower()
    ]
    return sorted(
        [{'title': r.get('title', ''), 'severity': r.get('severity', ''),
          'program': r.get('program', ''), 'url': r.get('url', ''),
          'bounty': r.get('bounty'), 'platform': r.get('platform', '')}
         for r in hits],
        key=lambda x: (x.get('bounty') or 0), reverse=True
    )[:limit]


def search(keyword: str, limit: int = 10) -> List[Dict]:
    """Full-text search across report titles."""
    reports = _load()
    kw = keyword.lower()
    hits = [r for r in reports if kw in (r.get('title') or '').lower()]
    return [
        {'title': r.get('title', ''), 'severity': r.get('severity', ''),
         'class': r.get('vulnerabilityClass', ''), 'program': r.get('program', ''),
         'url': r.get('url', '')}
        for r in hits[:limit]
    ]


def weakness_to_cwe(weakness: str) -> Optional[str]:
    """Map a weakness name to its CWE ID."""
    _MAP = {
        'Improper Access Control - Generic': 'CWE-284',
        'Cross-site Scripting (XSS) - Generic': 'CWE-79',
        'Cross-site Scripting (XSS) - Reflected': 'CWE-79',
        'Cross-site Scripting (XSS) - Stored': 'CWE-79',
        'Cross-Site Request Forgery (CSRF)': 'CWE-352',
        'Improper Authentication - Generic': 'CWE-287',
        'Information Disclosure': 'CWE-200',
        'Violation of Secure Design Principles': 'CWE-657',
        'Uncontrolled Resource Consumption': 'CWE-400',
        'SQL Injection': 'CWE-89',
        'Server-Side Request Forgery (SSRF)': 'CWE-918',
        'Command Injection': 'CWE-77',
        'XML External Entity (XXE)': 'CWE-611',
        'Path Traversal': 'CWE-22',
        'Insecure Direct Object Reference (IDOR)': 'CWE-639',
        'Privilege Escalation': 'CWE-269',
        'Business Logic Errors': 'CWE-840',
        'Improper Authorization': 'CWE-285',
        'Deserialization of Untrusted Data': 'CWE-502',
        'File Inclusion': 'CWE-98',
        'Insecure Deserialization': 'CWE-502',
        'HTTP Request Smuggling': 'CWE-444',
        'Subdomain Takeover': 'CWE-350',
        'Race Condition': 'CWE-362',
        'Open Redirect': 'CWE-601',
        'CRLF Injection': 'CWE-93',
        'Server-Side Template Injection (SSTI)': 'CWE-1336',
        'Use of Hard-coded Credentials': 'CWE-798',
        'Exposure of Sensitive Information': 'CWE-200',
        'Denial of Service': 'CWE-400',
        'Improper Input Validation': 'CWE-20',
        'Use of Insufficiently Random Values': 'CWE-330',
        'Leftover Debug Code': 'CWE-489',
        'Missing Encryption of Sensitive Data': 'CWE-311',
        'Use of a Broken or Risky Cryptographic Algorithm': 'CWE-327',
        'Sensitive Data Exposure': 'CWE-200',
    }
    return _MAP.get(weakness)


def payload_hints(vuln_class: str, limit: int = 20) -> List[str]:
    """Extract keyword hints from real report titles for a given vuln class.
    Returns a list of unique lowercase words that appear frequently in titles."""
    reports = _load()
    hits = [
        r for r in reports
        if vuln_class.lower() in (r.get('vulnerabilityClass') or '').lower()
    ]
    if len(hits) < 5:
        return []
    words = Counter()
    stop = {'the', 'a', 'an', 'in', 'to', 'of', 'and', 'or', 'is', 'by',
            'on', 'at', 'for', 'with', 'from', 'via', 'i', 'my', 'me',
            'we', 'you', 'he', 'she', 'it', 'they', 'that', 'this',
            'be', 'was', 'were', 'are', 'been', 'can', 'will', 'would',
            'could', 'should', 'has', 'have', 'had', 'do', 'does', 'did',
            'not', 'no', 'any', 'all', 'some', 'each', 'every', 'both',
            'when', 'where', 'who', 'why', 'how', 'what', 'which',
            'but', 'if', 'then', 'else', 'just', 'also', 'only', 'very',
            'too', 'so', 'as', 'into', 'up', 'out', 'its', 'get', 'got',
            'put', 'set', 'one', 'two', 'make', 'made', 'use', 'used',
            'using', 'well', 'way', 'may', 'many', 'much', 'more',
            'other', 'new', 'old', 'due', 'now', 'even', 'still',
            'found', 'able', 'would', 'since', 'about', 'after',
            'before', 'during', 'while', 'without', 'through',
            'being', 'having', 'these', 'those', 'over', 'under',
            'between', 'same', 'such', 'own', 'lead', 'leads',
            'leading', 'let', 'like', 'likely', 'possible',
            'potentially', 'potential', 'number', 'numbers',
            'result', 'results', 'case', 'cases', 'issue', 'issues',
            'report', 'reports', 'bug', 'bugs', 'fix', 'fixed',
            'one', 'two', 'three', 'part', 'level', 'high',
            'medium', 'low', 'critical', 'information',
            '—', '–', '&#39;', '&amp;', '&quot;', '&lt;', '&gt;',
            '&', '-', '|', '/', ':', '(', ')', '[', ']', '{', '}',
            '"', "'", '`', ',', '.', ';', '!', '?', '*', '#', '@',
    }
    for hit in hits:
        title = hit.get('title', '').lower()
        for word in re.findall(r'[a-z0-9_-]{3,}', title):
            if word not in stop:
                words[word] += 1
    return [w for w, _ in words.most_common(limit)]


def class_from_keyword(keyword: str) -> Optional[str]:
    """Map a keyword to its most likely vulnerability class."""
    keyword = keyword.lower().strip()
    _MAP = {
        'xss': 'Cross-site scripting', 'cross-site': 'Cross-site scripting',
        'dom': 'Cross-site scripting', 'reflected': 'Cross-site scripting',
        'stored': 'Cross-site scripting', 'csrf': 'CSRF',
        'idor': 'Access control', 'access': 'Access control',
        'authorization': 'Access control', 'auth': 'Authentication',
        'authentication': 'Authentication', 'ato': 'Authentication',
        'oauth': 'Authentication', 'saml': 'Authentication',
        'sso': 'Authentication', 'jwt': 'Authentication',
        'ssrf': 'SSRF', 'server-side': 'SSRF',
        'sqli': 'SQL injection', 'sql': 'SQL injection',
        'injection': 'Injection', 'nosql': 'Injection',
        'rce': 'Command execution', 'command': 'Command execution',
        'exec': 'Command execution', 'shell': 'Command execution',
        'deserialization': 'Command execution', 'deserialize': 'Command execution',
        'xxe': 'XXE', 'xml': 'XXE',
        'lfi': 'Command execution', 'path-traversal': 'Command execution',
        'traversal': 'Command execution', 'directory': 'Command execution',
        'ssti': 'Injection', 'template': 'Injection',
        'smuggling': 'Request smuggling', 'http-request': 'Request smuggling',
        'desync': 'Request smuggling', 'cl-te': 'Request smuggling',
        'te-cl': 'Request smuggling', 'subdomain': 'Subdomain takeover',
        'takeover': 'Subdomain takeover', 'cors': 'Information disclosure',
        'csp': 'Information disclosure', 'csrf-token': 'CSRF',
        'rate-limit': 'CSRF', 'rate': 'CSRF',
        'upload': 'File security', 'file': 'File security',
        'business': 'Business logic', 'logic': 'Business logic',
        'race': 'Business logic', 'mass-assignment': 'Business logic',
        'bopla': 'Access control', 'bola': 'Access control',
        'privilege': 'Access control', 'escalation': 'Access control',
        'information-disclosure': 'Information disclosure',
        'info-disclosure': 'Information disclosure', 'disclosure': 'Information disclosure',
        'leak': 'Information disclosure', 'exposed': 'Information disclosure',
        'secret': 'Information disclosure', 'api-key': 'Information disclosure',
        'hardcoded': 'Information disclosure', 'credential': 'Information disclosure',
        'open-redirect': 'CSRF', 'redirect': 'CSRF',
        'clickjacking': 'Information disclosure', 'cache': 'Information disclosure',
        'host-header': 'Injection', 'host': 'Injection',
        'crlf': 'Injection', 'http-parameter': 'Injection',
        'parameter': 'Injection', 'pollution': 'Injection',
        'prototype': 'Injection', 'proto': 'Injection',
        'buffer': 'Command execution', 'overflow': 'Command execution',
        'memory': 'Command execution', 'corruption': 'Command execution',
        'dos': 'CSRF', 'denial': 'CSRF',
        'smart-contract': 'Smart contracts', 'solidity': 'Smart contracts',
        'reentrancy': 'Smart contracts', 'blockchain': 'Smart contracts',
    }
    for k, v in _MAP.items():
        if k in keyword:
            return v
    return None


def enrichment_context(vuln_class: str, limit: int = 5) -> str:
    """Build a concise context string for AI analysis prompts."""
    similar = similar_findings(vuln_class, limit=limit)
    if not similar:
        return ''
    hints = payload_hints(vuln_class, limit=15)
    lines = [f"### Real-world {vuln_class} disclosures ({len(similar)}+ reports)"]
    for s in similar:
        lines.append(f"- [{s.get('severity', '?')}] {s.get('title', '')[:140]}")
    if hints:
        lines.append(f"\nCommon payload keywords: {', '.join(hints[:12])}")
    return '\n'.join(lines)


__all__ = [
    'stats', 'program_intel', 'similar_findings', 'search',
    'weakness_to_cwe', 'payload_hints', 'class_from_keyword',
    'enrichment_context',
]