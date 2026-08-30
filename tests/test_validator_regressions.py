from urllib.parse import parse_qs, urlparse

from app.modules.tools.cors_validator import CORSValidator
from app.modules.tools.idor_scanner import IDORScanner
from app.modules.tools.open_redirect_scanner import (
    _location_matches_canary,
    _redirect_variants,
)


def test_cors_requires_exact_echo_of_sent_origin():
    sent = 'https://trusted.example.evil.test'
    assert CORSValidator._classify(
        sent, 'https://trusted.example', 'true', '') is None
    assert CORSValidator._classify(
        sent, sent, 'true', '')['Result'] == 'CONFIRMED'


def test_redirect_variants_preserve_query_and_encoding_depth():
    variants = _redirect_variants(
        'https://target.test/go?lang=en&next=/home', 'canary.test')
    by_kind = {row['technique']: row['url'] for row in variants}

    assert 'lang=en' in by_kind['encoded']
    assert 'https%3A%2F%2Fcanary.test%2F' in by_kind['encoded']
    assert 'https%253A%252F%252Fcanary.test%252F' in by_kind['double']
    assert parse_qs(urlparse(by_kind['raw']).query)['next'] == ['https://canary.test/']


def test_redirect_evidence_requires_canary_as_destination_host():
    assert _location_matches_canary(
        'https://canary.test/path', 'https://target.test/go', 'canary.test')
    assert not _location_matches_canary(
        'https://target.test/?next=https://canary.test',
        'https://target.test/go', 'canary.test')
    assert not _location_matches_canary(
        'https://canary.test.evil.test/', 'https://target.test/go', 'canary.test')


def test_idor_replacement_is_segment_safe_and_supports_query_ids():
    scanner = IDORScanner({})
    assert scanner._replace_id_in_url(
        'https://api.test/users/12/orders/120', '12', '13') == (
        'https://api.test/users/13/orders/120')
    assert scanner._replace_id_in_url(
        'https://api.test/users?id=12&view=full', '12', '13', 'query') == (
        'https://api.test/users?id=13&view=full')
