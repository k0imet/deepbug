from collections import Counter

from app.modules.tools.bypass_403 import _is_freed
from app.modules.tools.graphql_scanner import GraphQLScanner
from app.modules.tools.graphql_security_probes import GraphQLSecurityProbes
from app.modules.tools.rate_limit_tester import RateLimitTester


def test_generic_400_is_not_rate_limit_evidence():
    verdict = RateLimitTester()._verdict(Counter({400: 10}), signals=0)
    assert verdict == {'limit_detected': False, 'limit_kind': 'none'}


def test_403_bypass_requires_success_not_error_or_redirect():
    assert _is_freed(200, 100, 403)
    assert not _is_freed(500, 1000, 403)
    assert not _is_freed(401, 1000, 403)
    assert not _is_freed(302, 1000, 403)


def test_plain_rest_unauthorized_error_is_not_graphql():
    assert GraphQLScanner._confirm_graphql(
        '{"errors":[{"message":"Unauthorized"}]}') is None
    assert GraphQLScanner._confirm_graphql(
        '{"errors":[{"message":"Unauthorized","errorType":"UnauthorizedException"}]}') == 'gated_auth'


def test_graphql_probe_requires_resolved_json_not_echoed_query():
    assert not GraphQLSecurityProbes._typename_resolved(
        '{"error":"query {__typename} rejected"}')
    assert GraphQLSecurityProbes._typename_resolved(
        '{"data":{"__typename":"Query"}}')
