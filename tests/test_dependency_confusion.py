from app.modules.tools.dependency_confusion import DependencyConfusionScanner


def test_extracts_scoped_and_unscoped_package_names():
    content = """
      require('company-private');
      import x from '@acme/internal-sdk';
      //# sourceURL=webpack:///./node_modules/lodash/index.js
    """

    assert DependencyConfusionScanner._extract_npm_names(content) == [
        '@acme/internal-sdk', 'company-private', 'lodash']


def test_registry_network_error_is_not_reported_as_not_found(tmp_path):
    scanner = DependencyConfusionScanner({
        'dependency_cache_db': str(tmp_path / 'cache.db'),
    })

    class BrokenSession:
        def get(self, *args, **kwargs):
            raise TimeoutError('offline')

    scanner.session = BrokenSession()
    result = scanner._check_npm_package('internal-build-kit')

    assert result['status'] == 'unknown'
    assert result['exists'] is False
