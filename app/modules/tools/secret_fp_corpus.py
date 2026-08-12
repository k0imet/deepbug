"""False-positive corpus for JS secret findings.

Loads app/modules/data/false_positive_corpus.json (path overridable via
config key `false_positive_corpus`) and drops secret findings that match
verified-false-positive records collected from previous scans.

Rule precedence:
  1. exact triage record (source, pattern, value)
  2. value is a generic keyword (framework/verb words)
  3. source URL contains a vendor-bundle marker
  4. source host listed as a third-party mirror
  5. (pattern, value) pair known benign
"""
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_CORPUS = Path(__file__).resolve().parent.parent / 'data' / 'false_positive_corpus.json'


class FalsePositiveCorpus:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else DEFAULT_CORPUS
        self.keyword_values: set = set()
        self.source_suffixes: list = []
        self.host_fp: list = []
        self.pattern_value_pairs: set = set()
        self.triaged: set = set()
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            logger.warning(f"FP corpus not found at {self.path}; running without it.")
            return
        try:
            data = json.loads(self.path.read_text())
            self.keyword_values = {v.lower() for v in data.get('keyword_values', [])}
            self.source_suffixes = data.get('source_suffixes', [])
            self.host_fp = data.get('host_fp', [])
            self.pattern_value_pairs = {tuple(p) for p in data.get('pattern_value_pairs', [])}
            self.triaged = {(r.get('source', ''), str(r.get('pattern') or ''), str(r.get('value', ''))[:50])
                            for r in data.get('triaged', [])}
            logger.info(f"FP corpus loaded from {self.path}: {len(self.triaged)} triaged, "
                        f"{len(self.keyword_values)} keywords, {len(self.source_suffixes)} suffixes")
        except Exception as e:
            logger.warning(f"Failed to load FP corpus from {self.path}: {e}")

    def is_false_positive(self, secret: Dict, source_url: str = '') -> bool:
        pattern = str(secret.get('pattern_name', '') or secret.get('pattern', '') or '')
        value = str(secret.get('value', ''))[:50]
        source = source_url or str(secret.get('source', ''))

        if (source, pattern, value) in self.triaged:
            return True
        if value.lower() in self.keyword_values:
            return True
        if source and any(marker in source for marker in self.source_suffixes):
            return True
        if source:
            host = source.split('/')[2] if source.startswith(('http://', 'https://')) and len(source.split('/')) > 2 else source
            if host in self.host_fp:
                return True
        if (pattern, value) in self.pattern_value_pairs:
            return True
        return False
