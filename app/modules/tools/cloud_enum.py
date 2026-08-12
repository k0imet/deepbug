# modules/tools/cloud_enum.py
# Cloud asset enumeration: external cloud_enum (when installed) + built-in
# async enumerator with OPEN BUCKET detection.
#
# The built-in path needs zero external tools: it permutes the target keyword
# against AWS S3 / Azure / GCP hostnames and classifies responses:
#   - public listing (ListBucketResult / EnumerationResults) -> OPEN, reportable
#   - 403/exists-but-protected -> exists
#   - NoSuchBucket/404 -> does not exist (dropped)
#
# Config (optional):
#   tools.paths.cloud_enum        -> external binary/script
#   cloud_enum.permutations       -> extra keywords to try (list)
#   cloud_enum.max_permutations   -> cap (default 25)

import asyncio
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Callable

import httpx

from app.utils.logger import get_logger
from app.utils.subprocess_runner import run_command

logger = get_logger()

# Hostname templates per provider; {kw} = permuted keyword
HOST_TEMPLATES = {
    "aws": [
        "https://{kw}.s3.amazonaws.com",
        "https://s3.amazonaws.com/{kw}",
        "https://{kw}.s3-website-us-east-1.amazonaws.com",
        "https://{kw}.s3-website.eu-west-1.amazonaws.com",
    ],
    "azure": [
        "https://{kw}.blob.core.windows.net",
        "https://{kw}.file.core.windows.net",
        "https://{kw}.azurewebsites.net",
        "https://{kw}.azure-api.net",
    ],
    "gcp": [
        "https://{kw}.storage.googleapis.com",
        "https://storage.googleapis.com/{kw}",
        "https://{kw}.appspot.com",
        "https://{kw}.firebaseapp.com",
    ],
}

DEFAULT_AFFIXES = ["", "-dev", "-development", "-test", "-testing", "-staging", "-stage",
                   "-prod", "-production", "-backup", "-backups", "-internal", "-data",
                   "-assets", "-static", "-media", "-public", "-private", "-files",
                   "-uploads", "-images", "-docs", "-app", "-web", "-api"]

# URL signatures -> provider (for parsing ANY external tool output)
URL_SIGNATURES = {
    "aws": ["s3.amazonaws.com", "s3-website", "amazonaws.com", "cloudfront.net"],
    "azure": ["blob.core.windows.net", "file.core.windows.net", "queue.core.windows.net",
              "table.core.windows.net", "azurewebsites.net", "azure-api.net",
              "cloudapp.azure.com", "azureedge.net"],
    "gcp": ["storage.googleapis.com", "appspot.com", "firebaseapp.com",
            "storage.cloud.google.com", "web.app"],
}


def _classify_url(url: str) -> Optional[str]:
    for provider, sigs in URL_SIGNATURES.items():
        if any(sig in url for sig in sigs):
            return provider
    return None


class CloudScanner:
    def __init__(self, config: Dict):
        self.config = config
        ce_cfg = config.get('cloud_enum', {})
        self.max_permutations = int(ce_cfg.get('max_permutations', 25))
        self.extra_permutations = ce_cfg.get('permutations', [])

        self.cloud_enum_path = Path(config.get('tools', {}).get('paths', {}).get('cloud_enum', 'cloud_enum'))
        if not self.cloud_enum_path.is_file():
            path = shutil.which('cloud_enum')
            if path:
                self.cloud_enum_path = Path(path)

        self.has_cloud_enum = self.cloud_enum_path.is_file()
        if not self.has_cloud_enum:
            logger.info("cloud_enum binary not found - using built-in async enumerator.")

    # -----------------------------------------------------------------
    # Keyword permutations
    # -----------------------------------------------------------------
    def _build_keywords(self, domain: str) -> List[str]:
        base = domain.split('.')[0]  # 'app.safaricom.com' -> 'app'; caller passes root
        root = '.'.join(domain.split('.')[-2:]).split('.')[0]  # 'safaricom.com' -> 'safaricom'
        keywords = set()
        for kw in {base, root}:
            for affix in DEFAULT_AFFIXES:
                keywords.add(f"{kw}{affix}")
            keywords.add(kw.replace('-', ''))
        keywords.update(self.extra_permutations)
        return sorted(keywords)[:self.max_permutations * 2]

    # -----------------------------------------------------------------
    # Built-in async enumerator
    # -----------------------------------------------------------------
    @staticmethod
    def _classify_response(provider: str, status: int, body: str) -> Optional[Dict]:
        """Decide if a response means 'resource exists' and whether it's publicly listable."""
        body_sample = body[:2000]

        # Public listing = the money finding
        if status == 200 and ("<ListBucketResult" in body_sample or "<EnumerationResults" in body_sample):
            return {"status": status, "exists": True, "public": True,
                    "notes": "PUBLIC LISTING - anonymous users can list objects"}

        if provider == "aws":
            if status == 200:
                return {"status": status, "exists": True, "public": False, "notes": "exists (website/200)"}
            if status == 403:
                return {"status": status, "exists": True, "public": False, "notes": "exists (403 - protected)"}
            if "NoSuchBucket" in body_sample or status == 404:
                return None
        elif provider == "azure":
            if status == 200:
                return {"status": status, "exists": True, "public": False, "notes": "exists (200)"}
            if status == 403:
                return {"status": status, "exists": True, "public": False, "notes": "exists (403 - protected)"}
            # Azure: 400 with "Value for one of the query parameters" can mean exists; 404 = no
            if status == 400 and "InvalidQueryParameterValue" in body_sample:
                return {"status": status, "exists": True, "public": False, "notes": "likely exists (400)"}
            if status in (404, 409):
                return None
        else:  # gcp
            if status == 200:
                return {"status": status, "exists": True, "public": False, "notes": "exists (200)"}
            if status == 403:
                return {"status": status, "exists": True, "public": False, "notes": "exists (403 - protected)"}
            if "NoSuchBucket" in body_sample or status == 404:
                return None

        return None

    async def _builtin_enumerate(self, domain: str,
                                 progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {"aws": [], "azure": [], "gcp": []}
        keywords = self._build_keywords(domain)

        targets = []
        for kw in keywords:
            for provider, templates in HOST_TEMPLATES.items():
                for tpl in templates:
                    targets.append((provider, tpl.format(kw=kw)))

        sem = asyncio.Semaphore(20)
        done = 0

        async def probe(client, provider, url):
            nonlocal done
            async with sem:
                try:
                    resp = await client.get(url)
                    info = self._classify_response(provider, resp.status_code, resp.text)
                    if info:
                        results[provider].append({"url": url, **info})
                except Exception:
                    pass  # DNS failure / timeout = doesn't exist
                done += 1
                if progress_callback and done % 50 == 0:
                    progress_callback(0.1 + 0.8 * (done / len(targets)),
                                      f"Probing cloud hostnames... {done}/{len(targets)}")

        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
            await asyncio.gather(*[probe(client, p, u) for p, u in targets])

        return results

    # -----------------------------------------------------------------
    # External cloud_enum (when installed) - output classified by URL signature
    # -----------------------------------------------------------------
    def _run_external(self, domain: str) -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {"aws": [], "azure": [], "gcp": []}
        cmd = [str(self.cloud_enum_path), '-k', domain]
        stdout, stderr, ret = run_command(cmd, timeout=600)
        if ret != 0:
            logger.warning(f"cloud_enum failed (falling back to built-in only): {stderr[:200]}")
            return results

        # Classify ANY line containing a cloud URL signature - robust to format changes
        import re
        for line in stdout.splitlines():
            for match in re.findall(r'https?://[^\s"\'<>]+', line):
                provider = _classify_url(match)
                if provider:
                    results[provider].append({"url": match.rstrip('/'), "status": None,
                                              "exists": True, "public": False,
                                              "notes": "reported by cloud_enum"})
        return results

    # -----------------------------------------------------------------
    # Main entry
    # -----------------------------------------------------------------
    def scan(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {"aws": [], "azure": [], "gcp": []}
        if not domain:
            return results

        # External tool first (if present)
        if self.has_cloud_enum:
            if progress_callback:
                progress_callback(0.05, "Running cloud_enum...")
            external = self._run_external(domain)
            for p in results:
                results[p].extend(external[p])

        # Built-in async enumerator (always runs - validates existence + public listing)
        if progress_callback:
            progress_callback(0.1, "Built-in cloud probing (permutations x AWS/Azure/GCP)...")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                builtin = ex.submit(asyncio.run, self._builtin_enumerate(domain, progress_callback)).result()
        else:
            builtin = asyncio.run(self._builtin_enumerate(domain, progress_callback))

        # Merge + dedupe by url
        seen = set()
        for provider in results:
            merged = []
            for item in builtin[provider] + results[provider]:
                if item["url"] not in seen:
                    seen.add(item["url"])
                    merged.append(item)
            results[provider] = merged

        total = sum(len(v) for v in results.values())
        public = sum(1 for v in results.values() for i in v if i.get("public"))
        if progress_callback:
            progress_callback(1.0, f"Done: {total} cloud resources ({public} PUBLICLY LISTABLE)")
        logger.info(f"Cloud scan: {total} resources for {domain} ({public} public)")
        return results