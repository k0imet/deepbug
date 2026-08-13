# app/modules/integrations/burp.py
"""Burp Suite REST API v0.1 client.

Talk to Burp's headless REST service (Doyensec burp-rest-api style): the API key
lives IN THE URL PATH, e.g. ``{base_url}/{api_key}/v0.1/scan``. Provides scan
lifecycle helpers (start / poll / results), a generic importer for a
Doyensec-style REST API extension's proxy history, and a tolerant parser for
Burp "Save items" JSON/XML exports.

All network errors raise with clear messages; parse-only helpers never raise.
"""

import base64
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

import httpx

from app.utils.logger import get_logger

logger = get_logger()

# Fields a normalized finding / history item always carries.
FINDING_KEYS = ("name", "path", "severity", "confidence", "evidence")
HISTORY_KEYS = ("url", "method", "status", "request_base64", "response_base64")


def _find_issues(payload) -> List[Dict]:
    """Recursively collect dicts that look like issue objects (have both a
    'name' and a 'severity' key) from an arbitrarily nested payload."""
    found: List[Dict] = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("name"), str) and isinstance(node.get("severity"), str):
                found.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return found


def _b64_or_plain(value) -> str:
    """Best-effort decode of a base64 blob; falls back to the raw string."""
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if not text:
        return ""
    try:
        decoded = base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
        # base64 can decode plain text that happens to be valid; only trust it
        # when it round-trips through a base64 alphabet look.
        return decoded
    except Exception:
        return text


class BurpClient:
    """Minimal client for Burp Suite's REST API v0.1 (API key in URL path)."""

    def __init__(self, base_url: str = "http://127.0.0.1:1337",
                 api_key: str = "", timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._http = httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------ auth
    def _endpoint(self, path: str) -> str:
        """Build a full API URL: ``{base_url}/{api_key}/v0.1/{path}``."""
        return f"{self.base_url}/{self.api_key}/v0.1/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Issue a request against the API and raise ValueError on HTTP errors."""
        try:
            resp = self._http.request(method, self._endpoint(path), **kwargs)
        except httpx.HTTPError as exc:
            raise ValueError(f"Burp REST API unreachable at {self.base_url}: {exc}") from exc
        if resp.status_code >= 400:
            message = resp.text.strip() or resp.reason_phrase
            raise ValueError(
                f"Burp REST API {method} {path} failed ({resp.status_code}): {message[:500]}")
        return resp

    # ---------------------------------------------------------------- scans
    def start_scan(self, urls: List[str], config: Optional[Dict] = None) -> str:
        """Start a scan for the given URLs; returns the scan task id.

        The task id comes from the ``Location`` header when present, otherwise
        from a JSON ``id``/``task_id`` field.
        """
        body = {"urls": list(urls)}
        if config:
            body.update(config)
        resp = self._request("POST", "scan", json=body)
        task_id = ""
        location = resp.headers.get("Location", "")
        if location:
            task_id = location.rstrip("/").split("/")[-1]
        if not task_id:
            try:
                data = resp.json()
            except Exception:
                data = {}
            task_id = str(data.get("id") or data.get("task_id") or "")
        if not task_id:
            raise ValueError(f"Burp scan response carried no task id: {resp.text[:500]}")
        return task_id

    def scan_status(self, task_id: str) -> Dict:
        """Return the parsed JSON status document for a scan task."""
        resp = self._request("GET", f"scan/{task_id}")
        try:
            return resp.json()
        except Exception as exc:
            raise ValueError(f"Burp scan status response was not JSON: {resp.text[:500]}") from exc

    def scan_results(self, task_id: str) -> List[Dict]:
        """Normalized findings for a scan task.

        ``issue_events`` entries are flattened defensively: every dict in the
        payload carrying both 'name' and 'severity' is treated as an issue.
        """
        data = self.scan_status(task_id)
        findings: List[Dict] = []
        for issue in _find_issues(data.get("issue_events", data)):
            evidence = ""
            if isinstance(issue.get("evidence"), str):
                evidence = issue["evidence"]
            elif isinstance(issue.get("evidence"), dict):
                evidence = str(issue["evidence"])
            findings.append({
                "name": str(issue.get("name", "")),
                "path": str(issue.get("path", "")),
                "severity": str(issue.get("severity", "")),
                "confidence": str(issue.get("confidence", "")),
                "evidence": evidence,
            })
        return findings

    def wait_for_scan(self, task_id: str, poll_interval: float = 10,
                      max_wait: float = 600) -> List[Dict]:
        """Poll a scan until it succeeds or fails; returns normalized findings.

        Raises ValueError on scan failure, timeout, or network error.
        """
        import time
        deadline = time.monotonic() + max_wait
        while True:
            data = self.scan_status(task_id)
            status = str(data.get("scan_status", "")).lower()
            if status in ("succeeded", "complete", "completed"):
                return self.scan_results(task_id)
            if status in ("failed", "error", "cancelled", "canceled"):
                raise ValueError(f"Burp scan {task_id} ended with status '{status}'")
            if time.monotonic() >= deadline:
                raise ValueError(
                    f"Burp scan {task_id} did not finish within {max_wait}s (status '{status}')")
            logger.info("Burp scan %s status=%s, polling again in %ss",
                        task_id, status, poll_interval)
            time.sleep(poll_interval)

    # ------------------------------------------------------------ proxy feed
    def fetch_proxy_history(self, endpoint_url: str = "",
                            api_key_header: Optional[str] = None) -> List[Dict]:
        """Generic importer for a Doyensec-style REST API extension.

        Calls ``GET {endpoint}/burp/proxy/history`` with header
        ``API-KEY: <key>`` and normalizes the returned items to
        {"url","method","status","request_base64","response_base64"}.
        Never raises on unexpected shapes — returns whatever parsed.
        """
        endpoint = (endpoint_url or self.base_url).rstrip("/")
        headers = {}
        if api_key_header:
            headers["API-KEY"] = api_key_header
        try:
            resp = self._http.get(f"{endpoint}/burp/proxy/history", headers=headers,
                                  timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning("fetch_proxy_history failed against %s: %s", endpoint, exc)
            return []
        items = data.get("items") or data.get("history") or data
        if isinstance(items, dict):
            items = items.get("items", [])
        if not isinstance(items, list):
            return []
        normalized: List[Dict] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            normalized.append({
                "url": str(item.get("url", "")),
                "method": str(item.get("method", "")),
                "status": item.get("status", ""),
                "request_base64": _b64_or_plain(item.get("request", "")),
                "response_base64": _b64_or_plain(item.get("response", "")),
            })
        return normalized

    # ------------------------------------------------------------- exports
    def parse_burp_export(self, text: str, fmt: str = "") -> List[Dict]:
        """Parse a Burp "Save items" export (JSON or XML) into history items.

        JSON exports carry {'url','host','request','response'} with base64
        request/response blobs; XML exports wrap the same fields in <item>
        elements. ``fmt`` is auto-detected from the text when omitted; never
        raises — returns [] on unparseable input.
        """
        if not text or not isinstance(text, str):
            return []
        detected = fmt.lower()
        if detected not in ("json", "xml"):
            stripped = text.lstrip()
            if stripped.startswith("<"):
                detected = "xml"
            elif stripped.startswith("{"):
                detected = "json"
            else:
                return []
        try:
            if detected == "json":
                return self._parse_json_export(text)
            return self._parse_xml_export(text)
        except Exception as exc:
            logger.warning("parse_burp_export failed for %s export: %s", detected, exc)
            return []

    @staticmethod
    def _parse_json_export(text: str) -> List[Dict]:
        import json
        data = json.loads(text)
        items = data.get("items", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            return []
        normalized: List[Dict] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            normalized.append({
                "url": str(item.get("url", "")),
                "method": str(item.get("method", "")),
                "status": item.get("status", ""),
                "request_base64": _b64_or_plain(item.get("request", "")),
                "response_base64": _b64_or_plain(item.get("response", "")),
            })
        return normalized

    @staticmethod
    def _parse_xml_export(text: str) -> List[Dict]:
        root = ET.fromstring(text)
        normalized: List[Dict] = []
        for item in root.iter("item"):
            def field(tag: str) -> str:
                el = item.find(tag)
                return el.text or "" if el is not None else ""

            normalized.append({
                "url": field("url"),
                "method": field("method"),
                "status": field("status"),
                "request_base64": _b64_or_plain(field("request")),
                "response_base64": _b64_or_plain(field("response")),
            })
        return normalized

    # --------------------------------------------------------------- misc
    def health(self) -> bool:
        """True when the REST service answers (proves service + key work)."""
        try:
            resp = self._http.get(
                self._endpoint("knowledge_base/issue_definitions"), timeout=10)
            return resp.status_code == 200
        except Exception:
            return False


def get_burp_client(config: Dict) -> BurpClient:
    """Build a BurpClient from a config dict + environment overrides."""
    burp_cfg = (config or {}).get("integrations", {}).get("burp", {})
    return BurpClient(
        base_url=str(burp_cfg.get("base_url", "http://127.0.0.1:1337")),
        api_key=os.environ.get("BURP_API_KEY", str(burp_cfg.get("api_key", ""))),
        timeout=float(burp_cfg.get("timeout", 30)),
    )
