# app/modules/integrations/caido.py
"""Caido GraphQL client.

Talks to a Caido instance's GraphQL endpoint (default
``http://127.0.0.1:8080/graphql``) using a Personal Access Token
(``Authorization: Bearer caido_...``). Only the documented mutation/query
names are used and responses are parsed defensively so schema drift across
Caido versions degrades to a clear error instead of a crash. The client only
works when a Caido instance is reachable — all failures surface as
ValueError/GraphQL-error messages the UI can show.
"""

import base64
import os
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.utils.logger import get_logger

logger = get_logger()


def _extract_urls(requests: List[Dict]) -> List[Dict]:
    """Pull {"url","method","status"} out of request.list entries defensively.

    'request' objects vary by Caido version: structured fields (url/method/
    host/scheme/port) or a raw HTTP message string. Never raises.
    """
    normalized: List[Dict] = []
    for entry in requests or []:
        if not isinstance(entry, dict):
            continue
        item = {
            "id": str(entry.get("id", "")),
            "url": "",
            "method": "",
            "status": "",
        }
        req = entry.get("request")
        if isinstance(req, dict):
            item["url"] = str(req.get("url") or "")
            item["method"] = str(req.get("method") or "")
            host = str(req.get("host") or "")
            scheme = str(req.get("scheme") or "")
            port = str(req.get("port") or "")
            path = str(req.get("path") or "")
            if item["url"] and not item["url"].startswith("http"):
                prefix = f"{scheme}://" if scheme else "http://"
                authority = host or ""
                if port:
                    authority += f":{port}"
                item["url"] = f"{prefix}{authority}{item['url']}" if authority else item["url"]
            elif not item["url"] and (host or scheme or path):
                # Caido exposes scheme/host/port/path as separate fields
                prefix = f"{scheme}://" if scheme else "http://"
                authority = host
                if port:
                    authority = f"{authority}:{port}"
                item["url"] = f"{prefix}{authority}{path or '/'}" if authority else path or ""
            if not item["method"] and isinstance(req.get("raw"), str):
                raw = req["raw"]
                try:
                    raw = base64.b64decode(raw).decode("utf-8", errors="replace")
                except Exception:
                    pass
                first_line = raw.splitlines()[0] if raw.splitlines() else ""
                if first_line:
                    parts = first_line.split(" ")
                    item["method"] = parts[0] if parts else ""
                    if len(parts) > 1 and parts[1].startswith(("http://", "https://")):
                        item["url"] = parts[1]
                    elif len(parts) > 1 and host:
                        item["url"] = f"http://{host}{parts[1]}"
        elif isinstance(req, str):
            lines = [ln for ln in req.splitlines() if ln]
            if lines:
                parts = lines[0].split(" ")
                item["method"] = parts[0] if parts else ""
                if len(parts) > 1:
                    item["url"] = parts[1]
                # absolute-ify relative request lines with the Host header
                if item["url"] and not item["url"].startswith("http"):
                    host_hdr = next((ln.split(":", 1)[1].strip() for ln in lines[1:]
                                     if ln.lower().startswith("host:")), "")
                    if host_hdr:
                        item["url"] = f"http://{host_hdr}{item['url']}"
        # try the raw string for the response status as well
        resp = entry.get("response")
        status = ""
        if isinstance(resp, dict):
            status = str(resp.get("status") or resp.get("statusCode") or "")
        elif isinstance(resp, str):
            first_line = resp.splitlines()[0] if resp.splitlines() else ""
            if first_line.startswith("HTTP/"):
                status = first_line.split(" ", 2)[1] if len(first_line.split(" ")) > 1 else ""
        item["status"] = status or str(entry.get("status") or "")
        normalized.append(item)
    return normalized


class CaidoClient:
    """Minimal GraphQL client for Caido (PAT bearer auth)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080",
                 pat: str = "", timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.pat = pat
        self.timeout = timeout
        self._http = httpx.Client(timeout=timeout)

    # ---------------------------------------------------------------- auth
    def _gql(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """POST a GraphQL operation; returns the JSON doc (with 'errors' if any).

        Raises ValueError on transport or HTTP errors.
        """
        headers = {"Content-Type": "application/json"}
        if self.pat:
            headers["Authorization"] = f"Bearer {self.pat}"
        try:
            resp = self._http.post(
                f"{self.base_url}/graphql",
                json={"query": query, "variables": variables or {}},
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise ValueError(f"Caido GraphQL unreachable at {self.base_url}: {exc}") from exc
        if resp.status_code >= 400:
            raise ValueError(
                f"Caido GraphQL {resp.status_code}: {(resp.text or resp.reason_phrase).strip()[:500]}")
        try:
            return resp.json()
        except Exception as exc:
            raise ValueError(f"Caido GraphQL response was not JSON: {resp.text[:500]}") from exc

    @staticmethod
    def _raise_graphql_errors(data: Dict) -> None:
        errors = data.get("errors")
        if errors:
            messages = "; ".join(
                str(e.get("message", e)) for e in errors if isinstance(e, dict))
            raise ValueError(f"Caido GraphQL error: {messages or errors}")

    @staticmethod
    def _parse_url(url: str) -> Dict:
        """Split a URL into host/port/scheme/tls/sni/raw-request parts."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        tls = scheme == "https"
        default_port = 443 if tls else 80
        host = parsed.hostname or ""
        port = parsed.port if parsed.port else default_port
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        raw = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        return {
            "host": host, "port": port, "tls": tls, "sni": host, "path": path,
            "raw": raw, "scheme": scheme,
        }

    # -------------------------------------------------------------- replay
    def import_replay_sessions(self, urls: List[str],
                               name: str = "DeepBug import") -> List[str]:
        """Create a replay session per URL and fire a raw GET replay task.

        Returns the list of successfully created replay-session ids; per-URL
        failures are logged (and skipped) rather than aborting the batch.
        """
        ids: List[str] = []
        for idx, url in enumerate(urls):
            try:
                parts = self._parse_url(url)
                if not parts["host"]:
                    raise ValueError(f"could not parse host from '{url}'")
                session_id = self._create_session(name, idx, parts)
                self._start_replay(session_id, parts)
                ids.append(session_id)
            except Exception as exc:
                logger.error("Caido import failed for %s: %s", url, exc)
        return ids

    def _create_session(self, name: str, idx: int, parts: Dict) -> str:
        query = """
        mutation createReplaySession($input: CreateReplaySessionInput!) {
          createReplaySession(input: $input) { replaySession { id } }
        }
        """
        variables = {"input": {
            "name": f"{name} {idx + 1}",
            "host": parts["host"],
            "port": parts["port"],
            "tls": parts["tls"],
            "sni": parts["sni"],
        }}
        data = self._gql(query, variables)
        self._raise_graphql_errors(data)
        try:
            return str(data["data"]["createReplaySession"]["replaySession"]["id"])
        except Exception as exc:
            raise ValueError(f"Caido createReplaySession shape mismatch: {data}") from exc

    def _start_replay(self, session_id: str, parts: Dict) -> None:
        query = """
        mutation startReplayTask($input: ReplayTaskInput!) {
          startReplayTask(input: $input) { replayTask { id status } }
        }
        """
        raw_b64 = base64.b64encode(parts["raw"].encode("utf-8")).decode("ascii")
        variables = {"input": {
            "replaySessionId": session_id,
            "request": {
                "kind": "Raw",
                "raw": raw_b64,
                "host": parts["host"],
                "port": parts["port"],
                "tls": parts["tls"],
                "sni": parts["sni"],
            },
        }}
        data = self._gql(query, variables)
        self._raise_graphql_errors(data)
        try:
            task = data["data"]["startReplayTask"]["replayTask"]
        except Exception as exc:
            raise ValueError(f"Caido startReplayTask shape mismatch: {data}") from exc
        logger.debug("Caido replay task started: id=%s status=%s",
                     task.get("id", "?"), task.get("status", "?"))

    # ------------------------------------------------------------- history
    def fetch_history(self, limit: int = 200, filter: str = "") -> List[Dict]:
        """Fetch recent request.list entries normalized to
        {"url","method","status","id"}. Defensive — never raises."""
        query = """
        query requestList($filter: String, $limit: Int) {
          request.list(filter: $filter, limit: $limit, offset: 0) {
            requests { id request }
          }
        }
        """
        try:
            data = self._gql(query, {"filter": filter, "limit": limit})
        except Exception as exc:
            logger.warning("Caido fetch_history failed: %s", exc)
            return []
        if data.get("errors"):
            logger.warning("Caido fetch_history GraphQL errors: %s", data["errors"])
            return []
        try:
            requests = data["data"]["request.list"]["requests"]
        except Exception:
            requests = []
        return _extract_urls(requests)

    # --------------------------------------------------------------- misc
    def health(self) -> bool:
        """Lightweight reachability + auth check (best-effort)."""
        try:
            data = self._gql("{ currentUser { username } }")
            return "errors" not in data
        except Exception:
            return False


def get_caido_client(config: Dict) -> CaidoClient:
    """Build a CaidoClient from a config dict + environment overrides."""
    caido_cfg = (config or {}).get("integrations", {}).get("caido", {})
    return CaidoClient(
        base_url=str(caido_cfg.get("base_url", "http://127.0.0.1:8080")),
        pat=os.environ.get("CAIDO_PAT", str(caido_cfg.get("pat", ""))),
        timeout=float(caido_cfg.get("timeout", 30)),
    )
