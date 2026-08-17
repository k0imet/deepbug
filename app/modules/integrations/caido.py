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
        self._guest_token: Optional[str] = None

    # ---------------------------------------------------------------- auth
    def _token(self) -> Optional[str]:
        """Return the best available token: configured PAT, else a guest token
        obtained via the public loginAsGuest mutation (works on instances with
        guest mode enabled — no manual PAT required)."""
        if self.pat:
            return self.pat
        if self._guest_token:
            return self._guest_token
        try:
            data = self._gql(
                "mutation { loginAsGuest { token { accessToken } error { __typename } } }",
                _with_token=False)
            payload = (data.get("data") or {}).get("loginAsGuest") or {}
            token = (payload.get("token") or {}).get("accessToken")
            if token:
                self._guest_token = token
        except Exception as exc:
            logger.debug("Caido guest login unavailable: %s", exc)
        return self._guest_token

    def _gql(self, query: str, variables: Optional[Dict] = None,
             _with_token: bool = True) -> Dict:
        """POST a GraphQL operation; returns the JSON doc (with 'errors' if any).

        Raises ValueError on transport or HTTP errors.
        """
        headers = {"Content-Type": "application/json"}
        if _with_token:
            token = self._token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
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
            messages = []
            for e in errors if isinstance(errors, list) else []:
                if not isinstance(e, dict):
                    messages.append(str(e))
                    continue
                msg = str(e.get("message", e))
                ext = e.get("extensions") or {}
                caido = ext.get("CAIDO") or {}
                if caido.get("reason") or caido.get("code"):
                    msg += f" [{caido.get('reason', '')}{':' + str(caido.get('code', '')) if caido.get('code') else ''}]"
                messages.append(msg)
            raise ValueError(f"Caido GraphQL error: {'; '.join(messages) or errors}")

    @staticmethod
    def _parse_url(url: str, headers: Optional[Dict[str, str]] = None) -> Dict:
        """Split a URL into host/port/scheme/tls/sni/raw-request parts.
        Extra headers (e.g. Authorization/cookies from an AuthSession) are
        injected into the raw request so authenticated testing works in Replay."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        tls = scheme == "https"
        default_port = 443 if tls else 80
        host = parsed.hostname or ""
        port = parsed.port if parsed.port else default_port
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        raw = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
        for k, v in (headers or {}).items():
            raw += f"{k}: {v}\r\n"
        raw += "Connection: close\r\n\r\n"
        return {
            "host": host, "port": port, "tls": tls, "sni": host, "path": path,
            "raw": raw, "scheme": scheme,
        }

    # -------------------------------------------------------------- replay
    def import_replay_sessions(self, urls: List[str],
                               name: str = "DeepBug import",
                               headers: Optional[Dict[str, str]] = None) -> List[str]:
        """Create a replay session per URL and fire a raw GET replay task.

        headers: extra request headers injected into each raw request (e.g.
        {'Authorization': 'Bearer ...', 'Cookie': '...'}) for authenticated
        testing inside Caido Replay.

        Returns the list of successfully created replay-session ids; per-URL
        failures are logged (and skipped) rather than aborting the batch.
        """
        ids: List[str] = []
        for idx, url in enumerate(urls):
            try:
                parts = self._parse_url(url, headers)
                if not parts["host"]:
                    raise ValueError(f"could not parse host from '{url}'")
                session_id = self._create_session(name, idx, parts)
                ids.append(session_id)
                try:
                    self._start_replay(session_id, parts)
                except Exception as exc:
                    # Session exists in Caido even if the fire/replay step
                    # failed - report it, don't lose the id.
                    logger.error("Caido startReplayTask failed for %s (session %s): %s",
                                 url, session_id, exc)
            except Exception as exc:
                logger.error("Caido import failed for %s: %s", url, exc)
        return ids

    def _create_session(self, name: str, idx: int, parts: Dict) -> str:
        # This Caido schema (2026): createReplaySession takes
        # requestSource.raw { connectionInfo { host, port, isTLS, SNI }, raw } and kind.
        raw_b64 = base64.b64encode(parts["raw"].encode("utf-8")).decode("ascii")
        query = """
        mutation createReplaySession($input: CreateReplaySessionInput!) {
          createReplaySession(input: $input) { session { id } error { __typename } }
        }
        """
        variables = {"input": {
            "kind": "HTTP",
            "requestSource": {
                "raw": {
                    "connectionInfo": {
                        "host": parts["host"],
                        "port": parts["port"],
                        "isTLS": parts["tls"],
                        "SNI": parts["sni"],
                    },
                    "raw": raw_b64,
                },
            },
        }}
        data = self._gql(query, variables)
        self._raise_graphql_errors(data)
        try:
            payload = data["data"]["createReplaySession"]
            if payload.get("error"):
                raise ValueError(f"Caido createReplaySession error: {payload['error']}")
            return str(payload["session"]["id"])
        except Exception as exc:
            raise ValueError(f"Caido createReplaySession shape mismatch: {data}") from exc

    def _start_replay(self, session_id: str, parts: Dict) -> None:
        # This schema passes sessionId as a direct argument (no `input` wrapper),
        # and ReplayTask has no `status` field.
        query = """
        mutation startReplayTask($sessionId: ID!) {
          startReplayTask(sessionId: $sessionId) { task { id } error { __typename } }
        }
        """
        data = self._gql(query, {"sessionId": session_id})
        self._raise_graphql_errors(data)
        try:
            payload = data["data"]["startReplayTask"]
            if payload.get("error"):
                raise ValueError(f"Caido startReplayTask error: {payload['error']}")
            task = payload.get("task") or {}
        except Exception as exc:
            raise ValueError(f"Caido startReplayTask shape mismatch: {data}") from exc
        logger.debug("Caido replay task started: id=%s status=%s",
                     task.get("id", "?"), task.get("status", "?"))

    # ------------------------------------------------------------- history
    def fetch_history(self, limit: int = 200, filter: str = "") -> List[Dict]:
        """Fetch recent requests normalized to {"url","method","status","id"}.
        Defensive — never raises. Requires auth (PAT or guest token).

        Note: the schema's `filter` arg is an HTTPQLInput object, not a string;
        it is simply omitted when no filter is requested.
        """
        if filter:
            query = """
            query requestsList($first: Int, $filter: HTTPQLInput) {
              requests(first: $first, filter: $filter) {
                nodes { id host method path query isTls port }
              }
            }
            """
            variables = {"first": limit, "filter": {"query": filter}}
        else:
            query = """
            query requestsList($first: Int) {
              requests(first: $first) {
                nodes { id host method path query isTls port }
              }
            }
            """
            variables = {"first": limit}
        try:
            data = self._gql(query, variables)
        except Exception as exc:
            logger.warning("Caido fetch_history failed: %s", exc)
            return []
        if data.get("errors"):
            logger.warning("Caido fetch_history GraphQL errors: %s", data["errors"])
            return []
        try:
            nodes = data["data"]["requests"]["nodes"] or []
        except Exception:
            nodes = []
        out = []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            host = node.get("host") or ""
            scheme = "https" if node.get("isTls") else "http"
            port = node.get("port") or (443 if node.get("isTls") else 80)
            path = node.get("path") or "/"
            q = node.get("query") or ""
            if q:
                path += ("?" + q) if "?" not in path else ("&" + q)
            url = f"{scheme}://{host}:{port}{path}" if port not in (80, 443) else f"{scheme}://{host}{path}"
            out.append({
                "id": str(node.get("id") or ""),
                "url": url,
                "method": str(node.get("method") or ""),
                "status": "",
            })
        return out

    # --------------------------------------------------------------- misc
    def health(self) -> bool:
        """Reachability + auth check: introspection, then token acquisition."""
        try:
            data = self._gql("{ __schema { queryType { name } } }")
            if "errors" in data:
                return False
            # Attempt token acquisition so subsequent ops are authorized.
            self._token()
            return True
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
