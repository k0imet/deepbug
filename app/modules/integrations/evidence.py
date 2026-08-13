"""DeepBug evidence store.

Captures per-target HTTP request/response evidence, free-form notes and
nuclei findings as JSON Lines (one dict per line) under
``<project>/<target_sanitized>/evidence/evidence.jsonl``, and exports an
in-memory ZIP bundle with a manifest plus a minimal HAR file.

Stdlib only and intentionally robust: no function in this module raises,
bad input is coerced or logged, never fatal.
"""

import io
import json
import math
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    from app.utils.logger import get_logger as _get_logger
except Exception:  # pragma: no cover - module still usable without the app package
    _get_logger = None

MAX_LIST_ENTRIES = 2000
EVIDENCE_DIRNAME = "evidence"
EVIDENCE_FILENAME = "evidence.jsonl"
MANIFEST_FILENAME = "manifest.json"
HAR_FILENAME = "deepbug.har"
VALID_KINDS = ("http", "note", "finding")

_UNSAFE = re.compile(r'[./:*?<>"|\\\x00-\x1f]')


def _logger():
    if _get_logger is not None:
        try:
            return _get_logger()
        except Exception:
            pass
    import logging
    return logging.getLogger("deepbug.evidence")


def _sanitize_target(target: Any) -> str:
    """Filesystem-safe target dir name: '.'/'/' and other unsafe chars -> '_'."""
    if not target or not isinstance(target, str):
        return ''
    return _UNSAFE.sub('_', target.strip())


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _jsonable(value: Any):
    """Recursively coerce values (incl. numpy/pandas scalars) to JSON-safe types."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        if isinstance(value, float) and not math.isfinite(value):
            return str(value)
        return value
    try:
        item = value.item()
        return _jsonable(item)
    except Exception:
        return str(value)


def _json_default(o: Any) -> str:
    """json.dumps default hook: last-resort conversion for exotic types."""
    try:
        if hasattr(o, 'item'):
            return o.item()
    except Exception:
        pass
    try:
        if isinstance(o, float) and not math.isfinite(o):
            return str(o)
    except Exception:
        pass
    try:
        if isinstance(o, (bytes, bytearray)):
            return o.decode('utf-8', errors='replace')
    except Exception:
        pass
    return str(o)


def _as_dict(value: Any) -> dict:
    if not value:
        return {}
    if isinstance(value, dict):
        return _jsonable(value)
    if isinstance(value, (list, tuple)):
        out = {}
        for pair in value:
            try:
                k, v = pair
                out[str(k)] = _jsonable(v)
            except Exception:
                continue
        return out
    try:
        return _jsonable(dict(value))
    except Exception:
        return {}


def _coerce_status(status: Any) -> Optional[int]:
    if status is None or isinstance(status, bool):
        return None
    try:
        return int(status)
    except (TypeError, ValueError, OverflowError):
        return None


def _build_entry(kind: str, scan_type: str, url: str, method: str, status: Optional[int],
                 request_headers: Optional[dict], request_body: str,
                 response_headers: Optional[dict], response_body_snippet: str,
                 curl: str, meta: Optional[dict]) -> dict:
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind if kind in VALID_KINDS else "note",
        "scan_type": _as_str(scan_type),
        "url": _as_str(url),
        "method": _as_str(method),
        "status": status,
        "request_headers": _as_dict(request_headers),
        "request_body": _as_str(request_body),
        "response_headers": _as_dict(response_headers),
        "response_body_snippet": _as_str(response_body_snippet),
        "curl": _as_str(curl),
        "meta": _as_dict(meta),
    }


def _append_entry(project_path: Any, target: str, kind: str, scan_type: str = "",
                  url: str = "", method: str = "GET", status: Optional[int] = None,
                  request_headers: Optional[dict] = None, request_body: str = "",
                  response_headers: Optional[dict] = None,
                  response_body_snippet: str = "", curl: str = "",
                  meta: Optional[dict] = None) -> None:
    """Core writer: append one JSONL entry, create dirs, never raise."""
    try:
        if not project_path:
            _logger().warning("Evidence: no project path; skipping %s capture.", kind)
            return
        project = Path(project_path)
        target_dir = _sanitize_target(target)
        if not target_dir:
            _logger().warning("Evidence: empty target name; skipping %s capture.", kind)
            return
        evid_dir = project / target_dir / EVIDENCE_DIRNAME
        evid_dir.mkdir(parents=True, exist_ok=True)
        entry = _build_entry(
            kind, scan_type, url, method,
            _coerce_status(status),
            request_headers, request_body,
            response_headers, response_body_snippet,
            curl, meta,
        )
        line = json.dumps(entry, ensure_ascii=False, default=_json_default) + "\n"
        with open(evid_dir / EVIDENCE_FILENAME, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception as exc:  # never raise
        _logger().error("Evidence: failed to append %s entry: %s", kind, exc)


def capture_http(project_path: Any, target: str, scan_type: str, url: str,
                 method: str = "GET", status: Optional[int] = None,
                 request_headers: Optional[dict] = None, request_body: str = "",
                 response_headers: Optional[dict] = None,
                 response_body_snippet: str = "", curl: str = "",
                 meta: Optional[dict] = None) -> None:
    """Append an HTTP request/response evidence entry (kind ``http``)."""
    _append_entry(project_path, target, "http", scan_type=scan_type, url=url,
                  method=method, status=status, request_headers=request_headers,
                  request_body=request_body, response_headers=response_headers,
                  response_body_snippet=response_body_snippet, curl=curl, meta=meta)


def capture_note(project_path: Any, target: str, text: str,
                 meta: Optional[dict] = None) -> None:
    """Append a free-form note (kind ``note``); text is stored as the body."""
    _append_entry(project_path, target, "note", scan_type="note", url="",
                  method="", status=None, request_headers=None,
                  request_body=_as_str(text), response_headers=None,
                  response_body_snippet="", curl="", meta=meta)


def capture_finding(project_path: Any, target: str, scan_type: str,
                    row: dict) -> None:
    """Append a finding-kind entry from a results-row dict.

    Pulls URL / curl / severity from common nuclei column names
    (Matched_At/URL/url, Curl_Command/curl, Severity/severity, Name,
    Extracted_Results) and stores the rest in ``meta``.
    """
    if not isinstance(row, dict):
        _logger().warning("Evidence: capture_finding got non-dict row %r", type(row))
        return
    url = row.get("Matched_At") or row.get("URL") or row.get("url") or ""
    curl = row.get("Curl_Command") or row.get("curl") or ""
    meta = {
        "name": row.get("Name") or row.get("name") or "",
        "severity": row.get("Severity") or row.get("severity") or "",
        "template_id": row.get("Template_ID") or row.get("template_id") or "",
        "extracted_results": row.get("Extracted_Results") or row.get("extracted_results") or "",
    }
    meta = {k: v for k, v in meta.items() if v not in (None, "")}
    _append_entry(project_path, target, "finding", scan_type=scan_type,
                  url=_as_str(url), method="GET", status=None,
                  request_headers=None, request_body="", response_headers=None,
                  response_body_snippet="", curl=_as_str(curl), meta=meta)


# ---------------------------------------------------------------------------
# Reading / listing
# ---------------------------------------------------------------------------

def _iter_jsonl_files(project_path: Any, target: Optional[str] = None
                      ) -> Iterator[Tuple[str, Path]]:
    """Yield (relative_arcname, file_path) for every evidence jsonl found."""
    if not project_path:
        return
    project = Path(project_path)
    if not project.is_dir():
        return
    target_dirs: List[Path] = []
    if target:
        t = _sanitize_target(target)
        if t:
            target_dirs = [project / t]
    else:
        target_dirs = [p for p in project.iterdir()
                       if p.is_dir() and not p.name.startswith('.')]
    for tdir in target_dirs:
        evid_dir = tdir / EVIDENCE_DIRNAME
        if not evid_dir.is_dir():
            continue
        for fpath in sorted(evid_dir.glob("*.jsonl")):
            arcname = f"{tdir.name}/{EVIDENCE_DIRNAME}/{fpath.name}"
            yield arcname, fpath


def _parse_lines(text: str) -> List[dict]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if isinstance(obj, dict):
            entries.append(obj)
    return entries


def list_evidence(project_path: Any, target: Optional[str] = None) -> List[dict]:
    """Read all evidence entries (one target or across targets), newest first."""
    entries: List[dict] = []
    try:
        for _arcname, fpath in _iter_jsonl_files(project_path, target):
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                _logger().warning("Evidence: cannot read %s: %s", fpath, exc)
                continue
            entries.extend(_parse_lines(text))
        entries.sort(key=lambda e: str(e.get("ts", "")), reverse=True)
        return entries[:MAX_LIST_ENTRIES]
    except Exception as exc:  # never raise
        _logger().error("Evidence: list_evidence failed: %s", exc)
        return entries


def evidence_count(project_path: Any, target: Optional[str] = None) -> int:
    """Count stored evidence entries (uncapped)."""
    total = 0
    try:
        for _arcname, fpath in _iter_jsonl_files(project_path, target):
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                _logger().warning("Evidence: cannot read %s: %s", fpath, exc)
                continue
            total += sum(1 for line in text.splitlines() if line.strip())
    except Exception as exc:  # never raise
        _logger().error("Evidence: evidence_count failed: %s", exc)
        return total
    return total


# ---------------------------------------------------------------------------
# Export: in-memory ZIP with manifest + minimal HAR
# ---------------------------------------------------------------------------

def _headers_list(headers: Any) -> List[dict]:
    """Convert a headers dict (or list of pairs) to HAR [{name, value}]."""
    out = []
    if isinstance(headers, dict):
        items = headers.items()
    elif isinstance(headers, (list, tuple)):
        items = headers
    else:
        return out
    for pair in items:
        try:
            name, value = pair
            out.append({"name": _as_str(name), "value": _as_str(value)})
        except Exception:
            continue
    return out


def _har_entry(entry: dict) -> dict:
    ts = _as_str(entry.get("ts") or datetime.now(timezone.utc).isoformat())
    status = _coerce_status(entry.get("status")) or 0
    body = _as_str(entry.get("request_body"))
    request = {
        "method": _as_str(entry.get("method") or "GET"),
        "url": _as_str(entry.get("url")),
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": _headers_list(entry.get("request_headers")),
        "queryString": [],
        "headersSize": -1,
        "bodySize": -1,
    }
    if body:
        request["postData"] = {"mimeType": "text/plain", "text": body}
    response = {
        "status": status,
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "cookies": [],
        "headers": _headers_list(entry.get("response_headers")),
        "content": {
            "size": -1,
            "mimeType": "",
            "text": _as_str(entry.get("response_body_snippet")),
        },
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": -1,
    }
    return {
        "startedDateTime": ts,
        "time": 0,
        "request": request,
        "response": response,
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
        "comment": _as_str(entry.get("scan_type")),
    }


def _build_har(project_path: Any, target: Optional[str] = None) -> Optional[dict]:
    """Best-effort minimal HAR from http-kind entries."""
    try:
        entries = []
        for entry in list_evidence(project_path, target=target):
            if entry.get("kind") != "http":
                continue
            try:
                entries.append(_har_entry(entry))
            except Exception:
                continue
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "DeepBug", "version": "1.0"},
                "entries": entries,
            }
        }
    except Exception as exc:  # never raise
        _logger().error("Evidence: HAR build failed: %s", exc)
        return None


def export_evidence_bundle(project_path: Any, target: Optional[str] = None) -> bytes:
    """Return an in-memory ZIP: per-target evidence jsonl + manifest + deepbug.har."""
    try:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest = {
                "generated": datetime.now(timezone.utc).isoformat(),
                "targets": {},
                "totals": {"total": 0, "http": 0, "note": 0, "finding": 0},
            }
            for arcname, fpath in _iter_jsonl_files(project_path, target):
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception as exc:
                    _logger().warning("Evidence: skip %s in export: %s", fpath, exc)
                    continue
                zf.writestr(arcname, text)
                counts = {"total": 0, "http": 0, "note": 0, "finding": 0}
                for entry in _parse_lines(text):
                    counts["total"] += 1
                    kind = entry.get("kind")
                    if kind in counts:
                        counts[kind] += 1
                target_name = arcname.split("/")[0]
                manifest["targets"][target_name] = counts
                for key in counts:
                    manifest["totals"][key] += counts[key]
            zf.writestr(MANIFEST_FILENAME, json.dumps(manifest, indent=2, ensure_ascii=False))
            har = _build_har(project_path, target=target)
            if har is not None:
                zf.writestr(HAR_FILENAME, json.dumps(har, indent=2, ensure_ascii=False))
        return buf.getvalue()
    except Exception as exc:  # never raise
        _logger().error("Evidence: export failed: %s", exc)
        return b""
