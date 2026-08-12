"""
graphql_clairvoyance.py — schema reconstruction when introspection is disabled.

Abuses graphql-js validation error messages to rebuild the schema:

  probe:  <op> { <path...> { <field> { CLAIR_BOGUS } } }

  * "Cannot query field \"CLAIR_BOGUS\" on type \"W\""      -> <field> is an OBJECT returning W
  * "Field \"<field>\" must not have a selection since
     type \"S\" has no subfields"                          -> <field> is a SCALAR of type S
  * "Cannot query field \"<field>\" on type \"T\".
     Did you mean ...?"                                     -> <field> invalid on T; harvest suggestions
  * "Field \"<field>\" argument \"a\" of type ... is
     required"                                              -> <field> exists, records arg (type still parsed)

These are *validation* errors, present even when the "Did you mean" suggestion
feature is switched off — suggestions just accelerate discovery when available.
BFS over (type, path); each type is enumerated once (cached by name) via the
shortest path found. Bounded by max_depth, max_requests, and concurrency.

Non-destructive: every request is a malformed READ query. Nothing mutates.
It IS noisy (one request per candidate word), so respect program scope/rate
limits before pointing it at a live target.
"""

import re
import json
import asyncio
import aiohttp
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from app.utils.logger import get_logger
logger = get_logger()

_BOGUS = "clair_probe_x9z7q"

_RE_UNKNOWN = re.compile(r'Cannot query field "([^"]+)" on type "([^"]+)"')
_RE_SCALAR = re.compile(
    r'Field "([^"]+)" must not have a selection since type "([^"]+)" has no subfields')
_RE_NEEDSEL = re.compile(
    r'Field "([^"]+)" of type "([^"]+)" must have a selection of subfields')
_RE_ARG = re.compile(
    r'Field "([^"]+)" argument "([^"]+)" of type "([^"]+)" is required')
_RE_DYM = re.compile(r'Did you mean (.+?)\?')
_RE_QUOTED = re.compile(r'"([^"]+)"')

# compact built-in seed list; pass a bigger wordlist for deeper coverage
_DEFAULT_WORDLIST = [
    "id", "node", "nodes", "edges", "viewer", "me", "user", "users", "account",
    "accounts", "profile", "email", "name", "username", "firstName", "lastName",
    "phone", "address", "role", "roles", "permission", "permissions", "isAdmin",
    "admin", "token", "secret", "apiKey", "password", "session", "createdAt",
    "updatedAt", "status", "type", "kind", "title", "description", "body",
    "content", "url", "slug", "count", "total", "page", "pageInfo", "cursor",
    "search", "query", "get", "list", "all", "find", "byId", "current",
    "organization", "org", "team", "teams", "member", "members", "group",
    "groups", "project", "projects", "repository", "repositories", "post",
    "posts", "comment", "comments", "message", "messages", "notification",
    "notifications", "order", "orders", "product", "products", "payment",
    "payments", "invoice", "invoices", "subscription", "billing", "customer",
    "customers", "file", "files", "image", "images", "avatar", "settings",
    "config", "metadata", "tags", "category", "categories", "owner", "author",
    "creator", "assignee", "parent", "children", "next", "previous", "first",
    "last", "data", "result", "results", "error", "errors", "success",
]


class GraphQLClairvoyance:
    def __init__(self, endpoint: str, session: aiohttp.ClientSession,
                 wordlist: Optional[List[str]] = None, max_depth: int = 3,
                 concurrency: int = 10, max_requests: int = 2500, timeout: int = 12):
        self.endpoint = endpoint
        self.session = session
        self.wordlist = list(dict.fromkeys(wordlist or _DEFAULT_WORDLIST))
        self.max_depth = max_depth
        self.timeout = timeout
        self.max_requests = max_requests
        self.sem = asyncio.Semaphore(concurrency)

        self.requests_made = 0
        self.types: Dict[str, Dict] = {}          # typename -> {'fields': {...}}
        self.enumerated: Set[str] = set()          # typenames already enumerated
        self.pending_suggestions: Dict[str, Set[str]] = {}  # typename -> harvested names

    # -----------------------------------------------------------------
    async def _request(self, query: str) -> Optional[List[str]]:
        """POST a query, return the list of error message strings (or None)."""
        if self.requests_made >= self.max_requests:
            return None
        self.requests_made += 1
        try:
            async with self.sem:
                async with self.session.post(self.endpoint, json={"query": query},
                                             timeout=self.timeout) as resp:
                    text = await resp.text()
        except Exception:
            return None
        try:
            data = json.loads(text)
        except Exception:
            return None
        errs = data.get("errors") if isinstance(data, dict) else None
        if not isinstance(errs, list):
            return []
        return [str(e.get("message", "")) if isinstance(e, dict) else str(e) for e in errs]

    @staticmethod
    def _wrap(op: str, path: List[str], inner: str) -> str:
        q = inner
        for seg in reversed(path):
            q = f"{seg} {{ {q} }}"
        return f"{op} {{ {q} }}"

    @staticmethod
    def _harvest(msg: str) -> List[str]:
        m = _RE_DYM.search(msg)
        return _RE_QUOTED.findall(m.group(1)) if m else []

    # -----------------------------------------------------------------
    async def _probe_field(self, op: str, type_name: str, path: List[str], w: str) -> Dict:
        """Classify a single candidate field w on type_name via the bogus-subfield trick."""
        query = self._wrap(op, path, f"{w} {{ {_BOGUS} }}")
        msgs = await self._request(query)
        out = {"field": w, "kind": "unknown", "type": None, "args": [], "suggestions": []}
        if msgs is None:
            out["kind"] = "budget"
            return out

        for msg in msgs:
            # scalar: we forced a selection on a scalar field
            ms = _RE_SCALAR.search(msg)
            if ms and ms.group(1) == w:
                out["kind"], out["type"] = "scalar", ms.group(2)

            # object: the bogus subfield is unknown on the field's return type
            for f, t in _RE_UNKNOWN.findall(msg):
                if f == _BOGUS:
                    out["kind"], out["type"] = "object", t
                    out["suggestions"] += self._harvest(msg)  # real fields of t
                elif f == w and t == type_name and out["kind"] == "unknown":
                    out["kind"] = "invalid"
                    out["suggestions"] += self._harvest(msg)

            # object needing a selection (some servers phrase it this way)
            mn = _RE_NEEDSEL.search(msg)
            if mn and mn.group(1) == w and out["kind"] in ("unknown", "invalid"):
                out["kind"], out["type"] = "object", mn.group(2)

            # required argument (field exists regardless of type resolution)
            ma = _RE_ARG.search(msg)
            if ma and ma.group(1) == w:
                out["args"].append({"name": ma.group(2), "type": ma.group(3)})
                if out["kind"] == "unknown":
                    out["kind"] = "exists"
        return out

    async def _enumerate_type(self, op: str, type_name: str, path: List[str]) -> List[Tuple[str, List[str]]]:
        """Enumerate fields of type_name; return discovered (object_type, path) to visit next."""
        if type_name in self.enumerated:
            return []
        self.enumerated.add(type_name)
        self.types.setdefault(type_name, {"fields": {}})

        candidates = deque(self.wordlist)
        for s in self.pending_suggestions.pop(type_name, set()):
            candidates.appendleft(s)
        probed: Set[str] = set()
        discovered: List[Tuple[str, List[str]]] = []

        while candidates:
            if self.requests_made >= self.max_requests:
                break
            # batch a chunk concurrently
            batch = []
            while candidates and len(batch) < self.sem._value + 8:
                w = candidates.popleft()
                if w and w not in probed:
                    probed.add(w)
                    batch.append(w)
            if not batch:
                break

            results = await asyncio.gather(
                *[self._probe_field(op, type_name, path, w) for w in batch])

            for r in results:
                w = r["field"]
                if r["kind"] == "budget":
                    candidates.clear()
                    break
                if r["kind"] in ("object", "scalar", "exists"):
                    self.types[type_name]["fields"][w] = {
                        "type": r["type"],
                        "kind": "OBJECT" if r["kind"] == "object" else
                                ("SCALAR" if r["kind"] == "scalar" else "UNKNOWN"),
                        "args": r["args"],
                    }
                    if r["kind"] == "object" and r["type"]:
                        discovered.append((r["type"], path + [w]))
                        if r["suggestions"]:
                            self.pending_suggestions.setdefault(r["type"], set()).update(r["suggestions"])
                # feed harvested suggestions for the CURRENT type back into the queue
                for s in r["suggestions"]:
                    if s not in probed and s not in candidates:
                        candidates.append(s)
        return discovered

    async def _discover_root(self, op: str) -> Optional[str]:
        """Find the root type name for an operation (query/mutation) if reachable."""
        msgs = await self._request(f"{op} {{ {_BOGUS} }}")
        if not msgs:
            return None
        for msg in msgs:
            for f, t in _RE_UNKNOWN.findall(msg):
                if f == _BOGUS:
                    return t
        return None

    # -----------------------------------------------------------------
    async def reconstruct(self) -> Dict:
        result = {
            "endpoint": self.endpoint, "viable": False,
            "root_query": None, "root_mutation": None,
            "types": {}, "requests_made": 0, "note": "",
        }

        # preflight: are standard validation errors even present?
        root_query = await self._discover_root("query")
        if not root_query:
            result["requests_made"] = self.requests_made
            result["note"] = ("No parseable validation errors — the server likely masks "
                              "GraphQL error messages; clairvoyance not viable here.")
            return result

        result["viable"] = True
        result["root_query"] = root_query
        root_mutation = await self._discover_root("mutation")
        result["root_mutation"] = root_mutation

        # BFS from each root; (type, op, path)
        queue: deque = deque()
        queue.append((root_query, "query", []))
        if root_mutation and root_mutation != root_query:
            queue.append((root_mutation, "mutation", []))

        depth_of: Dict[str, int] = {root_query: 0}
        if root_mutation:
            depth_of[root_mutation] = 0

        while queue:
            if self.requests_made >= self.max_requests:
                result["note"] = f"Stopped at request budget ({self.max_requests})."
                break
            type_name, op, path = queue.popleft()
            if depth_of.get(type_name, 0) >= self.max_depth:
                continue
            discovered = await self._enumerate_type(op, type_name, path)
            for sub_type, sub_path in discovered:
                if sub_type not in depth_of:
                    depth_of[sub_type] = len(sub_path)
                    queue.append((sub_type, op, sub_path))

        result["types"] = self.types
        result["requests_made"] = self.requests_made
        if not result["note"]:
            result["note"] = (f"Reconstructed {len(self.types)} type(s), "
                              f"{sum(len(t['fields']) for t in self.types.values())} field(s) "
                              f"in {self.requests_made} requests.")
        logger.info(f"Clairvoyance {self.endpoint}: {result['note']}")
        return result