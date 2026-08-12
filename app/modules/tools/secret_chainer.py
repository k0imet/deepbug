# modules/tools/secret_chainer.py
# Live-validation of JS-exposed secrets: takes the *candidate* secret strings
# found by the regex/GF layers and resolves each against the real provider
# with a single non-destructive read-only probe. A secret is only marked
# "verified" when the provider answers with authority -- turning raw pattern
# hits into actionable findings and killing placeholder/mis-parse FPs.
#
# Chains implemented (mirror blog.xboy.me crypt0g30rgy writeups -- the
# client_id/client_secret -> token endpoint -> admin API chain, Cognito
# identityPool -> temporary AWS creds chain, GitHub/Stripe/Slack validation,
# hardcoded AppKey/GraphQL header chain, etc.):
#
#   oauth_client_credentials : clientId + clientSecret + tokenEndpoint ->
#                        POST grant_type=client_credentials -> access_token
#   cognito_pool         : identityPoolId -> GetId ->
#                        GetCredentialsForIdentity -> temp AWS creds
#   aws_keys             : AKIA key (needs co-located secret, checked below)
#   github_token         : ghp_/gho_/ghu_ -> api.github.com/user
#   github_finegrained   : github_pat_ -> api.github.com/user
#   stripe_live / stripe_restricted : GET /v1/balance
#   slack                : xoxb-/xoxp- -> api.slack.com/api/auth.test
#   discord              : webhook URL -> GET (200 = still alive)
#   google_api           : AIza key -> maps geocode (cheap, read-only)
#   twilio_token         : SKxx -> GET /2010-04-01/Accounts.json
#   mailgun_key          : key-xxx -> GET /v3/domains
#   appkey_header        : hardcoded '<Name>Key: <value>' + an API/graphql
#                          endpoint -> probe endpoint accepting that header
#
# Safety contract: every check is ONE read-only request to the provider's
# public API. No writes, no deletes, no S3 PutObject, no brute-force -- the
# intent is to PROVE the leaked secret is LIVE, never to extend access.
# Every row keeps chain + evidence so a triager can re-run it.

import asyncio
import base64
import json
import re
from typing import Dict, List, Optional, Any
from urllib.parse import quote

import aiohttp

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)


class SecretChainer:
    """
    Validate leaked-candidate secrets with one read-only live probe each.

    Usage:
        chain = SecretChainer(config)
        res = chain.scan_sync(secrets=[{...}], endpoints=["https://api.x/graphql"],
                              js_file={'content': '...', 'url': 'https://x/a.js'})
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        if isinstance(config, dict) and "tools" in config:
            cfg = (config.get("tools") or {}).get("secret_chainer", {})
        else:
            cfg = config.get("secret_chainer", {}) or {}
        self.timeout = float(cfg.get("timeout", 12))
        self.max_checks = int(cfg.get("max_checks", 30))
        self.delay = float(cfg.get("delay", 0.0))
        self.enforce_chains = bool(cfg.get("chains"))
        self.enabled = set(k for k, v in (cfg.get("chains") or {}).items() if v)

    def _chain_enabled(self, chain: str) -> bool:
        if not self.enforce_chains:
            return True
        return chain in self.enabled

    # ------------------------------------------------------------------
    # chain detection (works on rows from the js_analyzer / js_gf layers)
    # ------------------------------------------------------------------
    def _discover(self, row: Dict) -> Optional[str]:
        t = ((row.get("type") or "") + " " + (row.get("pattern_name") or "")).lower()
        v = str(row.get("value") or "")
        lb = v.lower()
        ctx = (row.get("context") or "") + (row.get("raw_js") or "")

        if "cognito" in t or "identitypool" in lb or re.match(
                r"^[a-z]{2}-[a-z]+-\d:[0-9a-f-]{36}$", lb):
            return "cognito_pool"
        if ("oauth" in t or "client_secret" in t or "clientsecret" in lb) and \
                ("token_endpoint" in ctx or "tokenendpoint" in ctx or
                 "tokenUrl" in ctx or "token_url" in ctx or
                 re.search(r"grant_type=client_credentials", ctx) or
                 re.search(r"clientId", ctx)):
            return "oauth_client_credentials"
        if lb.startswith("github_pat_"):
            return "github_finegrained"
        if lb.startswith(("ghp_", "gho_", "ghu_")):
            return "github_token"
        if lb.startswith("sk_live_"):
            return "stripe_live"
        if lb.startswith("rk_live_"):
            return "stripe_restricted"
        if lb.startswith(("xoxb-", "xoxp-", "xoxa-", "xoxr-")):
            return "slack"
        if lb.startswith(("https://discord", "https://discordapp")):
            return "discord"
        if lb.startswith("AIza") and len(lb) >= 35:
            return "google_api"
        if re.match(r"^sk[a-f0-9]{32}$", lb):
            return "twilio_token"
        if re.match(r"^key-[0-9a-zA-Z]{20,}$", lb) and "mailgun" in t:
            return "mailgun_key"
        if ("aws" in t or "access key id" in t) and lb.startswith("aki"):
            return "aws_keys"
        if bool(re.search(r"[\"']([A-Za-z][A-Za-z0-9_-]*[Kk]ey)[\"']\s*[:=]", ctx)) and \
                re.findall(r"https?://[^\"'\\)]+", ctx):
            return "appkey_header"
        return None

    # ------------------------------------------------------------------
    # probes
    # ------------------------------------------------------------------
    async def _req(self, session, *, method="GET", url="", headers=None,
                   data=None):
        t = aiohttp.ClientTimeout(total=self.timeout)
        try:
            async with session.request(method, url, headers=headers,
                                       data=data, timeout=t,
                                       allow_redirects=True) as r:
                body = await r.text(errors="replace")
                return r.status, dict(r.headers), body
        except Exception as exc:
            return None, {}, f"__exc__:{exc}"

    async def _probe_oauth(self, session, row) -> Dict:
        ctx = (row.get("context") or "") + (row.get("raw_js") or "")
        extra = row.get("extra") or row.get("config") or {}
        te = re.search(r"token_?endpoint\s*[=:]\s*['\"]?(https?://[^'\"\\s),;]+)", ctx, re.I)
        oid = re.search(r"client_?id\s*[=:]\s*['\"]([0-9a-zA-Z._-]{4,})['\"]", ctx, re.I)
        sec = re.search(r"client_?secret\s*[=:]\s*['\"]([0-9a-zA-Z._-]{6,})['\"]", ctx, re.I)
        te = te.group(1) if te else extra.get("token_endpoint")
        oid = oid.group(1) if oid else extra.get("client_id")
        secv = sec.group(1) if sec else extra.get("client_secret")
        if not (te and oid and secv):
            return {"verified": False, "chain": "oauth", "evidence": "missing client_id/secret/token_endpoint"}
        auth = "Basic " + base64.b64encode(f"{oid}:{secv}".encode()).decode()
        body = "grant_type=client_credentials"
        status, _, out = await self._req(session, method="POST", url=te,
            headers={"Authorization": auth,
                     "Content-Type": "application/x-www-form-urlencoded"},
            data=body)
        if status == 200 and '"access_token"' in out:
            m = re.search(r'"access_token"\s*:\s*"([^"]+)"', out)
            return {"verified": True, "chain": "oauth", "value": oid,
                    "token": (m.group(1)[:20] + "…") if m else "",
                    "status": status,
                    "evidence": f"POST {te} -> 200 with access_token"}
        return {"verified": False, "chain": "oauth", "status": status,
                "evidence": f"token endpoint -> {status}"}

    async def _post(self, session, *, method="POST", url="", headers=None, data=None):
        return await self._req(session, method=method, url=url,
                               headers=headers, data=data)

    async def _probe_cognito(self, session, row) -> Dict:
        v = str(row.get("value") or "")
        region = v.split(":")[0] if ":" in v else "us-east-1"
        url = f"https://cognito-identity.{region}.amazonaws.com/"
        base_hdr = {"Content-Type": "application/x-amz-json-1.1"}
        status, _, out = await self._req(session, method="POST", url=url,
            headers={**base_hdr, "X-Amz-Target": "AWSCognitoIdentityService.GetId"},
            data=json.dumps({"IdentityPoolId": v}))
        if status != 200 or "IdentityId" not in out:
            return {"verified": False, "chain": "cognito", "status": status,
                    "evidence": f"GetId -> {status}"}
        m = re.search(r'"IdentityId"\s*:\s*"([^"]+)"', out)
        identity = m.group(1) if m else ""
        status2, _, out2 = await self._req(session, method="POST", url=url,
            headers={**base_hdr,
                     "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity"},
            data=json.dumps({"IdentityId": identity}))
        if status2 == 200 and "Credentials" in out2:
            return {"verified": True, "chain": "cognito", "identity_id": identity,
                    "status": status2,
                    "evidence": f"GetCredentialsForIdentity -> 200 with temp cloud creds"}
        return {"verified": False, "chain": "cognito", "status": status2,
                "evidence": "GetId ok but no temp creds (authenticated access only)"}

    async def _probe_aws(self, session, row) -> Dict:
        # Static AWS pair: only verified if both access key and its secret are
        # co-located (then STS GetCallerIdentity, read-only).
        ctx = (row.get("context") or "") + (row.get("raw_js") or "")
        sec = re.search(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", ctx)
        if not sec:
            return {"verified": False, "chain": "aws",
                    "evidence": "AKIA key without co-located secret key (can't validate)"}
        # We never store the secret; just note a full pair needs human triage.
        return {"verified": False, "chain": "aws",
                "evidence": "AWS pair needs manual STS probe (key + secret co-located)"}

    async def _probe_github(self, session, row, fine: bool) -> Dict:
        tok = str(row.get("value"))
        status, hdrs, body = await self._req(session,
            url="https://api.github.com/user",
            headers={"Authorization": "token " + tok,
                     "Accept": "application/vnd.github+json"})
        scopes = hdrs.get("X-OAuth-Scopes", "")
        if status == 200 and '"login"' in body:
            m = re.search(r'"login"\s*:\s*"([^"]+)"', body)
            return {"verified": True, "chain": "github_finegrained" if fine else "github",
                    "login": m.group(1) if m else "?", "scopes": scopes or "fine-grained",
                    "evidence": f"api.github.com/user 200 (scopes: {scopes or 'n/a'})"}
        return {"verified": False, "chain": "github", "status": status,
                "evidence": f"api.github.com/user -> {status}"}

    async def _probe_stripe(self, session, row) -> Dict:
        k = str(row.get("value"))
        status, _, body = await self._req(session, url="https://api.stripe.com/v1/balance",
            headers={"Authorization": "Basic " + base64.b64encode(f"{k}:".encode()).decode()})
        if status == 200 and '"available"' in body:
            m = re.search(r'"available"\s*:\s*\[\s*\{\s*"amount":\s*(\d+)', body)
            return {"verified": True, "chain": "stripe", "amount": m.group(1) if m else "?",
                    "status": status, "evidence": "GET /v1/balance 200"}
        return {"verified": False, "chain": "stripe", "status": status,
                "evidence": f"GET /v1/balance -> {status}"}

    async def _probe_slack(self, session, row) -> Dict:
        tok = row.get("value")
        status, _, body = await self._req(session, method="POST",
            url="https://slack.com/api/auth.test",
            data=f"token={quote(str(tok))}")
        if status == 200 and '"ok":true' in body:
            return {"verified": True, "chain": "slack", "status": status,
                    "evidence": "slack auth.test ok:true"}
        return {"verified": False, "chain": "slack", "status": status,
                "evidence": f"slack auth.test -> {status} {body[:60]}"}

    async def _probe_discord(self, session, row) -> Dict:
        url = row.get("value")
        status, _, body = await self._req(session, url=url)
        if status == 200 and '"name"' in body:
            return {"verified": True, "chain": "discord", "status": status,
                    "evidence": "GET webhook 200 (still alive)"}
        return {"verified": False, "chain": "discord", "status": status,
                "evidence": f"webhook -> {status}"}

    async def _probe_google(self, session, row) -> Dict:
        key = str(row.get("value"))
        q = quote("deepbug test", safe="")
        status, _, body = await self._req(session,
            url=f"https://maps.googleapis.com/maps/api/geocode/json?address={q}&key={quote(key, safe='')}")
        if status == 200 and '"status"' in body:
            m = re.search(r'"status"\s*:\s*"(\w+)"', body)
            if m and m.group(1) == "OK":
                return {"verified": True, "chain": "google", "status": 200,
                        "evidence": "maps geocode OK (key accepted)"}
        return {"verified": False, "chain": "google", "status": status,
                "evidence": f"google maps -> {status}"}

    async def _probe_twilio(self, session, row) -> Dict:
        tok = row.get("value")
        status, _, body = await self._req(session,
            url="https://api.twilio.com/2010-04-01/Accounts.json",
            headers={"Authorization": "Basic " + base64.b64encode(f"{tok}:".encode()).decode()})
        if status == 200 and '"sid"' in body:
            return {"verified": True, "chain": "twilio", "account": "?",
                    "evidence": "twilio Accounts.json 200"}
        return {"verified": False, "chain": "twilio", "status": status,
                "evidence": f"twilio -> {status}"}

    async def _probe_mailgun(self, session, row) -> Dict:
        tok = row.get("value")
        status, _, body = await self._req(session,
            url="https://api.mailgun.net/v3/domains",
            headers={"Authorization": "Basic " + base64.b64encode(f"api:{tok}".encode()).decode()})
        if status == 200 and '"items"' in body:
            return {"verified": True, "chain": "mailgun", "evidence": "mailgun /v3/domains 200"}
        return {"verified": False, "chain": "mailgun", "status": status,
                "evidence": f"mailgun -> {status}"}

    async def _probe_appkey(self, session, row, endpoints: List[str]) -> Dict:
        ctx = (row.get("context") or "") + (row.get("raw_js") or "")
        m = re.search(r"[\"']([A-Za-z][A-Za-z0-9_-]*[Kk]ey)[\"']\s*[:=]\s*['\"]([0-9a-zA-Z_-]{12,})['\"]", ctx)
        if not m:
            return {"verified": False, "chain": "appkey", "evidence": "no header/key pair"}
        header, key = m.group(1), m.group(2)
        target = endpoints and endpoints[0]
        if not target:
            return {"verified": False, "chain": "appkey",
                    "evidence": "no discovered endpoint to probe"}
        status, _, _ = await self._req(session, url=target,
            headers={header: key})
        if status in (200, 201):
            return {"verified": True, "chain": "appkey", "value": key[:8] + "…",
                    "status": status,
                    "evidence": f"probe {target} with {header} -> {status}"}
        return {"verified": False, "chain": "appkey", "status": status,
                "evidence": f"probe {target} -> {status}"}

    # ------------------------------------------------------------------
    # orchestration
    # ------------------------------------------------------------------
    async def _check(self, session, row: Dict, endpoints: List[str]) -> Dict:
        chain = self._discover(row)
        if not chain or not self._chain_enabled(chain):
            return {"verified": False, "chain": chain or "none",
                    "evidence": "no live chain"}
        try:
            if chain == "oauth_client_credentials":
                return await self._probe_oauth(session, row)
            if chain == "cognito_pool":
                return await self._probe_cognito(session, row)
            if chain == "aws_keys":
                return await self._probe_aws(session, row)
            if chain == "github_finegrained":
                return await self._probe_github(session, row, True)
            if chain == "github_token":
                return await self._probe_github(session, row, False)
            if chain in ("stripe_live", "stripe_restricted"):
                return await self._probe_stripe(session, row)
            if chain == "slack":
                return await self._probe_slack(session, row)
            if chain == "discord":
                return await self._probe_discord(session, row)
            if chain == "google_api":
                return await self._probe_google(session, row)
            if chain == "twilio_token":
                return await self._probe_twilio(session, row)
            if chain == "mailgun_key":
                return await self._probe_mailgun(session, row)
            if chain == "appkey_header":
                return await self._probe_appkey(session, row, endpoints)
        except Exception as exc:
            return {"verified": False, "chain": chain, "evidence": f"probe error: {exc}"}
        return {"verified": False, "chain": chain, "evidence": "unhandled chain"}

    async def scan(self, secrets: List[Dict], endpoints: Optional[List[str]] = None,
                   js_content: str = "") -> Dict[str, Any]:
        endpoints = list(endpoints or [])
        findings: List[Dict] = []
        scanned: List[Dict] = []
        async with aiohttp.ClientSession() as session:
            for row in secrets[: self.max_checks]:
                if js_content:
                    row["raw_js"] = js_content
                r = await self._check(session, row, endpoints)
                r.update({
                    "secret_type": row.get("type", ""),
                    "secret_preview": str(row.get("value", ""))[:20],
                    "source": row.get("source", ""),
                })
                scanned.append(r)
                if r.get("verified"):
                    findings.append(r)
                    logger.info("chain %-18s VERIFIED  %s", r.get("chain", "?"),
                                r.get("evidence", ""))
                elif js_content:
                    logger.info("chain %-18s not-verified %s", r.get("chain", "?"),
                                r.get("evidence", ""))
        return {"findings": findings, "scanned": scanned,
                "verified": findings}

    def scan_sync(self, secrets: List[Dict], endpoints: Optional[List[str]] = None,
                  js_content: str = "") -> Dict[str, Any]:
        try:
            return asyncio.run(self.scan(secrets, endpoints, js_content))
        except Exception as exc:
            logger.error("secret_chain scan_sync error: %s", exc)
            return {"findings": [], "scanned": [], "verified": []}

