"""
reporting.py — finding triage + report shaping for deepbug.

Implements the 7-Question Gate, the never-submit list, chain-required
mapping, CVSS 3.1 quick reference, and a submission-ready finding template —
the validation layer that keeps weak findings out of submissions.

The gate is deterministic where possible (keyword tables) and asks the
operator for the rest. One wrong answer = KILL the finding.
"""

import math
import uuid
from typing import Dict, List, Optional

from app.modules.tools.technique_library import is_never_submit, chain_table

# ---- CVSS 3.1 quick reference -------------------------------------------

CVSS_EXAMPLES = {
    "idor_read": ("6.5", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
    "idor_write": ("7.5", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "auth_bypass_admin": ("9.8", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "stored_xss": ("8.5", "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"),
    "sqli_dump": ("9.1", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "ssrf_metadata": ("9.1", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    "race_double_spend": ("7.5", "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    "jwt_none": ("9.1", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "graphql_authz": ("8.1", "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
}

# ---- 7-Question Gate ----------------------------------------------------

QUESTIONS = [
    ("Q1", "Can an attacker use this RIGHT NOW with a real HTTP request?",
     ["curl ", "POST ", "GET ", "HTTP/1.1", "PUT ", "DELETE ", "PATCH "]),
    ("Q2", "Is the impact on the program's accepted-impact list?",
     ["impact:", "severity:", "p1", "p2", "p3", "p4", "critical", "high",
      "medium", "low"]),
    ("Q3", "Is the asset in scope?",
     ["scope", "in-scope", "in scope", "target:", "asset:"]),
    ("Q4", "Does it work without privileged access an attacker can't get?",
     ["attacker", "unauthenticated", "user-role", "low-priv", "any user",
      "session"]),
    ("Q5", "Is this not already known or documented behavior?",
     ["disclosed-reports", "h1 hacktivity", "not duplicate", "novel",
      "first reported", "previously unknown", "previously"]),
    ("Q6", "Can impact be proved beyond 'technically possible'?",
     ["leaked", "exfiltrated", "rce", "data:", "credential", "session-id",
      "cookie:", "admin email", "production", "oob callback", "interactsh"]),
    ("Q7", "Is this not on the never-submit list?",
     ["self-xss", "rate-limit only", "click-jacking", "csrf on logout",
      "missing security headers"]),
]

# Q7 is inverted: a hit means NO.
_INVERTED = {"Q7"}


def triage_verdict(note: str) -> Dict:
    """Deterministic keyword pass over the finding note.

    PASS if no question fails. DOWNGRADE if exactly one failure and it is
    Q2 or Q5. KILL otherwise (or any Q7 hit).
    """
    t = note.lower()
    failed = []
    for qid, _q, keywords in QUESTIONS:
        hit = any(k in t for k in keywords)
        if qid in _INVERTED:
            if hit:
                failed.append(qid)
        else:
            if not hit:
                failed.append(qid)
    if not failed:
        return {"verdict": "PASS", "failed": []}
    if len(failed) == 1 and failed[0] in ("Q2", "Q5"):
        return {"verdict": "DOWNGRADE", "failed": failed}
    return {"verdict": "KILL", "failed": failed}


def gate_7(finding: Dict) -> Dict:
    """Full 7-question gate over a finding dict.

    finding keys: title, endpoint, request (curl-ready), impact, asset,
    auth_model, dup_check, proof, evidence. Missing answers default to NO
    for the automated part; the returned 'open' list names what the operator
    must answer manually before submit.
    """
    note = " ".join(
        str(finding.get(k, "")) for k in
        ("title", "endpoint", "request", "impact", "asset", "proof"))
    verdict = triage_verdict(note)

    open_qs = []
    if not finding.get("request"):
        open_qs.append("Q1: paste a real HTTP request")
    if not finding.get("impact"):
        open_qs.append("Q2: state concrete attacker impact")
    if not finding.get("asset"):
        open_qs.append("Q3: name the in-scope asset")
    if not finding.get("proof"):
        open_qs.append("Q6: attach response/body proof of impact")
    if is_never_submit(note):
        verdict["verdict"] = "KILL"
        verdict["never_submit"] = is_never_submit(note)

    verdict["open"] = open_qs
    verdict["chain"] = _chain_hint(finding)
    return verdict


def _chain_hint(finding: Dict) -> Optional[str]:
    """If the finding only proves a primitive, name the chain it needs."""
    note = (finding.get("title", "") + " " + finding.get("impact", "")).lower()
    for row in chain_table():
        primitive = row[0]
        if primitive in note:
            return f"{row[1]} -> {row[2]}"
    return None


# ---- severity -----------------------------------------------------------

def base_score(vector: str) -> str:
    """CVSS 3.1 base score from vector string (compact implementation)."""
    m = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(m.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(m.get("AC", "L"), 0.77)
    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(m.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(m.get("UI", "R"), 0.62)
    s = m.get("S", "U")
    c = {"N": 0, "L": 0.22, "H": 0.56}.get(m.get("C", "N"), 0)
    i = {"N": 0, "L": 0.22, "H": 0.56}.get(m.get("I", "N"), 0)
    a = {"N": 0, "L": 0.22, "H": 0.56}.get(m.get("A", "N"), 0)
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if s == "U":
        impact = 6.42 * iss
        base = impact + 8.22 * av * ac * pr * ui
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        base = 1.08 * (impact + 8.22 * av * ac * pr * ui)
    score = min(10.0, base)
    if score <= 0:
        return "0.0"
    return f"{math.ceil(score * 10) / 10:.1f}"


def severity_label(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


# ---- finding template ----------------------------------------------------

def finding_template() -> Dict:
    return {
        "id": f"finding-{uuid.uuid4().hex[:8]}",
        "status": "lead",
        "title": "[Bug Class] in [Endpoint] allows [actor] to [impact]",
        "asset": "",
        "request": "",
        "impact": "",
        "evidence": [],
        "severity": "",
        "cvss_vector": "",
        "vrt": "",
        "7q": {"Q1": None, "Q2": None, "Q3": None, "Q4": None,
               "Q5": None, "Q6": None, "Q7": None},
        "remediation": "",
        "submission_uuid": "",
        "triager_dialogue": "",
    }


def render_report(f: Dict) -> str:
    """Render a finding dict into a triager-ready markdown block."""
    return f"""## {f.get('title', '')}

**Asset:** {f.get('asset', '')}
**Severity:** {f.get('severity', '')} ({f.get('cvss_vector', '')})
{f.get('vrt', '')}

### Summary
{f.get('impact', '')}

### Steps to Reproduce
```
{f.get('request', '')}
```

### Impact
{f.get('impact', '')}

### Remediation
{f.get('remediation', '') or '(fill in 1-2 sentences)'}
"""


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        import json
        f = json.load(open(sys.argv[1]))
        g = gate_7(f)
        print(json.dumps(g, indent=2))
    else:
        print("usage: reporting.py <finding.json>")