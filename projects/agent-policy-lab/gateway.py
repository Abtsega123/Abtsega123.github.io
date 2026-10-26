"""Agent Policy Lab: deterministic authorization boundary for simulated AI tool calls.

Models are untrusted requesters: no prompt content can grant tool privileges.
All endpoints below are mocked; this module makes no network requests.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

@dataclass(frozen=True)
class Principal:
    identity: str
    tenant: str
    role: str

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    tool: str
    principal: str
    tenant: str
    risk: str

PERMISSIONS = {
    "analyst": {"search_documents", "read_ticket"},
    "support": {"search_documents", "read_ticket", "create_ticket"},
    "admin": {"search_documents", "read_ticket", "create_ticket", "close_ticket"},
}
SAFE_TOOLS = frozenset().union(*PERMISSIONS.values())
TOOL_ARGS = {
    "search_documents": frozenset({"tenant", "query", "limit"}),
    "read_ticket": frozenset({"tenant", "ticket_id"}),
    "create_ticket": frozenset({"tenant", "title", "description"}),
    "close_ticket": frozenset({"tenant", "ticket_id"}),
}
SUSPICIOUS = re.compile(r"(?:ignore (?:all |the )?(?:prior|previous|system) instructions|reveal (?:the )?(?:secret|api key|system prompt)|send (?:all )?(?:credentials|keys|secrets) to)", re.I)

class PolicyGateway:
    def __init__(self):
        self._seq = 0
        self._previous = "0" * 64
        self._records: list[dict] = []

    def evaluate(self, actor: Principal, call: dict[str, Any]) -> Decision:
        tool = call.get("tool")
        args = call.get("arguments")
        tool_label = tool if isinstance(tool, str) else "<invalid>"
        reason = "allowed"
        risk = "low"
        if not isinstance(tool, str) or tool not in SAFE_TOOLS:
            reason, risk = "tool_not_allowlisted", "critical"
        elif not isinstance(args, dict) or not set(args).issubset(TOOL_ARGS[tool]):
            reason, risk = "invalid_argument_schema", "high"
        elif actor.role not in PERMISSIONS or tool not in PERMISSIONS[actor.role]:
            reason, risk = "role_denied", "high"
        elif args.get("tenant") != actor.tenant:
            reason, risk = "cross_tenant_access_denied", "critical"
        elif any(isinstance(v, str) and SUSPICIOUS.search(v) for v in args.values()):
            reason, risk = "suspicious_instruction_content", "high"
        elif any(isinstance(v, str) and ("@" in v and ("http://" in v or "https://" in v)) for v in args.values()):
            reason, risk = "possible_sensitive_url", "medium"
        elif tool == "search_documents" and (not isinstance(args.get("query"), str) or not isinstance(args.get("limit", 5), int) or not 1 <= args.get("limit", 5) <= 20):
            reason, risk = "search_bounds_denied", "medium"
        elif tool in {"read_ticket", "close_ticket"} and (not isinstance(args.get("ticket_id"), str) or not re.fullmatch(r"TKT-[0-9]{3,8}", args["ticket_id"])):
            reason, risk = "ticket_id_invalid", "medium"
        elif tool == "create_ticket" and (not isinstance(args.get("title"), str) or not 1 <= len(args["title"]) <= 120 or not isinstance(args.get("description"), str) or len(args["description"]) > 1000):
            reason, risk = "ticket_validation_denied", "medium"
        decision = Decision(reason == "allowed", reason, tool_label, actor.identity, actor.tenant, risk)
        self._audit(decision)
        return decision

    def _audit(self, decision: Decision):
        # Hash chain detects accidental/in-place log editing; *not* an external attestation.
        self._seq += 1
        payload = {"seq": self._seq, "decision": asdict(decision), "previous_hash": self._previous}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self._records.append({**payload, "hash": digest})
        self._previous = digest

    def audit_events(self) -> list[dict]:
        return list(self._records)

    @staticmethod
    def verify(events: list[dict]) -> bool:
        previous = "0" * 64
        for count, rec in enumerate(events, 1):
            payload = {"seq": rec.get("seq"), "decision": rec.get("decision"), "previous_hash": rec.get("previous_hash")}
            expected = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if rec.get("seq") != count or rec.get("previous_hash") != previous or rec.get("hash") != expected: return False
            previous = expected
        return True


def main():
    parser = argparse.ArgumentParser(description="Replay synthetic agent tool requests against deterministic policy")
    parser.add_argument("--input", default="", help="JSON file with cases; defaults to bundled demo")
    args = parser.parse_args()
    from pathlib import Path
    path = Path(args.input) if args.input else Path(__file__).with_name("examples") / "requests.json"
    cases = json.loads(path.read_text())
    gateway = PolicyGateway()
    for case in cases:
        actor = Principal(**case["principal"])
        decision = gateway.evaluate(actor, case["call"])
        print(json.dumps({"id": case["id"], **asdict(decision)}))
    print(json.dumps({"audit_chain_valid": gateway.verify(gateway.audit_events()), "requests_evaluated": len(cases)}))

if __name__ == "__main__": main()
