# Agent Policy Lab — tool authorization for AI-driven workflows

A deterministic **policy enforcement point** between an untrusted agent and simulated tools. It is not an LLM or prompt-only filter: every proposed tool call is subject to an allowlist, role/tenant check, strict arguments and bounds validation. Outputs include a hash-chained redacted decision log for audit demonstrations.

## Run the replay
```bash
python projects/agent-policy-lab/gateway.py
python -m unittest discover -s projects/agent-policy-lab/tests -v
```

## Architecture
`LLM proposes tool call → gateway checks identity/tenant/tool/schema → allow or deny → mock executor (not included) → chained decision audit`.

**Adversarial cases:** cross-tenant ticket ID, privilege escalation, arbitrary tool name, prompt injection, and oversized search results. All examples use synthetic principals and tickets. The gateway checks tenant fields but a real production system would also require per-object row-level authorization in its data layer: **never trust the model-provided tenant alone**.

## Security boundaries
- Prompts never grant authority. Back-end verified principal claims would be sourced from signed identity tokens in production; demo principals are supplied by the caller.
- The prompt-injection regex is a limited *secondary heuristic* and cannot detect all injection. Tool ACL + argument validation are the primary controls.
- The audit hash chain is useful for local tamper detection; a malicious operator could rewrite the full log. Production needs a write-once external sink and signed checkpoints.
- No real services are contacted or data sent to outside endpoints.

## Next engineering steps
Wire an authenticated FastAPI proxy with JWT signature verification, resource ownership lookups, OpenTelemetry traces, policy versioning, and adversarial evaluation suites. These are extensions, **not implemented capabilities**.
