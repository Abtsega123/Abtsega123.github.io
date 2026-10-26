# Security and disclosure notes

The included projects are **safe local demonstrations**. They contain no real AWS credentials, no live customer data, and no real ML/LLM integration endpoints. All test fixtures are synthetic.

- Never put keys, tokens, passwords or customer configurations into the browser examples.
- Do not deploy the custom token scheme in `secure-ticket-api` to production; use a validated OIDC/JWT library and proper TLS ingress.
- Do not use the rule-based IaC scanner as your only cloud security control. It intentionally supports a narrow HCL subset.
- The agent gateway checks an untrusted tool proposal but its demo actor identity is not authenticated. Production requires signed identity verification and per-resource authorization.
- The cloud detector uses a simplified event shape. Production alerts need schema validation against actual CloudTrail, error handling, deduplication, enrichment and managed event storage.
- Apply CI and dependency audit controls before deploying any service to public infrastructure.
- Do not add real user or customer secrets to the GitHub repository. The `.gitignore` excludes typical local secrets and databases, but it is not a substitute for secret scanning.

Security issues in this source package should be reported privately to the repository owner rather than accompanied by secrets or exploit traffic in a public issue.
