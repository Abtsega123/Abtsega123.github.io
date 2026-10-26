# Secure Ticket API — authorization and API hardening

An **executable FastAPI + SQLite** example of a multi-tenant ticket backend with signed demo tokens, server-side tenant isolation, role-based write controls, type/size validation, parameterized database access, and basic security headers.

The project illustrates two common AppSec failure modes: **broken object level authorization (BOLA/IDOR)** and **injection-safe database access**.

## Install and run
```bash
python -m pip install -r projects/secure-ticket-api/requirements.txt
python -m unittest discover -s projects/secure-ticket-api/tests -v
# For an optional local server only: use a NEW local 32+ character secret
AUTH_SECRET='choose-a-random-local-test-secret-32-bytes-minimum' python projects/secure-ticket-api/app.py
```

A separate signed demo-token generator is exposed as `make_demo_token` in `app.py` for tests. The demo does not provide login, signup, password management, token minting endpoint, or real user accounts. The `TestClient` tests use synthetic tenant identities and in-memory requests.

## Trust boundaries and controls
- **Caller → API**: `Authorization: Bearer <demo HMAC token>`; invalid, expired or tampered tokens return 401.
- **API → relational store**: ticket lookup uses `WHERE id = ? AND tenant = ?` to prevent cross-tenant IDOR.
- **Role enforcement**: viewer can read; support can read and create; unsupported roles cannot authenticate.
- **Input**: Pydantic applies request schema and limits.
- **Output**: typed response models and no tokens reflected to clients; security headers include `no-store` and `nosniff`.

## Important production limitations
- HMAC token format is a **custom educational format**, not a JWT standard; **do not deploy it to production**. Replace with proper OIDC/JWT validation using maintained libraries, issuer/audience checks, and key rotation.
- No TLS termination, throttling, distributed locks, structured security audit logging, migration tooling, backups or observability in this starter.
- SQLite is suitable for deterministic local tests. Multi-instance deployments should use a managed relational database and migration pipeline.
- The demo server binds localhost only. No secrets or credential values are committed.

## Design sketch
`Bearer identity -> authentication -> role authorization -> tenant-scoped parameterized SQL -> typed response`.
