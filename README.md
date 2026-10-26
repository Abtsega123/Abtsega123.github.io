# Abtsega Tesfaye — security engineering portfolio + working labs

A redesigned, mobile-responsive, interactive technical portfolio **and source bundle**. Designed to replace the dated template at `Abtsega123/Abtsega123.github.io` after review. No extra npm packages, authentication, API keys, analytics, or cloud resources are required.

## What is included

| Component | Scope | Status |
|---|---|---|
| Portfolio website | Editorial hero, case studies, technical lab, research context, professional history, resume | Published to GitHub Pages from `main` |
| IaC Guard | Terraform HCL resource scanner, 6 explainable security rules, JSON/SARIF export | Runnable Python CLI + unit tests |
| Agent Policy Lab | Cross-tenant policy gateway, tool allowlist, role and schema checks, tamper-detectable decision log | Runnable Python CLI + adversarial unit tests |
| Cloud Detection Lab | CloudTrail-style event parsing, failure-burst correlation, risky API changes | Runnable Python CLI + unit tests |
| Secure Ticket API | FastAPI + SQLite, HMAC synthetic tokens, RBAC, tenant-scoped queries, IDOR and injection tests | Runnable API + unit tests |
| CI pipeline | Standard-library project tests, compile checks, static site smoke checks | GitHub Actions workflow included; runs once pushed |

The front-end lab uses **client-side simulations** of the Python projects for recruiter exploration. Python CLIs and their test suites are the more precise reference implementation. The front end intentionally uses no network calls.

### Run locally
```bash
cd eca_security_portfolio
python -m http.server 8080
# Open http://localhost:8080 in a browser
```
Run all tests from the root:
```bash
python -m unittest discover -s tests -v
python tests/site_smoke.py
python projects/iac-guard/guard.py projects/iac-guard/examples/insecure.tf --format json
python projects/agent-policy-lab/gateway.py
python projects/cloud-detection-lab/detect.py --format json
python -m unittest discover -s projects/secure-ticket-api/tests -v
```
**All data in the demo fixtures is synthetic.**

## Publish to your existing GitHub Pages repository

The working site and source are published in `Abtsega123/Abtsega123.github.io`. GitHub Pages serves the static portfolio from `main`, with the recruiter-facing PDF at `assets/Abtsega_Tesfaye_CV.pdf` and a printable HTML version at `resume.html`.

**Recommended safe path**: clone your existing site, create a feature branch, and copy this package into that clone. Keep your legacy assets and history in the repository so rollback is possible.

```bash
git clone https://github.com/Abtsega123/Abtsega123.github.io.git
cd Abtsega123.github.io
git switch -c security-portfolio-refresh
# Copy contents of this package over, including .github/ and assets/; do NOT remove any old files yet.
python -m unittest discover -s tests -v
python tests/site_smoke.py
git add .
git commit -m "Build security engineering portfolio and reproducible demos"
git push -u origin security-portfolio-refresh
# Open pull request, review, then merge to main to update GitHub Pages.
```

For GitHub Pages user sites, visit **Settings → Pages**, and verify that Pages serves the **main branch root**. GitHub Actions workflows may require Actions permission. After pushing, review the live site and confirm all links and your resume's content. If you instead deploy to Vercel, point a static-site project at this folder with no build command and output directory `.`; updating `abtsega101.vercel.app` requires connecting the original Vercel project, which this package does not access.

## Verified portfolio context and honesty

The previous GitHub Pages repository was based on `codewithsadee/vcard-personal-portfolio` and retained generic template text and placeholder testimonials. This replaces those claims with experience documented in supplied career materials. Current 2026 research numbers are identified explicitly as research results and are **not** benchmark claims for the new scanner or demos. No customer endorsements, enterprise ownership, paid deployments or new credentials have been invented.

Review all personal details, employer wording, research/paper status, and certification claims with your source records before publication. A printable browser CV is published as `resume.html`, with source DOCX/PDF available in the packaged download. It describes the newly implemented local prototypes, and provides code-level evidence for the technical claims. Review certification and experience wording before circulating the CV widely.

## Engineering limitations

- Terraform scanner only parses literal `.tf` block patterns; it is **not** a complete HCL parser and can miss dynamic resources.
- Agent gateway uses synthetic principals; real authentication, authorization at data layer, signed audit logs and enforcement with a model-serving tool backend are not implemented.
- Cloud detector processes synthetic CloudTrail-style JSONL, not AWS accounts, and does not cover production event schema variants.
- Browser demo checks are simplified. Do not paste private data, credentials or production configuration into demonstrations.

## Packaging
The root folder is deployable as a static site and can also be kept as a monorepo with project source. `projects/*/README.md` includes architecture, test commands, threat models, and future extensions.

### Windows shortcut (PowerShell)
Unzip the archive and run `./publish.ps1` inside the `eca_security_portfolio` folder in PowerShell. The script requires Git and Python with authenticated GitHub access, clones the existing repository into a *new sibling folder*, creates a feature branch, copies in the upgrade, tests it, commits and pushes the branch. It **does not** merge to main or change the live site automatically.
