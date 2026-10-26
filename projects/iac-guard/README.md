# IaC Guard — explainable Terraform security scanner

A dependency-free CLI security analyzer that checks literal AWS Terraform resource configurations for a deliberately constrained set of high-signal exposures. Its output records rules, file:line, CWE, evidence and remediation; JSON and SARIF exports support CI review.

## Try it
```bash
python projects/iac-guard/guard.py projects/iac-guard/examples/insecure.tf --format json
python projects/iac-guard/guard.py projects/iac-guard/examples/hardened.tf
python -m unittest discover -s projects/iac-guard/tests -v
```
The default exit code is **1** when a finding is `high` or `critical`. Set `--fail-on medium` for stricter thresholds. For shell demos use `... --format sarif > results.sarif` (the process may exit 1 when findings exist).

## Threat model and limits
- Checks SSH 0.0.0.0/0, public bucket ACL, broad inline IAM JSON wildcards, publicly accessible RDS, unencrypted EBS, and disabled S3 public ACL blocking.
- Parses static `resource` blocks and literal expressions only; ignores Terraform dynamic interpolation, modules, aliases, nested ingress address combinations, state drift, and provider default semantics.
- False negatives are expected for external variables and dynamic blocks. CI reviewers should combine this demo with Terraform plan-based tools such as Checkov, tfsec/Trivy, or OPA; this project **does not** claim equivalence.
- Included inputs are entirely synthetic and contain no real cloud credentials or infrastructure identifiers.

## System design
`.tf files → comment/string-aware resource extraction → rule evaluation → normalized finding → text/JSON/SARIF output`.

## Extension path
Replace the lightweight HCL parser with `terraform show -json` plan ingestion, add policy-as-code exceptions with expiry, and validate against publicly labeled IaC corpora. Historical 52,568-project research results are **separate** from this new reproducible scanner.
