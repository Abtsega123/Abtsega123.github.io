# Cloud Detection Lab — CloudTrail event correlation

A small, transparent Python detection engine for synthetic AWS CloudTrail-style JSONL events. It demonstrates event normalization, UTC ordering, sliding windows, identity/IP grouping, and actionable alerts.

```bash
python projects/cloud-detection-lab/detect.py --format json
python -m unittest discover -s projects/cloud-detection-lab/tests -v
```

## Detection library
| Rule | Signal | ATT&CK mapping | Defensive response |
|---|---|---|---|
| CLOUD-001 | ≥3 failed ConsoleLogin events from the same principal and source IP within 10 minutes | T1110 | Investigate MFA and activity after failures |
| CLOUD-002 | AuthorizeSecurityGroupIngress opens TCP/22 to 0.0.0.0/0 | T1562.007 | Remove unintended security-group exposure |
| CLOUD-003 | IAM user or role receives AdministratorAccess | T1098 | Validate change ticket and privilege owner |

## Scope and limitations
- Uses a minimal subset of CloudTrail event fields, with synthetic identities and reserved example IP blocks.
- Not a managed SIEM, not an event ingestion service, and has no AWS account access.
- The event-shape handling is intentionally narrow. Real CloudTrail can nest security group permissions and errors differently; production detectors must support those schemas plus normalization, enrichment, suppression, persistence and alert disposition.
- Repeat-alert suppression is intentionally simplified; this is a deterministic example rather than a production threat-hunting result.

`JSONL → parse/validate → time ordering → behavioral detection → MITRE ATT&CK tagged evidence → analyst recommendation`
