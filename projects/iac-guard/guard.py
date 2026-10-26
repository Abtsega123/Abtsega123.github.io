"""IaC Guard: dependency-free, explainable Terraform security rule scanner.

Educational/static scanner: purposely supports a subset of literal HCL blocks.
Not a replacement for Terraform plan parsing or enterprise IaC scanners.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    resource: str
    title: str
    evidence: str
    recommendation: str
    cwe: str


def _mask_comments(source: str) -> str:
    """Remove HCL //, # and /* */ comments without losing newlines or strings."""
    out = []
    i = 0
    state = "code"
    while i < len(source):
        c = source[i]
        nxt = source[i:i+2]
        if state == "code":
            if c == '"':
                state = "str"; out.append(c)
            elif nxt == "/*":
                state = "block"; out.extend("  "); i += 1
            elif nxt == "//" or c == "#":
                state = "line"; out.append(" " if c != "\n" else "\n")
                if nxt == "//": out.append(" "); i += 1
            else: out.append(c)
        elif state == "str":
            out.append(c)
            if c == "\\" and i + 1 < len(source): out.append(source[i+1]); i += 1
            elif c == '"': state = "code"
        elif state == "line":
            out.append("\n" if c == "\n" else " ")
            if c == "\n": state = "code"
        else:
            out.append("\n" if c == "\n" else " ")
            if nxt == "*/": out.append(" "); i += 1; state = "code"
        i += 1
    return "".join(out)

RESOURCE = re.compile(r'\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.M)

def _resources(source: str):
    text = _mask_comments(source)
    for match in RESOURCE.finditer(text):
        depth = 1; idx = match.end(); quoted = False
        while idx < len(text) and depth:
            c = text[idx]
            if c == '\\' and quoted: idx += 2; continue
            if c == '"': quoted = not quoted
            elif not quoted:
                if c == '{': depth += 1
                if c == '}': depth -= 1
            idx += 1
        if depth == 0:
            yield match.group(1), match.group(2), match.start(), text[match.end():idx-1]


def scan_text(source: str, filename: str = "sample.tf") -> list[Finding]:
    findings: list[Finding] = []
    for kind, name, start, body in _resources(source):
        display = f"{kind}.{name}"
        line = source[:start].count("\n") + 1
        def add(rule: str, severity: str, title: str, evidence: str, recommendation: str, cwe: str):
            findings.append(Finding(rule, severity, filename, line, display, title, evidence, recommendation, cwe))
        if kind == "aws_security_group" and re.search(r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', body, re.S):
            if re.search(r'from_port\s*=\s*22\b', body) and re.search(r'to_port\s*=\s*22\b', body):
                add("IAC-001", "critical", "SSH accessible from the internet", "22/tcp and 0.0.0.0/0", "Restrict ingress to trusted CIDRs or a private access path.", "CWE-284")
        if kind in {"aws_s3_bucket", "aws_s3_bucket_acl"} and re.search(r'\bacl\s*=\s*"public-(?:read|read-write)"', body):
            add("IAC-002", "high", "S3 bucket uses public ACL", "acl = public-read", "Use private ACL and S3 Block Public Access.", "CWE-732")
        if kind == "aws_iam_policy" and re.search(r'"Action"\s*:\s*"\*"', body, re.I) and re.search(r'"Resource"\s*:\s*"\*"', body, re.I):
            add("IAC-003", "high", "IAM policy grants wildcard action and resource", '"Action":"*", "Resource":"*"', "Grant only named actions on scoped resources.", "CWE-269")
        if kind == "aws_db_instance" and re.search(r'\bpublicly_accessible\s*=\s*true\b', body):
            add("IAC-004", "high", "RDS database configured as publicly accessible", "publicly_accessible = true", "Place the DB in private subnets and disable public access.", "CWE-668")
        if kind == "aws_ebs_volume" and re.search(r'\bencrypted\s*=\s*false\b', body):
            add("IAC-005", "medium", "EBS volume encryption explicitly disabled", "encrypted = false", "Enable encrypted volumes with a managed KMS key.", "CWE-311")
        if kind == "aws_s3_bucket_public_access_block" and re.search(r'\bblock_public_acls\s*=\s*false\b', body):
            add("IAC-006", "medium", "S3 public ACL blocking explicitly disabled", "block_public_acls = false", "Enable all S3 Block Public Access settings.", "CWE-732")
    return findings


def scan_directory(path: Path) -> list[Finding]:
    base = path.resolve()
    paths = [base] if base.is_file() else sorted(p for p in base.rglob("*.tf") if not p.is_symlink() and not any(s.startswith(".") for s in p.relative_to(base).parts))
    findings = []
    for p in paths:
        if not p.is_file() or p.suffix != ".tf": continue
        try: content = p.read_text(encoding="utf-8")
        except (UnicodeError, OSError): continue
        findings.extend(scan_text(content, str(p.relative_to(base)) if base.is_dir() else p.name))
    return findings


def sarif_output(findings: list[Finding]) -> dict:
    rules = {f.rule: {"id": f.rule, "shortDescription": {"text": f.title}, "properties": {"security-severity": str(SEVERITY_RANK[f.severity])}} for f in findings}
    return {"version":"2.1.0", "$schema":"https://json.schemastore.org/sarif-2.1.0.json", "runs":[{"tool":{"driver":{"name":"IaC Guard","rules":list(rules.values())}}, "results":[{"ruleId":f.rule,"level":"error" if SEVERITY_RANK[f.severity]>=3 else "warning","message":{"text": f.title+"; "+f.recommendation},"locations":[{"physicalLocation":{"artifactLocation":{"uri":f.file},"region":{"startLine":f.line}}}]} for f in findings]}]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Rule-based Terraform security screening")
    parser.add_argument("path", type=Path, help=".tf file or directory")
    parser.add_argument("--format", choices=("text","json","sarif"), default="text")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="high")
    args = parser.parse_args()
    if not args.path.exists(): parser.error("input path does not exist")
    findings = scan_directory(args.path)
    if args.format == "json": print(json.dumps([asdict(f) for f in findings], indent=2))
    elif args.format == "sarif": print(json.dumps(sarif_output(findings), indent=2))
    else:
        for f in findings: print(f"{f.severity.upper():8} {f.rule} {f.file}:{f.line} {f.title}\n        Fix: {f.recommendation}")
        print(f"{len(findings)} finding(s)")
    return int(any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in findings))

if __name__ == "__main__": sys.exit(main())
