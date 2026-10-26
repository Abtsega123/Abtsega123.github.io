"""Cloud Detection Lab: streaming-ish correlation of synthetic CloudTrail events.

No AWS API access, network traffic, or persistent SIEM ingestion is performed.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    title: str
    principal: str
    source_ip: str
    first_seen: str
    last_seen: str
    matched_events: int
    technique: str
    next_step: str


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None: raise ValueError("time must include timezone")
    return dt.astimezone(timezone.utc)


def detect(events: list[dict]) -> list[Alert]:
    valid: list[tuple[datetime,dict]] = []
    for event in events:
        if not isinstance(event,dict) or not all(k in event for k in ("eventTime","eventName","userIdentity","sourceIPAddress")):
            continue
        try: timestamp=parse_time(event["eventTime"])
        except (TypeError,ValueError): continue
        user=event["userIdentity"]
        if not isinstance(user,dict) or not isinstance(user.get("arn"),str): continue
        valid.append((timestamp,event))
    valid.sort(key=lambda x: x[0])
    alerts: list[Alert] = []
    grouped = defaultdict(list)
    for timestamp,event in valid:
        identity=event["userIdentity"]["arn"]
        ip=str(event["sourceIPAddress"])
        event_name=event["eventName"]
        if event_name == "ConsoleLogin" and event.get("responseElements",{}).get("ConsoleLogin") == "Failure":
            grouped[(identity,ip)].append((timestamp,event))
        if event_name == "AuthorizeSecurityGroupIngress":
            req=event.get("requestParameters",{})
            # Detect explicit 22/tcp exposure; in production inspect both ipv4 and ipv6 permission models.
            if str(req.get("cidrIp")) == "0.0.0.0/0" and str(req.get("fromPort")) == "22" and str(req.get("toPort")) == "22":
                alerts.append(Alert("CLOUD-002","critical","Public SSH ingress authorized",identity,ip,timestamp.isoformat(),timestamp.isoformat(),1,"T1562.007","Confirm authorization, review security group rules, and remove unintended ingress."))
        if event_name in ("AttachUserPolicy","AttachRolePolicy") and "AdministratorAccess" in str(event.get("requestParameters",{}).get("policyArn","")):
            alerts.append(Alert("CLOUD-003","high","AdministratorAccess attached",identity,ip,timestamp.isoformat(),timestamp.isoformat(),1,"T1098","Verify change ticket and revoke unauthorized privilege escalation."))
    for (identity,ip),failures in grouped.items():
        left=0; last_alert_index=-1
        for right,(timestamp,_) in enumerate(failures):
            while timestamp-failures[left][0] > timedelta(minutes=10): left+=1
            if right-left+1 >= 3 and left > last_alert_index:
                alerts.append(Alert("CLOUD-001","high","Multiple console login failures in 10 minutes",identity,ip,failures[left][0].isoformat(),timestamp.isoformat(),right-left+1,"T1110","Investigate source IP, MFA status, IAM activity, and successful follow-on logins."))
                last_alert_index=right
    return sorted(alerts,key=lambda a:(a.first_seen,a.rule,a.principal))


def run(path: Path) -> dict:
    entries=[]; errors=0
    for line in path.read_text().splitlines():
        if not line.strip(): continue
        try: entries.append(json.loads(line))
        except json.JSONDecodeError: errors+=1
    alerts=detect(entries)
    return {"analyzed_events":len(entries),"invalid_json_lines":errors,"alerts":[asdict(x) for x in alerts]}

def main():
    parser=argparse.ArgumentParser(description="Correlate CloudTrail-style JSONL security events")
    parser.add_argument("path",nargs="?",default=str(Path(__file__).with_name("examples")/"cloudtrail.jsonl"))
    parser.add_argument("--format",choices=("json","text"),default="text")
    args=parser.parse_args()
    report=run(Path(args.path))
    if args.format=="json": print(json.dumps(report,indent=2))
    else:
        print(f"Analyzed {report['analyzed_events']} events; {len(report['alerts'])} alert(s)")
        for a in report['alerts']: print(f"{a['severity'].upper():8} {a['rule']} {a['title']} | {a['principal']} | {a['source_ip']}")

if __name__ == '__main__': main()
