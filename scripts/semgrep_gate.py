"""Quality gate for Semgrep results.

Semgrep reports every finding (INFO, WARNING, ERROR...). The pipeline must not fail on
style-level noise, but MUST fail on a high-severity finding. This script reads the JSON
report and exits 1 if at least one finding is at a blocking severity.

    semgrep scan --config rules/ --config p/owasp-top-ten --json --output semgrep.json
    python scripts/semgrep_gate.py semgrep.json
"""
import json
import sys

# Semgrep has used ERROR/WARNING/INFO and, more recently, CRITICAL/HIGH/MEDIUM/LOW.
BLOCKING = {"ERROR", "CRITICAL", "HIGH"}


def blocking_findings(report):
    return [r for r in report.get("results", [])
            if str(r.get("extra", {}).get("severity", "")).upper() in BLOCKING]


def main(path):
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    if report.get("errors"):
        # A rule that failed to parse is a silent false negative: show it.
        for err in report["errors"]:
            print("semgrep error:", str(err.get("message", err))[:200])
    findings = blocking_findings(report)
    total = len(report.get("results", []))
    for r in findings:
        print(f"BLOCK {r['check_id']}  {r['path']}:{r['start']['line']}  "
              f"{r['extra']['message'][:120]}")
    print(f"semgrep gate: {total} finding(s), {len(findings)} blocking")
    return 1 if findings else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: semgrep_gate.py <semgrep.json>")
    sys.exit(main(sys.argv[1]))
