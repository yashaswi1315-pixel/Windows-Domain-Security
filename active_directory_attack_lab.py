#!/usr/bin/env python3
"""
Active Directory Attack Lab: Built a virtual Windows domain to test
Kerberoasting exposure and Group Policy hardening.

Defensive, offline audit utility:
- Reads a JSON inventory exported/created for the lab.
- Flags service accounts with SPNs for review (potential Kerberoasting exposure).
- Checks selected password hygiene indicators and encryption settings.
- Audits selected GPO hardening settings.
- Writes a JSON report and a human-readable console summary.

This script DOES NOT connect to a domain, request service tickets, dump credentials,
crack passwords, modify Active Directory, or change Group Policy. Use only with
authorized lab inventory data.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_GPO_EXPECTATIONS = {
    "min_password_length": {"expected": 14, "operator": "gte"},
    "lockout_threshold": {"expected": 10, "operator": "lte_positive"},
    "lm_hash_storage_disabled": {"expected": True, "operator": "eq"},
    "smbv1_disabled": {"expected": True, "operator": "eq"},
    "windows_firewall_enabled": {"expected": True, "operator": "eq"},
    "powershell_script_block_logging": {"expected": True, "operator": "eq"},
    "ldap_signing_required": {"expected": True, "operator": "eq"},
}

def load_inventory(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Inventory file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("Inventory JSON must be an object.")
    data.setdefault("service_accounts", [])
    data.setdefault("gpo_settings", {})
    if not isinstance(data["service_accounts"], list):
        raise SystemExit("'service_accounts' must be a list.")
    if not isinstance(data["gpo_settings"], dict):
        raise SystemExit("'gpo_settings' must be an object.")
    return data

def audit_service_accounts(accounts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for account in accounts:
        if not isinstance(account, dict):
            continue
        name = str(account.get("name", "UNKNOWN"))
        spns = account.get("spns", [])
        if not isinstance(spns, list):
            spns = []
        password_age_days = account.get("password_age_days")
        supported_encryption = account.get("supported_encryption", [])
        if not isinstance(supported_encryption, list):
            supported_encryption = []

        account_findings = []
        if spns:
            account_findings.append({
                "severity": "MEDIUM",
                "finding": "SPN-bearing account should be reviewed for Kerberoasting exposure.",
                "recommendation": (
                    "Prefer a gMSA where supported; use a long, random managed secret; "
                    "minimize privileges; monitor service-ticket activity."
                ),
            })
        if isinstance(password_age_days, (int, float)) and password_age_days > 365:
            account_findings.append({
                "severity": "HIGH",
                "finding": "Service-account password age exceeds 365 days.",
                "recommendation": "Rotate to a strong managed secret or migrate to a gMSA."
            })
        if supported_encryption and all(str(x).lower() in {"rc4", "rc4-hmac", "des"} for x in supported_encryption):
            account_findings.append({
                "severity": "HIGH",
                "finding": "Only legacy encryption types are listed for this account.",
                "recommendation": "Validate application compatibility and prefer AES encryption."
            })
        if account_findings:
            findings.append({
                "account": name,
                "spns": spns,
                "findings": account_findings
            })
    return findings

def compare_setting(actual: Any, expectation: dict[str, Any]) -> bool:
    expected = expectation["expected"]
    operator = expectation["operator"]
    if operator == "eq":
        return actual is expected if isinstance(expected, bool) else actual == expected
    if operator == "gte":
        return isinstance(actual, (int, float)) and actual >= expected
    if operator == "lte_positive":
        return isinstance(actual, (int, float)) and 0 < actual <= expected
    return False

def audit_gpo(settings: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for key, expectation in DEFAULT_GPO_EXPECTATIONS.items():
        actual = settings.get(key)
        if actual is None:
            findings.append({
                "setting": key,
                "status": "NOT_VERIFIED",
                "actual": None,
                "expected": expectation["expected"],
                "recommendation": "Collect the effective policy value and verify it."
            })
        elif not compare_setting(actual, expectation):
            findings.append({
                "setting": key,
                "status": "REVIEW",
                "actual": actual,
                "expected": expectation["expected"],
                "recommendation": "Update and test the applicable GPO in a controlled lab."
            })
    return findings

def build_report(inventory: dict[str, Any]) -> dict[str, Any]:
    account_findings = audit_service_accounts(inventory["service_accounts"])
    gpo_findings = audit_gpo(inventory["gpo_settings"])
    return {
        "project": "Active Directory Attack Lab",
        "mode": "offline_defensive_audit",
        "domain": inventory.get("domain", "not specified"),
        "summary": {
            "service_accounts_reviewed": len(inventory["service_accounts"]),
            "accounts_with_findings": len(account_findings),
            "gpo_settings_reviewed": len(DEFAULT_GPO_EXPECTATIONS),
            "gpo_settings_requiring_review": sum(x["status"] == "REVIEW" for x in gpo_findings),
            "gpo_settings_not_verified": sum(x["status"] == "NOT_VERIFIED" for x in gpo_findings),
        },
        "service_account_findings": account_findings,
        "gpo_findings": gpo_findings,
        "limitations": [
            "Results depend on the completeness and accuracy of the supplied inventory.",
            "This is a screening aid, not a substitute for a full security assessment.",
            "No domain connection, ticket requests, credential extraction, cracking, or policy changes are performed."
        ]
    }

def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print("\\n=== Active Directory Lab Audit Summary ===")
    print(f"Domain: {report['domain']}")
    print(f"Service accounts reviewed: {summary['service_accounts_reviewed']}")
    print(f"Accounts with findings: {summary['accounts_with_findings']}")
    print(f"GPO settings requiring review: {summary['gpo_settings_requiring_review']}")
    print(f"GPO settings not verified: {summary['gpo_settings_not_verified']}")
    print("\\nService-account findings:")
    if not report["service_account_findings"]:
        print("  No findings from the supplied fields.")
    for item in report["service_account_findings"]:
        print(f"  - {item['account']}:")
        for finding in item["findings"]:
            print(f"      [{finding['severity']}] {finding['finding']}")
    print("\\nGPO findings:")
    if not report["gpo_findings"]:
        print("  All checked settings met the configured expectations.")
    for item in report["gpo_findings"]:
        print(f"  - {item['setting']}: {item['status']} (actual={item['actual']!r}, expected={item['expected']!r})")

def main() -> None:
    parser = argparse.ArgumentParser(description="Offline defensive AD/SPN and GPO audit.")
    parser.add_argument("--input", required=True, type=Path, help="Path to lab inventory JSON.")
    parser.add_argument("--output", type=Path, default=Path("ad_lab_audit_report.json"),
                        help="Output JSON report path (default: ad_lab_audit_report.json)")
    args = parser.parse_args()

    inventory = load_inventory(args.input)
    report = build_report(inventory)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_summary(report)
    print(f"\\nJSON report written to: {args.output.resolve()}")

if __name__ == "__main__":
    main()
