# Active Directory Attack Lab
## Kerberoasting Exposure Review and Group Policy Hardening

A small, offline, defensive audit project for a virtual Windows domain lab. It reviews an inventory of service accounts/SPNs and selected Group Policy hardening settings, then writes a JSON findings report.

> **Safety scope:** This project does not perform Kerberoasting, request service tickets, extract credentials, crack passwords, connect to Active Directory, or change policies. It is designed for authorized lab documentation and defensive configuration review.

## Project files

- `active_directory_attack_lab.py` — Python audit utility.
- `sample_inventory.json` — synthetic example inventory for a quick test.
- `requirements.pdf` — requirements and environment notes.
- `project_report.pdf` — project report with Sandip University logo.
- `sandip_university_logo.png` — provided logo asset (if included in the package).

## Requirements

- Python 3.10 or newer
- No third-party Python packages; the script uses only the Python standard library
- A JSON inventory file using the schema shown in `sample_inventory.json`

## Run

```bash
python active_directory_attack_lab.py --input sample_inventory.json --output audit_report.json
```

The program prints a summary and writes the full report to `audit_report.json`.

## Input schema

- `domain`: optional lab domain name.
- `service_accounts`: list of objects with `name`, `spns`, `password_age_days`, and `supported_encryption`.
- `gpo_settings`: object containing values for the settings checked by the script.

Missing GPO values are reported as `NOT_VERIFIED`; values that do not meet the configured expectation are reported as `REVIEW`. A service account with an SPN is flagged for review, not automatically labeled vulnerable.

## Checks included

### Service-account/SPN review
- SPN-bearing account review
- Password age greater than 365 days
- Only legacy encryption types (`RC4`, `RC4-HMAC`, or `DES`) listed

### Selected GPO checks
- Minimum password length: at least 14
- Account lockout threshold: positive and no greater than 10
- LM hash storage disabled
- SMBv1 disabled
- Windows Firewall enabled
- PowerShell Script Block Logging enabled
- LDAP signing required

These are screening defaults for the lab and should be reviewed against your organization’s policy, Windows version, application compatibility, and applicable standards before use.

## Lab workflow

1. Build an isolated virtual Windows domain with snapshots and no production connectivity.
2. Create synthetic or approved inventory data from the lab.
3. Run this offline audit script against the inventory.
4. Review each finding and validate it against effective policy and application requirements.
5. Apply any changes manually in the lab, document before/after results, and retest.
6. Preserve logs and screenshots for the project report.

## Limitations

- The output is only as reliable as the supplied inventory.
- This is not a full Active Directory security scanner.
- No changes are made to AD or GPO settings.
- A finding is a prompt for investigation, not proof of exploitability.

## Suggested report evidence

- Virtual lab topology and VM specifications
- Domain and OU structure (redact secrets)
- Sanitized inventory input and generated JSON output
- GPO setting screenshots or exported effective-policy results
- Before/after comparison and validation notes

## License

Educational project template. Add an appropriate license before redistributing.
