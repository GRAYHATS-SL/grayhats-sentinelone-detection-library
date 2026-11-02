#!/usr/bin/env python3
"""Valida cada archivo de rules/**/*.yml contra schemas/star-rule.schema.json."""
import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schemas" / "star-rule.schema.json"
RULES_DIR = ROOT / "rules"

# Carpeta numerada -> táctica MITRE. El número es solo orden de kill-chain,
# no tiene significado propio más allá de eso.
FOLDER_TO_TACTIC = {
    "01-reconnaissance": "Reconnaissance",
    "02-resource-development": "Resource Development",
    "03-initial-access": "Initial Access",
    "04-execution": "Execution",
    "05-persistence": "Persistence",
    "06-privilege-escalation": "Privilege Escalation",
    "07-stealth": "Stealth",
    "08-defense-impairment": "Defense Impairment",
    "09-credential-access": "Credential Access",
    "10-discovery": "Discovery",
    "11-lateral-movement": "Lateral Movement",
    "12-collection": "Collection",
    "13-command-and-control": "Command and Control",
    "14-exfiltration": "Exfiltration",
    "15-impact": "Impact",
}

OS_SLUGS = {"windows": "win", "linux": "lnx", "macos": "mac"}

# <técnica>[.<subtécnica>].<os>.<nombre>.yml — p. ej. T1071.001.win.c2-direct-to-ip.yml
FILENAME_RE = re.compile(r"^(T[0-9]{4}(?:\.[0-9]{3})?)\.([a-z]+)\.([a-z0-9-]+)\.yml$")


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft7Validator(schema)

    errors_found = False
    for rule_file in sorted(RULES_DIR.rglob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text())
        rel_path = rule_file.relative_to(ROOT)

        for error in validator.iter_errors(rule):
            errors_found = True
            print(f"[ERROR] {rel_path}: {error.message}")

        if not isinstance(rule, dict):
            continue

        folder = rule_file.parent.name
        expected_tactic = FOLDER_TO_TACTIC.get(folder)
        actual_tactic = rule.get("mitre", {}).get("tactic")
        if expected_tactic and actual_tactic and actual_tactic != expected_tactic:
            errors_found = True
            print(
                f"[ERROR] {rel_path}: mitre.tactic ('{actual_tactic}') no coincide "
                f"con la carpeta '{folder}' (se esperaba '{expected_tactic}')"
            )

        match = FILENAME_RE.match(rule_file.name)
        if not match:
            errors_found = True
            print(
                f"[ERROR] {rel_path}: el nombre de archivo no sigue el formato "
                f"<tecnica>[.<subtecnica>].<os>.<nombre>.yml"
            )
            continue

        file_tech, file_os, _file_name = match.groups()
        techniques = rule.get("mitre", {}).get("techniques") or []
        primary_tech = techniques[0]["id"] if techniques else None
        if primary_tech and file_tech != primary_tech:
            errors_found = True
            print(
                f"[ERROR] {rel_path}: la técnica del nombre de archivo ('{file_tech}') "
                f"no coincide con mitre.techniques[0].id ('{primary_tech}')"
            )

        expected_os_slug = OS_SLUGS.get(rule.get("os"))
        if expected_os_slug and file_os != expected_os_slug:
            errors_found = True
            print(
                f"[ERROR] {rel_path}: el SO del nombre de archivo ('{file_os}') "
                f"no coincide con el campo os ('{rule.get('os')}' -> '{expected_os_slug}')"
            )

    if errors_found:
        return 1
    print("Todas las reglas son válidas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
