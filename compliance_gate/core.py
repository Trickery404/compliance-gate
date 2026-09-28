import json
import xml.etree.ElementTree as ET
import hashlib
import yaml
from pathlib import Path
from datetime import date, datetime, timezone
from .exit_codes import PASS, POLICY_FAILURE

EVALUATED_STATUSES = {
    "pass",
    "fail",
}

def validate_exceptions(policy):
    exceptions = policy.get("exceptions", [])

    if not isinstance(exceptions, list):
        raise ValueError(
            "Policy 'exceptions' must be a list"
        )

    for exception in exceptions:
        if not isinstance(exception, dict):
            raise ValueError(
                "Each exception must be an object"
            )

        for field in ("id", "expires", "justification"):
            if not exception.get(field):
                raise ValueError(
                    f"Each exception requires {field}"
                )

        try:
            date.fromisoformat(exception["expires"])
        except ValueError as error:
            raise ValueError(
                f"Invalid exception date: "
                f"{exception['expires']}"
            ) from error

def load_yaml(path):
    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError("Policy must contain a YAML object")

    return data


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")

    return data


def validate_policy(policy):
    if not isinstance(policy.get("policy"), dict):
        raise ValueError("Missing 'policy' section")

    policy_section = policy["policy"]

    if not policy_section.get("name"):
        raise ValueError("Policy name is required")

    if not policy_section.get("version"):
        raise ValueError("Policy version is required")

    baseline_mode = policy_section.get(
        "baseline_mode",
        "fail_on_new"
    )

    if baseline_mode not in {"fail_on_new", "fail_all"}:
        raise ValueError(
            "baseline_mode must be 'fail_on_new' or 'fail_all'"
        )

    rules = policy.get("rules")

    if not isinstance(rules, dict):
        raise ValueError("Missing 'rules' section")

    default = rules.get("default", {})
    if default.get("on_fail", "warn") not in {"pass", "warn", "fail"}:
        raise ValueError(
            "Default on_fail must be 'pass', 'warn', or 'fail'"
        )

    severity = rules.get("severity", {})
    for level, action in severity.items():
        if action not in {"pass", "warn", "fail"}:
            raise ValueError(
                f"Invalid action '{action}' for severity '{level}'"
            )
    
    validate_exceptions(policy)


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def parse_openscap_results(path):
    root = ET.parse(path).getroot()
    findings = []

    for element in root.iter():
        if local_name(element.tag) != "rule-result":
            continue

        status = None

        for child in element:
            if local_name(child.tag) == "result":
                status = (child.text or "").strip()
                break
        
        status = status or "unknown" 

        finding = {
            "id": element.attrib.get("idref"),
            "severity": element.attrib.get(
                "severity",
                "unknown"
            ),
            "status": status,
            "is_evaluated": status in EVALUATED_STATUSES,
        }

        if finding["id"] is None:
            continue

        findings.append(finding)

    return findings


def failed_findings(findings):
    return {
        finding["id"]: finding
        for finding in findings
        if (
            finding["is_evaluated"]
            and finding["status"] == "fail"
        )
    }


def baseline_findings(baseline):
    findings = baseline.get("findings", [])

    if not isinstance(findings, list):
        raise ValueError(
            "Baseline 'findings' must be a list"
        )

    result = {}

    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError(
                "Each baseline finding must be an object"
            )

        for field in ("id", "severity", "status"):
            if not finding.get(field):
                raise ValueError(
                    f"Every baseline finding requires {field}"
                )

        result[finding["id"]] = finding

    return result


def compare_findings(current, baseline):
    current_failed = failed_findings(current)
    baseline_failed = baseline_findings(baseline)

    current_ids = set(current_failed)
    baseline_ids = set(baseline_failed)

    new_ids = current_ids - baseline_ids
    existing_ids = current_ids & baseline_ids
    resolved_ids = baseline_ids - current_ids

    return {
        "new": [
            current_failed[finding_id]
            for finding_id in sorted(new_ids)
        ],
        "existing": [
            current_failed[finding_id]
            for finding_id in sorted(existing_ids)
        ],
        "resolved": [
            baseline_failed[finding_id]
            for finding_id in sorted(resolved_ids)
        ],
    }




def active_exceptions(policy, today=None):
    today = today or date.today()
    exceptions = {}

    for exception in policy.get("exceptions", []):
        expiration = date.fromisoformat(
            exception["expires"]
        )

        if expiration >= today:
            exceptions[exception["id"]] = exception

    return exceptions


def action_for_finding(finding, policy):
    rules = policy["rules"]
    severity = finding.get("severity", "unknown")

    severity_rules = rules.get("severity", {})
    default_rule = rules.get("default", {})

    return severity_rules.get(
        severity,
        default_rule.get("on_fail", "warn")
    )


def decide(comparison, policy, today=None):
    mode = policy["policy"].get(
        "baseline_mode",
        "fail_on_new"
    )

    exceptions = active_exceptions(
        policy,
        today=today,
    )

    priority = {
        "pass": 0,
        "warn": 1,
        "fail": 2,
    }

    evaluated = []
    decision = "pass"

    for classification in ("new", "existing"):
        for finding in comparison[classification]:
            finding_id = finding["id"]

            if finding_id in exceptions:
                action = "pass"
                final_classification = "excepted"
            elif (
                classification == "existing"
                and mode == "fail_on_new"
            ):
                action = "pass"
                final_classification = "existing"
            else:
                action = action_for_finding(
                    finding,
                    policy,
                )
                final_classification = classification

            evaluated.append({
                "id": finding_id,
                "severity": finding.get(
                    "severity",
                    "unknown"
                ),
                "status": finding.get(
                    "status",
                    "fail"
                ),
                "classification": final_classification,
                "action": action,
            })

            if priority[action] > priority[decision]:
                decision = action

    if decision == "pass":
        if mode == "fail_on_new":
            reason = (
                "No new blocking findings were detected."
            )
        else:
            reason = (
                "No blocking findings were detected."
            )

    elif decision == "warn":
        if mode == "fail_on_new":
            reason = (
                "New findings require attention."
            )
        else:
            reason = (
                "Findings require attention."
            )

    else:
        if mode == "fail_on_new":
            reason = (
                "New blocking findings were detected."
            )
        else:
            reason = (
                "Blocking findings were detected."
            )
    
    return {
        "decision": decision,
        "reason": reason,
        "evaluated_findings": evaluated,
    }

def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for block in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest()


def build_metadata(
    policy,
    results_path,
    policy_path,
    baseline_path,
):
    return {
        "prototype_version": "0.1.0",
        "scanner": "OpenSCAP",
        "policy_name": policy["policy"]["name"],
        "policy_version": policy["policy"]["version"],
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "input_hashes": {
            "results": sha256_file(results_path),
            "policy": sha256_file(policy_path),
            "baseline": sha256_file(baseline_path),
        },
    }


def build_report(
    results_path,
    policy_path,
    baseline_path,
    findings,
    comparison,
    decision,
    metadata,
):
    return {
        "metadata": metadata,
        "inputs": {
            "results": str(results_path),
            "policy": str(policy_path),
            "baseline": str(baseline_path),
        },
        "summary": {
            "all_results": len(findings),
            "evaluated_results": sum(
                finding["is_evaluated"]
                for finding in findings
            ),
            "new": len(comparison["new"]),
            "existing": len(comparison["existing"]),
            "resolved": len(comparison["resolved"]),
            "decision": decision["decision"],
            "decision_reason": decision["reason"],
        },
        "comparison": comparison,
        "decision": decision["decision"],
        "reason": decision["reason"],
        "evaluated_findings": decision[
        "evaluated_findings"
        ],
    }
def evaluate_results(
    results_path,
    policy_path,
    baseline_path,
    output_path=None,
):
    policy = load_yaml(policy_path)
    validate_policy(policy)

    baseline = load_json(baseline_path)
    findings = parse_openscap_results(results_path)
    comparison = compare_findings(findings, baseline)
    decision = decide(comparison, policy)

    metadata = build_metadata(
        policy,
        results_path,
        policy_path,
        baseline_path,
    )

    report = build_report(
        results_path,
        policy_path,
        baseline_path,
        findings,
        comparison,
        decision,
        metadata,
    )

    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        output.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    exit_code = (
        POLICY_FAILURE
        if decision["decision"] == "fail"
        else PASS
    )

    return report, exit_code
