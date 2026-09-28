# compliance_gate/baseline.py

import json
from datetime import datetime, timezone
from pathlib import Path

from .core import parse_openscap_results


def create_baseline(results_path, output_path):
    findings = parse_openscap_results(results_path)

    failed = [
        {
            "id": finding["id"],
            "severity": finding["severity"],
            "status": finding["status"],
        }
        for finding in findings
        if finding["is_evaluated"]
        and finding["status"] == "fail"
    ]

    baseline = {
        "format_version": "1.0",
        "source": "OpenSCAP",
        "created_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "findings": sorted(
            failed,
            key=lambda finding: finding["id"],
        ),
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(baseline, indent=2),
        encoding="utf-8",
    )

    return baseline
