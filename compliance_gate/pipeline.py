# compliance_gate/pipeline.py

from pathlib import Path
import json
from .core import evaluate_results
from .scanner import scan_system

# compliance_gate/pipeline.py

import json
from pathlib import Path

from .core import evaluate_results
from .scanner import scan_system


def run_pipeline(
    content_path,
    profile,
    policy_path,
    baseline_path,
    output_dir,
    timeout=600,
    verbose=False,
    verbosity_level="INFO",
):
    output_dir = Path(output_dir)
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    results_path = output_dir / "scan-results.xml"
    report_path = output_dir / "openscap-report.html"
    decision_path = output_dir / "decision.json"

    scan = scan_system(
        content_path=content_path,
        profile=profile,
        results_path=results_path,
        report_path=report_path,
        timeout=timeout,
        verbose=verbose,
        verbosity_level=verbosity_level,
    )

    report, exit_code = evaluate_results(
        results_path=results_path,
        policy_path=policy_path,
        baseline_path=baseline_path,
        output_path=decision_path,
    )

    report["scanner"] = {
        "command": scan.command,
        "returncode": scan.returncode,
        "results_path": str(scan.results_path),
        "report_path": str(scan.report_path),
    }

    decision_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(f"Results: {results_path}")
    print(f"Report: {report_path}")
    print(f"Decision: {decision_path}")
    print(f"Decision: {report['decision']}")

    return report, exit_code
