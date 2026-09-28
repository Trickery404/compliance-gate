# compliance_gate/main.py
import argparse
import sys
from pathlib import Path

from .baseline import create_baseline
from .core import evaluate_results
from .exit_codes import (
    CONFIGURATION_ERROR,
    RUNTIME_ERROR,
)
from .pipeline import run_pipeline
from .scanner import ScannerError, scan_system


def build_parser():
    parser = argparse.ArgumentParser(
        prog="compliance-gate",
        description="OpenSCAP CI/CD compliance gate",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Run OpenSCAP and save scan artifacts",
    )
    add_scan_arguments(scan_parser)
    scan_parser.set_defaults(handler=handle_scan)

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="Evaluate an existing OpenSCAP result",
    )
    add_evaluate_arguments(evaluate_parser)
    evaluate_parser.set_defaults(handler=handle_evaluate)

    baseline_parser = subparsers.add_parser(
        "approve-baseline",
        help="Create an approved baseline from a scan result",
    )
    baseline_parser.add_argument(
        "--results",
        required=True,
        type=Path,
        help="OpenSCAP result file",
    )
    baseline_parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output baseline JSON file",
    )
    baseline_parser.set_defaults(handler=handle_baseline)

    run_parser = subparsers.add_parser(
        "run",
        help="Run OpenSCAP and evaluate the result",
    )
    add_run_arguments(run_parser)
    run_parser.set_defaults(handler=handle_run)

    return parser

def add_scan_arguments(parser):
    parser.add_argument(
        "--content",
        required=True,
        type=Path,
        help="SCAP source data stream",
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="XCCDF profile identifier",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for scan artifacts",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="OpenSCAP timeout in seconds",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show live OpenSCAP output",
    )
    parser.add_argument(
        "--verbosity-level",
        choices=("DEVEL", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="OpenSCAP verbosity level",
    )

def add_evaluate_arguments(parser):
    parser.add_argument(
        "--results",
        required=True,
        type=Path,
        help="OpenSCAP result file",
    )
    parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Compliance policy YAML file",
    )
    parser.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Approved baseline JSON file",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Decision report JSON file",
    )

def add_run_arguments(parser):
    parser.add_argument(
        "--content",
        required=True,
        type=Path,
        help="SCAP source data stream",
    )
    parser.add_argument(
        "--profile",
        required=True,
        help="XCCDF profile identifier",
    )
    parser.add_argument(
        "--policy",
        required=True,
        type=Path,
        help="Compliance policy YAML file",
    )
    parser.add_argument(
        "--baseline",
        required=True,
        type=Path,
        help="Approved baseline JSON file",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for all pipeline artifacts",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="OpenSCAP timeout in seconds",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show live OpenSCAP output",
    )
    parser.add_argument(
        "--verbosity-level",
        choices=("DEVEL", "INFO", "WARNING", "ERROR"),
        default="INFO",
        help="OpenSCAP verbosity level",
    )

def handle_scan(args):
    scan = scan_system(
        content_path=args.content,
        profile=args.profile,
        results_path=(
            args.output_dir / "scan-results.xml"
        ),
        report_path=(
            args.output_dir / "openscap-report.html"
        ),
        timeout=args.timeout,
        verbose=args.verbose,
        verbosity_level=args.verbosity_level,
    )

    print(f"Results: {scan.results_path}")
    print(f"Report: {scan.report_path}")
    print(
        f"OpenSCAP exit code: {scan.returncode}"
    )

    return 0

def handle_evaluate(args):
    report, exit_code = evaluate_results(
        results_path=args.results,
        policy_path=args.policy,
        baseline_path=args.baseline,
        output_path=args.output,
    )

    print(f"Decision: {report['decision']}")
    print(f"Report: {args.output}")

    return exit_code


def handle_baseline(args):
    create_baseline(
        results_path=args.results,
        output_path=args.output,
    )

    print(f"Baseline: {args.output}")
    return 0

def handle_run(args):
    report, exit_code = run_pipeline(
        content_path=args.content,
        profile=args.profile,
        policy_path=args.policy,
        baseline_path=args.baseline,
        output_dir=args.output_dir,
        timeout=args.timeout,
        verbose=args.verbose,
        verbosity_level=args.verbosity_level,
    )

    return exit_code

def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        return args.handler(args)
    except (ValueError, FileNotFoundError) as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return CONFIGURATION_ERROR
    except ScannerError as error:
        print(f"Scanner error: {error}", file=sys.stderr)
        return RUNTIME_ERROR
    except Exception as error:
        print(f"Runtime error: {error}", file=sys.stderr)
        return RUNTIME_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
