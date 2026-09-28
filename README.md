# Compliance Gate

A Python command-line prototype for turning OpenSCAP compliance assessment results into a decision suitable for use in a CI/CD pipeline.

The prototype:
- runs OpenSCAP against a selected SCAP content file and profile;
- reads the generated machine-readable assessment result;
- compares failed findings with an approved baseline;
- applies configurable policy rules and exceptions;
- generates a structured JSON decision report; and
- returns an exit code that a CI/CD system can use to continue or stop a pipeline.

OpenSCAP performs the underlying compliance assessment. This project adds the policy-decision layer around that assessment.

## Requirements

- Python 3.10 or newer;
- OpenSCAP installed and available as `oscap` on `PATH` when using the `scan` or `run` commands;
- SCAP content suitable for the target Linux distribution;
- a valid XCCDF profile identifier;
- a policy file and approved baseline for evaluation.

The `evaluate` command can be used with an existing OpenSCAP result and does not itself start a scan.

## Command-line interface

The command-line interface provides four commands:

- `scan`: run OpenSCAP and save the scan artifacts;
- `evaluate`: evaluate an existing OpenSCAP result;
- `approve-baseline`: create an approved baseline from a result file;
- `run`: run OpenSCAP and evaluate the result in one pipeline operation.

### Run a scan

```bash
python -m compliance_gate scan \\
  --content path/to/content.xml \\
  --profile PROFILE_IDENTIFIER \\
  --output-dir artifacts/scan
```

The scan command writes a machine-readable result and a human-readable OpenSCAP report to the output directory. The exact filenames are shown by the command after execution.

Optional scan arguments include `--timeout`, `--verbose`, and `--verbosity-level`.

### Create a baseline

After obtaining an assessment result, create an approved baseline with:

```bash
python -m compliance_gate approve-baseline \\
  --results artifacts/scan/scan-results.xml \\
  --output config/baseline.json
```

Review the generated baseline before using it as an approval reference. A baseline represents findings that have been accepted as known compliance debt; it should not be created automatically from an unreviewed result in a production workflow.

### Evaluate a result

```bash
python -m compliance_gate evaluate \\
  --results artifacts/scan/scan-results.xml \\
  --policy config/policy.yaml \\
  --baseline config/baseline.json \\
  --output artifacts/decision.json
```

The command writes a JSON decision report and returns the decision exit code.

### Run the complete pipeline

```bash
python -m compliance_gate run \\
  --content path/to/content.xml \\
  --profile PROFILE_IDENTIFIER \\
  --policy config/policy.yaml \\
  --baseline config/baseline.json \\
  --output-dir artifacts/run
```

The `run` command creates the output directory, runs OpenSCAP, evaluates the result, and writes the scan, report, and decision artifacts there.
