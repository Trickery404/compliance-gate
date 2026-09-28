# compliance_gate/scanner.py

from dataclasses import dataclass
from pathlib import Path
import shutil
import subprocess


@dataclass
class ScanResult:
    command: list[str]
    returncode: int
    output: str
    results_path: Path
    report_path: Path


class ScannerError(RuntimeError):
    """Raised when OpenSCAP cannot be executed successfully."""


def scan_system(
    content_path,
    profile,
    results_path,
    report_path,
    timeout=600,
    executable="oscap",
    verbose=False,
    verbosity_level="INFO",
):
    content_path = Path(content_path)
    results_path = Path(results_path)
    report_path = Path(report_path)

    if not content_path.is_file():
        raise ScannerError(
            f"SCAP content file does not exist: {content_path}"
        )

    if shutil.which(executable) is None:
        raise ScannerError(
            f"OpenSCAP executable was not found: {executable}"
        )

    results_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    command = [
        executable,
        "xccdf",
        "eval",
    ]

    if verbose:
        command.extend([
            "--verbose",
            verbosity_level,
        ])

    command.extend([
        "--profile",
        profile,
        "--results-arf",
        str(results_path),
        "--report",
        str(report_path),
        str(content_path),
    ])

    if verbose:
        print("Starting OpenSCAP scan...", flush=True)
        print("Command:", " ".join(command), flush=True)
    else:
        print("Loading OpenSCAP scan...", flush=True)

    output_lines = []

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as error:
        raise ScannerError(
            f"Could not execute OpenSCAP: {error}"
        ) from error

    try:
        assert process.stdout is not None

        for line in process.stdout:
            output_lines.append(line)

            if verbose:
                print(line, end="", flush=True)

        returncode = process.wait(timeout=timeout)

    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()

        raise ScannerError(
            f"OpenSCAP scan exceeded timeout of {timeout} seconds"
        ) from error

    output = "".join(output_lines)

    if not results_path.is_file():
        message = "OpenSCAP did not produce a result file."

        if output.strip():
            message += f"\nOpenSCAP output:\n{output}"

        raise ScannerError(message)

    if verbose:
        print(
            f"OpenSCAP process finished with exit code {returncode}.",
            flush=True,
        )

    return ScanResult(
        command=command,
        returncode=returncode,
        output=output,
        results_path=results_path,
        report_path=report_path,
    )
