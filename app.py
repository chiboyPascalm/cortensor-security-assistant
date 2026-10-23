"""Demo entry point for Cortensor Security Assistant."""

import argparse
import json
import sys

from scanner import scan_file, scan_solidity

NOTICE = (
    "Pattern-based screening only. Findings require manual review; "
    "this tool does not establish that a contract is secure or vulnerable."
)


def print_report(report: dict) -> None:
    print(json.dumps(report, indent=2))


def run_ai_explanation(source_code: str, report: dict) -> int:
    """Use OpenMinion to explain findings with a concise prompt."""
    import os
    import subprocess

    findings = report.get("findings", [])
    if not findings:
        print("\nNo findings were reported; skipping AI explanation.")
        return 0

    summary = []
    for finding in findings:
        summary.append({
            key: finding.get(key)
            for key in ("rule_id", "id", "rule", "severity", "line", "title", "description", "recommendation", "message")
            if finding.get(key) is not None
        })

    prompt = (
        "You are a Solidity security reviewer. Briefly explain these pattern-based findings. "
        "For each, state the possible risk and one practical recommendation. "
        "Treat findings as potential risks, not confirmed vulnerabilities. "
        "Do not claim the contract is secure.\n\nFINDINGS:\n"
        + json.dumps(summary, ensure_ascii=False)
    )

    cli = os.path.join(os.path.dirname(sys.executable), "openminion")
    if not os.path.isfile(cli):
        print("Project OpenMinion CLI not found.", file=sys.stderr)
        return 1

    try:
        result = subprocess.run(
            [
                cli, "run", "--profile", "openminion",
                "--runtime-source", "inproc", "--reset-session",
                "--progress", "off", prompt,
            ],
            timeout=90,
        )
        if result.returncode != 0:
            print("OpenMinion CLI failed:", file=sys.stderr)
            print("OpenMinion exited with a non-zero status.", file=sys.stderr)
            print("The deterministic report remains available.", file=sys.stderr)
            return 1
        print("\n========== OPENMINION EXPLANATION =========")
        print("OpenMinion explanation completed successfully.")
        return 0
    except subprocess.TimeoutExpired:
        print("OpenMinion timed out after 90 seconds.", file=sys.stderr)
        print("The deterministic report remains available.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"OpenMinion unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("The deterministic report remains available.", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pattern-based Solidity screening for smart contracts."
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="samples/vulnerable_example.sol",
        help="Solidity file to scan (default: bundled vulnerable example)",
    )
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Also request an explanation through the OpenMinion Agent API",
    )
    args = parser.parse_args()

    try:
        report = scan_file(args.file)
    except (OSError, UnicodeError) as exc:
        print(f"Cannot read Solidity file: {exc}", file=sys.stderr)
        return 2

    print("========== CORTENSOR SECURITY ASSISTANT ==========")
    print_report(report)

    if args.ai:
        with open(args.file, encoding="utf-8") as file:
            source_code = file.read()
        return run_ai_explanation(source_code, report)

    print("\nAI explanation skipped. Use --ai to try OpenMinion.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
