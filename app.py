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
    """Ask OpenMinion to explain the deterministic scanner report."""
    try:
        from openminion import Agent
        import uuid

        instructions = """
You are the Cortensor Security Assistant, a Solidity security reviewer.
Explain only the findings provided in the current scan report.
For each finding, explain its rule ID, severity, line, risk, and recommendation.
Distinguish pattern matches from confirmed vulnerabilities.
Never claim that a contract is secure based only on this scanner.
"""

        prompt = (
            "Explain this Solidity scan report in plain English. "
            "Include every finding's rule ID, severity, and line number. "
            "Do not invent findings or claim that a pattern match proves a vulnerability.\n\n"
            "SCAN REPORT:\n"
            + json.dumps(report, indent=2)
            + "\n\nSOURCE CODE:\n"
            + source_code
        )

        with Agent(
            name="Cortensor Security Assistant",
            config_path=".openminion/agents.json",
            agent_id="openminion",
            instructions=instructions,
            session_id="cortensor-scan-" + uuid.uuid4().hex,
        ) as agent:
            result = agent.run(prompt)

        if getattr(result, "run_state", None) != "completed":
            print(
                "\nOpenMinion did not complete the explanation. "
                "The deterministic report remains available.",
                file=sys.stderr,
            )
            return 1

        print("\n========== OPENMINION EXPLANATION ==========")
        print(result.text or "(The model returned an empty response.)")
        return 0

    except Exception as exc:
        print(
            f"\nOpenMinion explanation unavailable: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            "The deterministic scanner report above is still available.",
            file=sys.stderr,
        )
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
