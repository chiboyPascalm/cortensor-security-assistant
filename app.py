"""Demo entry point for Cortensor Security Assistant."""
from pathlib import Path

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

    source_lines = source_code.splitlines()
    source_context = []
    for finding in findings:
        line = finding.get("line")
        if not isinstance(line, int) or line < 1:
            continue
        start = max(1, line - 5)
        end = min(len(source_lines), line + 5)
        source_context.append({
            "reported_line": line,
            "source_lines": [
                f"{number}: {source_lines[number - 1]}"
                for number in range(start, end + 1)
            ],
        })

    context_text = json.dumps(source_context, ensure_ascii=False)
    if len(context_text) > 12000:
        context_text = context_text[:12000] + " [context truncated]"

    prompt = (
        "You are a careful Solidity smart-contract security reviewer. "
        "Explain only the supplied pattern-based findings, using the supplied source context when available. "
        "For each finding, state the detected pattern, the conditional risk, and one practical, technically correct recommendation. "
        "Treat scanner output as a heuristic, not proof of a vulnerability or exploitability. "
        "Do not claim that the contract is secure or that you performed tests you did not perform. "
        "If the source context is insufficient, explicitly say manual review is required. "
        "Never invent Solidity APIs, return fields, compiler behavior, or code details. "
        "For tx.origin authorization checks, explain why tx.origin is unsafe for authorization; recommend msg.sender for direct-caller checks or an appropriate established access-control pattern such as Ownable or AccessControl, as the design requires. "
        "Do not recommend address(this).balance, assert(), or unrelated checks as replacements for authorization. "
        "For Solidity address.call(data), explain that it returns a success boolean and return-data bytes. A reverted call normally makes success false; return data alone does not indicate success. "
        "Mention checks-effects-interactions or a reentrancy guard only when the surrounding control flow warrants it. "
        "Do not change the scanner severity, and distinguish detected patterns from confirmed issues. "
        "Keep the explanation concise and grounded in the provided evidence.\n\nFINDINGS:\n"
        + json.dumps(summary, ensure_ascii=False)
        + "\n\nSOURCE CONTEXT (line-numbered excerpts; may be incomplete):\n"
        + context_text
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
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("OPENMINION_TIMEOUT_SECONDS", "150")),
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")

        lower_output = output.lower()
        quota_markers = (
            "free-models-per-day",
            "rate limit exceeded",
            "rate limited",
            "quota",
            "billing",
            "provider could not continue",
        )

        if any(marker in lower_output for marker in quota_markers):
            print("\nAI explanation unavailable: the model provider reported a quota, billing, or rate-limit problem.", file=sys.stderr)
            print("The scanner findings above are still available. Retry when a model is available.", file=sys.stderr)
            return 1

        if result.returncode != 0:
            print("AI explanation failed: OpenMinion exited with a non-zero status.", file=sys.stderr)
            print("The deterministic scanner report remains available.", file=sys.stderr)
            return 1

        print("\n========== OPENMINION EXPLANATION =========")
        print("OpenMinion returned successfully; review the output above for the explanation.")
        return 0
    except subprocess.TimeoutExpired:
        print("OpenMinion timed out. Check model availability or adjust OPENMINION_TIMEOUT_SECONDS.", file=sys.stderr)
        print("The deterministic report remains available.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"OpenMinion unavailable: {type(exc).__name__}: {exc}", file=sys.stderr)
        print("The deterministic report remains available.", file=sys.stderr)
        return 1



def build_local_explanations(report: dict) -> list:
    """Build structured, predefined explanations for JSON reports."""
    explanations = []

    for finding in report.get("findings", []):
        rule = str(
            finding.get("rule")
            or finding.get("rule_id")
            or finding.get("id")
            or "UNKNOWN"
        )
        message = (
            finding.get("message")
            or finding.get("description")
            or finding.get("title")
            or "No additional description supplied."
        )

        if rule == "SOL005" or "tx.origin" in str(message).lower():
            risk = (
                "tx.origin identifies the transaction originator, not the "
                "immediate caller. Using it for authorization can be unsafe."
            )
            recommendation = (
                "Review the authorization design. Use msg.sender for direct-caller "
                "checks where appropriate, or an established access-control pattern."
            )
        elif rule == "SOL002" or "low-level" in str(message).lower():
            risk = (
                "Low-level calls transfer control to another address. Incorrect "
                "success handling or state-update ordering may introduce risks."
            )
            recommendation = (
                "Check the success boolean and handle return data when appropriate. "
                "Review external-call ordering and surrounding state changes."
            )
        else:
            risk = "The detected pattern needs review in the context of the full contract."
            recommendation = (
                "Inspect the relevant source code and scanner rule documentation. "
                "This tool has no specialised explanation for this rule."
            )

        explanations.append({
            "rule": rule,
            "severity": finding.get("severity", "UNSPECIFIED"),
            "line": finding.get("line"),
            "detected": message,
            "possible_risk": risk,
            "recommendation": recommendation,
        })

    return explanations


def export_json_report(report: dict, output_path: str) -> None:
    """Save the scanner report and local explanations as JSON."""
    import json

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    data = dict(report)
    data["tool"] = "Cortensor Security Assistant"
    data["report_type"] = "Pattern-based Solidity screening"
    data["finding_count"] = len(report.get("findings", []))
    data["notice"] = NOTICE
    data["local_explanations"] = build_local_explanations(report)

    destination.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"JSON report saved to: {destination}")


def print_local_explanation(report: dict) -> None:
    """Explain known scanner rules locally without an AI provider."""
    findings = report.get("findings", [])

    print("\n========== LOCAL RULE-BASED EXPLANATION ==========")
    print("These explanations use predefined guidance, not an AI audit.")
    print("Findings are indicators for manual review, not proof of vulnerabilities.")

    if not findings:
        print("\nNo findings were reported by the scanner.")
        return

    for finding in findings:
        rule = str(
            finding.get("rule")
            or finding.get("rule_id")
            or finding.get("id")
            or "UNKNOWN"
        )
        severity = finding.get("severity", "UNSPECIFIED")
        line = finding.get("line", "?")
        message = (
            finding.get("message")
            or finding.get("description")
            or finding.get("title")
            or "No additional description supplied."
        )

        print(f"\n{rule} — {severity} — line {line}")
        print(f"Detected: {message}")

        if rule == "SOL005" or "tx.origin" in str(message).lower():
            print(
                "Possible risk: tx.origin identifies the transaction originator, "
                "not the immediate caller. Using it for authorization can be unsafe "
                "in contract-interaction scenarios."
            )
            print(
                "Recommendation: Review the intended authorization design. "
                "Use msg.sender for direct-caller checks where appropriate, "
                "or an established access-control pattern suited to the contract."
            )

        elif rule == "SOL002" or "low-level" in str(message).lower():
            print(
                "Possible risk: Low-level calls transfer control to another address. "
                "Incorrect success handling or state-update ordering may introduce risks."
            )
            print(
                "Recommendation: Check the call's success boolean and handle return data "
                "when appropriate. Review the surrounding state changes and external-call "
                "ordering for reentrancy risk; a low-level call alone does not prove reentrancy."
            )

        else:
            print(
                "Recommendation: Inspect the relevant source code and the scanner rule "
                "documentation. This local mode has no specialised explanation for this rule."
            )

    print(
        "\nImportant: This is predefined guidance, not a complete security audit. "
        "Verify each finding against the full contract and its intended behavior."
    )

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
    parser.add_argument(
        "--local-explanation",
        action="store_true",
        help="Show predefined local explanations without using AI",
    )
    parser.add_argument(
        "--json-output",
        metavar="PATH",
        help="Save the scan report and local explanations to a JSON file",
    )
    args = parser.parse_args()

    try:
        report = scan_file(args.file)
    except (OSError, UnicodeError) as exc:
        print(f"Cannot read Solidity file: {exc}", file=sys.stderr)
        return 2

    print("========== CORTENSOR SECURITY ASSISTANT ==========")
    print_report(report)

    if args.json_output:
        try:
            export_json_report(report, args.json_output)
        except (OSError, TypeError, ValueError) as exc:
            print(f"Could not export JSON report: {exc}", file=sys.stderr)
            return 2

    if args.local_explanation:
        print_local_explanation(report)
        return 0

    if args.ai:
        with open(args.file, encoding="utf-8") as file:
            source_code = file.read()
        return run_ai_explanation(source_code, report)

    print("\nAI explanation skipped. Use --ai to try OpenMinion.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
