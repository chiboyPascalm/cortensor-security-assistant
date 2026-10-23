"""Pattern-based Solidity source screening for Cortensor Security Assistant."""

import re
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    severity: str
    rule: str
    line: int
    message: str
    recommendation: str


RULES = [
    {
        "id": "SOL001",
        "pattern": r"\btx\.origin\b",
        "severity": "HIGH",
        "message": "tx.origin is used and may create an unsafe authorization pattern.",
        "recommendation": "Prefer msg.sender with appropriate access-control checks.",
    },
    {
        "id": "SOL002",
        "pattern": r"\.call\s*(?:\{[^}]*\}\s*)?\(",
        "severity": "REVIEW",
        "message": "A low-level external call was detected.",
        "recommendation": (
            "Review return-value handling, access controls, and reentrancy protections."
        ),
    },
    {
        "id": "SOL003",
        "pattern": r"\bdelegatecall\s*\(",
        "severity": "HIGH",
        "message": "delegatecall executes code in the caller's storage context.",
        "recommendation": (
            "Verify the target address and authorization; avoid untrusted targets."
        ),
    },
    {
        "id": "SOL004",
        "pattern": r"\bselfdestruct\s*\(",
        "severity": "REVIEW",
        "message": (
            "selfdestruct was detected; behavior depends on Solidity version and context."
        ),
        "recommendation": (
            "Review whether this operation is intended and safely controlled."
        ),
    },
    {
        "id": "SOL005",
        "pattern": r"\btx\.origin\b[^;\n]*==|==[^;\n]*\btx\.origin\b",
        "severity": "HIGH",
        "message": (
            "tx.origin appears in an equality check, possibly for authorization."
        ),
        "recommendation": (
            "Use explicit role-based or owner-based authorization instead."
        ),
    },
]


def _mask_comments_and_strings(source: str) -> str:
    """Mask comments and quoted strings while preserving offsets and line numbers."""
    chars = list(source)
    i = 0
    n = len(source)

    def mask(start: int, end: int) -> None:
        for pos in range(start, end):
            if chars[pos] != "\n":
                chars[pos] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            if end == -1:
                end = n
            mask(i, end)
            i = end
            continue

        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end == -1 else end + 2
            mask(i, end)
            i = end
            continue

        if source[i] in ("'", '"'):
            quote = source[i]
            start = i
            i += 1

            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1

            mask(start, min(i, n))
            continue

        i += 1

    return "".join(chars)


def scan_solidity(source: str) -> list[dict]:
    """Return potential risk-pattern findings; this is not a complete audit."""
    cleaned = _mask_comments_and_strings(source)
    findings = []

    for rule in RULES:
        for match in re.finditer(rule["pattern"], cleaned, flags=re.M):
            line = cleaned.count("\n", 0, match.start()) + 1
            findings.append(
                asdict(
                    Finding(
                        severity=rule["severity"],
                        rule=rule["id"],
                        line=line,
                        message=rule["message"],
                        recommendation=rule["recommendation"],
                    )
                )
            )

    # SOL005 is the more specific finding for tx.origin in an equality check.
    specific_lines = {
        item["line"]
        for item in findings
        if item["rule"] == "SOL005"
    }
    findings = [
        item
        for item in findings
        if not (
            item["rule"] == "SOL001"
            and item["line"] in specific_lines
        )
    ]

    findings.sort(key=lambda item: (item["line"], item["rule"]))
    return findings


def scan_file(path: str) -> dict:
    """Scan one Solidity file and return a JSON-serializable report."""
    with open(path, encoding="utf-8") as file:
        source = file.read()

    findings = scan_solidity(source)

    return {
        "file": path,
        "finding_count": len(findings),
        "notice": (
            "Pattern-based screening only. Findings require manual review; "
            "this tool does not establish that a contract is secure or vulnerable."
        ),
        "findings": findings,
    }
