# Cortensor Security Assistant

A Solidity smart-contract screening prototype combining deterministic pattern detection with optional AI explanations using the OpenMinion SDK.

## Features
- Detects potentially risky Solidity patterns.
- Reports rule IDs, severity, line numbers, and recommendations.
- Ignores patterns inside comments and quoted strings.
- Supports optional AI-assisted explanations.

## Detection rules
- SOL001: `tx.origin` usage — HIGH
- SOL002: Low-level `.call(...)` — REVIEW
- SOL003: `delegatecall(...)` — HIGH
- SOL004: `selfdestruct(...)` — REVIEW
- SOL005: Possible `tx.origin` authorization check — HIGH

## Usage
Run the sample scan:
` .venv/bin/python app.py `

Scan a Solidity file:
` .venv/bin/python app.py path/to/Contract.sol `

Run AI explanation:
` .venv/bin/python app.py --ai `

Run tests:
` .venv/bin/python -m unittest discover -s tests -v `

## Limitations
This is an early-stage pattern scanner, not a full smart-contract audit. Findings may be false positives or miss vulnerabilities. AI explanations may contain errors. Human review and additional security testing are required.

## Hackathon
This prototype explores using the OpenMinion SDK to explain Solidity scanner findings.
