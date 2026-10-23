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


## Verified demonstration

The included `samples/vulnerable_example.sol` produced two findings in the demonstrated run:

- **SOL005 — HIGH, line 12:** `tx.origin` appears in an equality check that may be used for authorization.
- **SOL002 — REVIEW, line 17:** A low-level external call was detected.

OpenMinion generated explanations and recommendations for both findings. The scanner tests also passed: all 11 unit tests succeeded.

## OpenMinion integration

The optional AI mode passes the scanner findings to the configured OpenMinion CLI for plain-language explanations and suggested mitigations. In the current implementation, OpenMinion prints its response directly to the terminal; the application does not save that response to a report file.

## Limitations and lessons learned

This is a prototype for pattern-based Solidity screening, not a complete audit or proof of security. Pattern matches may be false positives, vulnerabilities may be missed, and AI recommendations may be inaccurate. Findings require manual review and additional security testing. The deterministic scanner identifies candidate patterns; OpenMinion provides supplementary explanations rather than independently validating vulnerabilities.

## Hackathon
This prototype explores using the OpenMinion SDK to explain Solidity scanner findings.
