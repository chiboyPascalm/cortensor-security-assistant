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

OpenMinion generated explanations and recommendations for both findings. The scanner tests also passed: all 16 unit tests succeeded.

## OpenMinion integration

The optional AI mode passes the scanner findings to the configured OpenMinion CLI for plain-language explanations and suggested mitigations. In the current implementation, OpenMinion prints its response directly to the terminal; the application does not save that response to a report file.

## Limitations and lessons learned

This is a prototype for pattern-based Solidity screening, not a complete audit or proof of security. Pattern matches may be false positives, vulnerabilities may be missed, and AI recommendations may be inaccurate. Findings require manual review and additional security testing. The deterministic scanner identifies candidate patterns; OpenMinion provides supplementary explanations rather than independently validating vulnerabilities.

## Hackathon
This prototype explores using the OpenMinion SDK to explain Solidity scanner findings.

## Usage

Run the scanner:

    .venv/bin/python app.py

Show local explanations:

    .venv/bin/python app.py --local-explanation

Export a JSON report:

    .venv/bin/python app.py --json-output reports/sample-report.json

Run the tests:

    .venv/bin/python -m unittest discover -s tests -v

## Building Blocks Tested

- **Solidity pattern scanner:** Tested detection of `tx.origin`, possible `tx.origin` authorization checks, low-level `.call(...)`, `delegatecall`, and `selfdestruct` patterns.
- **Comment and string filtering:** Tests verify that supported patterns inside comments and quoted strings are ignored.
- **Local explanations:** Verified predefined explanations and recommendations for detected findings without requiring an external model.
- **JSON reports:** Automated tests cover valid JSON export, zero findings, local explanations, and the safety notice.
- **OpenMinion integration:** The application invokes OpenMinion in AI mode. During the latest demonstration, the configured model provider rejected the request because its free-model daily quota was exceeded.
- **Automated tests:** All 16 tests passed in the latest recorded test run.

## What We Learned

- Pattern-based scanning can highlight code that deserves review, but a pattern match does not establish that a vulnerability exists.
- A clean scan does not prove a smart contract is secure.
- Low-level calls require review of success handling, access controls, external-call ordering, and possible reentrancy. Detecting a call alone does not prove that these issues exist.
- Predefined local explanations allow the prototype to provide guidance even when an external model is unavailable.
- AI features depend on the configured model provider's availability and usage limits. Provider failures must be reported honestly without hiding the scanner's results.
- Further development should improve Solidity syntax and control-flow analysis, expand the test suite, and verify AI-generated recommendations against the actual contract.
