# Demo Runbook

## Preparation

- Run commands from the project root.
- Use the included sample contract for repeatable results.
- Never display API keys, `.env` files, or private configuration.
- The configured model provider recently returned a free-model daily quota error. Use local explanation mode for the reliable demonstration unless AI mode has been successfully re-tested.

## Suggested 2–3 Minute Demonstration

1. Introduce Cortensor Security Assistant as a Solidity pattern-screening prototype with local explanations and optional OpenMinion integration.
2. Run `.venv/bin/python app.py` to demonstrate deterministic scanning.
3. Highlight SOL005 (HIGH, line 12) and SOL002 (REVIEW, line 17).
4. Run `.venv/bin/python app.py --local-explanation` to show predefined explanations and recommendations without relying on an external model.
5. Run `.venv/bin/python -m unittest discover -s tests -v` to demonstrate the 16 passing tests.
6. Briefly explain that AI mode invokes OpenMinion, but the configured model provider rejected the latest request because its free-model daily quota was exceeded.
7. Explain the limitations: findings require manual review, local explanations are predefined guidance, AI output can be inaccurate, and this prototype does not replace a full security audit.

## Important Notes

- A pattern match does not prove a vulnerability.
- A clean scan does not prove a contract is secure.
- Review low-level calls in their full context, including success handling and external-call ordering.
- Verify recommendations against the actual contract and established security guidance.
- Do not claim successful AI-generated explanations unless a fresh run confirms them.
- Keep credentials and private configuration off-screen.
