# Demo Runbook

## Preparation
- Run from the project root.
- Confirm OpenMinion AI mode works before recording.
- Never display API keys, `.env` files, or private configuration.
- Use the included sample contract for repeatable results.

## Suggested 2–3 minute demonstration

1. Introduce Cortensor Security Assistant as a Solidity pattern-screening prototype with optional OpenMinion explanations.
2. Run `.venv/bin/python app.py` to show the deterministic scan.
3. Highlight SOL005 at line 12 and SOL002 at line 17.
4. Run `.venv/bin/python -m unittest discover -s tests -v` to show the 11 passing tests.
5. Run `.venv/bin/python app.py --ai` to demonstrate OpenMinion explanations and recommendations.
6. Explain that the AI response is printed to the terminal and is not saved to a report file.
7. Finish by explaining the limitations: findings require manual review, AI output can be wrong, and the prototype does not replace a full audit.

## Important notes
- A pattern match does not prove a vulnerability.
- A clean scan does not prove a contract is secure.
- Check AI recommendations against the actual contract and established security guidance.
- Keep credentials and private configuration off-screen.
