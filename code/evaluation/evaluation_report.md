# Evaluation Report

## Current milestone
A first-pass deterministic prediction pipeline is wired into the CLI. It includes evidence normalization for JSON, SQL, text/logs, identity resolution, rule-driven planning, output validation, and public sample comparison. This version has not yet been executed locally against the sample output, so no accuracy result is claimed.

## Metrics
After running the code:
```bash
python3 code/evaluation/main.py --predictions output.csv --json
```
Review status accuracy, exact-case accuracy, exact step arrays, step-field accuracy, and sequence accuracy. The public sample file is development ground truth; do not hard-code its case answers.

## Additional evaluation cases created
1. A direct English deletion request must be authorized.
2. A marketing-only unsubscribe is not a deletion request.
3. A data-access/export request is not a deletion request.
4. A Spanish permanent account deletion request must be recognized.

Run with `python3 -m unittest discover -s code/evaluation`.

## Known limitations and planned improvements
- PDF and screenshot evidence need dedicated parsers/readers.
- Intent detection uses phrase matching and needs full multilingual and negation coverage.
- The planner still needs resource join and state-transition refinement, policy exception handling, and regression review across all 32 sample cases.
- Absence of matching evidence must not automatically be treated as proof of deletion.
- Confirm that every selected fact is timestamped at or before the case `audit_at`, and do not rely on reported workflow state.
