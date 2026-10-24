# Evaluation Report

## Current milestone
The branch contains an evidence normalizer, historical identity resolver, initial rule-driven planner, output contract validator, and public-sample evaluator. The planner is a first pass and must be tested against all 32 public sample cases before being considered submission-ready.

## Metrics
Run:
```bash
python3 code/evaluation/main.py --predictions output.csv --json
```
The evaluator reports sample coverage, status accuracy, exact-case accuracy, exact step arrays, step-field accuracy, and sequence accuracy.

## Additional cases created
1. A direct English deletion request is authorized.
2. A marketing-only unsubscribe is not a deletion request.
3. A user data export/access request is not a deletion request.
4. A Spanish permanent account deletion request is authorized.

Run with `python3 -m unittest discover -s code/evaluation`.

## Known limitations and improvements
- PDF and screenshot evidence are not parsed by the initial normalizer.
- Intent detection uses phrase matching and needs fuller multilingual coverage.
- The planner needs test-driven refinement for policy exceptions, resource joins, timestamp cutoffs, and whether lack of matching evidence can prove absence.
- Never infer state from the reported workflow status; use evidence timestamped at or before each case's `audit_at`.
