# Evaluation Report

## Milestone status
The output contract validator and sample evaluator are implemented. The evidence-based prediction engine is not implemented yet, so no full-dataset accuracy claim is made.

## Metrics
Run `python3 code/evaluation/main.py --predictions output.csv` after predictions are generated. It reports prediction coverage, status accuracy, exact-case accuracy, exact step arrays, step-field accuracy, and sequence accuracy.

## Additional evaluation cases (planned)
1. **Historical identifier:** the request uses an old email, and a timestamped identity audit links it to the current stable user ID. Evidence under either identifier must be considered.
2. **Replica drift:** the primary record is absent but a read-replica snapshot before `audit_at` still contains the record; status must remain incomplete.
3. **Recreation path:** a related connector remains enabled at `audit_at`; remediation must disable it before downstream deletion and verification.

These cases are currently specifications, not yet executable test fixtures.

## Failures and improvements
- Risk: trusting reported workflow statuses. Improvement: use participant-visible evidence, time-filtered at `audit_at`.
- Risk: unsupported operation names or bad ordering. Improvement: fixed operation vocabulary and contract validation.
- Risk: missing historical identifiers and secondary data copies. Improvement: build an evidence index and parsers for structured files, logs, SQL snapshots, PDFs and screenshots.

## Final full-dataset result
Not available yet. Populate after generating and validating the 518-row output.
