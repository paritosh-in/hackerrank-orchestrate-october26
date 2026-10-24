# Evaluation Report

## Current milestone
Output contract validation and sample comparison are implemented. The evidence-grounded prediction engine is not yet implemented, so no accuracy result is claimed.

## Metrics
The evaluator reports sample coverage, status accuracy, exact-case accuracy, exact step arrays, step-field accuracy, and sequence accuracy. Run `python3 code/evaluation/main.py --predictions output.csv --json` when a prediction file exists.

## Additional evaluation cases
1. **Historical identifier:** a request uses an old email that maps to a current stable user ID through an audit record. Evidence under current and historical identifiers must be considered.
2. **Replica drift:** a primary profile is absent but a read-replica snapshot captured before audit time still contains the record. The case must be incomplete.
3. **Recreation path:** a connector remains enabled at audit time. The plan must disable the connector before deleting dependent copies and verifying.

These are test specifications and must be implemented as executable fixtures in a later milestone.

## Failures and improvements
- Do not trust reported workflow status or activity result as proof: reconstruct state from timestamped evidence.
- Use a fixed operation vocabulary, evidence validation, and deterministic ordering to avoid malformed output.
- Implement identity history and parsing across structured records, logs, SQL, PDFs, and screenshots before making final predictions.

## Final-run metrics
Not available yet. Populate this section after the complete 518-row output is generated and validated.
