# Ghost Data Still Exists solution

## Status
Initial implementation slice: strict output-contract validation and public sample evaluator are in place. The evidence-based prediction engine is intentionally not wired up yet; the entry point fails explicitly rather than fabricating answers.

## Run from repository root
```bash
python3 code/main.py
```

Validate an already-generated root-level output:
```bash
python3 code/main.py --validate-only
```

Evaluate predictions against the public sample:
```bash
python3 code/evaluation/main.py --predictions output.csv
```

The solution uses participant-facing files under `dataset/`. No model API is called in this milestone.
