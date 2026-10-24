# Ghost Data Still Exists solution

## Current implementation

The branch contains a first-pass deterministic pipeline with:
- timestamp-aware evidence normalization for JSON, SQL, log, and text files;
- current and historical identity resolution;
- an initial policy-driven deletion planner;
- strict CSV/JSON output validation; and
- a public sample evaluator and intent regression tests.

**This is not yet submission-ready.** PDF and image parsing, nuanced policy handling, broad sample validation, and execution/testing in a local worktree remain.

## Run from repository root

```bash
python3 code/main.py
python3 code/main.py --validate-only
python3 code/evaluation/main.py --predictions output.csv --json
python3 -m unittest discover -s code/tests
python3 -m unittest discover -s code/evaluation
```

The runner reads participant-facing inputs under `dataset/` and writes root-level `output.csv`. It makes no model API calls.
