# Deletion audit agent

## Run

From the repository root with Python 3.10+:

```bash
python3 code/main.py
python3 code/evaluation/main.py
```

The main command reads participant-facing files from `dataset/`, writes `output.csv` at the repository root, and validates the output contract. Optional PDF extraction uses `pypdf`; optional image OCR uses `Pillow` and `pytesseract` plus a local Tesseract installation. Core CSV, JSON, log, and SQLite-compatible SQL parsing uses the Python standard library.

To use another dataset/output location:

```bash
python3 code/main.py /path/to/dataset /path/to/output.csv
python3 code/evaluation/main.py /path/to/dataset
```

## Design

The pipeline reconstructs identity aliases from the current identity snapshot and historical audit log, parses evidence into resource-level observations, filters evidence by `audit_at`, applies policy-based remediation, sorts steps by phase/operation/system/resource, and validates the output schema. Workflow-reported status is not treated as proof.

This is a first deterministic baseline. Review the generated public-sample evaluation report and improve evidence coverage before treating output as submission-ready. No organizer-only data or hidden labels are used.
