# Ghost Data Still Exists solution

## Current implementation

This is an experimental, deterministic first pass with:
- timestamp-aware evidence normalization for JSON, SQL, text/logs, PDFs, and OCR-capable images;
- current and historical identity resolution;
- deletion policy mapping, resource state classification, and remediation/verification planning;
- strict CSV/JSON output validation;
- contract, parser, intent, and planner tests; and
- a public-sample evaluator.

This is **not yet submission-ready** until the GitHub Actions run is green and the public-sample results have been reviewed. Treat scores as a development diagnostic and improve systematic rules rather than hard-coding case IDs.

## Run from the repository root

Install Python dependencies:
\`\`\`bash
python -m pip install -r code/requirements.txt
\`\`\`

For OCR of screenshot evidence, install the system Tesseract binary as well (for example, \`sudo apt-get install tesseract-ocr\` on Ubuntu).

Run the pipeline and checks:
\`\`\`bash
PYTHONPATH=code python -m unittest discover -s code/tests -v
PYTHONPATH=code python -m unittest discover -s code/evaluation -p "test_*.py" -v
python code/main.py
python code/main.py --validate-only
python code/evaluation/main.py --predictions output.csv --json
\`\`\`

Inputs are read from the provided \`dataset/\` folder and the generated output is written to root-level \`output.csv\`. The code makes no model API calls.
