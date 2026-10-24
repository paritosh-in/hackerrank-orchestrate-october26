# Ghost Data Still Exists solution

The initial slice implements the exact output schema, allowed operation vocabulary,
step ordering checks, and a public-sample comparison utility. The prediction engine
is not yet connected and intentionally fails rather than fabricating results.

From the repository root:
```bash
python3 code/main.py
python3 code/main.py --validate-only
python3 code/evaluation/main.py --predictions output.csv
python3 -m unittest discover -s code/tests
```

All inputs must come from the participant-facing `dataset/` directory. The final
program must write root-level `output.csv`. No model APIs are called in this slice.
