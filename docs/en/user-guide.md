# User guide

Install the released report-contract dependency before this wheel. Explicit --format neutral-json-v1 is mandatory. Output files must not exist. Codes: 0 passes/inapplicable, 1 failure, 2 incomplete evidence without failures, 3 invalid input/output. Unsupported format is an argparse usage error (2), not a coverage assessment. Inspection is offline; no DNS or device connection is performed.

```bash
python -m pip install -r requirements-bootstrap.txt
python -m pip install .
network-audit examples/safe.synthetic.json --format neutral-json-v1 --observed-at 2026-10-12T00:00:00Z --output report.json
opsec-report validate report.json
opsec-report html report.json --output report.html
```

[Index](index.md)
