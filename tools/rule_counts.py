"""Per-rule finding counts for one or more findings.json files, side by side.

    poetry run python tools/rule_counts.py before.json after.json
"""

import json
import sys
from collections import Counter


def main(paths: list[str]) -> None:
    counts = [Counter(f["rule_id"] for f in json.load(open(p))["findings"]) for p in paths]
    rules = sorted(set().union(*counts), key=lambda r: -max(c[r] for c in counts))
    width = max(len(r) for r in rules)
    print(f"{'rule':{width}} " + " ".join(f"{p[-12:]:>12}" for p in paths))
    for rule in rules:
        print(f"{rule:{width}} " + " ".join(f"{c[rule]:12}" for c in counts))
    print(f"{'total':{width}} " + " ".join(f"{sum(c.values()):12}" for c in counts))


if __name__ == "__main__":
    main(sys.argv[1:])
