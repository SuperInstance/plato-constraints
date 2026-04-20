"""Constraint assertion engine with forbidden patterns."""

import re
from dataclasses import dataclass

@dataclass
class ConstraintResult:
    passed: bool
    constraint: str
    message: str
    severity: str = "warning"

class ConstraintEngine:
    def __init__(self):
        self._constraints: list[dict] = []
        self._forbidden: list[tuple[str, re.Pattern]] = []

    def add_constraint(self, name: str, check_fn, severity: str = "warning"):
        self._constraints.append({"name": name, "fn": check_fn, "severity": severity})

    def add_forbidden(self, name: str, pattern: str):
        self._forbidden.append((name, re.compile(pattern, re.IGNORECASE)))

    def check(self, content: str) -> list[ConstraintResult]:
        results = []
        for c in self._constraints:
            try:
                passed, msg = c["fn"](content)
                results.append(ConstraintResult(passed, c["name"], msg, c["severity"]))
            except Exception as e:
                results.append(ConstraintResult(False, c["name"], str(e), "error"))
        for name, pattern in self._forbidden:
            if pattern.search(content):
                results.append(ConstraintResult(False, f"forbidden:{name}",
                    f"Forbidden pattern '{name}' found", "error"))
        return results

    def check_all(self, items: list[str]) -> list[list[ConstraintResult]]:
        return [self.check(item) for item in items]

    def validate(self, content: str) -> bool:
        return all(r.passed for r in self.check(content))

    @property
    def stats(self) -> dict:
        return {"constraints": len(self._constraints), "forbidden_patterns": len(self._forbidden)}

# Built-in constraint factories
def max_length(n: int):
    def check(content):
        return (len(content) <= n, f"Length {len(content)} <= {n}")
    return check

def min_length(n: int):
    def check(content):
        return (len(content) >= n, f"Length {len(content)} >= {n}")
    return check

def contains_any(terms: list[str], case_insensitive: bool = True):
    flags = re.IGNORECASE if case_insensitive else 0
    patterns = [re.compile(t, flags) for t in terms]
    def check(content):
        found = [t for t, p in zip(terms, patterns) if p.search(content)]
        return (len(found) > 0, f"Contains: {', '.join(found)}")
    return check

def confidence_range(lo: float = 0.0, hi: float = 1.0):
    def check(confidence):
        return (lo <= confidence <= hi, f"Confidence {confidence} in [{lo}, {hi}]")
    return check
