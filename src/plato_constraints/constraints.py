"""Constraint engine — rules, validators, scoring, and dependency resolution."""
import time
import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Any
from enum import Enum
from collections import defaultdict

class ConstraintSeverity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"

class ConstraintStatus(Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    PENDING = "pending"

@dataclass
class ConstraintResult:
    constraint_id: str
    status: ConstraintStatus
    severity: ConstraintSeverity
    message: str = ""
    score: float = 1.0
    checked_at: float = field(default_factory=time.time)
    details: dict = field(default_factory=dict)

@dataclass
class Constraint:
    id: str
    name: str
    check_fn: str = ""  # reference to registered checker
    severity: ConstraintSeverity = ConstraintSeverity.ERROR
    depends_on: list[str] = field(default_factory=list)
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

class ConstraintEngine:
    def __init__(self):
        self._constraints: dict[str, Constraint] = {}
        self._checkers: dict[str, Callable] = {}
        self._results: dict[str, list[ConstraintResult]] = {}
        self._score_cache: dict[str, float] = {}
        self._evaluation_order: list[str] = []

    def add(self, constraint_id: str, name: str, severity: str = "error",
            depends_on: list[str] = None, tags: list[str] = None) -> Constraint:
        sev = ConstraintSeverity(severity.lower())
        c = Constraint(id=constraint_id, name=name, severity=sev,
                      depends_on=depends_on or [], tags=tags or [])
        self._constraints[constraint_id] = c
        return c

    def register_checker(self, name: str, fn: Callable):
        self._checkers[name] = fn

    def evaluate(self, data: dict = None, constraint_ids: list[str] = None) -> list[ConstraintResult]:
        data = data or {}
        order = self._resolve_order(constraint_ids)
        results = []
        for cid in order:
            c = self._constraints.get(cid)
            if not c or not c.enabled:
                results.append(ConstraintResult(cid, ConstraintStatus.SKIP,
                                              ConstraintSeverity.INFO, "Disabled or not found"))
                continue
            # Check dependencies
            dep_failed = False
            for dep in c.depends_on:
                dep_results = [r for r in results if r.constraint_id == dep]
                if dep_results and dep_results[0].status == ConstraintStatus.FAIL:
                    dep_failed = True
                    break
            if dep_failed:
                results.append(ConstraintResult(cid, ConstraintStatus.SKIP,
                                              ConstraintSeverity.INFO, "Dependency failed"))
                continue
            # Run checker
            checker = self._checkers.get(c.check_fn)
            if checker:
                try:
                    passed, message, score = checker(data)
                    status = ConstraintStatus.PASS if passed else ConstraintStatus.FAIL
                    results.append(ConstraintResult(cid, status, c.severity, message, score))
                except Exception as e:
                    results.append(ConstraintResult(cid, ConstraintStatus.FAIL,
                                                  ConstraintSeverity.ERROR, str(e), 0.0))
            else:
                results.append(ConstraintResult(cid, ConstraintStatus.PENDING,
                                              ConstraintSeverity.INFO, "No checker registered"))
        self._cache_results(results)
        return results

    def _resolve_order(self, ids: list[str] = None) -> list[str]:
        """Topological sort of constraints by dependencies."""
        targets = set(ids) if ids else set(self._constraints.keys())
        visited = set()
        order = []
        def visit(cid):
            if cid in visited or cid not in targets:
                return
            visited.add(cid)
            c = self._constraints.get(cid)
            if c:
                for dep in c.depends_on:
                    visit(dep)
            order.append(cid)
        for cid in sorted(targets):
            visit(cid)
        return order

    def _cache_results(self, results: list[ConstraintResult]):
        for r in results:
            if r.constraint_id not in self._results:
                self._results[r.constraint_id] = []
            self._results[r.constraint_id].append(r)
        # Keep last 100 per constraint
        for cid in self._results:
            self._results[cid] = self._results[cid][-100:]

    def score(self, constraint_ids: list[str] = None) -> float:
        """Overall compliance score (0.0-1.0)."""
        ids = constraint_ids or list(self._constraints.keys())
        total = len(ids)
        if total == 0:
            return 1.0
        passing = 0
        for cid in ids:
            history = self._results.get(cid, [])
            if not history:
                continue
            latest = history[-1]
            if latest.status == ConstraintStatus.PASS:
                passing += 1
        return passing / total

    def failures(self) -> list[ConstraintResult]:
        results = []
        for cid, hist in self._results.items():
            for r in hist:
                if r.status == ConstraintStatus.FAIL:
                    results.append(r)
        results.sort(key=lambda r: r.checked_at, reverse=True)
        return results[:50]

    def history(self, constraint_id: str, n: int = 10) -> list[ConstraintResult]:
        return self._results.get(constraint_id, [])[-n:]

    def enable(self, cid: str):
        c = self._constraints.get(cid)
        if c: c.enabled = True

    def disable(self, cid: str):
        c = self._constraints.get(cid)
        if c: c.enabled = False

    def by_tag(self, tag: str) -> list[Constraint]:
        return [c for c in self._constraints.values() if tag in c.tags]

    @property
    def stats(self) -> dict:
        return {"constraints": len(self._constraints), "checkers": len(self._checkers),
                "evaluated": len(self._results), "compliance": round(self.score(), 3)}
