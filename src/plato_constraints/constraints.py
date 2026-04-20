"""Constraint engine — rules, validators, scoring, dependency resolution, and batch evaluation."""
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
    duration_ms: float = 0.0

@dataclass
class Constraint:
    id: str
    name: str
    check_fn: str = ""
    severity: ConstraintSeverity = ConstraintSeverity.ERROR
    depends_on: list[str] = field(default_factory=list)
    enabled: bool = True
    tags: list[str] = field(default_factory=list)
    timeout_ms: float = 5000.0
    retry_count: int = 0
    max_retries: int = 0
    weight: float = 1.0  # weight in aggregate scoring

@dataclass
class ValidationReport:
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    score: float = 0.0  # 0.0-1.0 weighted aggregate
    duration_ms: float = 0.0
    results: list[ConstraintResult] = field(default_factory=list)

class ConstraintEngine:
    def __init__(self, fail_fast: bool = False):
        self._constraints: dict[str, Constraint] = {}
        self._checkers: dict[str, Callable] = {}
        self._results: dict[str, ConstraintResult] = {}
        self._dependency_graph: dict[str, list[str]] = defaultdict(list)
        self._reverse_deps: dict[str, list[str]] = defaultdict(list)
        self.fail_fast = fail_fast
        self._execution_log: list[dict] = []

    def add(self, constraint: Constraint):
        self._constraints[constraint.id] = constraint
        for dep in constraint.depends_on:
            self._dependency_graph[constraint.id].append(dep)
            self._reverse_deps[dep].append(constraint.id)

    def register_checker(self, name: str, fn: Callable):
        self._checkers[name] = fn

    def check_circular_deps(self) -> list[list[str]]:
        """Detect circular dependency chains using DFS."""
        visited = set()
        path = []
        cycles = []
        def dfs(node):
            if node in path:
                cycle_start = path.index(node)
                cycles.append(path[cycle_start:] + [node])
                return
            if node in visited:
                return
            visited.add(node)
            path.append(node)
            for dep in self._dependency_graph.get(node, []):
                dfs(dep)
            path.pop()
        for cid in self._constraints:
            visited.clear()
            dfs(cid)
        return cycles

    def topological_order(self) -> list[str]:
        """Return constraints in dependency order."""
        visited = set()
        order = []
        def visit(cid):
            if cid in visited:
                return
            visited.add(cid)
            for dep in self._dependency_graph.get(cid, []):
                visit(dep)
            order.append(cid)
        for cid in self._constraints:
            visit(cid)
        return order

    def validate(self, context: dict = None) -> ValidationReport:
        if context is None:
            context = {}
        report = ValidationReport()
        report.total = sum(1 for c in self._constraints.values() if c.enabled)
        start = time.time()
        # Execute in topological order
        order = self.topological_order()
        for cid in order:
            constraint = self._constraints.get(cid)
            if not constraint or not constraint.enabled:
                report.skipped += 1
                continue
            # Check dependencies passed
            dep_failed = False
            for dep_id in constraint.depends_on:
                dep_result = self._results.get(dep_id)
                if dep_result and dep_result.status == ConstraintStatus.FAIL:
                    dep_failed = True
                    break
            if dep_failed:
                result = ConstraintResult(
                    constraint_id=cid, status=ConstraintStatus.SKIP,
                    severity=constraint.severity,
                    message=f"Skipped: dependency {dep_id} failed")
                report.skipped += 1
                self._results[cid] = result
                report.results.append(result)
                continue
            # Execute check
            check_start = time.time()
            last_error = ""
            status = ConstraintStatus.FAIL
            message = ""
            score = 0.0
            for attempt in range(constraint.max_retries + 1):
                try:
                    if constraint.check_fn and constraint.check_fn in self._checkers:
                        fn = self._checkers[constraint.check_fn]
                        check_result = fn(context)
                        if isinstance(check_result, bool):
                            status = ConstraintStatus.PASS if check_result else ConstraintStatus.FAIL
                            message = "Passed" if check_result else "Failed"
                            score = 1.0 if check_result else 0.0
                        elif isinstance(check_result, dict):
                            status = ConstraintStatus(check_result.get("status", "fail"))
                            message = check_result.get("message", "")
                            score = check_result.get("score", 0.0)
                        elif isinstance(check_result, ConstraintResult):
                            status = check_result.status
                            message = check_result.message
                            score = check_result.score
                        else:
                            status = ConstraintStatus.PASS
                            score = 1.0
                        break
                    else:
                        status = ConstraintStatus.SKIP
                        message = "No checker registered"
                        break
                except Exception as e:
                    last_error = str(e)
                    if attempt < constraint.max_retries:
                        time.sleep(0.1 * (attempt + 1))
                        continue
            result = ConstraintResult(
                constraint_id=cid, status=status, severity=constraint.severity,
                message=message or last_error, score=score,
                duration_ms=(time.time() - check_start) * 1000)
            self._results[cid] = result
            report.results.append(result)
            if status == ConstraintStatus.PASS:
                report.passed += 1
            elif status == ConstraintStatus.SKIP:
                report.skipped += 1
            else:
                report.failed += 1
                if constraint.severity == ConstraintSeverity.ERROR:
                    report.errors += 1
                elif constraint.severity == ConstraintSeverity.WARNING:
                    report.warnings += 1
                else:
                    report.infos += 1
            if self.fail_fast and status == ConstraintStatus.FAIL and constraint.severity == ConstraintSeverity.ERROR:
                break
        # Compute weighted score
        total_weight = sum(c.weight for c in self._constraints.values() if c.enabled)
        if total_weight > 0:
            report.score = sum(
                self._results[cid].score * self._constraints[cid].weight
                for cid in self._results
                if cid in self._constraints and self._constraints[cid].enabled
            ) / total_weight
        report.duration_ms = (time.time() - start) * 1000
        self._execution_log.append({"timestamp": time.time(), "report": report.total,
                                   "passed": report.passed, "failed": report.failed,
                                   "score": report.score})
        return report

    def validate_batch(self, contexts: list[dict]) -> list[ValidationReport]:
        return [self.validate(ctx) for ctx in contexts]

    def get_result(self, constraint_id: str) -> Optional[ConstraintResult]:
        return self._results.get(constraint_id)

    def failed_constraints(self) -> list[tuple[Constraint, ConstraintResult]]:
        failed = []
        for cid, result in self._results.items():
            if result.status == ConstraintStatus.FAIL:
                c = self._constraints.get(cid)
                if c:
                    failed.append((c, result))
        return failed

    def by_tag(self, tag: str) -> list[Constraint]:
        return [c for c in self._constraints.values() if tag in c.tags]

    def by_severity(self, severity: ConstraintSeverity) -> list[Constraint]:
        return [c for c in self._constraints.values() if c.severity == severity]

    def reset(self):
        self._results.clear()

    @property
    def stats(self) -> dict:
        enabled = sum(1 for c in self._constraints.values() if c.enabled)
        return {"constraints": len(self._constraints), "enabled": enabled,
                "checkers": len(self._checkers),
                "results": len(self._results),
                "cycles": len(self.check_circular_deps()),
                "executions": len(self._execution_log)}
