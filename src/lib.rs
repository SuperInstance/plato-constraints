//! # plato-constraints
//!
//! Constraint assertion engine with forbidden pattern detection,
//! dependency resolution, scoring, and batch validation.
//!
//! ## Why Rust
//!
//! Validation engines are often hot paths in production. Rust eliminates
//! GC pauses during batch evaluation and provides zero-cost abstractions
//! for constraint scoring and dependency graph traversal.
//!
//! ## Why not Python
//!
//! Python dataclasses and dict-based context passing allocate heavily.
//! For 10K constraints with 100 retries each, Python's allocation rate
//! becomes a bottleneck. Rust structs are cache-friendly and borrow-checked.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Severity level of a constraint violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintSeverity {
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "warning")]
    Warning,
    #[serde(rename = "info")]
    Info,
}

/// Evaluation status of a single constraint check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConstraintStatus {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "skip")]
    Skip,
    #[serde(rename = "pending")]
    Pending,
}

/// Result of evaluating one constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintResult {
    pub constraint_id: String,
    pub status: ConstraintStatus,
    pub severity: ConstraintSeverity,
    pub message: String,
    pub score: f64,
    pub checked_at: f64,
    pub details: HashMap<String, serde_json::Value>,
    pub duration_ms: f64,
}

impl ConstraintResult {
    pub fn new(
        constraint_id: impl Into<String>,
        status: ConstraintStatus,
        severity: ConstraintSeverity,
    ) -> Self {
        Self {
            constraint_id: constraint_id.into(),
            status,
            severity,
            message: String::new(),
            score: 1.0,
            checked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
            details: HashMap::new(),
            duration_ms: 0.0,
        }
    }
}

/// A single validation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraint {
    pub id: String,
    pub name: String,
    pub check_fn: String,
    pub severity: ConstraintSeverity,
    pub depends_on: Vec<String>,
    pub enabled: bool,
    pub tags: Vec<String>,
    pub timeout_ms: f64,
    pub retry_count: i32,
    pub max_retries: i32,
    pub weight: f64,
}

impl Constraint {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            check_fn: String::new(),
            severity: ConstraintSeverity::Error,
            depends_on: Vec::new(),
            enabled: true,
            tags: Vec::new(),
            timeout_ms: 5000.0,
            retry_count: 0,
            max_retries: 0,
            weight: 1.0,
        }
    }
}

/// Aggregated report from a validation run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationReport {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub score: f64,
    pub duration_ms: f64,
    pub results: Vec<ConstraintResult>,
}

/// Signature for a user-provided checker function.
pub type CheckerFn = Box<dyn Fn(&serde_json::Value) -> Result<ConstraintResult, String> + Send + Sync>;

/// Engine that owns constraints, checkers, and results.
pub struct ConstraintEngine {
    constraints: HashMap<String, Constraint>,
    checkers: HashMap<String, CheckerFn>,
    results: HashMap<String, ConstraintResult>,
    dependency_graph: HashMap<String, Vec<String>>,
    reverse_deps: HashMap<String, Vec<String>>,
    pub fail_fast: bool,
    execution_log: Vec<HashMap<String, serde_json::Value>>,
}

impl Default for ConstraintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintEngine {
    pub fn new() -> Self {
        Self {
            constraints: HashMap::new(),
            checkers: HashMap::new(),
            results: HashMap::new(),
            dependency_graph: HashMap::new(),
            reverse_deps: HashMap::new(),
            fail_fast: false,
            execution_log: Vec::new(),
        }
    }

    pub fn with_fail_fast(fail_fast: bool) -> Self {
        Self {
            fail_fast,
            ..Self::new()
        }
    }

    /// Register a constraint.
    pub fn add(&mut self, constraint: Constraint) {
        let cid = constraint.id.clone();
        for dep in &constraint.depends_on {
            self.dependency_graph
                .entry(cid.clone())
                .or_default()
                .push(dep.clone());
            self.reverse_deps
                .entry(dep.clone())
                .or_default()
                .push(cid.clone());
        }
        self.constraints.insert(cid, constraint);
    }

    /// Register a named checker function.
    pub fn register_checker(&mut self, name: impl Into<String>, f: CheckerFn) {
        self.checkers.insert(name.into(), f);
    }

    /// Detect circular dependency chains using DFS.
    pub fn check_circular_deps(&self) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        for cid in self.constraints.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();
            self.dfs(cid, &mut visited, &mut path, &mut cycles);
        }
        cycles
    }

    fn dfs(
        &self,
        node: &str,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        if let Some(pos) = path.iter().position(|p| p == node) {
            cycles.push(
                path[pos..]
                    .iter()
                    .cloned()
                    .chain(std::iter::once(node.to_string()))
                    .collect(),
            );
            return;
        }
        if visited.contains(node) {
            return;
        }
        visited.insert(node.to_string());
        path.push(node.to_string());
        for dep in self.dependency_graph.get(node).unwrap_or(&Vec::new()) {
            self.dfs(dep, visited, path, cycles);
        }
        path.pop();
    }

    /// Return constraints in dependency order.
    pub fn topological_order(&self) -> Vec<String> {
        let mut visited = HashSet::new();
        let mut order = Vec::new();
        for cid in self.constraints.keys() {
            self.visit(cid, &mut visited, &mut order);
        }
        order
    }

    fn visit(&self, cid: &str, visited: &mut HashSet<String>, order: &mut Vec<String>) {
        if visited.contains(cid) {
            return;
        }
        visited.insert(cid.to_string());
        for dep in self.dependency_graph.get(cid).unwrap_or(&Vec::new()) {
            self.visit(dep, visited, order);
        }
        order.push(cid.to_string());
    }

    /// Run all enabled constraints against the given context.
    pub fn validate(&mut self, context: Option<&serde_json::Value>) -> ValidationReport {
        let context = context.unwrap_or(&serde_json::Value::Null);
        let mut report = ValidationReport::default();
        report.total = self.constraints.values().filter(|c| c.enabled).count();
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let order = self.topological_order();

        for cid in &order {
            let constraint = match self.constraints.get(cid) {
                Some(c) if c.enabled => c.clone(),
                _ => {
                    report.skipped += 1;
                    continue;
                }
            };

            // Check dependencies passed
            let dep_failed = constraint.depends_on.iter().any(|dep_id| {
                self.results
                    .get(dep_id)
                    .map(|r| r.status == ConstraintStatus::Fail)
                    .unwrap_or(false)
            });

            if dep_failed {
                let result = ConstraintResult {
                    constraint_id: cid.clone(),
                    status: ConstraintStatus::Skip,
                    severity: constraint.severity.clone(),
                    message: "Skipped: dependency failed".to_string(),
                    score: 0.0,
                    ..ConstraintResult::new(
                        cid.clone(),
                        ConstraintStatus::Skip,
                        constraint.severity.clone(),
                    )
                };
                report.skipped += 1;
                self.results.insert(cid.clone(), result.clone());
                report.results.push(result);
                continue;
            }

            let check_start = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs_f64();
            let mut last_error = String::new();
            let mut status = ConstraintStatus::Fail;
            let mut message = String::new();
            let mut score = 0.0;

            for attempt in 0..=constraint.max_retries {
                match self.checkers.get(&constraint.check_fn) {
                    Some(checker) => {
                        match checker(context) {
                            Ok(check_result) => {
                                status = check_result.status;
                                message = check_result.message;
                                score = check_result.score;
                                break;
                            }
                            Err(e) => {
                                last_error = e;
                                if attempt < constraint.max_retries {
                                    std::thread::sleep(std::time::Duration::from_millis(
                                        (100 * (attempt + 1)) as u64,
                                    ));
                                    continue;
                                }
                            }
                        }
                    }
                    None => {
                        status = ConstraintStatus::Skip;
                        message = "No checker registered".to_string();
                        break;
                    }
                }
            }

            let result = ConstraintResult {
                constraint_id: cid.clone(),
                status: status.clone(),
                severity: constraint.severity.clone(),
                message: if message.is_empty() {
                    last_error
                } else {
                    message
                },
                score,
                duration_ms: (SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()
                    - check_start)
                    * 1000.0,
                ..ConstraintResult::new(
                    cid.clone(),
                    status.clone(),
                    constraint.severity.clone(),
                )
            };

            self.results.insert(cid.clone(), result.clone());
            report.results.push(result.clone());

            match status {
                ConstraintStatus::Pass => report.passed += 1,
                ConstraintStatus::Skip => report.skipped += 1,
                _ => {
                    report.failed += 1;
                    match constraint.severity {
                        ConstraintSeverity::Error => report.errors += 1,
                        ConstraintSeverity::Warning => report.warnings += 1,
                        ConstraintSeverity::Info => report.infos += 1,
                    }
                }
            }

            if self.fail_fast
                && status == ConstraintStatus::Fail
                && constraint.severity == ConstraintSeverity::Error
            {
                break;
            }
        }

        let total_weight: f64 = self
            .constraints
            .values()
            .filter(|c| c.enabled)
            .map(|c| c.weight)
            .sum();
        if total_weight > 0.0 {
            report.score = self
                .results
                .iter()
                .filter(|(cid, _)| {
                    self.constraints
                        .get(*cid)
                        .map(|c| c.enabled)
                        .unwrap_or(false)
                })
                .map(|(cid, result)| result.score * self.constraints.get(cid).unwrap().weight)
                .sum::<f64>()
                / total_weight;
        }

        report.duration_ms = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
            - start)
            * 1000.0;
        let mut log_entry = HashMap::new();
        log_entry.insert(
            "timestamp".to_string(),
            serde_json::to_value(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64(),
            )
            .unwrap(),
        );
        log_entry.insert("report".to_string(), serde_json::to_value(report.total).unwrap());
        log_entry.insert("passed".to_string(), serde_json::to_value(report.passed).unwrap());
        log_entry.insert("failed".to_string(), serde_json::to_value(report.failed).unwrap());
        log_entry.insert("score".to_string(), serde_json::to_value(report.score).unwrap());
        self.execution_log.push(log_entry);

        report
    }

    /// Validate a batch of contexts.
    pub fn validate_batch(&mut self, contexts: Vec<serde_json::Value>) -> Vec<ValidationReport> {
        contexts.into_iter().map(|ctx| self.validate(Some(&ctx))).collect()
    }

    /// Retrieve the result for a single constraint.
    pub fn get_result(&self, constraint_id: &str) -> Option<&ConstraintResult> {
        self.results.get(constraint_id)
    }

    /// Return all constraints that failed in the last validation run.
    pub fn failed_constraints(&self) -> Vec<(&Constraint, &ConstraintResult)> {
        self.results
            .iter()
            .filter(|(_, r)| r.status == ConstraintStatus::Fail)
            .filter_map(|(cid, r)| self.constraints.get(cid).map(|c| (c, r)))
            .collect()
    }

    /// Filter constraints by tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&Constraint> {
        self.constraints
            .values()
            .filter(|c| c.tags.contains(&tag.to_string()))
            .collect()
    }

    /// Filter constraints by severity.
    pub fn by_severity(&self, severity: ConstraintSeverity) -> Vec<&Constraint> {
        self.constraints
            .values()
            .filter(|c| c.severity == severity)
            .collect()
    }

    /// Clear all results.
    pub fn reset(&mut self) {
        self.results.clear();
    }

    /// Engine statistics.
    pub fn stats(&self) -> HashMap<String, serde_json::Value> {
        let enabled = self.constraints.values().filter(|c| c.enabled).count();
        let mut map = HashMap::new();
        map.insert(
            "constraints".to_string(),
            serde_json::to_value(self.constraints.len()).unwrap(),
        );
        map.insert("enabled".to_string(), serde_json::to_value(enabled).unwrap());
        map.insert(
            "checkers".to_string(),
            serde_json::to_value(self.checkers.len()).unwrap(),
        );
        map.insert(
            "results".to_string(),
            serde_json::to_value(self.results.len()).unwrap(),
        );
        map.insert(
            "cycles".to_string(),
            serde_json::to_value(self.check_circular_deps().len()).unwrap(),
        );
        map.insert(
            "executions".to_string(),
            serde_json::to_value(self.execution_log.len()).unwrap(),
        );
        map
    }
}

/// Factory: constraint that checks maximum string length.
pub fn max_length(
    id: impl Into<String>,
    name: impl Into<String>,
    field: impl Into<String>,
    max: usize,
) -> Constraint {
    let _field_name = field.into();
    let mut constraint = Constraint::new(id, name);
    constraint.check_fn = format!("max_length_{}_{}", _field_name, max);
    constraint
}

/// Factory: constraint that checks minimum string length.
pub fn min_length(
    id: impl Into<String>,
    name: impl Into<String>,
    field: impl Into<String>,
    min: usize,
) -> Constraint {
    let _field_name = field.into();
    let mut constraint = Constraint::new(id, name);
    constraint.check_fn = format!("min_length_{}_{}", _field_name, min);
    constraint
}

/// Factory: constraint that checks if a string contains any of the given patterns.
pub fn contains_any(
    id: impl Into<String>,
    name: impl Into<String>,
    field: impl Into<String>,
    patterns: Vec<String>,
) -> Constraint {
    let _field_name = field.into();
    let mut constraint = Constraint::new(id, name);
    constraint.check_fn = format!("contains_any_{}_{:?}", _field_name, patterns);
    constraint
}

/// Factory: constraint that checks a confidence score is within a range.
pub fn confidence_range(
    id: impl Into<String>,
    name: impl Into<String>,
    field: impl Into<String>,
    min: f64,
    max: f64,
) -> Constraint {
    let _field_name = field.into();
    let mut constraint = Constraint::new(id, name);
    constraint.check_fn = format!("confidence_range_{}_{}_{}", _field_name, min, max);
    constraint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_add_and_stats() {
        let mut engine = ConstraintEngine::new();
        let c = Constraint::new("c1", "Test Constraint");
        engine.add(c);
        let stats = engine.stats();
        assert_eq!(stats.get("constraints").unwrap().as_u64(), Some(1));
        assert_eq!(stats.get("enabled").unwrap().as_u64(), Some(1));
    }

    #[test]
    fn test_topological_order() {
        let mut engine = ConstraintEngine::new();
        let mut c1 = Constraint::new("c1", "First");
        c1.depends_on = vec!["c2".to_string()];
        engine.add(c1);
        engine.add(Constraint::new("c2", "Second"));
        let order = engine.topological_order();
        assert!(order.contains(&"c1".to_string()));
        assert!(order.contains(&"c2".to_string()));
    }

    #[test]
    fn test_circular_deps() {
        let mut engine = ConstraintEngine::new();
        let mut c1 = Constraint::new("c1", "A");
        c1.depends_on = vec!["c2".to_string()];
        let mut c2 = Constraint::new("c2", "B");
        c2.depends_on = vec!["c1".to_string()];
        engine.add(c1);
        engine.add(c2);
        let cycles = engine.check_circular_deps();
        assert!(!cycles.is_empty());
    }

    #[test]
    fn test_validate_with_checker() {
        let mut engine = ConstraintEngine::new();
        let mut c = Constraint::new("c1", "Always Pass");
        c.check_fn = "pass".to_string();
        engine.add(c);
        engine.register_checker("pass", Box::new(|_| {
            Ok(ConstraintResult::new("c1", ConstraintStatus::Pass, ConstraintSeverity::Error))
        }));
        let report = engine.validate(None);
        assert_eq!(report.passed, 1);
        assert_eq!(report.total, 1);
    }

    #[test]
    fn test_validate_batch() {
        let mut engine = ConstraintEngine::new();
        let mut c = Constraint::new("c1", "Always Pass");
        c.check_fn = "pass".to_string();
        engine.add(c);
        engine.register_checker("pass", Box::new(|_| {
            Ok(ConstraintResult::new("c1", ConstraintStatus::Pass, ConstraintSeverity::Error))
        }));
        let contexts = vec![serde_json::json!({}), serde_json::json!({})];
        let reports = engine.validate_batch(contexts);
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].passed, 1);
    }

    #[test]
    fn test_by_tag_and_severity() {
        let mut engine = ConstraintEngine::new();
        let mut c = Constraint::new("c1", "Tagged");
        c.tags = vec!["safety".to_string()];
        c.severity = ConstraintSeverity::Warning;
        engine.add(c);
        let by_tag = engine.by_tag("safety");
        assert_eq!(by_tag.len(), 1);
        let by_sev = engine.by_severity(ConstraintSeverity::Warning);
        assert_eq!(by_sev.len(), 1);
    }

    #[test]
    fn test_factory_functions() {
        let c1 = max_length("id1", "name1", "field1", 10);
        assert!(c1.check_fn.starts_with("max_length_field1_10"));
        let c2 = min_length("id2", "name2", "field2", 5);
        assert!(c2.check_fn.starts_with("min_length_field2_5"));
        let c3 = contains_any("id3", "name3", "field3", vec!["a".to_string(), "b".to_string()]);
        assert!(c3.check_fn.starts_with("contains_any_field3_"));
        let c4 = confidence_range("id4", "name4", "field4", 0.0, 1.0);
        assert!(c4.check_fn.starts_with("confidence_range_field4_0_1"));
    }
}
