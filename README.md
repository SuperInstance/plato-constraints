# plato-constraints

Constraint assertion engine with forbidden pattern detection, dependency resolution, scoring, and batch validation.

## Usage

```rust
use plato_constraints::{ConstraintEngine, Constraint, ConstraintResult, ConstraintStatus, ConstraintSeverity};

let mut engine = ConstraintEngine::new();
engine.add(Constraint::new("c1", "No empty strings"));
engine.register_checker("c1", Box::new(|ctx| {
    Ok(ConstraintResult::new("c1", ConstraintStatus::Pass, ConstraintSeverity::Error))
}));
let report = engine.validate(None);
```

## License

MIT
