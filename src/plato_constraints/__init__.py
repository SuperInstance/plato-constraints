"""Constraints — assertion engine, forbidden patterns, constraint checking.
Part of the PLATO framework."""
from .constraints import ConstraintEngine, ConstraintResult, max_length, min_length, contains_any, confidence_range
__version__ = "0.1.0"
__all__ = ["ConstraintEngine", "ConstraintResult", "max_length", "min_length", "contains_any", "confidence_range"]
