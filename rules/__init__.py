"""
rules
~~~~~
Public API for GuardRail rule definitions.

Usage
-----
    from rules import load_ruleset, default_ruleset, Severity

    # Load the built-in BFSI rule set
    rs = default_ruleset()

    # Iterate rules at CRITICAL or HIGH severity
    for rule in rs.at_or_above(Severity.HIGH):
        print(rule.id, rule.name)

    # Load a custom rule YAML
    custom = load_ruleset("/path/to/my_rules.yaml")
"""

from __future__ import annotations

from pathlib import Path

import yaml

from rules.schema import Detection, DetectionType, Rule, RuleSet, RuleSetMeta, Severity

__all__ = [
    "load_ruleset",
    "default_ruleset",
    # re-exports for consumer convenience
    "Detection",
    "DetectionType",
    "Rule",
    "RuleSet",
    "RuleSetMeta",
    "Severity",
]

# Path to the bundled BFSI rule YAML, co-located with this package.
_BUILTIN_RULESET = Path(__file__).parent / "bfsi_ruleset.yaml"


def load_ruleset(path: str | Path) -> RuleSet:
    """Parse and validate a rule YAML file, returning a :class:`RuleSet`.

    Parameters
    ----------
    path:
        Filesystem path to the YAML rule file.

    Raises
    ------
    FileNotFoundError
        If the path does not exist.
    yaml.YAMLError
        If the file is not valid YAML.
    pydantic.ValidationError
        If the YAML structure does not conform to the :class:`RuleSet` schema.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    return RuleSet.model_validate(raw)


def default_ruleset() -> RuleSet:
    """Return the built-in BFSI/FinTech rule set bundled with GuardRail."""
    return load_ruleset(_BUILTIN_RULESET)
