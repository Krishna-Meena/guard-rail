"""
rules.schema
~~~~~~~~~~~~
Pydantic v2 models that describe the structure of a GuardRail rule YAML file.

These models are used by rules.loader to validate and deserialise the YAML
into strongly-typed Python objects consumed by scanner and report modules.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Risk severity levels, ordered low → high."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank for severity comparisons (higher = worse)."""
        return list(Severity).index(self)


class DetectionType(StrEnum):
    """Supported detection engine types."""

    REGEX = "regex"
    AST = "ast"
    SEMGREP = "semgrep"


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------


class Detection(BaseModel):
    """Detection strategy attached to a single rule."""

    type: DetectionType
    patterns: Annotated[list[str], Field(min_length=1)]
    file_glob: str | None = Field(
        default=None,
        description="Optional glob pattern restricting which files are scanned.",
    )

    @field_validator("patterns")
    @classmethod
    def patterns_non_empty_strings(cls, v: list[str]) -> list[str]:
        for pattern in v:
            if not pattern.strip():
                raise ValueError("Detection pattern must not be an empty string.")
        return v


class Rule(BaseModel):
    """A single compliance / security rule."""

    id: Annotated[str, Field(pattern=r"^GR-[A-Z]+-\d{3}$")]
    name: str
    category: str
    severity: Severity
    frameworks: list[str] = Field(default_factory=list)
    detection: Detection
    explanation: str
    fix: str
    references: list[str] = Field(default_factory=list)

    @field_validator("explanation", "fix")
    @classmethod
    def non_empty_text(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field must not be blank.")
        return v.strip()


class RuleSetMeta(BaseModel):
    """Metadata block at the top of the rule YAML."""

    version: str
    name: str
    description: str


class RuleSet(BaseModel):
    """Top-level container parsed from a rule YAML file."""

    ruleset: RuleSetMeta
    rules: Annotated[list[Rule], Field(min_length=1)]

    # ---- convenience helpers ------------------------------------------------

    def by_id(self, rule_id: str) -> Rule:
        """Return a rule by its id; raises KeyError if not found."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(f"Rule '{rule_id}' not found in ruleset.")

    def by_severity(self, severity: Severity) -> list[Rule]:
        """Return all rules matching the given severity."""
        return [r for r in self.rules if r.severity == severity]

    def at_or_above(self, minimum: Severity) -> list[Rule]:
        """Return rules whose severity rank is >= the minimum."""
        return [r for r in self.rules if r.severity.rank >= minimum.rank]
