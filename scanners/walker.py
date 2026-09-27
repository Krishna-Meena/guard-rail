"""
scanners.walker
~~~~~~~~~~~~~~~
Codebase walker — the top-level entry point for a full scan.

:func:`scan` is the primary public function.  It:

1. Accepts a root directory (or a single file) and a :class:`~rules.schema.RuleSet`.
2. Discovers all source files under the root that match each rule's
   ``file_glob`` restriction.
3. Dispatches each (file, rule) pair to the appropriate engine:
   - ``DetectionType.REGEX``  →  :class:`~scanners.regex_scanner.RegexScanner`
   - ``DetectionType.AST``    →  :class:`~scanners.ast_scanner.AstScanner`
   - ``DetectionType.SEMGREP`` → skipped (not yet implemented)
4. Collects and de-duplicates findings, then returns them sorted by
   (file, line, rule_id).

The walker intentionally skips:
* Binary files (detected by a quick null-byte check).
* Files larger than ``max_file_bytes`` (default 1 MB) to avoid reading
  minified bundles or generated sources.
* Directories listed in ``exclude_dirs`` (default: common build / vendor
  directories).
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from rules.schema import DetectionType, Rule, RuleSet
from scanners.ast_scanner import AstScanner
from scanners.models import Finding
from scanners.regex_scanner import RegexScanner

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "*.egg-info",
    }
)

_DEFAULT_MAX_FILE_BYTES: int = 1 * 1024 * 1024  # 1 MiB


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def count_files(
    root: str | Path,
    *,
    exclude_dirs: frozenset[str] | None = None,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
) -> int:
    """Return the number of scannable (non-binary, within-size) files under *root*.

    Used by the CLI to report how many files were inspected without changing
    the public signature of :func:`scan`.
    """
    if exclude_dirs is None:
        exclude_dirs = _DEFAULT_EXCLUDE_DIRS
    return len(_iter_files(Path(root), exclude_dirs, max_file_bytes))


def scan(
    root: str | Path,
    ruleset: RuleSet,
    *,
    exclude_dirs: frozenset[str] | None = None,
    max_file_bytes: int = _DEFAULT_MAX_FILE_BYTES,
    min_severity: str | None = None,
) -> list[Finding]:
    """Walk *root* and apply every rule in *ruleset*.

    Parameters
    ----------
    root:
        Directory (or single file) to scan.
    ruleset:
        The :class:`~rules.schema.RuleSet` whose rules are applied.
    exclude_dirs:
        Directory *names* (not paths) to skip.  Defaults to a sensible set
        of build / vendor / VCS directories.
    max_file_bytes:
        Files larger than this are silently skipped.
    min_severity:
        If provided (e.g. ``"HIGH"``), only rules at or above that severity
        level are applied.

    Returns
    -------
    list[Finding]
        All findings, sorted by (file, line, rule_id).  Duplicate findings
        for the same (file, line, rule_id) are deduplicated.
    """
    if exclude_dirs is None:
        exclude_dirs = _DEFAULT_EXCLUDE_DIRS

    root = Path(root)

    # Filter rules by minimum severity when requested.
    rules = ruleset.rules
    if min_severity is not None:
        from rules.schema import Severity

        threshold = Severity(min_severity.upper())
        rules = [r for r in rules if r.severity.rank >= threshold.rank]

    regex_engine = RegexScanner()
    ast_engine = AstScanner()

    # Collect files once, then iterate per rule.
    all_files = list(_iter_files(root, exclude_dirs, max_file_bytes))

    seen: set[tuple[Path, int, str]] = set()
    raw: list[Finding] = []

    for rule in rules:
        engine: RegexScanner | AstScanner | None = _engine_for(rule, regex_engine, ast_engine)
        if engine is None:
            continue

        for path in all_files:
            if not _file_matches_glob(path, root, rule):
                continue

            for finding in engine.scan_file(path, rule):
                key = (finding.file, finding.line, finding.rule_id)
                if key not in seen:
                    seen.add(key)
                    raw.append(finding)

    return sorted(raw, key=lambda f: (str(f.file), f.line, f.rule_id))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _engine_for(
    rule: Rule,
    regex_engine: RegexScanner,
    ast_engine: AstScanner,
) -> RegexScanner | AstScanner | None:
    if rule.detection.type == DetectionType.REGEX:
        return regex_engine
    if rule.detection.type == DetectionType.AST:
        return ast_engine
    # DetectionType.SEMGREP — not yet implemented
    return None


def _file_matches_glob(path: Path, root: Path, rule: Rule) -> bool:
    """Return True if *path* matches the rule's ``file_glob``, if set.

    Handles shell-style ``{a,b,c}`` alternation, which ``fnmatch`` does not
    support natively.  The implementation expands the first ``{...}`` group
    found in the pattern and tries each alternative in turn.
    """
    if rule.detection.file_glob is None:
        return True
    # Make the path relative to root for glob matching.
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    rel_str = str(rel).replace("\\", "/")
    return _fnmatch_brace(rel_str, rule.detection.file_glob)


def _fnmatch_brace(name: str, pattern: str) -> bool:
    """Recursively expand ``{a,b,...}`` in *pattern* and test each alternative.

    Also normalises ``**/<rest>`` to additionally try ``<rest>`` so that
    files directly inside the scanned root (no subdirectory) are not missed.
    Python's ``fnmatch`` does not treat ``**`` as a multi-segment wildcard.
    """
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        # Normalise **/ prefix: also try matching without it.
        normalised = re.sub(r"^\*\*/", "", pattern)
        return fnmatch.fnmatch(name, pattern) or (
            normalised != pattern and fnmatch.fnmatch(name, normalised)
        )
    prefix = pattern[: m.start()]
    suffix = pattern[m.end() :]
    for alt in m.group(1).split(","):
        if _fnmatch_brace(name, prefix + alt.strip() + suffix):
            return True
    return False


def _iter_files(
    root: Path,
    exclude_dirs: frozenset[str],
    max_file_bytes: int,
) -> list[Path]:  # type: ignore[type-arg]
    """Yield all non-binary files under *root* that are within size limit."""
    if not root.exists():
        return []

    if root.is_file():
        if _is_eligible(root, max_file_bytes):
            return [root]
        return []

    result: list[Path] = []
    _walk(root, exclude_dirs, max_file_bytes, result)
    return result


def _walk(
    directory: Path,
    exclude_dirs: frozenset[str],
    max_file_bytes: int,
    result: list[Path],
) -> None:
    try:
        entries = list(directory.iterdir())
    except PermissionError:
        return

    for entry in entries:
        if entry.is_dir():
            if entry.name in exclude_dirs or any(
                fnmatch.fnmatch(entry.name, pat) for pat in exclude_dirs
            ):
                continue
            _walk(entry, exclude_dirs, max_file_bytes, result)
        elif entry.is_file() and _is_eligible(entry, max_file_bytes):
            result.append(entry)


def _is_eligible(path: Path, max_file_bytes: int) -> bool:
    """Return True if the file is within size limit and appears to be text."""
    try:
        if path.stat().st_size > max_file_bytes:
            return False
        # Quick binary check: read first 8 KB and look for null bytes.
        chunk = path.read_bytes()[:8192]
        return b"\x00" not in chunk
    except OSError:
        return False
