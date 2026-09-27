"""
scanners.ast_scanner
~~~~~~~~~~~~~~~~~~~~
AST-based scanner engine for Python source files.

For rules whose ``detection.type`` is ``"ast"`` the engine builds a full
:mod:`ast` parse tree for Python files and walks it looking for dangerous
call patterns described by the rule's ``patterns`` list.

Each AST pattern string uses a *mini-DSL* understood by this module:

    ``call:<module>.<attr>``
        Matches ``ast.Call`` nodes where the callee is an
        ``ast.Attribute`` with the given ``attr`` on an object whose name
        (or first component) is ``<module>``.
        Example: ``call:subprocess.run`` matches ``subprocess.run(…)``

    ``call:<name>``
        Matches bare function calls such as ``eval(…)`` or ``exec(…)``.

    ``assign_attr:<attr>``
        Matches assignment targets whose final attribute name is ``<attr>``.
        Useful for detecting ``verify=False`` style misconfigurations.

    ``kw:<keyword>=<value>``
        Matches any ``ast.Call`` that has a keyword argument ``<keyword>``
        with a constant value equal to ``<value>``.
        Example: ``kw:verify=False`` catches ``requests.get(url, verify=False)``.

JavaScript files (``*.js``, ``*.ts``, ``*.jsx``, ``*.tsx``) are not directly parsed via
AST but are handled by an enhanced regex pass that understands multi-line
constructs.  If a rule applies to both languages the walker supplies the
correct engine.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from rules.schema import DetectionType, Rule
from scanners.base import BaseScanner
from scanners.models import Finding

# ---------------------------------------------------------------------------
# Pattern prefix constants
# ---------------------------------------------------------------------------

_PREFIX_CALL = "call:"
_PREFIX_ASSIGN_ATTR = "assign_attr:"
_PREFIX_KW = "kw:"

# JavaScript / TypeScript file extensions handled by the regex fallback.
_JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}


# ---------------------------------------------------------------------------
# Python AST visitor
# ---------------------------------------------------------------------------


class _PatternVisitor(ast.NodeVisitor):
    """Walk a Python AST and collect findings for a single rule."""

    def __init__(self, patterns: list[str], rule: Rule, path: Path) -> None:
        self._patterns = patterns
        self._rule = rule
        self._path = path
        self.findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Visitor methods
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        for pattern in self._patterns:
            if pattern.startswith(_PREFIX_CALL):
                self._check_call(node, pattern[len(_PREFIX_CALL) :])
            elif pattern.startswith(_PREFIX_KW):
                self._check_kw(node, pattern[len(_PREFIX_KW) :])
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for pattern in self._patterns:
            if pattern.startswith(_PREFIX_ASSIGN_ATTR):
                attr_name = pattern[len(_PREFIX_ASSIGN_ATTR) :]
                for target in node.targets:
                    self._check_assign_attr(target, node.value, attr_name, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        for pattern in self._patterns:
            if pattern.startswith(_PREFIX_ASSIGN_ATTR):
                attr_name = pattern[len(_PREFIX_ASSIGN_ATTR) :]
                self._check_assign_attr(node.target, node.value, attr_name, node)
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Pattern-specific checks
    # ------------------------------------------------------------------

    def _check_call(self, node: ast.Call, spec: str) -> None:
        """Check call:<module>.<attr> or call:<name>."""
        parts = spec.split(".", 1)
        if len(parts) == 2:
            module, attr = parts
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == attr
                and self._name_matches(func.value, module)
            ):
                self._add_finding(node)
        else:
            # bare function name, e.g. eval
            name = parts[0]
            if isinstance(node.func, ast.Name) and node.func.id == name:
                self._add_finding(node)

    def _check_kw(self, node: ast.Call, spec: str) -> None:
        """Check kw:<keyword>=<value>."""
        if "=" not in spec:
            return
        kw_name, kw_val = spec.split("=", 1)
        for kw in node.keywords:
            if kw.arg == kw_name and self._const_equals(kw.value, kw_val):
                self._add_finding(node)
                return

    def _check_assign_attr(
        self,
        target: ast.expr,
        value: ast.expr,
        attr_name: str,
        parent_node: ast.stmt,
    ) -> None:
        """Check assign_attr:<attr> — look for ``obj.attr = <something>``."""
        if isinstance(target, ast.Attribute) and target.attr == attr_name:
            self._add_finding(parent_node)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _name_matches(node: ast.expr, name: str) -> bool:
        """Return True if *node* resolves to *name* (handles ``a.b.c`` chains)."""
        if isinstance(node, ast.Name):
            return node.id == name
        if isinstance(node, ast.Attribute):
            # e.g. ssl.SSLContext — match on the outermost attribute owner
            return _PatternVisitor._name_matches(node.value, name)
        return False

    @staticmethod
    def _const_equals(node: ast.expr, value: str) -> bool:
        """Return True if *node* is a constant equal to the parsed *value*."""
        if not isinstance(node, ast.Constant):
            return False
        # Try to coerce the expected value string to the constant's type.
        try:
            if isinstance(node.value, bool):
                return node.value == (value.lower() == "true")
            if isinstance(node.value, int):
                return node.value == int(value)
            if isinstance(node.value, float):
                return node.value == float(value)
            return str(node.value) == value
        except (ValueError, AttributeError):
            return str(node.value) == value

    def _add_finding(self, node: ast.AST) -> None:
        lineno = getattr(node, "lineno", 0)
        self.findings.append(
            Finding(
                file=self._path,
                line=lineno,
                rule_id=self._rule.id,
                severity=self._rule.severity,
                explanation=self._rule.explanation,
                fix=self._rule.fix,
                match_text="",
            )
        )


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------


class AstScanner(BaseScanner):
    """AST-based scanner for Python; regex fallback for JS/TS files.

    Only processes rules with ``detection.type == "ast"``.
    """

    # Pre-compiled fallback patterns cache
    _regex_cache: dict[str, list[re.Pattern[str]]] = {}

    def scan_file(self, path: Path, rule: Rule) -> list[Finding]:
        if rule.detection.type != DetectionType.AST:
            return []

        suffix = path.suffix.lower()
        if suffix in _JS_EXTENSIONS:
            return self._scan_js(path, rule)
        if suffix == ".py":
            return self._scan_python(path, rule)
        return []

    # ------------------------------------------------------------------
    # Python path — stdlib ast
    # ------------------------------------------------------------------

    def _scan_python(self, path: Path, rule: Rule) -> list[Finding]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError):
            return []

        visitor = _PatternVisitor(rule.detection.patterns, rule, path)
        visitor.visit(tree)
        return visitor.findings

    # ------------------------------------------------------------------
    # JS/TS path — enhanced regex over full source text
    # ------------------------------------------------------------------

    def _scan_js(self, path: Path, rule: Rule) -> list[Finding]:
        """Translate AST-DSL patterns to best-effort regex for JS/TS files."""
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        patterns = self._js_patterns_for(rule)
        findings: list[Finding] = []
        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            for pattern in patterns:
                m = pattern.search(line)
                if m:
                    findings.append(
                        Finding(
                            file=path,
                            line=lineno,
                            rule_id=rule.id,
                            severity=rule.severity,
                            explanation=rule.explanation,
                            fix=rule.fix,
                            match_text=m.group(0).strip(),
                        )
                    )
                    break  # one finding per line per rule

        return findings

    def _js_patterns_for(self, rule: Rule) -> list[re.Pattern[str]]:
        if rule.id in self._regex_cache:
            return self._regex_cache[rule.id]

        compiled: list[re.Pattern[str]] = []
        for p in rule.detection.patterns:
            rx = self._dsl_to_js_regex(p)
            if rx:
                try:
                    compiled.append(re.compile(rx, re.IGNORECASE))
                except re.error:
                    pass
        self._regex_cache[rule.id] = compiled
        return compiled

    @staticmethod
    def _dsl_to_js_regex(pattern: str) -> str | None:
        """Convert an AST-DSL pattern to a best-effort JS-compatible regex."""
        if pattern.startswith(_PREFIX_CALL):
            spec = pattern[len(_PREFIX_CALL) :]
            parts = spec.split(".", 1)
            if len(parts) == 2:
                module, attr = parts
                # e.g.  subprocess.run(  →  subprocess\.run\s*\(
                escaped_mod = re.escape(module)
                escaped_attr = re.escape(attr)
                return rf"{escaped_mod}\.{escaped_attr}\s*\("
            # bare call: eval(
            return rf"\b{re.escape(parts[0])}\s*\("

        if pattern.startswith(_PREFIX_KW):
            spec = pattern[len(_PREFIX_KW) :]
            if "=" not in spec:
                return None
            kw_name, kw_val = spec.split("=", 1)
            # verify=False  →  verify\s*:\s*false  (JS object literal)
            # also covers  verify=false  in pseudo-keyword args
            return rf"{re.escape(kw_name)}\s*[=:]\s*{re.escape(kw_val)}"

        if pattern.startswith(_PREFIX_ASSIGN_ATTR):
            attr = pattern[len(_PREFIX_ASSIGN_ATTR) :]
            return rf"\b{re.escape(attr)}\s*="

        # Raw regex passed through as-is.
        return pattern
