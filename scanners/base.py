"""
scanners.base
~~~~~~~~~~~~~
Abstract base class that every GuardRail scanner engine must implement.
"""

from __future__ import annotations

import abc
from pathlib import Path

from rules.schema import Rule
from scanners.models import Finding


class BaseScanner(abc.ABC):
    """Contract for a scanner engine.

    Sub-classes implement :meth:`scan_file` which analyses a single source
    file against one rule and yields zero or more :class:`~scanners.models.Finding`
    objects.  The walker calls this for every (file, rule) pair.
    """

    @abc.abstractmethod
    def scan_file(self, path: Path, rule: Rule) -> list[Finding]:
        """Scan *path* against *rule* and return any findings.

        Parameters
        ----------
        path:
            Absolute or relative path to the file to scan.
        rule:
            The rule to check.

        Returns
        -------
        list[Finding]
            Empty list when the file is clean w.r.t. this rule.
        """
