from __future__ import annotations

from abc import ABC, abstractmethod
from hashlib import sha256
from pathlib import Path

from doc_ai_slopcheck.config import AppConfig
from doc_ai_slopcheck.models import Confidence, Finding, Location, Severity


class Rule(ABC):
    rule_id: str
    title: str
    supported_extensions: set[str] | None = None
    # Findings on lines that are only comments/docstrings are dropped unless the
    # rule is about comments itself (TODOs, plan IDs, chat bleed, ...).
    code_only: bool = True
    # RulesConfig field holding this rule's settings, when shared with a sibling
    # rule (e.g. bare_except_pass_js uses bare_except_pass). Default: rule_id.
    config_key: str | None = None
    # Findings in test code drop one severity level unless the rule is about
    # tests themselves (e.g. tests that can't fail).
    downgrade_in_tests: bool = True

    @property
    def category(self) -> str:
        """The rules/ folder the rule lives in: ai_slop, security, error_handling, ..."""
        return type(self).__module__.split(".")[-2]

    def enabled(self, config: AppConfig) -> bool:
        """Whether config turns this rule on; rules without a config section are on."""
        section = getattr(config.rules, self.config_key or self.rule_id, None)
        return section is None or section.enabled

    def applies_to_path(self, relative_path: str) -> bool:
        if self.supported_extensions is None:
            return True

        return Path(relative_path).suffix.lower() in self.supported_extensions

    @staticmethod
    def fingerprint(*parts: str) -> str:
        joined = "\x00".join(parts)
        return sha256(joined.encode("utf-8")).hexdigest()

    def build_finding(
        self,
        *,
        relative_path: str,
        line: int,
        message: str,
        severity: Severity,
        confidence: Confidence,
        evidence: str,
        suggestion: str | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        fingerprint = self.fingerprint(
            self.rule_id,
            relative_path,
            str(line),
            evidence,
        )
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=message,
            severity=severity,
            confidence=confidence,
            location=Location(path=relative_path, line=line),
            fingerprint=fingerprint,
            suggestion=suggestion,
            evidence=evidence,
            tags=tags or [],
        )

    @abstractmethod
    def scan_file(
        self,
        *,
        repo_root: Path,
        relative_path: str,
        content: str,
        config: AppConfig,
    ) -> list[Finding]:
        raise NotImplementedError
