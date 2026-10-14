from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path

# PHP plus the PHP file types Drupal uses for modules, themes and profiles.
PHP_EXTENSIONS = frozenset({
    ".php", ".module", ".inc", ".install", ".theme", ".profile", ".engine",
})

DEFAULT_CODE_EXTENSIONS = PHP_EXTENSIONS | {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".cs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".md",
}


# Header markers of generated code (OpenAPI/protobuf clients, Go `Code
# generated ... DO NOT EDIT`, Facebook-style @generated). Findings there can't
# be fixed by hand.
_GENERATED_RE = re.compile(r"@generated\b|\bDO NOT EDIT\b|\bauto-?generated\b", re.IGNORECASE)
_HEADER_LINES = 40


# Bundled third-party files keep a /*! license banner as their first line.
_VENDORED_RE = re.compile(r"\A\s*/\*!")


def is_generated(content: str) -> bool:
    """Generated (header marker) or vendored (/*! banner) code nobody edits here."""
    header = "\n".join(content.split("\n", _HEADER_LINES)[:_HEADER_LINES])
    return bool(_GENERATED_RE.search(header) or _VENDORED_RE.match(content))


def is_ignored(relative_path: str, ignored_patterns: list[str]) -> bool:
    return any(fnmatch(relative_path, pattern) for pattern in ignored_patterns)


def is_candidate_file(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in DEFAULT_CODE_EXTENSIONS


def discover_files(
    repo_root: Path,
    targets: list[Path] | None,
    ignored_patterns: list[str],
) -> list[Path]:
    if targets:
        candidates = []
        for target in targets:
            if target.is_absolute():
                absolute = target.resolve()
            else:
                absolute = (repo_root / target).resolve()
            if absolute.is_dir():
                for nested in absolute.rglob("*"):
                    if is_candidate_file(nested):
                        candidates.append(nested)
            elif is_candidate_file(absolute):
                candidates.append(absolute)
    else:
        candidates = [path for path in repo_root.rglob("*") if is_candidate_file(path)]

    unique: list[Path] = []
    seen: set[str] = set()
    resolved_root = repo_root.resolve()

    for path in candidates:
        # Reject symlinks whose real target is outside the repo root
        if not path.resolve().is_relative_to(resolved_root):
            continue

        try:
            relative = path.relative_to(repo_root).as_posix()
        except ValueError:
            continue

        if is_ignored(relative, ignored_patterns):
            continue

        if relative in seen:
            continue

        seen.add(relative)
        unique.append(path)

    return sorted(unique, key=lambda item: item.relative_to(repo_root).as_posix())
