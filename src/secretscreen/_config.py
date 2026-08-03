"""Configuration file loading, discovery, and merging.

Config exists to stop the same false positive being re-diagnosed every run.
It cannot do the same for false negatives — a missed secret leaves no trace to
configure against — which is why ``--explain`` came first and why the rules
here lean asymmetric:

- ``hide`` accepts globs. Over-redaction is visible and harmless.
- ``show`` does not. ``show = ["*_KEY"]`` would print ``AWS_SECRET_ACCESS_KEY``,
  and it would go on matching keys nobody has written yet. Every entry is a
  credential someone is choosing to print, so every entry gets named in full.

``hide`` always beats ``show``, at every scope. A narrower rule that could
un-hide something would be the one setting where being more specific makes the
tool quieter, and that is not a direction worth supporting.

Files are read, never written; nothing here creates or edits a config.
"""

from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

CONFIG_BASENAME = ".secretscreen.toml"
USER_CONFIG_BASENAME = "secretscreen.toml"

_WILDCARD_CHARACTERS = "*?["

_TOP_LEVEL_KEYS = frozenset({"show", "hide", "root", "detection", "files"})
_DETECTION_KEYS = frozenset({"mode", "entropy_threshold"})
_FILE_SECTION_KEYS = frozenset({"show", "hide"})
_MODES = frozenset({"normal", "aggressive"})


class ConfigError(Exception):
    """A config file is unreadable, malformed, or asks for something unsafe.

    Always fatal. A typo that silently disabled a ``hide`` rule would leave the
    user believing they had configured something they had not.
    """


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved settings from one file, or several merged together."""

    show: tuple[str, ...] = ()
    hide: tuple[str, ...] = ()
    mode: str | None = None
    entropy_threshold: float | None = None
    root: bool = False
    files: tuple[tuple[str, Config], ...] = ()
    sources: tuple[str, ...] = field(default=())

    def for_file(self, basename: str) -> Config:
        """Apply any ``[files."<basename>"]`` section for this input."""
        lowered = basename.lower()
        result = self
        for name, section in self.files:
            if name.lower() == lowered:
                result = merge(result, section)
        return result

    def shows(self, key: str) -> str | None:
        """Return the matching show entry, or None. Exact, case-insensitive."""
        lowered = key.lower()
        for entry in self.show:
            if entry.lower() == lowered:
                return entry
        return None

    def hides(self, key: str) -> str | None:
        """Return the matching hide pattern, or None. Glob, case-insensitive."""
        lowered = key.lower()
        for pattern in self.hide:
            if fnmatch.fnmatch(lowered, pattern.lower()):
                return pattern
        return None


def merge(base: Config, overlay: Config) -> Config:
    """Combine two configs. Lists union, scalars last-wins.

    Union rather than replacement so a narrower config extends the broader one
    instead of silently discarding it — the mistake ``safe_suffixes`` makes in
    the library API, where passing one suffix drops the other twenty.
    """
    return Config(
        show=_union(base.show, overlay.show),
        hide=_union(base.hide, overlay.hide),
        mode=overlay.mode if overlay.mode is not None else base.mode,
        entropy_threshold=(
            overlay.entropy_threshold if overlay.entropy_threshold is not None else base.entropy_threshold
        ),
        root=overlay.root or base.root,
        files=base.files + overlay.files,
        sources=_union(base.sources, overlay.sources),
    )


def check_show_entries(entries: tuple[str, ...], label: str) -> None:
    """Reject wildcards in show entries. Raises ConfigError.

    Shared by the file loader and ``--show`` so the flag cannot do what the
    file is forbidden to. An unenforced ``--show '*_KEY'`` would not even fail
    loudly — exact matching makes it a silent no-op, which reads as a rule
    that is in force when it never fired once.
    """
    offenders = [entry for entry in entries if any(char in entry for char in _WILDCARD_CHARACTERS)]
    if offenders:
        raise ConfigError(
            f"{label} must name keys exactly — {', '.join(repr(o) for o in offenders)} "
            f"contains a wildcard. A pattern would also match keys that do not exist yet, "
            f"and every show entry is a value chosen to be printed."
        )


def without_show(config: Config) -> Config:
    """Drop every show entry, including inside file sections.

    Applied to configs that were merely found on disk rather than written by
    the person running the command. A discovered file may make the tool more
    paranoid; letting it make the tool quieter would mean a repository could
    decide which of your credentials get printed.
    """
    if not config.show and not any(section.show for _, section in config.files):
        return config
    stripped_files = tuple((name, replace(section, show=())) for name, section in config.files)
    return replace(config, show=(), files=stripped_files)


def _union(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    """Concatenate, preserving order and dropping duplicates."""
    return tuple(dict.fromkeys(first + second))


def load(path: Path) -> Config:
    """Read and validate one config file. Raises ConfigError on any problem."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read: {exc}") from exc

    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    return _from_mapping(data, str(path))


def _from_mapping(data: dict[str, object], source: str) -> Config:
    _reject_unknown(data, _TOP_LEVEL_KEYS, source, "")

    detection = data.get("detection", {})
    if not isinstance(detection, dict):
        raise ConfigError(f"{source}: [detection] must be a table")
    _reject_unknown(detection, _DETECTION_KEYS, source, "detection.")

    mode = detection.get("mode")
    if mode is not None:
        if not isinstance(mode, str) or mode not in _MODES:
            raise ConfigError(f"{source}: detection.mode must be one of {sorted(_MODES)}")

    threshold = detection.get("entropy_threshold")
    if threshold is not None:
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise ConfigError(f"{source}: detection.entropy_threshold must be a number")
        threshold = float(threshold)

    root = data.get("root", False)
    if not isinstance(root, bool):
        raise ConfigError(f"{source}: root must be true or false")

    files_table = data.get("files", {})
    if not isinstance(files_table, dict):
        raise ConfigError(f"{source}: [files] must be a table of file names")

    sections: list[tuple[str, Config]] = []
    for name, section in files_table.items():
        if not isinstance(section, dict):
            raise ConfigError(f'{source}: [files."{name}"] must be a table')
        _reject_unknown(section, _FILE_SECTION_KEYS, source, f'files."{name}".')
        sections.append(
            (
                name,
                Config(
                    show=_string_list(section.get("show"), source, f'files."{name}".show', allow_wildcards=False),
                    hide=_string_list(section.get("hide"), source, f'files."{name}".hide', allow_wildcards=True),
                ),
            )
        )

    return Config(
        show=_string_list(data.get("show"), source, "show", allow_wildcards=False),
        hide=_string_list(data.get("hide"), source, "hide", allow_wildcards=True),
        mode=mode,
        entropy_threshold=threshold,
        root=root,
        files=tuple(sections),
        sources=(source,),
    )


def _reject_unknown(table: dict[str, object], allowed: frozenset[str], source: str, prefix: str) -> None:
    """A misspelled key must fail loudly rather than be quietly ignored."""
    unknown = sorted(set(table) - allowed)
    if unknown:
        names = ", ".join(f"{prefix}{name}" for name in unknown)
        raise ConfigError(f"{source}: unknown setting(s): {names}")


def _string_list(value: object, source: str, name: str, *, allow_wildcards: bool) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{source}: {name} must be a list of strings")
    entries = tuple(value)

    if not allow_wildcards:
        check_show_entries(entries, f"{source}: {name}")
    return entries


def user_config_path() -> Path:
    """Location of the user's own config, honouring XDG_CONFIG_HOME."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / USER_CONFIG_BASENAME


def discover(start: Path, *, stop_at: Path | None = None) -> list[Path]:
    """Find project configs from `start` upward, nearest last.

    Nearest last so the caller can fold them in order and let the closest file
    win. The walk stops at the home directory, at a filesystem root, or at the
    first config declaring ``root = true``.
    """
    boundary = stop_at if stop_at is not None else Path.home()
    found: list[Path] = []

    current = start.resolve() if start.exists() else start.absolute()
    seen: set[Path] = set()
    while current not in seen:
        seen.add(current)
        candidate = current / CONFIG_BASENAME
        if candidate.is_file():
            found.append(candidate)
            if _declares_root(candidate):
                break
        if current == boundary or current == current.parent:
            break
        current = current.parent

    found.reverse()
    return found


def _declares_root(path: Path) -> bool:
    """Check the root flag without failing the walk on a broken file.

    A malformed config still has to be reported, but that happens when it is
    loaded. Here a read failure simply means the walk continues.
    """
    try:
        return bool(tomllib.loads(path.read_text(encoding="utf-8")).get("root", False))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return False
