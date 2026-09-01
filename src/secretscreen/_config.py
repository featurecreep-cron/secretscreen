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

# Mirrors the library default. Needed here to bound what a discovered config
# may do to the threshold when there is no other value to compare against.
DEFAULT_ENTROPY_THRESHOLD = 4.5

# A config file is a short list of key names. Anything larger is not one, and
# reading it is how a planted file becomes a denial of service.
MAX_CONFIG_BYTES = 256 * 1024

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
        """Apply any ``[files."<basename>"]`` section for this input.

        Section names glob. A name is a scoping selector, not a rule: matching
        more files cannot grant a section anything a top-level entry does not
        already have, and matching literally meant ``[files."*.env"]`` loaded
        without complaint and never fired once.
        """
        lowered = basename.lower()
        result = self
        for name, section in self.files:
            if fnmatch.fnmatch(lowered, name.lower()):
                result = merge(result, section)
        return result

    @property
    def has_rules(self) -> bool:
        """Whether any show or hide entry is in force."""
        return bool(self.show or self.hide)

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


def merge_tightening(base: Config, overlay: Config) -> Config:
    """Merge a config that was found on disk rather than written by the caller.

    A discovered file may make the tool more paranoid and nothing else. It can
    arrive with a repository cloned five minutes ago, or be planted in a shared
    directory by anyone with write access there, so every setting it carries is
    read as a request to tighten:

    - ``hide`` merges normally. Over-redaction is visible and harmless.
    - ``show`` is dropped. It is the one setting that prints a credential.
    - ``mode`` may only go up, normal to aggressive, never back down.
    - ``entropy_threshold`` may only fall. A lower cutoff catches more.
    - ``root`` is ignored; truncating the walk drops other files' hide rules,
      which is loosening by omission.

    Stripping only ``show`` was the original mistake: the three settings that
    quietly stop a secret being *found* are as good as the one that prints it.
    """
    show_free = (
        replace(overlay, show=(), files=tuple((name, replace(s, show=())) for name, s in overlay.files))
        if overlay.show or any(s.show for _, s in overlay.files)
        else overlay
    )
    tightened = replace(
        show_free,
        mode="aggressive" if "aggressive" in (base.mode, overlay.mode) else base.mode,
        entropy_threshold=_lower_threshold(base.entropy_threshold, overlay.entropy_threshold),
        root=base.root,
    )
    return merge(base, tightened)


def _lower_threshold(base: float | None, overlay: float | None) -> float | None:
    """The stricter of two entropy cutoffs, bounded by the default.

    Bounded because a discovered file is otherwise free to raise the cutoff
    out of reach when nothing else set one — 99.0 turns layer 5 off without
    ever naming a key.
    """
    if overlay is None:
        return base
    ceiling = base if base is not None else DEFAULT_ENTROPY_THRESHOLD
    return min(ceiling, overlay)


def drops_show(config: Config) -> bool:
    """Whether this config carries show entries anywhere, including sections."""
    return bool(config.show) or any(section.show for _, section in config.files)


def _union(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    """Concatenate, preserving order and dropping duplicates."""
    return tuple(dict.fromkeys(first + second))


def _read_toml(path: Path) -> dict[str, object]:
    """Read and parse one config file. Raises ConfigError on any problem."""
    try:
        if path.is_file() and path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path}: larger than {MAX_CONFIG_BYTES} bytes; not a config file")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: cannot read: {exc}") from exc

    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except RecursionError as exc:
        # tomllib recurses per nesting level, so a file of nothing but open
        # brackets exits through the interpreter rather than through our own
        # error handling — and exit 1 reads as "--audit found something".
        raise ConfigError(f"{path}: nested too deeply to parse") from exc


class Loader:
    """Reads each config file once for the run that owns it.

    Discovery happens per input file, and the root check needs the same file
    the loader is about to parse — so the naive arrangement read every config
    twice per input, and re-walked the same directories for each. Fifty files
    in a twelve-deep tree came to some twelve hundred reads of a handful of
    files.

    Scoped to one run rather than kept module-level: a config edited between
    two invocations has to be seen, and a cache nobody can invalidate is how
    that stops being true.
    """

    def __init__(self) -> None:
        self._parsed: dict[str, dict[str, object]] = {}
        self._walks: dict[tuple[str, str, bool], list[Path]] = {}

    def load(self, path: Path) -> Config:
        """Read and validate one config file. Raises ConfigError on any problem."""
        return _from_mapping(self._raw(path), str(path))

    def discover(self, start: Path, *, stop_at: Path | None = None, honour_root: bool = True) -> list[Path]:
        """Find project configs from `start` upward, nearest last."""
        current = start.resolve() if start.exists() else start.absolute()
        key = (str(current), str(stop_at), honour_root)
        if key not in self._walks:
            self._walks[key] = self._walk(current, stop_at, honour_root)
        return self._walks[key]

    def _raw(self, path: Path) -> dict[str, object]:
        key = str(path)
        if key not in self._parsed:
            self._parsed[key] = _read_toml(path)
        return self._parsed[key]

    def _declares_root(self, path: Path) -> bool:
        """Check the root flag without failing the walk on a broken file.

        A malformed config still has to be reported, but that happens when it
        is loaded. Here a read failure simply means the walk continues.
        """
        try:
            return bool(self._raw(path).get("root", False))
        except ConfigError:
            return False

    def _walk(self, start: Path, stop_at: Path | None, honour_root: bool) -> list[Path]:
        boundary = stop_at if stop_at is not None else Path.home()
        found: list[Path] = []

        current = start
        seen: set[Path] = set()
        while current not in seen:
            seen.add(current)
            candidate = current / CONFIG_BASENAME
            if candidate.is_file():
                found.append(candidate)
                if honour_root and self._declares_root(candidate):
                    break
            if current == boundary or current == current.parent:
                break
            current = current.parent

        found.reverse()
        return found


def load(path: Path) -> Config:
    """Read and validate one config file. Raises ConfigError on any problem."""
    return Loader().load(path)


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


def discover(start: Path, *, stop_at: Path | None = None, honour_root: bool = True) -> list[Path]:
    """Find project configs from `start` upward, nearest last.

    Nearest last so the caller can fold them in order and let the closest file
    win. The walk stops at the home directory, at a filesystem root, or at the
    first config declaring ``root = true``.

    ``honour_root`` is False when the files being walked are not trusted. A
    ``root = true`` in a directory anyone can write to needs no rules of its
    own to strand the reader's: it ends the walk before their own config one
    level up is ever read, and the output looks the same either way.
    """
    return Loader().discover(start, stop_at=stop_at, honour_root=honour_root)
