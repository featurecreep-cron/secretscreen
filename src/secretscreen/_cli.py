"""Command-line interface — format-aware redaction of config-shaped data.

    secretscreen tandoor.env           # redact and print, cat-like
    docker exec app env | secretscreen --format env
    secretscreen --audit config.json   # findings only, exit 1 if any

Design constraint: the library is best-effort defense-in-depth, not a security
boundary, and a cat-replacement is exactly the tool people stop thinking about.
So the failure that matters here is not a false positive — it is silently
printing content that was never structurally parsed, which looks screened and
is not. Every such line is replaced with the redaction token, reported on
stderr, and turns the exit code non-zero. Nothing unparsed reaches stdout
verbatim.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from secretscreen import __version__, _config
from secretscreen._config import Config, ConfigError
from secretscreen._core import (
    _MAX_DETECT_LENGTH,
    _MAX_RECURSIVE_DEPTH,
    REDACTED,
    STATE_REDACTED,
    STATE_VETOED,
    Explanation,
    Finding,
    Mode,
    audit_dict,
    audit_pair,
    explain_dict,
    explain_pair,
    redact_dict,
    redact_pair,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

FORMATS = ("env", "json", "ini", "yaml", "dsn", "auto")

_JSON_EXTENSIONS = {".json"}
_INI_EXTENSIONS = {".ini", ".cfg", ".conf", ".properties"}
_ENV_EXTENSIONS = {".env", ".envrc"}
_YAML_EXTENSIONS = {".yaml", ".yml"}

# grep prefixes its output with `file:` and `line:` when given -n or several
# files. Those colons break any colon-separated format: the first ':' belongs
# to the prefix, so the key becomes a line number and the rest of the line —
# including any secret — becomes one opaque value that no layer matches.
#
# Detection is document-wide rather than per-line. A single line starting with
# digits and a colon is ambiguous (a timestamp, a port); a whole input shaped
# that way is grep output. Prefixes are stripped for detection and put back on
# output, so `file:line:` context survives into the redacted result.
# grep marks matching lines `file:NN:` and context lines `file-NN-`, mixing both
# delimiters in one stream whenever -A/-B/-C is used. Matching only the colon
# form drops the ratio below the threshold on such a stream, which skips
# stripping and lets the colon format be chosen anyway — the leak this guard
# exists to prevent. The filename may not contain whitespace, which keeps the
# pattern off ordinary content like `command: run --port 8080-9090-x`.
_GREP_PREFIX = re.compile(r"^(?:\S*?([:-])\d+\1|\d+[:-])")
_GREP_SEPARATOR = "--"
_GREP_MIN_LINES = 2
_GREP_PREFIX_RATIO = 0.8

# A YAML list entry carrying a bare value: `- prod`. There is no key, but there
# is a value, so it is scanned rather than passed through or redacted wholesale.
_YAML_LIST_ITEM = re.compile(r"^(\s*-\s+)(\S.*)$")

# Column widths for --explain output. The key column is capped so one very long
# key (a grep prefix, a deep JSON path) cannot push every reason off the screen.
_EXPLAIN_KEY_MAX_WIDTH = 44

# Imported rather than repeated: the rule overlay has to stop exactly where
# redaction did, and a comment saying two literals agree is not a mechanism.
_JSON_RULE_MAX_DEPTH = _MAX_RECURSIVE_DEPTH
_EXPLAIN_LAYER_WIDTH = 17

# Separator characters by format, in precedence order.
# YAML separates a mapping key from its value with a colon *and a space*.
# Splitting on a bare colon would cut `- discord://token@id` at the scheme,
# leaving `//token@id` as a value under the key `- discord` — which matches
# nothing, so the token prints. INI keeps the bare colon: `key:value` is valid
# there, and its values do not usually carry URLs.
_SEPARATORS = {"env": ("=",), "ini": ("=", ":"), "yaml": ("=", ": ")}
_COMMENT_PREFIXES = {"env": ("#",), "ini": ("#", ";"), "yaml": ("#",)}


@dataclass(frozen=True, slots=True)
class _Settings:
    """Everything one input needs, after config and flags are folded together."""

    mode: Mode
    entropy_threshold: float
    config: Config


class _Report:
    """Accumulates findings and problems across all inputs.

    Not a dataclass: the architecture tests require every dataclass in the
    package to be frozen, and this is mutable by nature.
    """

    def __init__(self) -> None:
        self.findings: list[tuple[str, int, Finding]] = []
        self.problems: list[str] = []
        self.explanations: list[tuple[str, int, Explanation]] = []
        self.notes: list[str] = []

    def problem(self, source: str, lineno: int, message: str) -> None:
        self.problems.append(f"{source}:{lineno}: {message}")


def _strip_quotes(value: str) -> tuple[str, str]:
    """Split a value into (quote_char, inner). Quote char is '' when unquoted."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[0], value[1:-1]
    return "", value


def _split_grep_prefixes(text: str) -> list[tuple[str, str]] | None:
    """Split grep-style `file:line:` prefixes off each line, or None if absent.

    Returns (prefix, remainder) per line so the prefix can be reprinted while
    only the remainder is parsed. The decision is made for the whole input:
    one line that happens to start with digits and a colon is ambiguous, an
    input where nearly every line does is grep output.
    """
    lines = text.splitlines()
    candidates = [line for line in lines if line.strip() and line.strip() != _GREP_SEPARATOR]
    if len(candidates) < _GREP_MIN_LINES:
        return None

    matched = sum(1 for line in candidates if _GREP_PREFIX.match(line))
    if matched < len(candidates) * _GREP_PREFIX_RATIO:
        return None

    split: list[tuple[str, str]] = []
    for line in lines:
        match = _GREP_PREFIX.match(line)
        split.append((match.group(0), line[match.end() :]) if match else ("", line))
    return split


def _detect_format(text: str, filename: str | None) -> str:
    """Pick a parser from the file extension, falling back to content sniffing."""
    if filename:
        lowered = filename.lower()
        dot = lowered.rfind(".")
        extension = lowered[dot:] if dot != -1 else ""
        if extension in _JSON_EXTENSIONS:
            return "json"
        if extension in _INI_EXTENSIONS:
            return "ini"
        if extension in _YAML_EXTENSIONS:
            return "yaml"
        if extension in _ENV_EXTENSIONS or lowered.split("/")[-1].startswith(".env"):
            return "env"

    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "json"
    for line in text.splitlines():
        bare = line.strip()
        if bare.startswith("[") and bare.endswith("]"):
            return "ini"

    # Colon-separated content only after any grep prefixes have been removed.
    # Sniffing before that would read grep's own `line:` as the separator and
    # hand the whole remainder — secret included — to detection as one value.
    body = _split_grep_prefixes(text)
    if body is not None:
        lines = [rest for _, rest in body]
    elif any(_GREP_PREFIX.match(line) for line in text.splitlines()):
        # Some lines look prefixed and not enough to strip with confidence.
        # Refuse the colon format: env redacts what it cannot parse, which is
        # useless but loud, and that is the right way to be wrong here.
        return "env"
    else:
        lines = text.splitlines()
    equals = colons = 0
    for line in lines:
        bare = line.strip()
        if not bare or bare.startswith("#"):
            continue
        equals += "=" in bare
        colons += ":" in bare and "=" not in bare.split(":", 1)[0]
    if colons > equals:
        return "yaml"
    return "env"


def _resolve_settings(path: str | None, args: argparse.Namespace, report: _Report, loader: _config.Loader) -> _Settings:
    """Fold config files and command-line flags into settings for one input.

    Discovery runs per input, not once per process: `secretscreen a/compose.yaml
    b/compose.yaml` must be able to pick up a different `.secretscreen.toml`
    beside each one. Order is user config, then project configs from furthest to
    nearest, then flags — so the closest file wins and an explicit flag beats
    every file.
    """
    merged = Config()

    if args.config:
        merged = _config.merge(merged, loader.load(Path(args.config)))
    elif not args.no_config:
        user = _config.user_config_path()
        if user.is_file():
            merged = _config.merge(merged, loader.load(user))

        start = Path(path).absolute().parent if path else Path.cwd()
        for found in loader.discover(start, honour_root=args.trust_config):
            discovered = loader.load(found)
            if args.trust_config:
                merged = _config.merge(merged, discovered)
                continue
            # A discovered file may tighten redaction but not loosen it: it
            # may have arrived with a repository rather than being written by
            # whoever is running the command.
            if _config.drops_show(discovered):
                report.notes.append(f"{found}: show entries ignored (pass --trust-config to honour them)")
            if discovered.root:
                report.notes.append(f"{found}: root ignored (pass --trust-config to honour it)")
            merged = _config.merge_tightening(merged, discovered)

    if path:
        merged = merged.for_file(Path(path).name)

    for source in merged.sources:
        report.notes.append(f"loaded config {source}")

    flag_show = tuple(args.show or ())
    _config.check_show_entries(flag_show, "--show")
    merged = _config.merge(merged, Config(show=flag_show, hide=tuple(args.hide or ())))

    mode = args.mode
    if mode is None:
        mode = Mode.AGGRESSIVE if merged.mode == "aggressive" else Mode.NORMAL

    threshold = args.entropy_threshold
    if threshold is None:
        threshold = (
            merged.entropy_threshold if merged.entropy_threshold is not None else _config.DEFAULT_ENTROPY_THRESHOLD
        )

    return _Settings(mode=mode, entropy_threshold=threshold, config=merged)


def _rule_finding(key: str, pattern: str) -> Finding:
    """A hide rule redacts without any layer having matched."""
    return Finding(key=key, reason=f"hide:{pattern}", layer="rule", detail=f"hide rule {pattern!r}")


def _rule_explanation(key: str, kind: str, name: str) -> Explanation:
    """Report a config decision distinctly from a detection one.

    A show rule reads as `vetoed` rather than `clean`: the value was not
    examined, it was vouched for. That is the line to look at when a rule
    written a year ago is quietly covering a secret added last week.
    """
    if kind == "hide":
        return Explanation(key, STATE_REDACTED, "rule", f"hide rule {name!r}")
    return Explanation(key, STATE_VETOED, "rule", f"show rule {name!r} — not examined")


def _ancestors(path: str) -> list[str]:
    """Plain key names of every container a display path passes through.

    `services[0].db.region` came from `services`, then `db`. Index suffixes
    are dropped: the list belongs to the key, and a rule names the key.
    """
    segments = path.split(".")[:-1]
    return [segment.split("[", 1)[0] for segment in segments if segment]


def _rule_covering(explanation: Explanation, config: Config) -> tuple[str, str] | None:
    """The rule that decided this value, including one applied further up.

    A hide rule replaces everything under the key it names, so an account of
    what happened to a value inside that subtree has to name the rule rather
    than the layer that would have run. show does not inherit downward — it
    vouches for one named key, not for whatever the key contains.
    """
    direct = _rule_for(explanation.name or explanation.key, config)
    if direct is not None:
        return direct
    for ancestor in _ancestors(explanation.key):
        hidden = config.hides(ancestor)
        if hidden is not None:
            return ("hide", hidden)
    return None


def _shown_non_strings(data: object, config: Config, _depth: int = 0) -> list[str]:
    """Keys a show rule names whose value is not a string.

    Reported rather than obeyed. Restoring an object or an array would vouch
    for every value inside it, including ones added later — the same argument
    that keeps wildcards out of show. Silence is the one option not available:
    a rule that neither fires nor complains reads as a rule in force.
    """
    if _depth >= _JSON_RULE_MAX_DEPTH:
        return []
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if not isinstance(value, str) and config.shows(str(key)) is not None:
                found.append(str(key))
            if isinstance(value, (dict, list)):
                found.extend(_shown_non_strings(value, config, _depth + 1))
    elif isinstance(data, list):
        for item in data:
            found.extend(_shown_non_strings(item, config, _depth + 1))
    return found


def _rule_for(key: str, config: Config) -> tuple[str, str] | None:
    """Return ("hide"|"show", rule) when a config rule decides this key.

    hide is checked first and wins outright. A narrower rule that could un-hide
    something would make being more specific make the tool quieter.
    """
    hidden = config.hides(key)
    if hidden is not None:
        return ("hide", hidden)
    shown = config.shows(key)
    if shown is not None:
        return ("show", shown)
    return None


def _redact_value(key: str, value: str, settings: _Settings, replacement: str) -> tuple[str, bool]:
    """Redact one value. Returns (result, unscanned) — unscanned means the size cap hit."""
    result = redact_pair(
        key, value, mode=settings.mode, replacement=replacement, entropy_threshold=settings.entropy_threshold
    )
    # Ask the library rather than re-deriving it from the size. The old form
    # inferred unscanned from `oversized and unchanged`, which duplicated a
    # private constant and stopped being true once redaction started failing
    # closed. secretscreen now reports the state directly.
    finding = audit_pair(key, value, mode=settings.mode, entropy_threshold=settings.entropy_threshold)
    unscanned = finding is not None and finding.layer == "size_cap"
    return result, unscanned


def _process_lines(
    text: str, fmt: str, source: str, args: argparse.Namespace, settings: _Settings, report: _Report
) -> list[str]:
    """Redact a line-oriented format (env, ini), preserving comments and layout."""
    separators = _SEPARATORS[fmt]
    comments = _COMMENT_PREFIXES[fmt]
    out: list[str] = []

    rows = _split_grep_prefixes(text)
    if rows is None:
        rows = [("", line) for line in text.splitlines()]
    elif any(prefix for prefix, _ in rows):
        report.notes.append("detected grep-style line prefixes; stripped before parsing, restored on output")

    for lineno, (prefix, raw) in enumerate(rows, 1):
        stripped = raw.strip()

        # Comments and blanks are judged after the grep prefix is removed.
        # `compose.yaml:24:# note` does not start with '#', which is why piped
        # comments used to be redacted while the same file read directly was fine.
        if not stripped or stripped.startswith(comments) or stripped == _GREP_SEPARATOR:
            out.append(prefix + raw)
            continue

        if fmt in ("ini", "yaml") and stripped.startswith("[") and stripped.endswith("]"):
            out.append(prefix + raw)
            continue

        # `services:` opens a block. There is no value slot on the line, so
        # there is nothing to screen and nothing to vouch for.
        if fmt == "yaml" and stripped.endswith(":"):
            out.append(prefix + raw)
            continue

        found = [(raw.find(sep), sep) for sep in separators if raw.find(sep) != -1]
        if not found:
            # A YAML list entry has a value but no key, so it is scanned as one
            # rather than redacted for lacking a separator it was never going
            # to have.
            item = _YAML_LIST_ITEM.match(raw) if fmt == "yaml" else None
            if item is not None:
                marker, content = item.group(1), item.group(2)
                redacted, unscanned = _redact_value("", content, settings, args.replacement)
                if args.explain:
                    report.explanations.append(
                        (
                            source,
                            lineno,
                            explain_pair("", content, mode=settings.mode, entropy_threshold=settings.entropy_threshold),
                        )
                    )
                if args.audit:
                    finding = audit_pair("", content, mode=settings.mode, entropy_threshold=settings.entropy_threshold)
                    if finding is not None:
                        report.findings.append((source, lineno, finding))
                    continue
                if unscanned:
                    report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
                out.append(f"{prefix}{marker}{redacted}")
                continue

            # Structurally unparseable. Redact rather than echo it — an unparsed
            # line is exactly the one we cannot vouch for.
            report.problem(source, lineno, "no key=value separator; line redacted unscanned")
            out.append(args.replacement)
            continue

        # preserve the separator as written rather than normalising it
        split_at, separator = min(found)
        # `left` is echoed verbatim so that spacing and any `export ` prefix survive
        # the round trip; only the detection key is normalised.
        left, value = raw[:split_at], raw[split_at + len(separator) :]
        key = left.strip()
        if fmt == "env" and key.startswith("export "):
            key = key[len("export ") :].strip()
        if fmt == "yaml" and key.startswith("- "):
            key = key[2:].strip()

        quote, inner = _strip_quotes(value.strip())
        leading = value[: len(value) - len(value.lstrip())]

        rule = _rule_for(key, settings.config)
        if rule is not None:
            kind, name = rule
            if args.explain:
                report.explanations.append((source, lineno, _rule_explanation(key, kind, name)))
            if args.audit:
                if kind == "hide":
                    report.findings.append((source, lineno, _rule_finding(key, name)))
                continue
            body = args.replacement if kind == "hide" else inner
            out.append(f"{prefix}{left}{separator}{leading}{quote}{body}{quote}")
            continue

        if args.explain:
            report.explanations.append(
                (
                    source,
                    lineno,
                    explain_pair(key, inner, mode=settings.mode, entropy_threshold=settings.entropy_threshold),
                )
            )

        if args.audit:
            finding = audit_pair(key, inner, mode=settings.mode, entropy_threshold=settings.entropy_threshold)
            if finding is not None:
                report.findings.append((source, lineno, finding))
            if len(inner) > _MAX_DETECT_LENGTH and finding is None:
                report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
            continue

        redacted, unscanned = _redact_value(key, inner, settings, args.replacement)
        if unscanned:
            report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
        out.append(f"{prefix}{left}{separator}{leading}{quote}{redacted}{quote}")

    return out


def _process_json(text: str, source: str, args: argparse.Namespace, settings: _Settings, report: _Report) -> list[str]:
    """Redact a JSON document by walking the parsed structure."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        report.problem(source, exc.lineno, f"invalid JSON ({exc.msg}); nothing printed")
        return []

    rules = settings.config.has_rules

    if rules:
        for key in _shown_non_strings(data, settings.config):
            report.notes.append(f"show rule {key!r} names a value that is not a string; ignored")

    if args.explain:
        for explanation in explain_dict(data, mode=settings.mode, entropy_threshold=settings.entropy_threshold):
            # Rules match the plain key, never the display path: `hide =
            # ["region"]` has to fire on services[0].db.region, and an account
            # that says `clean` while stdout says [REDACTED] is worse than no
            # account at all.
            rule = _rule_covering(explanation, settings.config) if rules else None
            resolved = _rule_explanation(explanation.key, *rule) if rule else explanation
            report.explanations.append((source, 0, resolved))

    if args.audit:
        reported: set[str] = set()
        for finding in audit_dict(data, mode=settings.mode, entropy_threshold=settings.entropy_threshold):
            # Match on the rule kind, not on the entry spelling: matching is
            # case-insensitive everywhere else, and an --audit that reported a
            # key the redact pass prints would disagree with itself.
            rule = _rule_for(finding.key, settings.config) if rules else None
            if rule is not None and rule[0] == "show":
                continue
            reported.add(finding.key.lower())
            report.findings.append((source, 0, finding))
        if rules:
            # Only keys no layer already reported. A hide rule on a key
            # detection also catches is one finding, not two — anything
            # counting or diffing --audit output would see the duplicate.
            for key in _hidden_keys(data, settings.config):
                if key.lower() in reported:
                    continue
                reported.add(key.lower())
                report.findings.append((source, 0, _rule_finding(key, settings.config.hides(key) or "")))
        return []

    redacted = redact_dict(
        data, mode=settings.mode, replacement=args.replacement, entropy_threshold=settings.entropy_threshold
    )
    if rules:
        redacted = _apply_rules_to_structure(data, redacted, settings.config, args.replacement)
    return json.dumps(redacted, indent=2).splitlines()


def _apply_rules_to_structure(
    original: object, redacted: object, config: Config, replacement: str, _depth: int = 0
) -> object:
    """Overlay config rules onto an already-redacted structure.

    Walks the original and the redacted copy together: a hide rule replaces the
    value, a show rule restores the original, and everything else keeps what
    detection decided. Working from redact_dict's output rather than
    reimplementing it keeps partial URL redaction and the depth caps intact.

    A hide rule covers whatever the key holds — an object, an array, a port
    number — and replaces the whole of it. Redacting only the leaves inside
    would leave the shape of a hidden subtree on display, and its key names
    are usually the half worth hiding. A show rule is the asymmetric case: it
    is honoured for a string and refused for anything else, because vouching
    for one named key is a decision about one value, and vouching for a
    subtree is a decision about values nobody has added yet.
    """
    if _depth >= _JSON_RULE_MAX_DEPTH:
        return redacted

    if isinstance(original, dict) and isinstance(redacted, dict):
        result: dict[object, object] = {}
        for key, value in original.items():
            key_str = str(key)
            current = redacted.get(key)
            rule = _rule_for(key_str, config)
            if rule is not None and rule[0] == "hide":
                result[key] = replacement
            elif rule is not None and isinstance(value, str):
                result[key] = value
            elif isinstance(value, (dict, list)):
                result[key] = _apply_rules_to_structure(value, current, config, replacement, _depth + 1)
            else:
                result[key] = current
        return result

    if isinstance(original, list) and isinstance(redacted, list) and len(original) == len(redacted):
        return [
            _apply_rules_to_structure(item, redacted[i], config, replacement, _depth + 1)
            for i, item in enumerate(original)
        ]

    return redacted


def _hidden_keys(data: object, config: Config, _depth: int = 0) -> list[str]:
    """Keys a hide rule covers, so --audit reports them as findings.

    Whatever the key holds, matching redaction: a hidden object is one
    finding for the object, not a walk of everything inside it.
    """
    if _depth >= _JSON_RULE_MAX_DEPTH:
        return []
    found: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if config.hides(str(key)) is not None:
                found.append(str(key))
            elif isinstance(value, (dict, list)):
                found.extend(_hidden_keys(value, config, _depth + 1))
    elif isinstance(data, list):
        for item in data:
            found.extend(_hidden_keys(item, config, _depth + 1))
    return found


def _process_dsn(text: str, source: str, args: argparse.Namespace, settings: _Settings, report: _Report) -> list[str]:
    """Redact bare connection strings, one per line."""
    out: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            out.append(raw)
            continue

        rule = _rule_for("dsn", settings.config)
        if rule is not None:
            kind, name = rule
            if args.explain:
                report.explanations.append((source, lineno, _rule_explanation("dsn", kind, name)))
            if args.audit:
                if kind == "hide":
                    report.findings.append((source, lineno, _rule_finding("dsn", name)))
                continue
            out.append(args.replacement if kind == "hide" else raw.strip())
            continue

        if args.explain:
            report.explanations.append(
                (
                    source,
                    lineno,
                    explain_pair("dsn", raw.strip(), mode=settings.mode, entropy_threshold=settings.entropy_threshold),
                )
            )
        if args.audit:
            finding = audit_pair("dsn", raw.strip(), mode=settings.mode, entropy_threshold=settings.entropy_threshold)
            if finding is not None:
                report.findings.append((source, lineno, finding))
            continue
        redacted, unscanned = _redact_value("dsn", raw.strip(), settings, args.replacement)
        if unscanned:
            report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
        out.append(redacted)
    return out


def _read(path: str, report: _Report) -> str | None:
    """Read a file or stdin, reporting IO problems rather than raising."""
    if path == "-":
        return sys.stdin.read()
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        report.problem(path, 0, f"cannot read: {exc}")
        return None


def _print_explanations(report: _Report) -> None:
    """Write the accounting to stderr so stdout stays a usable redacted stream.

    Location is shown only when more than one input contributed, so the common
    single-file case stays readable.
    """
    if not report.explanations:
        return

    print("secretscreen: explain — key names and reasons only, no values", file=sys.stderr)

    sources = {source for source, _, _ in report.explanations}
    show_location = len(sources) > 1
    labels = [
        f"{source}:{lineno}" if show_location and lineno else source if show_location else ""
        for source, lineno, _ in report.explanations
    ]

    state_width = max(len(e.state) for _, _, e in report.explanations)
    key_width = min(max(len(e.key) for _, _, e in report.explanations), _EXPLAIN_KEY_MAX_WIDTH)
    label_width = max((len(label) for label in labels), default=0)

    for label, (_, _, explanation) in zip(labels, report.explanations, strict=True):
        prefix = f"{label:<{label_width}}  " if show_location else ""
        layer = explanation.layer or "-"
        # The width caps the column; it never truncated the key that overran
        # it, so one deep path still pushed every reason off the screen. The
        # tail is the informative half of a path — keep that end.
        key = explanation.key
        if len(key) > key_width:
            key = "…" + key[-(key_width - 1) :]
        columns = f"{explanation.state:<{state_width}}  {key:<{key_width}}  {layer:<{_EXPLAIN_LAYER_WIDTH}}"
        print(f"  {prefix}{columns}  {explanation.reason}", file=sys.stderr)


# Kept in the help rather than the README: the exit codes are what a script
# author needs, and --audit's guarantee is what makes it safe to paste output
# into a bug report. Neither is discoverable from the flag list alone.
_EPILOG = """\
examples:
  secretscreen app.env                  redact and print, cat-like
  docker exec app env | secretscreen    screen a running container's environment
  grep -rn TOKEN . | secretscreen       grep's file:line: prefixes are stripped, then restored
  secretscreen --audit config.json      report findings only; never prints a value
  secretscreen --explain app.env        account for every value, including the untouched ones
  secretscreen --show DEPLOY_KEY x.env  vouch for one key by exact name

exit codes:
  0  nothing to report
  1  --audit found something
  2  a line could not be parsed, a file could not be read, a config is invalid,
     or no input was given

--audit prints key names, layers, and reasons — never a value, in either mode.
--explain does the same for values that were left alone.

Best-effort defense-in-depth, not a security boundary. Lines that cannot be
structurally parsed are redacted and reported on stderr; nothing unparsed
reaches stdout verbatim."""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscreen",
        description="Redact secrets from config-shaped data and print the result.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("files", nargs="*", metavar="FILE", help="files to redact; reads stdin when omitted or '-'")
    parser.add_argument("--audit", action="store_true", help="report findings without values; exit 1 if any are found")
    parser.add_argument("--format", choices=FORMATS, default="auto", help="input format (default: auto-detect)")
    parser.add_argument("--aggressive", action="store_true", help="add entropy detection; more false positives")
    parser.add_argument(
        "--explain",
        action="store_true",
        help="report on stderr what happened to every value and why, including the ones left alone",
    )
    parser.add_argument("--replacement", default=REDACTED, help=f"replacement text (default: {REDACTED})")
    parser.add_argument(
        "--show",
        action="append",
        metavar="KEY",
        help="never redact this key; exact name, no wildcards. Repeatable.",
    )
    parser.add_argument(
        "--hide",
        action="append",
        metavar="GLOB",
        help="always redact keys matching this glob. Repeatable.",
    )
    parser.add_argument("--entropy-threshold", type=float, metavar="N", help="entropy cutoff (default: 4.5)")
    # Mutually exclusive rather than one silently winning: --no-config says
    # "ignore all config files", and honouring one anyway is the difference
    # between a flag that did nothing and a flag that did the opposite.
    sources = parser.add_mutually_exclusive_group()
    sources.add_argument(
        "--config",
        metavar="FILE",
        help="use only this config file: skips discovery and the user config, and is trusted",
    )
    sources.add_argument("--no-config", action="store_true", help="ignore all config files")
    parser.add_argument(
        "--trust-config",
        action="store_true",
        help="honour show entries from discovered project configs (they are ignored by default)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    # None rather than NORMAL: config may set the mode, and only an explicit
    # flag should override it.
    args.mode = Mode.AGGRESSIVE if args.aggressive else None

    # No files and a terminal on stdin: nothing was given to read and nothing
    # is coming. Blocking on the terminal there is indistinguishable from a
    # hang, and a cat-replacement that appears to hang on the first bare run is
    # one nobody runs twice. An explicit `-` still reads the terminal — that is
    # someone asking for it on purpose.
    if not args.files and sys.stdin.isatty():
        parser.print_help(sys.stderr)
        print(
            "\nsecretscreen: no input — pass a FILE, pipe something in, or use '-' to read the terminal.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    report = _Report()
    # One loader for the run: discovery repeats per input, and the files it
    # finds do not change underneath a single invocation.
    loader = _config.Loader()
    sources = args.files or ["-"]
    lines: list[str] = []

    for path in sources:
        text = _read(path, report)
        if text is None:
            continue

        try:
            settings = _resolve_settings(None if path == "-" else path, args, report, loader)
        except ConfigError as exc:
            # Fatal rather than skipped: continuing would screen this input with
            # rules the user believes are in force and are not.
            print(f"secretscreen: {exc}", file=sys.stderr)
            return EXIT_ERROR

        label = "<stdin>" if path == "-" else path
        fmt = args.format if args.format != "auto" else _detect_format(text, None if path == "-" else path)

        if fmt == "json":
            lines.extend(_process_json(text, label, args, settings, report))
        elif fmt == "dsn":
            lines.extend(_process_dsn(text, label, args, settings, report))
        else:
            lines.extend(_process_lines(text, fmt, label, args, settings, report))

    if args.audit:
        for source, lineno, finding in report.findings:
            location = f"{source}:{lineno}" if lineno else source
            print(f"{location}: {finding.key}: {finding.layer} ({finding.reason})")
    else:
        for line in lines:
            print(line)

    for note in dict.fromkeys(report.notes):
        print(f"secretscreen: {note}", file=sys.stderr)

    _print_explanations(report)

    for problem in report.problems:
        print(f"secretscreen: {problem}", file=sys.stderr)

    if report.problems:
        return EXIT_ERROR
    if args.audit and report.findings:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
