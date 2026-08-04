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
from typing import TYPE_CHECKING

from secretscreen._core import (
    _MAX_DETECT_LENGTH,
    REDACTED,
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

    from secretscreen._core import Explanation, Finding

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
_EXPLAIN_LAYER_WIDTH = 17

# Separator characters by format, in precedence order.
# YAML separates a mapping key from its value with a colon *and a space*.
# Splitting on a bare colon would cut `- discord://token@id` at the scheme,
# leaving `//token@id` as a value under the key `- discord` — which matches
# nothing, so the token prints. INI keeps the bare colon: `key:value` is valid
# there, and its values do not usually carry URLs.
_SEPARATORS = {"env": ("=",), "ini": ("=", ":"), "yaml": ("=", ": ")}
_COMMENT_PREFIXES = {"env": ("#",), "ini": ("#", ";"), "yaml": ("#",)}


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


def _redact_value(key: str, value: str, mode: Mode, replacement: str) -> tuple[str, bool]:
    """Redact one value. Returns (result, unscanned) — unscanned means the size cap hit."""
    result = redact_pair(key, value, mode=mode, replacement=replacement)
    unscanned = len(value) > _MAX_DETECT_LENGTH and result == value
    return result, unscanned


def _process_lines(text: str, fmt: str, source: str, args: argparse.Namespace, report: _Report) -> list[str]:
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
                redacted, unscanned = _redact_value("", content, args.mode, args.replacement)
                if args.explain:
                    report.explanations.append((source, lineno, explain_pair("", content, mode=args.mode)))
                if args.audit:
                    finding = audit_pair("", content, mode=args.mode)
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

        if args.explain:
            report.explanations.append((source, lineno, explain_pair(key, inner, mode=args.mode)))

        if args.audit:
            finding = audit_pair(key, inner, mode=args.mode)
            if finding is not None:
                report.findings.append((source, lineno, finding))
            if len(inner) > _MAX_DETECT_LENGTH and finding is None:
                report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
            continue

        redacted, unscanned = _redact_value(key, inner, args.mode, args.replacement)
        if unscanned:
            report.problem(source, lineno, f"value exceeds the {_MAX_DETECT_LENGTH}-byte scan cap; not scanned")
        out.append(f"{prefix}{left}{separator}{leading}{quote}{redacted}{quote}")

    return out


def _process_json(text: str, source: str, args: argparse.Namespace, report: _Report) -> list[str]:
    """Redact a JSON document by walking the parsed structure."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        report.problem(source, exc.lineno, f"invalid JSON ({exc.msg}); nothing printed")
        return []

    if args.explain:
        for explanation in explain_dict(data, mode=args.mode):
            report.explanations.append((source, 0, explanation))

    if args.audit:
        for finding in audit_dict(data, mode=args.mode):
            report.findings.append((source, 0, finding))
        return []

    redacted = redact_dict(data, mode=args.mode, replacement=args.replacement)
    return json.dumps(redacted, indent=2).splitlines()


def _process_dsn(text: str, source: str, args: argparse.Namespace, report: _Report) -> list[str]:
    """Redact bare connection strings, one per line."""
    out: list[str] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            out.append(raw)
            continue
        if args.explain:
            report.explanations.append((source, lineno, explain_pair("dsn", raw.strip(), mode=args.mode)))
        if args.audit:
            finding = audit_pair("dsn", raw.strip(), mode=args.mode)
            if finding is not None:
                report.findings.append((source, lineno, finding))
            continue
        redacted, unscanned = _redact_value("dsn", raw.strip(), args.mode, args.replacement)
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscreen",
        description="Redact secrets from config-shaped data and print the result.",
        epilog="Best-effort defense-in-depth, not a security boundary. "
        "Lines that cannot be structurally parsed are redacted and reported on stderr.",
    )
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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    args.mode = Mode.AGGRESSIVE if args.aggressive else Mode.NORMAL

    report = _Report()
    sources = args.files or ["-"]
    lines: list[str] = []

    for path in sources:
        text = _read(path, report)
        if text is None:
            continue

        label = "<stdin>" if path == "-" else path
        fmt = args.format if args.format != "auto" else _detect_format(text, None if path == "-" else path)

        if fmt == "json":
            lines.extend(_process_json(text, label, args, report))
        elif fmt == "dsn":
            lines.extend(_process_dsn(text, label, args, report))
        else:
            lines.extend(_process_lines(text, fmt, label, args, report))

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
