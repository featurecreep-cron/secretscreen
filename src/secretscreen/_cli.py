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

FORMATS = ("env", "json", "ini", "dsn", "auto")

_JSON_EXTENSIONS = {".json"}
_INI_EXTENSIONS = {".ini", ".cfg", ".conf", ".properties"}
_ENV_EXTENSIONS = {".env", ".envrc"}

# Column widths for --explain output. The key column is capped so one very long
# key (a grep prefix, a deep JSON path) cannot push every reason off the screen.
_EXPLAIN_KEY_MAX_WIDTH = 44
_EXPLAIN_LAYER_WIDTH = 17

# Separator characters by format, in precedence order.
_SEPARATORS = {"env": ("=",), "ini": ("=", ":")}
_COMMENT_PREFIXES = {"env": ("#",), "ini": ("#", ";")}


class _Report:
    """Accumulates findings and problems across all inputs.

    Not a dataclass: the architecture tests require every dataclass in the
    package to be frozen, and this is mutable by nature.
    """

    def __init__(self) -> None:
        self.findings: list[tuple[str, int, Finding]] = []
        self.problems: list[str] = []
        self.explanations: list[tuple[str, int, Explanation]] = []

    def problem(self, source: str, lineno: int, message: str) -> None:
        self.problems.append(f"{source}:{lineno}: {message}")


def _strip_quotes(value: str) -> tuple[str, str]:
    """Split a value into (quote_char, inner). Quote char is '' when unquoted."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[0], value[1:-1]
    return "", value


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
        if extension in _ENV_EXTENSIONS or lowered.split("/")[-1].startswith(".env"):
            return "env"

    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "json"
    for line in text.splitlines():
        bare = line.strip()
        if bare.startswith("[") and bare.endswith("]"):
            return "ini"
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

    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()

        if not stripped or stripped.startswith(comments):
            out.append(raw)
            continue

        if fmt == "ini" and stripped.startswith("[") and stripped.endswith("]"):
            out.append(raw)
            continue

        positions = [raw.find(sep) for sep in separators if raw.find(sep) != -1]
        if not positions:
            # Structurally unparseable. Redact rather than echo it — an unparsed
            # line is exactly the one we cannot vouch for.
            report.problem(source, lineno, "no key=value separator; line redacted unscanned")
            out.append(args.replacement)
            continue

        split_at = min(positions)
        separator = raw[split_at]  # preserve ':' vs '=' rather than normalising
        # `left` is echoed verbatim so that spacing and any `export ` prefix survive
        # the round trip; only the detection key is normalised.
        left, value = raw[:split_at], raw[split_at + 1 :]
        key = left.strip()
        if fmt == "env" and key.startswith("export "):
            key = key[len("export ") :].strip()

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
        out.append(f"{left}{separator}{leading}{quote}{redacted}{quote}")

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
        columns = f"{explanation.state:<{state_width}}  {explanation.key:<{key_width}}  {layer:<{_EXPLAIN_LAYER_WIDTH}}"
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
