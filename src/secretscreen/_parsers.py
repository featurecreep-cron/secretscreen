"""Structured value parsing for secret detection.

Layer 2: parse values as structured data and recursively check extracted keys.
Supports JSON, Python literals, INI-style, DSN/connection strings, and URL query params.

Security notes:
- Parser exceptions are caught and suppressed (they may contain the secret value
  in the error message, e.g. json.JSONDecodeError includes the problematic string).
- Input size is capped before parsing to prevent DoS on adversarial input.
"""

from __future__ import annotations

import ast
import configparser
import json
import re
from urllib.parse import parse_qs, urlsplit

# Maximum value length to attempt structured parsing on.
# Anything longer is likely a data dump, not a config value.
MAX_PARSE_LENGTH = 65536


def extract_pairs(value: str) -> list[tuple[str, str]]:
    """Extract key-value pairs from a structured value string.

    Tries parsers in order of likelihood. Returns all discovered pairs
    from the first parser that succeeds, or an empty list.
    """
    if len(value) > MAX_PARSE_LENGTH:
        return []

    stripped = value.strip()
    if len(stripped) < 3:
        return []

    # Try each parser, return first success
    for parser in (_parse_json, _parse_python_literal, _parse_dsn, _parse_url_query, _parse_ini):
        try:
            pairs = parser(stripped)
            if pairs:
                return pairs
        except Exception:
            # Suppress all parser errors — they may contain the secret value
            # in the exception message (e.g., json.JSONDecodeError includes
            # the problematic string).
            continue

    return []


def _parse_json(value: str) -> list[tuple[str, str]]:
    """Extract pairs from JSON objects."""
    if not (value.startswith("{") or value.startswith("[")):
        return []

    data = json.loads(value)
    return _flatten(data)


def _parse_python_literal(value: str) -> list[tuple[str, str]]:
    """Extract pairs from Python dict/list literals.

    Uses ast.literal_eval which is safe — only parses literals,
    not arbitrary expressions.
    """
    if not (value.startswith("{") or value.startswith("[") or value.startswith("(")):
        return []

    data = ast.literal_eval(value)
    return _flatten(data)


def _parse_dsn(value: str) -> list[tuple[str, str]]:
    """Extract pairs from DSN/connection strings.

    Handles formats like:
    - host=localhost port=5432 user=admin password=secret dbname=mydb
    - Server=host;Database=db;User Id=admin;Password=secret
    - key1=val1;key2=val2
    """
    pairs: list[tuple[str, str]] = []

    # Semicolon-delimited (SQL Server style)
    if ";" in value and "=" in value and not value.startswith(("http", "{")):
        for segment in value.split(";"):
            segment = segment.strip()
            if "=" in segment:
                k, _, v = segment.partition("=")
                k = k.strip()
                v = v.strip()
                if k and v:
                    pairs.append((k, v))
        if pairs:
            return pairs

    # Space-delimited (PostgreSQL style)
    if " " in value and "=" in value and not value.startswith(("http", "{")):
        dsn_re = re.compile(r"(\w+)\s*=\s*(?:'([^']*)'|(\S+))")
        for match in dsn_re.finditer(value):
            k = match.group(1)
            v = match.group(2) if match.group(2) is not None else match.group(3)
            pairs.append((k, v))

    return pairs


def _parse_url_query(value: str) -> list[tuple[str, str]]:
    """Extract pairs from URL query parameters."""
    if "://" not in value and "?" not in value:
        return []

    parsed = urlsplit(value)
    if not parsed.query:
        return []

    pairs: list[tuple[str, str]] = []
    for k, values in parse_qs(parsed.query).items():
        for v in values:
            pairs.append((k, v))

    # Also extract credentials from the URL itself
    if parsed.username:
        pairs.append(("username", parsed.username))
    if parsed.password:
        pairs.append(("password", parsed.password))

    return pairs


def _parse_ini(value: str) -> list[tuple[str, str]]:
    """Extract pairs from INI-style content."""
    if "=" not in value or "\n" not in value:
        return []

    # configparser needs a section header
    content = value if value.strip().startswith("[") else f"[DEFAULT]\n{value}"

    parser = configparser.ConfigParser()
    parser.read_string(content)

    pairs: list[tuple[str, str]] = []
    for section in parser.sections():
        for k, v in parser.items(section):
            pairs.append((k, v))

    # Also check DEFAULT
    for k, v in parser.defaults().items():
        pairs.append((k, v))

    return pairs


def _flatten(data: object, _prefix: str = "") -> list[tuple[str, str]]:
    """Recursively flatten nested structures into key-value pairs."""
    pairs: list[tuple[str, str]] = []

    if isinstance(data, dict):
        for k, v in data.items():
            key = f"{_prefix}.{k}" if _prefix else str(k)
            if isinstance(v, (dict, list)):
                pairs.extend(_flatten(v, key))
            else:
                pairs.append((key, str(v) if v is not None else ""))

    elif isinstance(data, (list, tuple)):
        for i, item in enumerate(data):
            key = f"{_prefix}[{i}]" if _prefix else f"[{i}]"
            if isinstance(item, (dict, list)):
                pairs.extend(_flatten(item, key))
            else:
                pairs.append((key, str(item) if item is not None else ""))

    return pairs
