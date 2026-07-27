# secretscreen

[![CI](https://github.com/featurecreep-cron/secretscreen/actions/workflows/ci.yml/badge.svg)](https://github.com/featurecreep-cron/secretscreen/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/featurecreep-cron/secretscreen/graph/badge.svg)](https://codecov.io/gh/featurecreep-cron/secretscreen)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/featurecreep-cron/secretscreen/badge)](https://scorecard.dev/viewer/?uri=github.com/featurecreep-cron/secretscreen)
[![License: MIT](https://img.shields.io/github/license/featurecreep-cron/secretscreen)](https://github.com/featurecreep-cron/secretscreen/blob/main/LICENSE)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https%3A%2F%2Fraw.githubusercontent.com%2Ffeaturecreep-cron%2Fsecretscreen%2Fmain%2Fpyproject.toml)](https://www.python.org/downloads/)
[![PyPI](https://img.shields.io/pypi/v/secretscreen)](https://pypi.org/project/secretscreen/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Detect and redact secrets in key-value pairs, dicts, and environment variables.

Best-effort defense-in-depth. Not a security boundary.

## Install

```
pip install secretscreen
```

## Quick start

```python
from secretscreen import redact_pair, redact_dict, audit_dict, Mode

# Single pair
redact_pair("DB_PASSWORD", "hunter2")  # → "[REDACTED]"
redact_pair("APP_NAME", "myapp")  # → "myapp"

# Dict with recursion
redact_dict({"db": {"password": "x", "host": "localhost"}})
# → {"db": {"password": "[REDACTED]", "host": "localhost"}}

# Aggressive mode (adds entropy detection)
redact_dict(env, mode=Mode.AGGRESSIVE)

# Audit mode (structured findings, no mutation)
findings = audit_dict(env)
# → [Finding(key="DB_PASSWORD", reason="key_pattern:password", ...)]

# Custom safe suffixes (keys ending with these are never redacted)
redact_dict(env, safe_suffixes=("_config", "_enabled"))
```

## Command line

The library only helps Python callers. The CLI covers the shell side — `docker exec`, Makefiles, CI logs, anything you are about to paste somewhere.

```
secretscreen tandoor.env                    # redact and print, cat-like
docker exec app env | secretscreen          # scrub a stream before it hits your terminal
secretscreen --audit config.json            # findings only, no values, exit 1 if any
```

```
secretscreen [FILE...]              reads stdin when FILE is omitted or '-'
  --audit                           report findings without values; exit 1 if any
  --format env|json|ini|dsn|auto    default: auto-detect from extension, then content
  --aggressive                      add entropy detection; more false positives
  --replacement TEXT                default: [REDACTED]
```

Redaction is structural, not line-based: it parses the format, so it catches `DB_PASSWORD=hunter2` on the key name and rewrites `postgres://admin:s3cr3t@host/db` to `postgres://admin:[REDACTED]@host/db` without destroying the rest of the line. Comments, blank lines, quoting, `export` prefixes, INI sections and `:` separators all survive the round trip.

**What the exit code means:**

| Code | Meaning |
|------|---------|
| 0 | Everything was parsed and screened |
| 1 | `--audit` found secrets |
| 2 | Something could not be parsed or read — see stderr |

That third case is the one that matters. This is best-effort defense-in-depth, and a cat-replacement is exactly the tool people stop thinking about, so the CLI never prints unparsed content verbatim: a line it cannot structure is replaced with the redaction token, named on stderr, and turns the exit code non-zero. The same applies to values above the 1 MB detection cap — they are reported as unscanned rather than passed off as clean.

If you are scanning a git repository rather than config-shaped data, use [gitleaks](https://github.com/gitleaks/gitleaks) instead. That is a different job.

## Detection layers

1. **Key-name denylist** — substring match against ~30 known secret key patterns
2. **Structured value parsing** — JSON, Python literals, DSN, INI, URL query params
3. **Value-format detection** — 222 known formats via vendored [gitleaks](https://github.com/gitleaks/gitleaks) patterns (MIT)
4. **URL credential detection** — partial redaction of `user:pass@host` URLs
5. **Entropy detection** — Shannon entropy for machine-generated strings (aggressive mode only)

## Contributing

Bug reports and pull requests welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

If you find secretscreen useful, consider [buying us a coffee](https://buymeacoffee.com/featurecreep).

## License

MIT. Gitleaks patterns are also MIT-licensed.
