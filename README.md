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
redact_pair("DB_PASSWORD", "hunter2")        # → "[REDACTED]"
redact_pair("APP_NAME", "myapp")             # → "myapp"

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
