# Security Audit Report — 2026-04-05

## Summary

| | Critical | High | Medium | Low |
|--|----------|------|--------|-----|
| **Found** | 0 | 1 | 4 | 3 |

- **Language/Framework**: Python 3.11-3.13, pure library (no network surface)
- **Files Audited**: 14 / 14 (all source + CI/CD)
- **Scope**: deep
- **Focus**: all

---

## Findings

### [HIGH-1] Detection bypass via deeply nested JSON — `_parsers.py:155`

**Category**: Logic / Detection bypass
**CVSS estimate**: 7.1
**Description**: `_flatten` in `_parsers.py` recurses unboundedly into nested dicts/lists. At ~1000 levels of nesting (~7KB payload, well under the 64KB cap), Python raises `RecursionError`. The bare `except Exception` in `extract_pairs` silently swallows it and returns `[]`. With no pairs extracted, structured parsing is skipped. If the value doesn't match a gitleaks format pattern, the secret passes through unredacted.

**Data flow**:
```
redact_pair("config", crafted_json)
  → _detect(depth=0)
  → extract_pairs(value)
  → _parse_json → json.loads (succeeds)
  → _flatten(data) → RecursionError
  → caught by bare except → pairs = []
  → structured parsing skipped
  → format detection on raw JSON string → no match
  → return original value unredacted
```

**Proof of concept**:
```python
import json
from secretscreen import redact_pair


def nested_json(depth, key, val):
    d = {key: val}
    for _ in range(depth):
        d = {"x": d}
    return json.dumps(d)


payload = nested_json(1000, "cookie", "session_abc123xyz")  # ~7KB
result = redact_pair("config", payload)
assert payload == result  # passes — secret unredacted
```

**Impact**: An adversary who controls the structure of data being screened can reliably suppress detection. Affects logging/audit pipelines where secretscreen is used to sanitize output.

**Fix**: Add a depth parameter to `_flatten` with a cap (e.g., 50). When exceeded, return pairs collected so far rather than raising. Alternatively, use iterative flattening with an explicit stack.

---

### [MEDIUM-1] Secret plaintext exposed in Finding._parsed_pairs — `_core.py:42`

**Category**: Data exposure
**CVSS estimate**: 5.3
**Description**: When `audit_pair`/`audit_dict` fires via structured parsing, the returned `Finding` carries `_parsed_pairs` containing all extracted key-value pairs — including the plaintext secret. The leading underscore is convention, not access control. Any caller that logs or serializes Finding objects leaks the secret the library was meant to detect.

**Data flow**:
```
audit_pair("config", '{"password": "sup3r_s3cr3t"}')
  → _detect → structured parsing
  → Finding(_parsed_pairs=(("password","sup3r_s3cr3t"),))
  → returned to caller → logged/serialized
```

**Proof of concept**:
```python
from secretscreen import audit_pair

finding = audit_pair("config", '{"password": "sup3r_s3cr3t"}')
print(finding._parsed_pairs)  # (('password', 'sup3r_s3cr3t'),)
```

**Impact**: Audit consumers that serialize findings inadvertently log the secrets secretscreen detected.

**Fix**: Exclude `_parsed_pairs` from the dataclass `__repr__` and `__str__`. Consider making it truly private by not exposing it on the Finding at all — pass it through the internal call chain instead (e.g., return a tuple of (Finding, cached_pairs) from _detect, consumed only by _apply_redaction).

---

### [MEDIUM-2] Safe suffix swallows subsequent dangerous patterns — `_keys.py:109`

**Category**: Logic / Detection bypass
**CVSS estimate**: 5.0
**Description**: `matches_key_pattern` iterates patterns in declaration order. When the first matching pattern triggers a safe-suffix hit, the function returns `None` immediately — without checking subsequent patterns. A key like `cookie_secret_url` matches `cookie` first, hits the `_url` safe suffix, and returns `None` — never reaching the `secret` pattern.

**Data flow**:
```
matches_key_pattern("cookie_secret_url")
  → pattern "cookie" matches (index 9)
  → safe suffix "_url" matches → return None
  → pattern "secret" (index 13) never checked
```

**Proof of concept**:
```python
from secretscreen._keys import matches_key_pattern

matches_key_pattern("cookie_secret_url")  # → None (should be "secret")
matches_key_pattern("credential_url")  # → None
matches_key_pattern("password_token_url")  # → None
```

**Impact**: Keys containing both a dangerous substring and a safe suffix bypass Layer 1 entirely. If the value also lacks a recognizable format (Layer 3), the secret passes through.

**Fix**: Change logic: if *any* matching pattern has no safe-suffix override, return that pattern. Only return None if *all* matching patterns are overridden by safe suffixes.

---

### [MEDIUM-3] No size cap before format detection — `_formats.py:104`

**Category**: Denial of service
**CVSS estimate**: 4.8
**Description**: `MAX_PARSE_LENGTH = 65536` guards only `extract_pairs`. `matches_known_format` has no size limit — it runs keyword scans and up to 221 regex matches on arbitrarily large inputs. At 50MB, this takes ~7.7s per call.

**Impact**: In hot-path usage (middleware, log processors), an adversary controlling input values can cause thread starvation.

**Fix**: Add a size cap at the top of `_detect` (before any layer), returning early for values exceeding a reasonable maximum (e.g., 1MB).

**Correction (2026-07-27)**: The fix as prescribed above was wrong and was implemented as
written. Returning early *before any layer* skips Layer 1, which matches on the key name and
never touches the value — so `AWS_SECRET_ACCESS_KEY=<2MB blob>` passed through completely
unredacted and `audit_pair` reported no finding. Trading a 7.7s CPU stall for a silent secret
leak is the wrong direction for a redaction library.

**Second correction (2026-07-27)**: the 1MB threshold was also wrong, and for the same
reason the finding understated the problem — both were measured on benign input. The
"~7.7s at 50MB" figure above reproduces (I measured 11.7s for 50MB of `"x"`), but a run of
one character is not the worst case. On random high-entropy text — what a secret-shaped
blob actually looks like — at least one vendored pattern backtracks and cost goes roughly
quadratic above ~128KB:

| size | `"x" * n` | random |
|------|-----------|--------|
| 64KB | — | 0.57s |
| 128KB | — | 1.00s |
| 256KB | — | 14s |
| 1MB | 0.195s | **107s** |
| 10MB | 1.8s | 20.7 min |

A 1MB cap therefore admitted exactly the input that hurts most: a value one byte under it
pinned a core for nearly two minutes. Lowered to 64KB (0.57s worst case), matching
`MAX_PARSE_LENGTH`, which already bounded Layer 2 — so only Layers 3–5 narrow, and only
for values large enough to be data dumps rather than config. Pinned by
`test_worst_case_input_at_the_cap_stays_sub_second`.

Not yet identified: *which* rule backtracks. Tracked with the gitleaks sync work in #1.

The cap now gates Layers 2–5 only; Layer 1 always runs. Residual gap, accepted and tested
(`test_oversized_value_under_non_denylisted_key_is_a_known_gap`): an oversized value under a key
that Layer 1 does not match — including safe-suffix keys like `DATABASE_URL`, which depend on
Layer 4's value scan — is not scanned and passes through. Callers that print values must surface
the skip rather than let unscanned output look screened.

---

### [MEDIUM-4] redact_dict/audit_dict crash on deeply nested dicts — `_core.py:296`

**Category**: Denial of service
**CVSS estimate**: 4.3
**Description**: `_redact_recursive` and `_audit_recursive` recurse on Python dicts/lists without depth guards. Unlike `_detect` (which has `_MAX_DETECT_DEPTH = 3`), these functions are unbounded. A dict nested ~1000 levels deep causes uncaught `RecursionError`.

**Proof of concept**:
```python
from secretscreen import redact_dict

data = {}
current = data
for _ in range(1000):
    current["x"] = {}
    current = current["x"]
current["leaf"] = "val"
redact_dict(data)  # raises RecursionError
```

**Impact**: Crashes the calling process. Unlike Finding HIGH-1, this is not caught — it propagates.

**Fix**: Add a depth parameter to `_redact_recursive` and `_audit_recursive` with a reasonable cap (e.g., 100). Return the value unmodified when exceeded.

---

### [LOW-1] JDBC URLs bypass credential detection — `_urls.py:17`

**Category**: Detection bypass (edge case)
**Description**: `has_url_credentials` uses `urlsplit`, which parses `jdbc:postgresql://user:pass@host/db` with scheme `jdbc` and treats the rest as opaque. `parsed.password` is `None`. Common in Docker Compose files via `SPRING_DATASOURCE_URL`.

**Fix**: Pre-strip known URL prefixes (`jdbc:`, `odbc:`) before parsing.

---

### [LOW-2] IPv6 URL redaction produces invalid URLs — `_urls.py:39`

**Category**: Output correctness
**Description**: `redact_url_password` uses `parsed.hostname` which strips IPv6 brackets. The reconstructed URL is invalid for IPv6 addresses.

**Fix**: Re-add brackets when hostname contains `:`.

---

### [LOW-3] Non-str values pass through unredacted — `_core.py:84`

**Category**: Type handling
**Description**: `redact_pair` returns non-str values (bytes, int) unchanged. The return type annotation says `str`. Edge case — env vars are always str — but parsed YAML can produce bytes.

**Fix**: Convert bytes to str before detection, or document the limitation.

---

### CI/CD Findings (validated against current main)

**CI/CD-1: INVALIDATED** — Actions pinning (Critical). All actions are pinned to commit SHAs on current main. The agent read stale local files.

**CI/CD-2: CONFIRMED (Medium)** — Dependabot auto-merge has no CI gate. `dependabot-automerge.yml` enables auto-merge for all dependabot PRs without checking CI status. GitHub's auto-merge feature respects branch protection required checks *if configured*, but this is a defense-in-depth gap. Dependabot cooldowns (30d/7d/3d) partially mitigate by delaying compromised version adoption.

**CI/CD-3: CONFIRMED (Medium)** — `id-token: write` at workflow level in publish.yml. Grants OIDC capability to `pip install build` step, not just the publish step. If a build dependency is compromised, it could request an OIDC token and publish directly. Fix: split into two jobs — build (no id-token) and publish (id-token: write).

**CI/CD-4: LOW** — CodeQL `security-events: write` on fork PRs. Low practical impact.

---

## Attack Surface Summary

- **Entry points**: `redact_pair`, `redact_dict`, `audit_pair`, `audit_dict` — all accept arbitrary strings from callers
- **Auth boundaries**: None (pure library)
- **Trust boundaries**: Caller-provided key-value pairs are untrusted input; vendored gitleaks.toml is trusted

## Recommendations

1. Add depth guard to `_flatten` (HIGH-1 fix)
2. Remove `_parsed_pairs` from Finding dataclass — pass through internal call chain only (MEDIUM-1 fix)
3. Fix safe-suffix logic to check all matching patterns (MEDIUM-2 fix)
4. Add global size cap in `_detect` (MEDIUM-3 fix)
5. Add depth guard to `_redact_recursive` / `_audit_recursive` (MEDIUM-4 fix)
6. Split publish.yml into build + publish jobs (CI/CD-3 fix)

## Files Audited

All 6 source modules, `__init__.py`, 6 test files, 5 workflow files, `pyproject.toml`, `dependabot.yml`, `SECURITY.md` — complete coverage.
