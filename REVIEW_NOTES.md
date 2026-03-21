# Code Review Notes

Review of claude-bash-hook (commit 8484a66), Feb 2026.

## Overall

Legitimate, well-structured security tooling. Not malicious. No network access
(except optional `claude-safe` AI advice feature, disabled by default). Fails
safe in most cases. ~80 tests.

## Issues

### `realpath -m` doesn't work on macOS

`rm.rs`, `tee.rs`, and `tar.rs` shell out to `realpath -m --` for path
resolution. macOS `realpath` doesn't support `-m`. The calls silently fail,
causing those checks to fall through to the default permission (passthrough).
Fail-safe, but means rm/tee/tar path validation is inoperative on macOS.

### SQL comment stripping bypass

`sql.rs:strip_sql_comments` doesn't track string literal context. A query like
`SELECT '--'; DROP TABLE users;` causes the `--` inside the string to be treated
as a comment start, hiding the `DROP TABLE`. The cleaned result starts with
`SELECT` and is auto-allowed. Exploiting this requires Claude to construct such a
query, likely via prompt injection in data it reads.

### Python/PHP script analysis is string-matching, not AST-based

`scripts/python.rs` checks for substrings like `"subprocess"`, `"os.system"`.
Bypassable with string concatenation, variable indirection, or encoding. The
default for unrecognized patterns is Ask (not Allow), so the failure mode is
conservative -- it prompts the user rather than auto-allowing.

Same story for `scripts/php.rs` (function allowlist approach).

### Default config is permissive in some areas

- SSH allows all hosts: `{ pattern = "*", permission = "allow" }`
- `docker compose exec` is auto-allowed locally (can do anything inside container)
- Curl host rules include `claude-agent.globalcomixdev.com` (author's domain)

These should be customized before use.

### Minor

- Uncertain flow detection (`main.rs:291-296`) uses substring matching
  (`command.contains(" || ")`) rather than AST analysis. Could false-match on
  strings containing these patterns, but consequence is just extra caution
  (fail-safe).
- `advice.rs` AI advice output is included verbatim in permission reason. If
  `enable_advice` is on and `claude-safe` is compromised, this is a prompt
  injection vector. But feature is opt-in and disabled by default.
