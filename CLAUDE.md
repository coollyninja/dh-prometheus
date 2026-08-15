# dh-prometheus agent context

Read `../CLAUDE.md` before changing this repository.

This is a public, read-only Deckhand plugin. Preserve configured logical checks, fixed Prometheus API
paths, file-based credentials, TLS verification, redirect refusal, minimized output, typed sanitized
errors, and the full adapter lifecycle. Clients must never submit PromQL, label selectors, URLs, or
credentials. Do not add real endpoints, expressions, labels, job names, secrets, or site policy.

Run Ruff, Ruff format check, strict mypy, pytest, and the public-surface scanner before publishing.
