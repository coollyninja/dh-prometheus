# dh-prometheus

`dh-prometheus` is the read-only Prometheus integration for
[Deckhand](https://github.com/coollyninja/deckhand). It turns private, operator-defined
Prometheus checks into logical status domains and one typed observation action. Stream Deck clients
select a configured alias; they cannot submit PromQL, label filters, URLs, or credentials.

## Check types

- `scalar`: runs one configured instant query and compares its single finite value with a typed
  threshold.
- `alerts`: counts matching pending and firing alerts using exact labels configured by the site.
- `targets`: summarizes active and healthy scrape targets, optionally for one configured job.

Returned details contain only scalar values and aggregate counts. Series labels, target addresses,
alert annotations, and query expressions are not returned to clients.

## Configuration

```yaml
schema_version: 1
plugins:
  dh-prometheus:
    enabled: true
    runtime:
      timeout_seconds: 8
      max_concurrency: 4
      requests_per_second: 10
      burst: 10
      failure_threshold: 3
      recovery_seconds: 30
    config:
      endpoint: https://prometheus.example.invalid
      bearer_token_file: /run/secrets/deckhand/prometheus-token
      verify_tls: true
      ca_file: /run/secrets/deckhand/prometheus-ca.pem
      timeout_seconds: 5
      checks:
        scrape_health:
          kind: scalar
          expression: scalar(sum(up) > 0)
          operator: eq
          threshold: 1
          stale_after_seconds: 30
        critical_alerts:
          kind: alerts
          match_labels:
            severity: critical
        target_health:
          kind: targets
```

The endpoint must be an HTTPS origin without credentials, a path, query, or fragment. Token and CA
paths must be absolute. Real expressions, label values, job names, endpoints, and credentials belong
in a private `deckhand-site-<site>` repository.

Use a dedicated read-only Prometheus identity or authenticated reverse-proxy identity. Restrict
egress to the configured origin and keep TLS verification enabled.

## Development

```bash
uv sync --locked --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv run python scripts/check_public_surface.py
```

The plugin is MIT licensed. Its initial core dependency is pinned to the exact Deckhand resilience
contract commit; this changes to a released compatibility range after the first stable core release.
