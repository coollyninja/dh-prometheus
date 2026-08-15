# Security policy

Please report suspected vulnerabilities privately through GitHub's security-advisory feature for
this repository. Do not open a public issue containing secrets, internal topology, query contents,
series labels, or exploit details.

## Deployment expectations

- Use a dedicated read-only Prometheus or reverse-proxy identity.
- Keep bearer values outside repository configuration and provide them through restricted files.
- Keep TLS verification enabled. Use `ca_file` for a private certificate authority.
- Restrict network egress to the configured Prometheus origin.
- Put real endpoints, PromQL, labels, job names, and policy in a private site overlay.

The plugin refuses redirects and never includes upstream response bodies in errors. Clients can
select only configured logical aliases and cannot supply PromQL or upstream request parameters.
Version 0.1.x implements no mutation actions.
