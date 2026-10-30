# Security Policy

## Supported versions

Only the latest release on the default branch is supported with security fixes.

| Crate | Version |
|-------|---------|
| `bxmap` | 1.0.4 |
| `bxmap-cli` | 1.0.14 |

## Reporting a vulnerability

Do **not** open a public issue for security problems.

Please report vulnerabilities to the maintainers privately by email or via
GitHub's private vulnerability reporting on this repository:
<https://github.com/N0moreher0/bxmap/security/advisories/new>

Include, where possible:
- The version / commit you tested.
- A minimal reproduction input (`.dmp` file or Rust snippet). For binary
  samples, provide a SHA-256 and a download link; do **not** attach real
  memory dumps from live systems.
- Whether the input was untrusted and the impact (panic, OOM, arbitrary
  code execution).

### Scope notes
`bxmap` scans **untrusted bytes** by design (real memory dumps may come
from compromised hosts). Parser bugs (minidump / VMSS) are in scope. Known
limits we accept: entropy reporting is a heuristic, detectors are triage
hints, not malware verdicts.

## Disclosure

We aim to acknowledge reports within 7 days and ship a fix or mitigation
within 30 days.
