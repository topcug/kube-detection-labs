# Kube Detection Labs

Open detection content for Kubernetes and cloud-native security teams.

Each lab covers one real threat scenario: what it looks like at runtime, why it matters, how to detect it with Falco, how to triage the alert, and how to remediate the underlying condition.

All content is free, MIT licensed, and designed to be used directly — not just read.

---

## What is in this repo

```
labs/          — Detection labs (one folder per scenario)
falco-rules/   — Standalone Falco rules, ready to load
sigma-rules/   — Sigma-format detection specs for backend portability
docs/          — Supporting documentation (setup guides, glossary)
scripts/       — Helper scripts (test simulation, rule validation)
```

---

## Labs

| Lab | Threat | MITRE | Severity |
|-----|--------|-------|----------|
| [LAB-001](labs/lab-001-shell-in-container/) | Shell spawned in container | T1059 | High |
| [LAB-002](labs/lab-002-privileged-container/) | Privileged container started | T1611 | Critical |
| [LAB-003](labs/lab-003-cryptominer-detection/) | Cryptominer process detected | T1496 | Critical |
| [LAB-004](labs/lab-004-sensitive-file-read/) | Sensitive file read (/etc/shadow, SA token) | T1552 | High |
| [LAB-005](labs/lab-005-kubectl-exec/) | kubectl exec into running container | T1609 | High |
| [LAB-006](labs/lab-006-reverse-shell/) | Reverse shell from container | T1059 | Critical |
| [LAB-007](labs/lab-007-data-exfiltration/) | Data exfiltration via curl/wget | T1041 | High |
| [LAB-008](labs/lab-008-secret-enumeration/) | Kubernetes Secret enumeration via API | T1552.007 | Critical |
| [LAB-009](labs/lab-009-privilege-escalation/) | Privilege escalation via setuid binary | T1548 | High |
| [LAB-010](labs/lab-010-mutable-image-tag/) | Container running from mutable image tag | T1525 | Medium |
| [LAB-011](labs/lab-011-unexpected-outbound-connection/) | Unexpected outbound network connection | T1071 | High |
| [LAB-012](labs/lab-012-host-path-escape/) | Container escape via host path mount | T1611 | Critical |

New labs are added regularly. Watch the repo to get notified.

---

## How to use this

### Read a lab

Each lab folder contains a `README.md` with:
- Threat scenario
- Why it matters
- Attack simulation steps
- Falco detection rule
- Triage guide
- Remediation (immediate + structural)
- False positive notes

### Load a Falco rule

Rules are also available as standalone files in `falco-rules/`. To load a single rule:

```bash
falco -r falco-rules/shell-in-container.yaml
```

To load all rules:

```bash
falco -r falco-rules/
```

### Use a Sigma rule

Sigma rules in `sigma-rules/` can be converted to your SIEM's format using [sigma-cli](https://github.com/SigmaHQ/sigma-cli):

```bash
sigma convert -t splunk sigma-rules/shell-in-container.yml
sigma convert -t elastic-dsl sigma-rules/shell-in-container.yml
```

---

## Requirements

- Kubernetes cluster (local: kind, k3s, minikube — or any managed cluster)
- [Falco](https://falco.org/docs/getting-started/) installed as a DaemonSet or in eBPF mode
- `kubectl` access to your test cluster
- Optional: Kubernetes audit logging enabled for API-level detections

---

## MITRE ATT&CK coverage

This repo maps detections to the [MITRE ATT&CK Containers matrix](https://attack.mitre.org/matrices/enterprise/containers/).

Current coverage:

| Tactic | Techniques covered |
|--------|--------------------|
| Execution | T1059, T1609 |
| Persistence | T1525 |
| Privilege Escalation | T1548, T1611 |
| Credential Access | T1552, T1552.007 |
| Exfiltration | T1041 |
| Command and Control | T1071 |
| Impact | T1496 |

Coverage expands with each new lab.

---

## Contributing

Labs follow a standard structure. To contribute a new lab:

1. Copy the `labs/_template/` folder
2. Fill in all sections of the README
3. Add a corresponding Falco rule to `falco-rules/`
4. Add a Sigma rule to `sigma-rules/` if applicable
5. Open a PR with a clear description of the threat scenario

See [docs/contributing.md](docs/contributing.md) for the full guide.

---

## License

MIT. Use freely, fork, adapt, build on top of.

---

## Related

- [ClarifyIntel](https://clarifyintel.com) — detection packs, Pod Security rollout, and supply chain reviews for cloud-native teams
- [Kube Detection Labs](https://clarifyintel.com/labs/) — web version of these labs with additional context
- [Falco](https://falco.org) — the runtime security tool these rules are built for
- [MITRE ATT&CK Containers](https://attack.mitre.org/matrices/enterprise/containers/) — the threat framework these labs map to
