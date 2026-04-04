# Contributing to Kube Detection Labs

Thanks for your interest in contributing. Labs are the core of this repo — each one represents a real, documented threat scenario with working detection content.

## Lab structure

Every lab lives in `labs/<lab-id>/` and contains a single `README.md` with these sections in order:

```
# LAB-NNN: <Title>

MITRE / Severity / Tactic header

## Threat scenario
## Why this matters
## Attack simulation
## Falco detection rule
## Triage guide
## Remediation
## False positive notes
## References
```

All sections are required. Do not skip triage or false positive notes — these are what make the labs useful in production.

## Adding a new lab

1. Pick an unused lab number (check existing labs)
2. Copy `labs/_template/` to `labs/lab-NNN-your-name/`
3. Fill in all sections of README.md
4. Add the standalone Falco rule to `falco-rules/your-rule-name.yaml`
5. Add a Sigma rule to `sigma-rules/your-rule-name.yml`
6. Add your lab to the table in the root README.md
7. Open a PR with a short description of the threat scenario

## Rule quality bar

Falco rules must:
- Use precise conditions (not broad catch-alls)
- Include a `trusted_*` or `known_*` list for exceptions
- Have output fields that identify container, namespace, pod, image
- Be tagged with the MITRE technique (e.g., `T1059`)

Sigma rules must:
- Follow [Sigma rule format](https://github.com/SigmaHQ/sigma/wiki/Rule-Format)
- Reference the Falco rule name in the detection condition
- Include a realistic `falsepositives` section

## Style

- Write in plain English. No jargon without explanation.
- Triage steps should be numbered and actionable.
- Remediation should include both immediate (kubectl commands) and structural (policy/RBAC) steps.
- False positive notes should be a table with source, pattern, and mitigation.

## Questions

Open an issue or email hello@clarifyintel.com.
