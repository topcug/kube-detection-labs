---
title: "LAB-004: Sensitive File Read Inside a Container"
description: "A process inside a container reads /etc/shadow, /etc/passwd, or service account tokens. Detect credential access attempts before the attacker uses what they found."
date: "2026-04-05"
mitre: "T1552 - Unsecured Credentials"
mitre_url: "https://attack.mitre.org/techniques/T1552/"
severity: "high"
tags: ["Falco", "runtime detection", "credential access", "MITRE T1552", "sensitive files", "container"]
github_path: "labs/lab-004-sensitive-file-read"
---

## Threat scenario

An attacker has gained code execution inside a container — via a remote code execution vulnerability, a compromised dependency, or a supply chain attack. Their first move is reconnaissance: read `/etc/shadow` to harvest password hashes, read `/etc/passwd` to enumerate users, or read the auto-mounted Kubernetes service account token at `/var/run/secrets/kubernetes.io/serviceaccount/token` to authenticate to the API server.

In many environments this goes undetected because the read is a normal filesystem operation. Falco's syscall-level visibility catches it regardless of how it was triggered.

---

## Why this matters

Credential files inside containers are a direct path to lateral movement. The attack chain is short:

1. Attacker reads `/var/run/secrets/kubernetes.io/serviceaccount/token`
2. Attacker uses the token to call `kubectl` or the Kubernetes API directly
3. Depending on the ServiceAccount's RBAC permissions, they can list secrets, create pods, or escalate to cluster-admin

This is why [F-09 (automountServiceAccountToken not disabled)](/services/#detection-starter) matters at the manifest level — but manifest controls alone do not catch it at runtime. This detection closes that gap.

**MITRE ATT&CK:** [T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)  
**Tactic:** Credential Access  
**Severity:** High

---

## Attack simulation

```bash
# Deploy a test pod
kubectl run lab004 --image=ubuntu:22.04 --restart=Never -- sleep 3600

# Wait for it to be running
kubectl wait --for=condition=ready pod/lab004

# Read sensitive files — these should trigger Falco
kubectl exec lab004 -- cat /etc/shadow
kubectl exec lab004 -- cat /etc/passwd
kubectl exec lab004 -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

Expected result: Falco fires a HIGH or CRITICAL alert for each sensitive file read, identifying the process name, user, container, and file path.

---

## Falco detection rule

```yaml
- rule: Sensitive File Read in Container
  desc: >
    A process inside a container read a sensitive credential file.
    This may indicate an attacker performing credential access after
    gaining initial execution.
  condition: >
    open_read and container and
    (fd.name startswith /etc/shadow or
     fd.name startswith /etc/passwd or
     fd.name startswith /etc/sudoers or
     fd.name startswith /root/.ssh or
     fd.name startswith /var/run/secrets/kubernetes.io/serviceaccount/token) and
    not proc.name in (sshd, sudo, passwd)
  output: >
    Sensitive file read in container
    (user=%user.name proc=%proc.name file=%fd.name
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, credential_access, T1552, sensitive_files]
```

---

## Triage guide

When this alert fires:

1. **Identify the process** — is `proc.name` a known application binary? Or is it `cat`, `curl`, `python`, or another unexpected tool?

2. **Check the file path** — `/var/run/secrets/kubernetes.io/serviceaccount/token` is the highest-risk read. If this was accessed, check the ServiceAccount's RBAC permissions immediately.

3. **Check what came before** — look for a shell spawn event (LAB-001) or an unexpected network connection in the minutes before this alert. If both are present, this is an active intrusion.

4. **Check for API calls** — if the service account token was read, check the Kubernetes API server audit log for requests using that token from inside the cluster.

**Escalate if:** The process that read the file is not a known application binary, or the service account token was read and the ServiceAccount has broad RBAC permissions.  
**Close if:** The read was from a known init process, a secrets management sidecar (Vault Agent, External Secrets), or a health check script — and the timing matches a deployment event.

---

## Remediation

**Immediate:**
```bash
# Check the ServiceAccount's RBAC bindings
kubectl get rolebindings,clusterrolebindings -A \
  -o jsonpath='{range .items[?(@.subjects[*].name=="default")]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'

# If the token was read, rotate the ServiceAccount token
kubectl delete secret $(kubectl get sa default -o jsonpath='{.secrets[0].name}')
```

**Structural:**
- Set `automountServiceAccountToken: false` on all pods that do not need API server access — this removes the token from the container filesystem entirely.
- Use projected service account tokens with short TTLs instead of long-lived secrets.
- Remove read access to `/etc/shadow` from container base images by using non-root users and minimal base images.
- The [Detection Starter Pack](/services/#detection-starter) includes tuned versions of this rule with false-positive suppressions for common secrets management sidecars.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Vault Agent sidecar | Reads service account token to authenticate with Vault | Add container name to exception |
| External Secrets Operator | Reads token for API authentication | Add known ESO container names |
| Health check scripts | Some init scripts read `/etc/passwd` | Scope exception to specific process name |
| Debug images | Ubuntu/Debian base images include `cat` and `less` | Use distroless images in production |

---

## References

- [MITRE ATT&CK T1552](https://attack.mitre.org/techniques/T1552/)
- [Falco — Sensitive file access rules](https://falco.org/docs/rules/default-rules/)
- [Kubernetes — Service account token projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
