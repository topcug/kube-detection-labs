---
title: "LAB-012: Container Escape via Host Path Mount"
description: "A container has a hostPath volume that gives it access to the host filesystem. Detect the mount at runtime and understand the full escape chain — from container to node to cluster."
date: "2026-04-05"
mitre: "T1611 - Escape to Host"
mitre_url: "https://attack.mitre.org/techniques/T1611/"
severity: "critical"
tags: ["Falco", "runtime detection", "privilege escalation", "MITRE T1611", "hostPath", "container escape", "container"]
github_path: "labs/lab-012-host-path-escape"
---

## Threat scenario

A developer deployed a workload with `hostPath: /` — mounting the entire host filesystem into the container at `/host`. This gives the container read and write access to every file on the underlying node: host SSH keys, node certificates, Docker socket, containerd socket, and the files of every other container on the node.

The attacker who gains execution inside this container does not need a container escape vulnerability. The escape path is already opened by the misconfiguration.

---

## Why this matters

A `hostPath` mount is not a container escape in the traditional sense — it is an escape-by-design. With write access to the host filesystem:

1. Write a cron job or systemd service to `/etc/cron.d` → code execution on the host
2. Write to `/root/.ssh/authorized_keys` → SSH access to the node
3. Read `/var/run/secrets` of other containers on the node → harvest tokens from more privileged workloads
4. Access the container runtime socket (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) → create new privileged containers, pull images, or stop running containers

This is the highest-severity misconfiguration class in Kubernetes, and it is detected purely at the manifest level — but runtime detection catches it if a pod is created outside of your normal admission path (via a compromised service account, a direct API call, or a namespace that bypasses admission webhooks).

**MITRE ATT&CK:** [T1611 — Escape to Host](https://attack.mitre.org/techniques/T1611/)  
**Tactic:** Privilege Escalation  
**Severity:** Critical

---

## Attack simulation

```bash
# Deploy a pod with a sensitive hostPath mount
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: lab012
spec:
  containers:
    - name: escape-test
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /
EOF

kubectl wait --for=condition=ready pod/lab012

# From inside the container, access the host filesystem
kubectl exec lab012 -- ls /host/etc/
kubectl exec lab012 -- cat /host/etc/shadow

# Access other containers' secrets from the host path
kubectl exec lab012 -- ls /host/var/run/secrets/

# Access the container runtime socket
kubectl exec lab012 -- ls /host/var/run/containerd/
```

Expected result: Falco fires on the sensitive host file reads. The container start event (if Falco is configured with admission-time checks) should also flag the hostPath mount.

---

## Falco detection rule

```yaml
- rule: Container with Sensitive Host Path Mount
  desc: >
    A container was started with a sensitive hostPath volume mount.
    This gives the container direct access to the host filesystem and
    represents a potential full node compromise path.
  condition: >
    container.mounts contains "/" or
    container.mounts contains "/etc" or
    container.mounts contains "/var/run/docker.sock" or
    container.mounts contains "/run/containerd" or
    container.mounts contains "/proc" or
    container.mounts contains "/sys"
  output: >
    Sensitive hostPath mount in container
    (container=%container.name image=%container.image.repository
     mounts=%container.mounts
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, host_escape, T1611, hostpath]

- rule: Host File Write via Mounted Volume
  desc: >
    A process in a container wrote to a path that appears to be a
    host filesystem mount point. This may indicate an active escape attempt.
  condition: >
    open_write and container and
    (fd.name startswith /host/ or
     fd.name startswith /proc/1/ or
     fd.name startswith /node-root/)
  output: >
    Write to mounted host path from container
    (user=%user.name proc=%proc.name file=%fd.name
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, host_escape, T1611, filesystem_write]

- rule: Container Runtime Socket Access
  desc: >
    A container accessed the Docker or containerd socket.
    Access to the container runtime socket allows creating, modifying,
    or destroying any container on the node.
  condition: >
    open_read and container and
    (fd.name = /var/run/docker.sock or
     fd.name = /run/containerd/containerd.sock or
     fd.name startswith /run/docker/)
  output: >
    Container runtime socket accessed
    (user=%user.name proc=%proc.name
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, host_escape, T1611, runtime_socket]
```

---

## Triage guide

When this alert fires:

1. **Isolate immediately** — a container with a sensitive hostPath mount is an immediate containment priority. Do not wait for full investigation before isolating.

2. **Check the mount path** — what exactly is mounted? `/` is worst case. `/var/log` is lower risk. `/var/run/docker.sock` is equivalent to node root access.

3. **Check for writes** — did any process write to the mounted host path? Check for new files in `/etc/cron.d`, `/root/.ssh`, or systemd directories on the host.

4. **Check other pods on the node** — if the container had host filesystem access, it may have read tokens from other pods on the same node. Enumerate all pods on that node and assess whether their service account tokens should be considered compromised.

**Escalate if:** Always. A sensitive hostPath mount is a critical finding regardless of whether it has been exploited.  
**Close if:** The pod is a known, intentional system component (node agent, DaemonSet with documented host access) with a tracked exception and owner.

---

## Remediation

**Immediate:**
```bash
# Find all pods with hostPath mounts in your cluster
kubectl get pods -A -o json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for pod in data['items']:
    ns = pod['metadata']['namespace']
    name = pod['metadata']['name']
    for vol in pod['spec'].get('volumes', []):
        if 'hostPath' in vol:
            print(f'{ns}/{name}: hostPath={vol[\"hostPath\"][\"path\"]}')
"

# Delete pods with sensitive mounts
kubectl delete pod <pod-name> -n <namespace>
```

**Structural:**
- Enforce Pod Security Standards at the `restricted` or `baseline` level in all application namespaces. Both levels prohibit sensitive hostPath mounts.
- Use a policy controller (Kyverno, OPA Gatekeeper) to block hostPath volumes in production namespaces. Allow only specific, documented exceptions for DaemonSets like node exporters.
- The [Detection Starter Pack](/services/#detection-starter) and [Pod Security Rollout Sprint](/services/#pod-security-rollout) together cover this: the Sprint handles the policy rollout order, the Starter Pack adds runtime detection for the cases that bypass admission.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Node monitoring DaemonSets | Node exporter mounts `/proc`, `/sys` for metrics | Document and add to exception list with owner |
| Log collection agents | Fluent Bit, Fluentd mount `/var/log` from host | Scope exception to specific image and mount path |
| CSI drivers | Some storage drivers need host socket access | Review per-driver requirements; use minimal paths |
| Kubernetes system components | `kube-proxy`, `kubelet` need host access | Scope exceptions to `kube-system` namespace |

---

## References

- [MITRE ATT&CK T1611](https://attack.mitre.org/techniques/T1611/)
- [Kubernetes — hostPath volume security](https://kubernetes.io/docs/concepts/storage/volumes/#hostpath)
- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Falco — Container escape detection](https://falco.org/docs/rules/default-rules/)
- [ClarifyIntel Pod Security Rollout Sprint](/services/#pod-security-rollout)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
