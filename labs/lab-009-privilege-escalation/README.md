---
title: "LAB-009: Privilege Escalation via allowPrivilegeEscalation"
description: "A process inside a container gains more privileges than its parent. Detect setuid/setgid execution and understand why allowPrivilegeEscalation: false is not just a checkbox."
date: "2026-04-05"
mitre: "T1548 - Abuse Elevation Control Mechanism"
mitre_url: "https://attack.mitre.org/techniques/T1548/"
severity: "high"
tags: ["Falco", "runtime detection", "privilege escalation", "MITRE T1548", "setuid", "container"]
github_path: "labs/lab-009-privilege-escalation"
---

## Threat scenario

An attacker has limited execution inside a container — perhaps as a non-root user via a compromised dependency. They find a setuid binary inside the container image: `sudo`, `newgrp`, `pkexec`, or a custom application binary that was shipped with the setuid bit set by mistake. They execute it to escalate from a low-privilege process to root inside the container.

If the container is also missing `allowPrivilegeEscalation: false`, the kernel allows the privilege gain. From root inside the container, the path to host escape (especially in misconfigured environments) is significantly shorter.

---

## Why this matters

`allowPrivilegeEscalation: false` is a single manifest field, but it enforces a kernel-level restriction: the `no_new_privs` flag prevents any child process from gaining more privileges than the parent via setuid, setgid, or file capabilities.

Without it:

1. A non-root process can execute a setuid binary and gain root inside the container
2. From root inside the container, capabilities like `CAP_SYS_PTRACE` or `CAP_NET_ADMIN` become accessible
3. Combined with other misconfigurations (privileged mode, host path mounts), container escape becomes possible

This is why `allowPrivilegeEscalation: false` is in the [scanner's F-05 check](/services/#detection-starter) — but detection catches the runtime attempt, not just the manifest gap.

**MITRE ATT&CK:** [T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)  
**Tactic:** Privilege Escalation  
**Severity:** High

---

## Attack simulation

```bash
# Deploy a test pod WITHOUT allowPrivilegeEscalation: false
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: lab009
spec:
  containers:
    - name: app
      image: ubuntu:22.04
      command: ["sleep", "3600"]
      # Note: allowPrivilegeEscalation NOT set to false
EOF

kubectl wait --for=condition=ready pod/lab009

# Install a setuid binary inside the container (simulate misconfigured image)
kubectl exec lab009 -- bash -c "cp /bin/bash /tmp/suid-bash && chmod u+s /tmp/suid-bash"

# Execute the setuid binary as a non-root user
kubectl exec lab009 -- bash -c "useradd -m testuser && su - testuser -c '/tmp/suid-bash -p -c id'"
```

Expected result: Falco fires on the setuid execution event, capturing the process name, the parent process, and the privilege gain.

---

## Falco detection rule

```yaml
- rule: Setuid or Setgid Bit Set in Container
  desc: >
    The setuid or setgid bit was set on a file inside a container.
    This is preparation for privilege escalation and should not happen
    in production container filesystems.
  condition: >
    open_write and container and
    (evt.arg.flags contains S_ISUID or evt.arg.flags contains S_ISGID)
  output: >
    Setuid/setgid bit set on file
    (user=%user.name proc=%proc.name file=%fd.name
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, privilege_escalation, T1548, setuid]

- rule: Privilege Escalation via Setuid Binary
  desc: >
    A process executed a setuid binary inside a container.
    If allowPrivilegeEscalation is not disabled, this results in a
    privilege gain within the container.
  condition: >
    spawned_process and container and
    proc.is_suid = true and
    not proc.name in (sudo) and
    not container.image.repository in (known_privileged_images)
  output: >
    Setuid binary executed in container
    (user=%user.name proc=%proc.name parent=%proc.pname
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, privilege_escalation, T1548]

- rule: Container Running as Root After Escalation
  desc: >
    A process is running as root (uid=0) inside a container that
    did not start with root. This may indicate successful privilege escalation.
  condition: >
    spawned_process and container and
    user.uid = 0 and
    not proc.pname in (runc, containerd-shim) and
    not container.image.repository in (known_root_images)
  output: >
    Root process in container after escalation
    (user=%user.name uid=%user.uid proc=%proc.name parent=%proc.pname
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, privilege_escalation, T1548]
```

---

## Triage guide

When this alert fires:

1. **Check the binary** — which setuid binary was executed? `sudo` in a container is almost always a misconfiguration. Custom application binaries with setuid set are a build pipeline problem.

2. **Check the user** — was the executing user already root? If so, the setuid execution is less meaningful. If the user was non-root and the process escalated, this is the signal.

3. **Check the image** — does the container image ship setuid binaries intentionally? Run `find / -perm -4000 2>/dev/null` inside a test instance of the image to enumerate them. This is an image hygiene audit.

4. **Check what happened after** — if privilege escalation succeeded, what did the root process do next? File writes to system directories? Network connections? New process spawns?

**Escalate if:** A non-root user successfully escalated to root, or any post-escalation activity (file writes, network connections) is observed.  
**Close if:** The setuid binary is `sudo` being called by a known init script in a development namespace, with no subsequent suspicious activity.

---

## Remediation

**Immediate:**
```bash
# Check for setuid binaries in a running container
kubectl exec <pod-name> -- find / -perm -4000 -type f 2>/dev/null

# Verify allowPrivilegeEscalation is set on all containers
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}
{range .spec.containers[*]}  {.name}: allowPrivilegeEscalation={.securityContext.allowPrivilegeEscalation}{"\n"}{end}{end}'
```

**Structural:**
- Set `allowPrivilegeEscalation: false` in the `securityContext` of every container. This is a one-line manifest change with no application impact for workloads that do not use setuid binaries.
- Remove setuid binaries from container images during the build process. Add a `RUN find / -perm -4000 -exec chmod u-s {} \;` layer to your Dockerfile.
- Set `runAsNonRoot: true` at the pod level to prevent processes from starting as root in the first place.
- The [Detection Starter Pack](/services/#detection-starter) includes these three rules as a coordinated privilege escalation detection chain.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Debian/Ubuntu base images | `sudo`, `newgrp`, `chsh` ship with setuid | Use distroless or strip setuid in Dockerfile |
| SSH-based images | `ssh` binary may have setuid | Remove SSH from container images |
| Package installs during init | `apt-get` installs setuid binaries | Bake dependencies into the image layer |
| Development environments | Developers may use sudo inside dev containers | Scope exceptions to dev namespaces only |

---

## References

- [MITRE ATT&CK T1548](https://attack.mitre.org/techniques/T1548/)
- [Falco — Privilege escalation rules](https://falco.org/docs/rules/default-rules/)
- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Linux — no_new_privs flag](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
