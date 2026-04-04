# LAB-001: Shell Spawned Inside a Container

**MITRE ATT&CK:** [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  
**Tactic:** Execution  
**Severity:** HIGH  

---

## Threat scenario

An attacker has exploited a vulnerability in a web application running inside a Kubernetes pod. They now have code execution and use it to spawn an interactive bash shell. Alternatively, a developer has used `kubectl exec` to get a shell inside a production container for debugging  -  and left it open.

In either case, a shell process is now running inside a container that should have no shells at runtime.

---

## Why this matters

Containers are supposed to run a single, well-defined process. When a shell spawns, one of three things is happening:

1. An attacker has gained execution and is exploring the container
2. A developer is debugging in production (which is a risk and an audit event)
3. A misconfigured entrypoint or init process is spawning shells unexpectedly

All three are worth knowing about. The first is a security incident. The second is a policy and audit issue. The third is a configuration quality issue.

**MITRE ATT&CK:** [T1059  -  Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  
**Tactic:** Execution  
**Severity:** High

---

## Attack simulation

To simulate this detection in a test cluster:

```bash
# Deploy a test pod
kubectl run lab001 --image=nginx --restart=Never

# Exec into it  -  this should trigger the detection
kubectl exec -it lab001 -- /bin/bash

# Inside the shell, try something visible
ls /etc/shadow
```

Expected result: Falco fires on the shell spawn event, and a second event fires on the sensitive file read.

---

## Falco detection rule

```yaml
- rule: Shell Spawned in Container
  desc: >
    A shell was spawned inside a container. This may indicate an attacker
    has gained execution, or a developer is accessing production directly.
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    not proc.pname in (shell_binaries) and
    not container.image.repository in (trusted_shell_images)
  output: >
    Shell spawned in container
    (user=%user.name container=%container.name image=%container.image.repository
    shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: HIGH
  tags: [container, shell, T1059, execution]
```

**Macro dependency:** This rule uses the built-in `shell_binaries` macro from Falco's default ruleset, which covers `bash`, `sh`, `zsh`, `dash`, `fish`, and others.

---

## Triage guide

When this alert fires:

1. **Check the container image**  -  is this a known image that legitimately uses shells (e.g., a debug image, a CI runner)? If yes, add it to `trusted_shell_images` and close.

2. **Check who triggered it**  -  if it came from a `kubectl exec` event, check the Kubernetes audit log for the user and service account. Was this an authorized developer? Was it during an incident?

3. **Check what happened after**  -  look at subsequent process events from the same container. Did the shell access sensitive files? Did it make outbound network connections? If yes, escalate.

4. **Check the timing**  -  a shell spawned during a deployment rollout is likely benign. A shell spawned at 3am is not.

**Escalate if:** The shell was followed by sensitive file reads, outbound network connections, or writes to system directories.  
**Close if:** The container image is a known debug image, or the exec was performed by an authorized user during a documented incident response.

---

## Remediation

**Immediate:** If the shell was spawned by an unexpected process (not via `kubectl exec`), isolate the pod immediately:

```bash
kubectl label pod <pod-name> quarantine=true
kubectl cordon <node-name>  # if node compromise is suspected
```

**Structural:**
- Remove shells from production container images. Use distroless or scratch base images where possible.
- Enforce `kubectl exec` restrictions via RBAC  -  remove the `pods/exec` permission from all service accounts that do not need it.
- Add Pod Security Admission controls to prevent privileged containers from running in production namespaces.
- Enable Kubernetes audit logging and alert on `exec` subresource calls in production namespaces.

---

## False positive notes

| Source | Pattern | Mitigation |
|---|---|---|
| CI/CD smoke tests | `kubectl exec` into pods to run test commands | Add CI service account to exceptions, or run tests differently |
| Debug images | Images that include shells by design | Add image to `trusted_shell_images` list |
| Init containers | Shell-based init scripts | Scope exception to container name, not image |
| Helm hooks | Some chart hooks spawn shells | Review hook design; add image exception if needed |

---

## References

- [Falco documentation  -  Rules](https://falco.org/docs/rules/)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [Kubernetes RBAC  -  pods/exec](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Distroless container images](https://github.com/GoogleContainerTools/distroless)
