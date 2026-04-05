---
title: "LAB-005: kubectl exec into a Running Container"
description: "Someone ran kubectl exec into a production pod. It might be a developer debugging, or it might be an attacker who stole a kubeconfig. Detect it and know how to tell the difference."
date: "2026-04-05"
mitre: "T1609 - Container Administration Command"
mitre_url: "https://attack.mitre.org/techniques/T1609/"
severity: "high"
tags: ["Falco", "runtime detection", "execution", "MITRE T1609", "kubectl exec", "container"]
github_path: "labs/lab-005-kubectl-exec"
---

## Threat scenario

An attacker has obtained a kubeconfig file — from a developer's laptop, a CI/CD pipeline secret, or a leaked environment variable. They use `kubectl exec` to get an interactive shell inside a production pod. From there they can read secrets, call the Kubernetes API with the pod's service account token, or pivot to other services inside the cluster network.

The same action also happens legitimately when a developer debugs a production issue. Your detection needs to fire in both cases — and your triage process needs to distinguish them.

---

## Why this matters

`kubectl exec` bypasses most application-level security controls. It:

- Lands the attacker directly inside the container network namespace
- Gives them access to all environment variables (where secrets often live)
- Gives them access to the auto-mounted service account token
- Does not go through the application's authentication layer

The Kubernetes API server audit log records every exec call, but most teams do not alert on it. This detection closes that gap at the Falco level and pairs with audit log monitoring for full coverage.

**MITRE ATT&CK:** [T1609 — Container Administration Command](https://attack.mitre.org/techniques/T1609/)  
**Tactic:** Execution  
**Severity:** High

---

## Attack simulation

```bash
# Deploy a test pod
kubectl run lab005 --image=nginx --restart=Never

# Wait for it to be running
kubectl wait --for=condition=ready pod/lab005

# Execute a command — this should trigger detection
kubectl exec lab005 -- id

# Interactive shell — higher severity trigger
kubectl exec -it lab005 -- /bin/bash
```

Expected result: Falco fires on the shell spawn triggered by exec. The Kubernetes audit log records the exec subresource call with the user identity.

---

## Falco detection rule

```yaml
# Falco detects the shell spawn that kubectl exec triggers.
# Pair this with a Kubernetes audit log rule for full coverage.

- rule: Interactive Shell via kubectl exec
  desc: >
    An interactive shell was spawned inside a container, consistent with
    kubectl exec. This could be an authorized developer or an attacker
    using a stolen kubeconfig.
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    proc.pname in (runc, containerd-shim, docker) and
    container.id != host
  output: >
    Interactive shell via exec
    (user=%user.name container=%container.name image=%container.image.repository
     shell=%proc.name parent=%proc.pname
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, exec, T1609, execution]

# Kubernetes audit log rule (for audit-log-based backends)
- rule: kubectl exec in Production Namespace
  desc: >
    kubectl exec was called against a pod in a production namespace.
    All exec calls should be reviewed.
  condition: >
    ka.verb = exec and
    ka.target.resource = pods and
    ka.target.subresource = exec and
    ka.target.namespace in (production, prod, default)
  output: >
    kubectl exec in production
    (user=%ka.user.name pod=%ka.target.name ns=%ka.target.namespace
     command=%ka.uri.param[command])
  priority: WARNING
  tags: [k8s_audit, exec, T1609]
  source: k8s_audit
```

---

## Triage guide

When this alert fires:

1. **Check the namespace** — exec into a production namespace is always worth investigating. Exec into a development or staging namespace is lower priority.

2. **Check the Kubernetes audit log** — the audit log records the user identity that called exec. Was it a human user with a named account? A service account? An unknown identity?

3. **Check the timing** — does this exec correlate with a known incident, a deployment, or an on-call response? Or did it come out of nowhere at an unusual hour?

4. **Check what happened inside** — after the exec, look for sensitive file reads (LAB-004), outbound network connections (LAB-008), or new process spawns that are unusual for this image.

**Escalate if:** The exec was made by an unknown identity, a service account that should not have exec permissions, or is followed by any suspicious behavior inside the container.  
**Close if:** The exec was made by a named, authorized user during a documented incident response or deployment procedure.

---

## Remediation

**Immediate:**
```bash
# Check who has exec permissions in a namespace
kubectl auth can-i create pods/exec --as=<user> -n production

# List all RoleBindings that grant exec in a namespace
kubectl get rolebindings -n production -o yaml | grep -A5 "pods/exec"
```

**Structural:**
- Remove `pods/exec` from all service accounts and user roles that do not explicitly require it. This is one of the most effective single controls for reducing exec risk.
- Require MFA or short-lived tokens for any role that retains exec permissions.
- Enable Kubernetes audit logging and alert on exec subresource calls in production namespaces.
- The [Detection Starter Pack](/services/#detection-starter) includes this rule tuned with namespace-aware exceptions and paired audit log coverage.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Authorized incident response | On-call engineers exec during outages | Correlate with PagerDuty/alerting system events |
| CI/CD smoke tests | Pipelines exec into pods to run test commands | Use a dedicated CI namespace and scope exceptions |
| Kubernetes operators | Some operators exec into managed pods | Add operator service account to exception list |
| Readiness check scripts | Some platform tooling execs to verify health | Replace with proper probes; add exception if needed |

---

## References

- [MITRE ATT&CK T1609](https://attack.mitre.org/techniques/T1609/)
- [Falco — Kubernetes audit log rules](https://falco.org/docs/event-sources/kubernetes-audit/)
- [Kubernetes — RBAC pods/exec](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [CIS Kubernetes Benchmark — exec restrictions](https://www.cisecurity.org/benchmark/kubernetes)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
