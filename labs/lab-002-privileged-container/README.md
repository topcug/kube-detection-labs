# LAB-002: Privileged Container Started

**MITRE ATT&CK:** [T1611 - Escape to Host](https://attack.mitre.org/techniques/T1611/)  
**Tactic:** Privilege Escalation  
**Severity:** CRITICAL  

---

## Threat scenario

A workload is deployed with `securityContext.privileged: true`  -  either deliberately by an attacker who has gained access to the cluster's deployment pipeline, or accidentally by a developer who copied a manifest from a legacy system.

A privileged container has access to all Linux capabilities, all host devices, and the host kernel's namespace. From a privileged container, escaping to the host is significantly easier than from a standard container.

---

## Why this matters

`privileged: true` in a container security context is one of the most dangerous misconfigurations in Kubernetes. A privileged container can:

- Mount the host filesystem
- Read and write to host processes via `/proc`
- Load kernel modules
- Modify host network configuration
- Access raw block devices

In most production environments, privileged containers should be extremely rare  -  limited to specific node-level agents (e.g., CNI plugins, storage drivers) with documented justification.

**MITRE ATT&CK:** [T1611  -  Escape to Host](https://attack.mitre.org/techniques/T1611/)  
**Tactic:** Privilege Escalation  
**Severity:** Critical

---

## Attack simulation

To simulate a privileged container starting:

```yaml
# privileged-test.yaml  -  DO NOT USE IN PRODUCTION
apiVersion: v1
kind: Pod
metadata:
  name: lab002-privileged
  namespace: default
spec:
  containers:
  - name: test
    image: ubuntu
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
```

```bash
kubectl apply -f privileged-test.yaml
```

Expected result: Falco fires a CRITICAL alert when the container starts. If Pod Security Admission is active at `restricted` level, the pod will also be rejected at admission time.

To verify what a privileged container can do:

```bash
kubectl exec -it lab002-privileged -- bash
# Inside:
ls /dev  # shows host devices
mount /dev/sda1 /mnt  # can mount host volumes
cat /proc/1/environ  # can read host process environment
```

---

## Falco detection rule

```yaml
- rule: Privileged Container Started
  desc: >
    A container started with privileged mode enabled.
    Privileged containers have near-full host access and represent
    a critical security risk if not explicitly expected.
  condition: >
    container_started and container.privileged = true and
    not container.image.repository in (known_privileged_images)
  output: >
    Privileged container started
    (user=%user.name container=%container.name
    image=%container.image.repository
    namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, privileged, T1611, privilege_escalation]
```

**Note:** `known_privileged_images` must be defined as a list macro in your Falco configuration. Start with an empty list and build it from your audit of legitimate privileged workloads.

---

## Triage guide

When this alert fires:

1. **Identify the workload**  -  get the pod name, namespace, and image. Is this a known node-level agent (CNI, CSI, monitoring agent)?

2. **Check the deployment source**  -  who applied this manifest? When? Look at the Kubernetes audit log for the create/apply event on this pod or deployment.

3. **Check if it is in the allowlist**  -  if this image is a known legitimate privileged workload, add it to `known_privileged_images` and document why it needs privilege.

4. **If unknown or unexpected**  -  treat as a security incident. The workload should be deleted immediately, and the deployment pipeline that allowed it should be investigated.

**Escalate if:** The privileged container was deployed outside of a known deployment pipeline, or the image is unknown.  
**Close if:** The image is a documented node-level agent (e.g., `calico-node`, `aws-node`, `kube-proxy`) and the namespace matches its expected deployment location.

---

## Remediation

**Immediate:** Delete the privileged pod if it should not be running:

```bash
kubectl delete pod lab002-privileged
```

**Structural  -  Pod Security Admission:**

Apply `restricted` or `baseline` policy to production namespaces. The `restricted` profile blocks privileged containers at admission:

```bash
kubectl label namespace production \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted
```

**Structural  -  RBAC:**

Restrict who can create pods in production namespaces. Remove `pods/create` and `deployments/create` permissions from service accounts that do not need them.

**Structural  -  Admission Controller:**

If you need more granular control than PSA provides, an admission controller (Kyverno or OPA Gatekeeper) can enforce a policy that blocks `privileged: true` with named exceptions:

```yaml
# Kyverno example
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-containers
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-privileged
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "Privileged containers are not allowed."
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
```

---

## False positive notes

| Source | Pattern | Mitigation |
|---|---|---|
| CNI plugins | `calico-node`, `aws-node`, `flannel` | Add to `known_privileged_images` with documented justification |
| Storage drivers | CSI node plugins | Same as above |
| Monitoring agents | Some node-level agents (e.g., Datadog agent) | Review if privileged mode is actually required; many support non-privileged mode |
| Legacy workloads | Old manifests copied without review | Audit source; remove `privileged: true` if not required |

---

## References

- [Kubernetes Pod Security Standards  -  Restricted](https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted)
- [MITRE ATT&CK T1611  -  Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [Falco  -  container_started condition](https://falco.org/docs/rules/supported-fields/)
- [Kyverno  -  Disallow Privileged Containers](https://kyverno.io/policies/pod-security/restricted/disallow-privileged-containers/)
