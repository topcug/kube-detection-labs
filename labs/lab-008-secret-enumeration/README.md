---
title: "LAB-008: Kubernetes Secret Enumeration"
description: "An identity inside the cluster lists or reads Kubernetes Secrets via the API server. Detect it at the audit log level — this is the attack that follows a stolen service account token."
date: "2026-04-05"
mitre: "T1552.007 - Container API"
mitre_url: "https://attack.mitre.org/techniques/T1552/007/"
severity: "critical"
tags: ["Falco", "runtime detection", "credential access", "MITRE T1552", "secrets", "kubernetes API", "container"]
github_path: "labs/lab-008-secret-enumeration"
---

## Threat scenario

An attacker has a service account token — read from a container's filesystem (LAB-004), extracted from a CI/CD pipeline, or obtained via a misconfigured RBAC binding. They use it to call the Kubernetes API and enumerate Secrets in the cluster: `kubectl get secrets -A` or a direct API call to `/api/v1/namespaces/{namespace}/secrets`.

This is not theoretical. Kubernetes Secrets store database passwords, API tokens, TLS certificates, and cloud provider credentials. A single `list secrets` call with a sufficiently privileged service account can hand an attacker the keys to everything your cluster touches.

---

## Why this matters

Kubernetes Secrets are the most valuable target in a cluster compromise. The attack chain from secret enumeration to full blast radius is short:

1. Attacker lists secrets in the `production` namespace
2. Finds a `DATABASE_URL` secret with a PostgreSQL connection string
3. Connects directly to the database using the production credentials
4. Exfiltrates all customer data

The control failure that enables this is almost always an RBAC policy that grants `list` or `get` on `secrets` to a service account that does not need it. This is exactly what [F-07 (RBAC over-privilege)](/services/#detection-starter) flags at the manifest level — but API server audit logging catches it in real time.

**MITRE ATT&CK:** [T1552.007 — Container API](https://attack.mitre.org/techniques/T1552/007/)  
**Tactic:** Credential Access  
**Severity:** Critical

---

## Attack simulation

```bash
# Create a service account with excessive secret access (for testing only)
kubectl create serviceaccount secret-reader -n default
kubectl create clusterrolebinding secret-reader-binding \
  --clusterrole=view --serviceaccount=default:secret-reader

# Deploy a pod using this SA
kubectl run lab008 \
  --image=bitnami/kubectl:latest \
  --serviceaccount=secret-reader \
  --restart=Never \
  -- sleep 3600

kubectl wait --for=condition=ready pod/lab008

# From inside the pod, enumerate secrets (triggers audit log)
kubectl exec lab008 -- kubectl get secrets -A
kubectl exec lab008 -- kubectl get secret <secret-name> -o yaml
```

Expected result: The Kubernetes API server audit log records `list` and `get` verbs on the `secrets` resource. Falco's k8s_audit source fires if configured with the secret enumeration rule.

---

## Falco detection rule

```yaml
# Requires Falco's Kubernetes audit log integration
# https://falco.org/docs/event-sources/kubernetes-audit/

- rule: Kubernetes Secret Enumeration
  desc: >
    A service account or user listed or read Kubernetes Secrets.
    This is a high-value credential access event, especially when performed
    by a service account that is not a known secrets management tool.
  condition: >
    ka.verb in (list, get, watch) and
    ka.target.resource = secrets and
    not ka.user.name in (
      system:serviceaccount:kube-system:default,
      vault-agent,
      external-secrets-operator
    )
  output: >
    Kubernetes secret enumeration
    (user=%ka.user.name ns=%ka.target.namespace
     verb=%ka.verb secret=%ka.target.name
     source_ip=%ka.source_ip)
  priority: CRITICAL
  tags: [k8s_audit, secrets, credential_access, T1552_007]
  source: k8s_audit

- rule: Cross-Namespace Secret Read
  desc: >
    An identity read a secret in a namespace other than its own.
    Cross-namespace secret access is rarely legitimate and often indicates
    over-privileged RBAC or active credential harvesting.
  condition: >
    ka.verb in (get) and
    ka.target.resource = secrets and
    ka.user.name startswith "system:serviceaccount:" and
    not (ka.user.name contains ka.target.namespace)
  output: >
    Cross-namespace secret read
    (user=%ka.user.name target_ns=%ka.target.namespace
     secret=%ka.target.name)
  priority: CRITICAL
  tags: [k8s_audit, secrets, lateral_movement, T1552_007]
  source: k8s_audit
```

---

## Triage guide

When this alert fires:

1. **Identify the identity** — `ka.user.name` tells you exactly who made the call. Is it a known service account (Vault Agent, External Secrets, ArgoCD)? Or is it an application service account that has no business reading secrets?

2. **Check the RBAC binding** — how did this service account get `list` or `get` on secrets? Trace back to the Role or ClusterRole. Is this an intentional permission or an over-privileged binding left from a previous configuration?

3. **Check what secrets were accessed** — `ka.target.name` and `ka.target.namespace` tell you which secret. Are these database credentials? API tokens? TLS certificates? The severity of follow-on actions depends on what was read.

4. **Check for follow-on activity** — after the secret read, did any new process spawn? Did any outbound connection appear from the pod that accessed the secret? Did any new pod get created using those credentials?

**Escalate if:** The accessing identity is an application service account, the secret contains database credentials or cloud provider keys, or there is any follow-on activity in the minutes after.  
**Close if:** The access was from a known secrets management tool (Vault Agent, External Secrets Operator, ArgoCD) accessing its expected secrets during a scheduled sync.

---

## Remediation

**Immediate:**
```bash
# Identify what the service account can access
kubectl auth can-i list secrets --as=system:serviceaccount:default:my-sa -A

# Remove overly broad RBAC bindings
kubectl delete clusterrolebinding <binding-name>

# Rotate any secrets that were enumerated
kubectl create secret generic <secret-name> \
  --from-literal=key=<new-value> \
  --dry-run=client -o yaml | kubectl apply -f -
```

**Structural:**
- Never grant `list` or `get` on `secrets` to application service accounts. Applications should access secrets via projected volumes or a secrets management system, not direct API calls.
- Use [External Secrets Operator](https://external-secrets.io/) or [Vault Agent](https://developer.hashicorp.com/vault/docs/platform/k8s/injector) to decouple secret access from application RBAC.
- Enable Kubernetes API server audit logging and ship logs to a SIEM. This detection only works if audit logs are collected.
- The [Detection Starter Pack](/services/#detection-starter) includes the audit log configuration and this rule tuned for common secrets management tools.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| External Secrets Operator | Lists secrets it manages | Add ESO service account to exception list |
| Vault Agent | Reads SA token secret for auth | Expected — add to exception list |
| ArgoCD | Reads secrets for deployment sync | Add ArgoCD service accounts to exception |
| Cert-manager | Reads TLS secrets it manages | Add cert-manager SA to exception |
| Cluster upgrades | Control plane components read secrets | Scope exception to `kube-system` namespace |

---

## References

- [MITRE ATT&CK T1552.007](https://attack.mitre.org/techniques/T1552/007/)
- [Falco — Kubernetes audit log](https://falco.org/docs/event-sources/kubernetes-audit/)
- [Kubernetes — RBAC best practices for secrets](https://kubernetes.io/docs/concepts/security/rbac-good-practices/#secret-access)
- [External Secrets Operator](https://external-secrets.io/)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
