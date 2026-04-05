---
title: "LAB-010: Container Running from a Mutable Image Tag"
description: "A container starts using :latest or a floating tag. Detect image tag hygiene violations at runtime and understand why this is both a security and reliability risk."
date: "2026-04-05"
mitre: "T1525 - Implant Internal Image"
mitre_url: "https://attack.mitre.org/techniques/T1525/"
severity: "medium"
tags: ["Falco", "runtime detection", "supply chain", "MITRE T1525", "image tags", "container"]
github_path: "labs/lab-010-mutable-image-tag"
---

## Threat scenario

An attacker has write access to a container registry — via a compromised CI/CD service account, a misconfigured registry policy, or a dependency confusion attack. They push a malicious image to `myrepo/api:latest`, overwriting the previous version. The next time a pod restarts, Kubernetes pulls the new image. The container now runs attacker-controlled code.

This attack is only possible because the manifest uses a mutable tag. If the manifest referenced a digest (`myrepo/api@sha256:abc123...`), the image could not be silently replaced.

---

## Why this matters

`:latest` and other floating tags make three guarantees impossible:

1. **Reproducibility** — you cannot know which exact image version ran in production last Tuesday
2. **Rollback** — if the tag was overwritten, rolling back the deployment does not restore the previous image
3. **Integrity** — an attacker with registry write access can silently replace the image the next time any pod restarts

This is why [F-01 (mutable image tags)](/services/#detection-starter) is the first finding in the scanner — it is the most common violation and one of the highest-leverage fixes in a supply chain hardening program.

**MITRE ATT&CK:** [T1525 — Implant Internal Image](https://attack.mitre.org/techniques/T1525/)  
**Tactic:** Persistence  
**Severity:** Medium

---

## Attack simulation

```bash
# Deploy a pod using :latest (should trigger detection)
kubectl run lab010 --image=nginx:latest --restart=Never

# Deploy a pod with no tag at all (also mutable)
kubectl run lab010b --image=nginx --restart=Never

# For comparison — a pinned pod (should NOT trigger)
kubectl run lab010c --image=nginx:1.25.3 --restart=Never

# Check what image is actually running
kubectl get pod lab010 -o jsonpath='{.spec.containers[0].image}'
```

Expected result: Falco fires on the container start event for `lab010` and `lab010b` (mutable tags). No alert for `lab010c` (pinned tag).

---

## Falco detection rule

```yaml
- rule: Container Started with Mutable Image Tag
  desc: >
    A container started using :latest or a tag that was not resolved to
    a digest at admission time. Mutable tags make supply chain attacks
    possible and rollbacks unreliable.
  condition: >
    container.image.tag = "latest" or
    container.image.tag = "" and
    container and
    not container.image.repository in (known_debug_images)
  output: >
    Container started with mutable image tag
    (container=%container.name image=%container.image.repository
     tag=%container.image.tag
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, supply_chain, T1525, image_tag]

- rule: Container Image Not Pinned to Digest
  desc: >
    A container started with an image reference that is not pinned to a
    specific digest (sha256:...). Digest pinning is the strongest guarantee
    of image integrity and is recommended for production workloads.
  condition: >
    container and
    not container.image.digest startswith "sha256:" and
    not container.image.repository in (known_debug_images) and
    k8s.ns.name in (production, prod)
  output: >
    Container image not digest-pinned
    (container=%container.name image=%container.image.repository
     tag=%container.image.tag digest=%container.image.digest
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: WARNING
  tags: [container, supply_chain, T1525, image_digest]
```

---

## Triage guide

When this alert fires:

1. **Check the namespace** — a `:latest` tag in production is urgent. The same tag in development is a lower priority but still worth fixing.

2. **Check when the image was last pulled** — if the image was pulled recently and the tag points to an unexpected digest, this could be an active supply chain compromise.

3. **Check the registry** — who has write access to this repository? When was the last push? Does the push timestamp correlate with any deployment event?

4. **Verify the image digest** — compare the digest of the running container against the expected baseline. If they differ and no deployment occurred, treat this as a potential compromise.

**Escalate if:** The image digest changed without a corresponding deployment event, or the registry shows an unexpected push from an unknown identity.  
**Close if:** The team is aware of the floating tag and has a tracked issue to pin it. This is a hygiene finding, not an active incident — unless the digest is unexpected.

---

## Remediation

**Immediate:**
```bash
# Find all pods using :latest or no tag in production
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}
{range .spec.containers[*]}  {.name}: {.image}{"\n"}{end}{end}' \
  | grep -E ":latest|[a-z0-9/]:[^:]" | grep -v "sha256"

# Check the actual digest of a running container
kubectl get pod <pod-name> \
  -o jsonpath='{.status.containerStatuses[0].imageID}'
```

**Structural:**
- Require image digests or fixed semantic version tags in all production manifests. A policy rule (`disallow-latest-tag`) enforced via Kyverno or OPA Gatekeeper catches violations at admission time.
- Enable image digest pinning in your CI/CD pipeline — most tools (Cosign, Crane, Skopeo) can resolve a tag to a digest and update the manifest automatically.
- Sign images with [Cosign](https://github.com/sigstore/cosign) and verify signatures at admission via a policy controller. This prevents registry tampering from being exploited even if a tag is reused.
- The [Detection Starter Pack](/services/#detection-starter) includes this rule and the Kyverno policy for tag enforcement together.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Debug/ephemeral containers | `kubectl debug` uses images without pinned tags | Scope exception to ephemeral container events |
| Development namespaces | Teams use `:latest` during active development | Scope alert to production namespaces only |
| Base infrastructure images | Some platform tools use floating tags | Pin these as part of the baseline hardening process |

---

## References

- [MITRE ATT&CK T1525](https://attack.mitre.org/techniques/T1525/)
- [Sigstore — Cosign image signing](https://github.com/sigstore/cosign)
- [Kyverno — disallow-latest-tag policy](https://kyverno.io/policies/best-practices/disallow-latest-tag/disallow-latest-tag/)
- [Kubernetes — Image pull policy](https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
