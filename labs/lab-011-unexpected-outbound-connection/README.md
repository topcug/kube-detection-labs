---
title: "LAB-011: Unexpected Outbound Network Connection from a Container"
description: "A container opens a connection to an external IP or domain it has no business contacting. Detect network anomalies at the syscall level and understand how NetworkPolicy and runtime detection work together."
date: "2026-04-05"
mitre: "T1071 - Application Layer Protocol"
mitre_url: "https://attack.mitre.org/techniques/T1071/"
severity: "high"
tags: ["Falco", "runtime detection", "command and control", "MITRE T1071", "network", "egress", "container"]
github_path: "labs/lab-011-unexpected-outbound-connection"
---

## Threat scenario

A compromised container opens an outbound HTTPS connection to a command-and-control server — disguised as normal HTTPS traffic on port 443. NetworkPolicy blocks most connections, but this container legitimately needs to reach an external payment API, so port 443 egress is permitted. The attacker piggybacks on that permitted path.

Alternatively: a container opens a connection to `169.254.169.254` — the AWS EC2 metadata service — to harvest IAM role credentials. This endpoint is reachable from every EC2-hosted pod unless explicitly blocked, and it is not a port 443 connection.

Both cases are invisible to application logs. Syscall-level network monitoring catches them.

---

## Why this matters

Most network controls operate at the connection level (NetworkPolicy, firewalls). They do not inspect which process inside the container made the connection, or whether the destination is expected for that specific container.

Falco's process-aware network monitoring adds the missing layer:

- **Who** opened the connection (`proc.name`, `user.name`)
- **From where** (container identity, namespace, pod name)
- **To where** (`fd.sip`, `fd.rip`, `fd.port`)
- **On which protocol** (TCP/UDP, port)

Combined with NetworkPolicy (which restricts what connections are allowed), this detection catches what NetworkPolicy cannot: unexpected processes using permitted egress paths.

This is why [F-08 (namespaces without NetworkPolicy)](/services/#detection-starter) matters — but NetworkPolicy alone is not enough. Runtime detection catches what policy cannot.

**MITRE ATT&CK:** [T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)  
**Tactic:** Command and Control  
**Severity:** High

---

## Attack simulation

```bash
# Deploy a test pod
kubectl run lab011 --image=ubuntu:22.04 --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod/lab011
kubectl exec lab011 -- apt-get install -y curl -qq

# Unexpected external connection (simulates C2 callback)
kubectl exec lab011 -- curl -s https://ifconfig.me

# Cloud metadata endpoint (AWS/GCP SSRF simulation)
kubectl exec lab011 -- curl -s http://169.254.169.254/latest/meta-data/

# Unexpected internal connection to another namespace
kubectl exec lab011 -- curl -s http://kube-dns.kube-system.svc.cluster.local
```

Expected result: Falco fires on the network connection events, capturing the destination IP, port, process name, and container identity.

---

## Falco detection rule

```yaml
- rule: Unexpected Outbound Connection from Container
  desc: >
    A container opened an outbound network connection to an unexpected
    destination. For containers with known egress requirements, tune this
    rule to flag connections outside the expected destination set.
  condition: >
    outbound and container and
    not fd.sip in (known_internal_ranges) and
    not container.image.repository in (known_external_access_images) and
    fd.sport != 53
  output: >
    Unexpected outbound connection
    (user=%user.name proc=%proc.name
     container=%container.name image=%container.image.repository
     dest_ip=%fd.rip dest_port=%fd.rport proto=%fd.l4proto
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, network, command_and_control, T1071]

- rule: Cloud Metadata Service Access
  desc: >
    A container accessed the cloud provider metadata service endpoint
    (169.254.169.254). This endpoint provides IAM role credentials and
    instance identity documents. Access from application containers is
    rarely legitimate.
  condition: >
    outbound and container and
    fd.sip = "169.254.169.254"
  output: >
    Cloud metadata service accessed from container
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, cloud_metadata, credential_access, T1552]
```

---

## Triage guide

When this alert fires:

1. **Check the destination** — is `fd.rip` a known external service (payment gateway, CDN, monitoring endpoint)? Or is it an unknown IP, a known threat intelligence hit, or a cloud metadata endpoint?

2. **Check the process** — is the connecting process the expected application binary? Or is it `curl`, `wget`, `python`, `bash`, or another unexpected tool?

3. **Check the port** — connections on unusual ports (not 80, 443, or your known service ports) are higher priority. Connections to port 4444, 1337, or other common C2 ports are immediately suspicious.

4. **Check for a preceding event** — was there a shell spawn, a sensitive file read, or a download tool execution in the minutes before this connection? A chain of events escalates the priority significantly.

**Escalate if:** The destination is unknown, the connecting process is not the expected application binary, the connection was to the cloud metadata endpoint, or there is a preceding shell spawn or file read event.  
**Close if:** The destination is a known external service, the process is the expected application binary, and the timing correlates with normal application traffic.

---

## Remediation

**Immediate:**
```bash
# Apply a default-deny egress NetworkPolicy to the affected namespace
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: <affected-namespace>
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - port: 53
          protocol: UDP
EOF
```

**Structural:**
- Define explicit egress NetworkPolicies for every production namespace. Allow only the specific destinations each workload needs to reach.
- Block access to the cloud metadata endpoint (`169.254.169.254`) via NetworkPolicy for all pods that do not explicitly need instance identity.
- Use a service mesh (Istio, Linkerd) to get application-layer visibility into which service is talking to which.
- The [Detection Starter Pack](/services/#detection-starter) includes this rule family with tuned known-good destination lists and paired NetworkPolicy templates.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Package managers | `apt`, `apk` connect to external repositories during init | Bake dependencies into image; add pkg manager to exception |
| DNS resolution | All outbound connections trigger a DNS lookup first | Exclude port 53 traffic from this rule |
| Health check endpoints | Some health checks call external URLs | Replace with internal checks; add to known-good list |
| Node exporter / metrics | Some metrics agents connect to external collectors | Add known metrics destinations to allowed list |

---

## References

- [MITRE ATT&CK T1071](https://attack.mitre.org/techniques/T1071/)
- [Falco — Network detection](https://falco.org/docs/rules/)
- [Kubernetes — NetworkPolicy egress](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [AWS — IMDSv2 hardening](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
