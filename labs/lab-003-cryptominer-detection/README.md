# LAB-003: Cryptominer Process Detected

**MITRE ATT&CK:** [T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)  
**Tactic:** Impact  
**Severity:** CRITICAL  

---

## Threat scenario

An attacker has compromised a container in your cluster  -  likely via an exposed service, a vulnerable application, or a misconfigured admission policy. Their first move is not lateral movement or data exfiltration. It is to install a cryptominer and start generating revenue using your compute.

This is the most common first-stage attack against Kubernetes clusters with exposed endpoints. It is also one of the easiest attacks to detect, because miners use well-known binaries with distinctive names.

---

## Why this matters

Cryptomining attacks are noisy in terms of compute usage, but quiet in terms of network and filesystem activity. The attacker does not need to exfiltrate data or move laterally. They just need your CPU.

**Why this is a high-priority detection:**

1. **High signal, near-zero false positives**  -  production containers almost never run `xmrig`, `minerd`, or `cgminer` legitimately
2. **Indicates full execution**  -  if a miner is running, the attacker has already gained execution inside a container
3. **Leads to larger bill and degraded performance**  -  cryptomining consumes CPU aggressively and will affect other workloads
4. **Often the first indicator of a broader compromise**  -  detect it early and you may catch the attacker before they move to more damaging techniques

**MITRE ATT&CK:** [T1496  -  Resource Hijacking](https://attack.mitre.org/techniques/T1496/)  
**Tactic:** Impact  
**Severity:** Critical

---

## Attack simulation

To simulate a cryptominer detection **in a test environment only**:

```bash
# Deploy a test pod
kubectl run lab003 --image=ubuntu --restart=Never -- sleep 3600

# Exec into the pod
kubectl exec -it lab003 -- bash

# Inside  -  simulate the process name only (do NOT run actual miner)
# Just create a binary with the miner name to trigger the process name check
cp /bin/sleep /tmp/xmrig
/tmp/xmrig 300
```

Expected result: Falco fires a CRITICAL alert on the process name `xmrig` regardless of what binary it actually is. The rule matches on `proc.name`.

For a more realistic test, check if your Falco installation includes `xmrig` in the `crypto_miners` macro:

```bash
# On a node running Falco
grep -r "crypto_miners" /etc/falco/
```

---

## Falco detection rule

```yaml
- macro: crypto_miners
  condition: >
    proc.name in (xmrig, xmrig-notls, xmrig-cuda, minerd, cgminer,
                  bfgminer, cpuminer, ethminer, t-rex, nbminer,
                  lolminer, phoenixminer, gminer, teamredminer)

- rule: Cryptominer Process Detected
  desc: >
    A known cryptomining process was detected inside a container.
    This indicates the container has been compromised and is being
    used to mine cryptocurrency using cluster resources.
  condition: >
    spawned_process and container and
    crypto_miners
  output: >
    Cryptominer process detected
    (user=%user.name container=%container.name
    image=%container.image.repository
    process=%proc.name cmdline=%proc.cmdline
    namespace=%k8s.ns.name pod=%k8s.pod.name)
  priority: CRITICAL
  tags: [container, cryptominer, T1496, impact]
```

**Note:** The `crypto_miners` macro above is a superset of Falco's default list. Add new miner names as they are discovered. This list evolves  -  check for updates periodically.

---

## Triage guide

When this alert fires, treat it as a confirmed incident immediately:

1. **Identify and isolate the pod**  -  do not wait to investigate. Isolate first.

```bash
# Remove the pod from service
kubectl label pod <pod-name> quarantine=true
# If you have a network policy that blocks quarantined pods, this takes effect immediately

# Or delete immediately if you have confirmed it is compromised
kubectl delete pod <pod-name>
```

2. **Preserve evidence if needed**  -  before deleting, capture the running process list and any network connections:

```bash
kubectl exec <pod-name> -- ps aux > /tmp/lab003-processes.txt
kubectl exec <pod-name> -- netstat -tulpn > /tmp/lab003-netstat.txt
```

3. **Trace the entry point**  -  how did the attacker get execution? Check:
   - Kubernetes audit log for recent `exec` events into this pod
   - Application logs for exploitation attempts
   - Image history  -  was the miner baked into the image or installed post-start?

4. **Check for lateral movement**  -  look at network connections from the compromised pod. Did it connect to other cluster services? Did it attempt to access the Kubernetes API?

5. **Review the deployment pipeline**  -  if the miner was in the image, your image registry or CI/CD pipeline may be compromised.

**Escalate immediately.** There are no legitimate reasons for a cryptominer to run in a production container. This is always a true positive.

---

## Remediation

**Immediate:**
```bash
# Delete the compromised pod
kubectl delete pod <pod-name> --grace-period=0 --force

# If the workload was a deployment, scale it down while investigating
kubectl scale deployment <deployment-name> --replicas=0
```

**Structural  -  Image scanning:**

Add Trivy to your CI pipeline to scan images before they are pushed to your registry. Known miner binaries are caught by vulnerability and misconfiguration scans:

```bash
trivy image --severity HIGH,CRITICAL <your-image>
```

**Structural  -  Admission control:**

Use an admission controller to block images from untrusted registries. If the miner was installed post-start (not baked in), this does not help directly  -  but blocking shell access to containers reduces the attacker's ability to install miners at runtime.

**Structural  -  Network policy:**

Cryptominers need to reach the mining pool. A default-deny egress network policy dramatically reduces the attacker's ability to run a miner even if they gain execution:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: production
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
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

---

## False positive notes

| Source | False positive rate | Notes |
|---|---|---|
| Legitimate applications | Virtually none | Production workloads do not run `xmrig` or `minerd` |
| Test environments | Possible if testing Falco itself | Use the simulation method above (rename a sleep binary) instead of running real miners |
| Custom binary names | Possible if attacker uses renamed binary | Layer with behavior-based detection (CPU usage spikes, unexpected network connections) |

This is the lowest false positive rate of any runtime detection rule. If this fires, it is almost certainly real.

---

## References

- [MITRE ATT&CK T1496  -  Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [Falco default rules  -  spawned_process](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Trivy  -  image scanning](https://trivy.dev/docs/)
- [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
