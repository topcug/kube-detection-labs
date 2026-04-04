# LAB-NNN: <Title>

**MITRE ATT&CK:** [TNNN - Technique Name](https://attack.mitre.org/techniques/TNNN/)  
**Tactic:** <Tactic>  
**Severity:** CRITICAL | HIGH | MEDIUM | LOW  

---

## Threat scenario

<!-- Describe the real-world scenario. Who is the attacker, what have they done, what is happening now? Keep it concrete and specific. -->

---

## Why this matters

<!-- Explain the impact. What can the attacker do from this position? What is the blast radius? -->

**MITRE ATT&CK:** [TNNN - Technique Name](https://attack.mitre.org/techniques/TNNN/)  
**Tactic:** <Tactic>  
**Severity:** CRITICAL | HIGH | MEDIUM | LOW

---

## Attack simulation

<!-- Step-by-step commands to reproduce this scenario in a test cluster. -->

```bash
# Step 1: set up
# Step 2: trigger the behavior
# Step 3: verify Falco fires
```

Expected result: <!-- what Falco output should appear -->

---

## Falco detection rule

```yaml
- rule: <Rule Name>
  desc: >
    <Description>
  condition: >
    <condition>
  output: >
    <output format>
  priority: CRITICAL | HIGH | MEDIUM | LOW
  tags: [container, <tag>, <mitre_tactic>, TNNN]
```

---

## Triage guide

When this alert fires:

1. **Step one** — what to check first
2. **Step two** — what to check second
3. **Step three** — what to check third

**Escalate if:** <condition>  
**Close if:** <condition>

---

## Remediation

**Immediate:**
```bash
# command
```

**Structural:**
- Action 1
- Action 2

---

## False positive notes

| Source | Pattern | Mitigation |
|---|---|---|
| Source | What triggers it | How to handle |

---

## References

- [Reference 1](url)
- [Reference 2](url)
