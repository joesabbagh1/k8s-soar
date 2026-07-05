# Stage 1 — Shell In Victim Container: Detection Gap

## Summary
During execution of Stage 1 of the custom exploitation chain (DVWA command
injection → reverse shell → `bash` spawn inside the `dvwa` pod in
`security-lab`), Falco's custom rule `K8sSoar Shell In Victim Container`
did not fire, despite the underlying attacker action (an interactive shell
spawned via command injection) being a textbook match for the rule's
intent.

## Root causes identified and fixed
1. **Null-unsafe rule conditions.** All four custom rules in
   `policies/falco/k8s-soar_rules.yaml` used the condition
   `k8s.ns.name != "kube-system"`. In Falco's filter syntax, comparing an
   unset/null field with `!=` evaluates to `false`, not `true` — so any
   pod whose `k8s.ns.name` metadata had not yet been enriched would never
   match, regardless of the actual namespace. Fixed by rewriting the
   condition as `(not k8s.ns.name exists or k8s.ns.name != "kube-system")`,
   which fails safe (alerts) rather than fails open (silently drops)
   when metadata is missing.
2. **Undefined macro in "K8sSoar Reverse Shell Outbound".** The rule
   referenced an `outbound` macro that was never defined anywhere in the
   ruleset, causing Falco to reject that specific rule at load time
   (`LOAD_ERR_VALIDATE: Undefined macro 'outbound' used in filter`).
   Fixed by replacing it with an explicit `evt.type = connect and
   evt.dir = "<"` condition.

## Remaining, unresolved gap
Even after both fixes above, and after restarting both the Falco
DaemonSet and the `falco-k8s-metacollector` Deployment, custom rules
still did not fire against pods created after Falco's own startup —
including a fresh, minimal `busybox` test pod created specifically to
isolate the issue from DVWA/security-lab-specific factors.

Critically, this is **not** a wholesale detection failure:
- Falco's own **stock** rules (e.g. "Read sensitive file untrusted")
  fired correctly against the same class of newly-created pods,
  confirming the eBPF kernel capture engine and rule-matching engine
  are both healthy.
- The custom rule "K8sSoar Sensitive Credential Access" fired
  correctly and repeatedly — but only for pods that already existed
  before Falco's own startup (Loki, Prometheus, Kyverno control-plane
  pods).

This strongly suggests a **metadata-enrichment timing issue** specific
to how the custom rules interact with the `container` plugin / k8s
metadata plugin, rather than a problem with the eBPF probe or the rule
engine itself. The exact mechanism was not identified despite testing:
socket path configuration, plugin reinstallation, rule null-safety,
and restarting every related component individually and in combination.

## Evidence
- Falco stock rule detection of a fresh pod's sensitive file read
  (proves eBPF + rule engine health): see `stock-rule-detection.log`
- Custom rule firing correctly for a pre-existing pod (proves rule
  syntax is valid once loaded): see `custom-rule-preexisting-pod.log`
- Custom rule silent on identical action against a newly-created pod:
  see `custom-rule-new-pod-silence.log`

## Implication for the thesis
This is documented as a known limitation of the current k8s-soar Falco
deployment rather than a failure of the exploitation chain: the
attacker action was successfully executed and is independently
verifiable (see Stage 1 exploitation log), but the detection layer's
custom ruleset has a reproducible gap for freshly-created workloads.
This is flagged as a concrete item for future work: either backfilling
k8s-metacollector's initial sync to include a full resync trigger, or
restarting Falco as an explicit pre-condition immediately before each
scenario run (a viable operational workaround, though not a real fix).
