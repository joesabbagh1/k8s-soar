# Stage 4 — Command & Control (T1071)

## Action
From the Stage 1 foothold shell, opened a second/third reverse shell
back to Kali, simulating an attacker re-establishing or expanding C2
channels after initial compromise.

## Detection
Tetragon's existing `k8s-soar-detect-reverse-shell` TracingPolicy
(scoped to pods labeled `scenario: "04"`) correctly fired once the
DVWA pod template was fixed to actually carry that label (see the
"fix: add scenario=04 label to DVWA pod template" commit — the
Deployment's own metadata had app=victim/scenario=chain, but that
does not propagate to the pods themselves, which take their labels
from spec.template.metadata.labels).

Full kernel-level detection: exact pod, process, and 4-tuple
connection captured (see tetragon-detection.log).

## No automated response
The connection was **not blocked**. Two independent reasons:

1. Tetragon's detect-reverse-shell policy uses `action: Post`
   (log-only), by original design — it observes, it does not enforce.
2. The SOAR quarantine loop (Falco -> falcosidekick -> Shuffle ->
   label pod -> Cilium deny) was never triggered at all for this pod,
   because Falco's custom rules have a documented detection gap for
   pods created after Falco's own startup (see
   ../falco-detection-gap.md and ../stage2-credential-access/).
   Tetragon detections are not wired into the same SOAR pipeline as
   Falco detections in this architecture.

## Implication
This demonstrates a real architectural finding: detection and
automated response are not the same guarantee. A defense-in-depth
platform can correctly *observe* an attack at multiple independent
layers (Tetragon here) while still failing to *act* on it, if the
automated response pipeline is wired to only one of those layers
(Falco) and that layer has a gap. This is flagged as a concrete
recommendation for future work: wire Tetragon's Post-action events
into the same SOAR pipeline as Falco, so response is layer-agnostic.
