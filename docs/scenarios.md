# Attack scenarios, the demo app, and verifying the response

`scenarios/<id>-<name>/` holds attack simulations for validating k8s-soar against your own
cluster. Run one, then check what k8s-soar did. They are meant for clusters you own and
operate: lab, staging, or a customer environment you're authorised to test.

```bash
make <attack>                  # run one, e.g. make crypto-miner (runs in the default namespace)
make verify-attack ATTACK=crypto-miner    # what did k8s-soar do?
make verify-attack ATTACK=all ARGS="--since 60"
```

## What `verify-attack` checks

It doesn't run anything; it reads the case Workflows. For each Falco rule named in backticks
in the scenario's README it checks:

| Check | Level |
|-------|-------|
| a case was opened for the rule inside the window (`--since`, default 15 min) | FAIL if not |
| rules tagged `soar_contain` were routed to containment and the pod was quarantined | FAIL if not (WARN in `dry-run`) |
| the AI gave a verdict | WARN if AI is off or unavailable; INFO while it is still running |
| later alerts on the same pod | INFO: folded into the open case; other rules that fired on the pod |

The expected rules come from the README itself (`scripts/check-scenarios.sh` runs in CI and
fails if a README names a rule that doesn't exist), and containment expectations come from the
rule tags in `charts/k8s-soar/files/falco-rules/`. Scenarios whose README names no Falco rule
(Kyverno or Tetragon scenarios, or ones not yet mapped) report `SKIP`.

## The demo customer app

`make demo-app` installs a small three-tier application in the `shop` namespace (`web` nginx,
`api` podinfo, `db` redis, with ServiceAccounts, Services and tier-to-tier NetworkPolicies) so
k8s-soar protects something that looks like a real workload. Nothing depends on it:
`make demo-app-delete` removes it.

To aim a scenario at it instead of its own pod, run with `TARGET=demo`
(`make <attack> TARGET=demo`). A scenario opts in by asking the shared library for a target:

```bash
source scripts/lab/scenario-lib.sh
if pod=$(scenario_demo_pod web); then
  :   # TARGET=demo: use "$pod"; SCENARIO_NS is now "shop"
else
  :   # default: create the scenario's own pod, as before
fi
```

`scenario_demo_pod <web|api|db>` fails unless `TARGET=demo`, so existing scenarios behave exactly
as before until they opt in. It also switches `SCENARIO_NS`, so `scenario_expect_case` and
`scenario_expect_quarantine` look in the right namespace.
