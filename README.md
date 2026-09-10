# Epidemic Broadcast Tree — OMNeT++ (Adversarial Research Architecture)

This project simulates epidemic broadcast tree dissemination with reproducible
adversarial behavior, configurable overlays, repeated broadcast sessions, and a
global metrics sink suitable for research experiments.

## Architecture

- `EpidemicNode.{h,cc,ned}`: Node-level protocol state machine per broadcast,
  deterministic parent selection, duplicate handling, and attack hooks.
- `AttackModel.{h,cc}`: Attack type abstraction and per-neighbor malicious
  forwarding decisions.
- `ExperimentController.{h,cc,ned}`: Session orchestration, repeated source
  broadcasts, malicious-role assignment (fraction-based or fixed list).
- `TopologyBuilder.{h,cc,ned}`: Overlay generation (`complete`, `erdosRenyi`,
  `fixedDegree`, `file`) and runtime wiring of node ports.
- `StatsCollector.{h,cc,ned}`: Global dissemination sink that computes
  coverage, completion time, duplicates, transmissions, tree validity, and
  attack-related counters.
- `BroadcastId.h`: Session/origin/sequence identifier used as the broadcast key.
- `EpidemicMessage.msg`: Session-scoped packet schema with attack metadata.

## Research metrics

Metrics are collected globally in `StatsCollector` and include:

- coverage ratio over time
- total transmissions
- duplicate receptions
- completion time
- time to 90% of reachable nodes
- tree validity checks (`|E| = |V|-1`, acyclicity, parent consistency)
- malicious actions, drops, and forged metadata observations
- topology summary (components, source component size, edge count, average degree)

## Running sweeps

`omnetpp.ini` includes sweep-ready configurations for:

- malicious fraction (`mf`)
- attack type (`attack`)
- topology mode (`topo`) and topology parameters
- repeated broadcast sessions (`numBroadcasts`, `broadcastInterval`)
- repetition and seed controls

Use `Baseline`, `Adversarial`, and `TopologyStudy` configurations for
comparative studies.

## Notes

- Topologies are built at runtime by `TopologyBuilder` and no longer assume a
  complete graph.
- Broadcast identity is explicitly scoped by `(sessionId, originId, broadcastSeq)`
  to avoid contamination across repeated sessions.
- `maxMessages` is enforced to bound per-node accepted broadcasts.
