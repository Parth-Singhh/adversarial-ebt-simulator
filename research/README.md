# EBT simulation results: automated analysis

## Contents
- `broadcast_metrics.csv`: one row per broadcast observation (330 expected).
- `run_metrics.csv`: one row per independent simulation repetition (110 expected).
- `condition_summary.csv`: mean metrics by experimental condition.
- `quality_checks.csv`: structural validation issues.
- PNG files: key plots.

## Experiment coverage
- 135 selected `.sca` files analyzed: 110 sweep outputs from the ZIP plus 25 selected fixed-60-node outputs; five seeds/repetitions per condition; three broadcasts per file (405 observations).
- Malicious-fraction study: N=60; fractions 5%, 20%, 30%; four attack types; five repetitions each.
- Network-size study: N=30, 60, and 100; baseline plus four attack conditions; five repetitions each. N=30/100 are from the ZIP; N=60 is from the matching fixed-size runs uploaded separately.
- Topology is reported as one connected component in the parsed results; edge counts were checked against a complete graph for each N.
- All observed `treeValid` scalar values are 1.

## Measurement notes
- Coverage, transmission count, duplicates, drops, malicious actions and tree statistics are first averaged over the three broadcasts inside each repetition; condition-level means and standard deviations are then computed across five repetitions where applicable.
- Full delivery means the recorded `completionTime` is non-negative. Coverage can be close to 100% even when full delivery is not achieved.
- `timeTo90pctReachable` and `timeTo95pctReachable` are reported only when those thresholds were reached. Threshold rates use only broadcast observations where the respective metric was instrumented. The earlier fixed-60-node `.sca` files predate the `timeTo95pctReachable` scalar, so their T95 result is blank—not zero. The CSV includes instrumentation counts to make this explicit.
- Do not interpret three broadcasts within one simulation repetition as three independent random seeds.

## Important limitation
- The ZIP alone contains the 110 sweep runs. To complete the 30/60/100-node scaling analysis, I separately included only one consistent five-repetition set for each of the earlier fixed-60-node configurations and excluded duplicate uploads/reruns.
- The results are simulator observations for the configured complete topology, fanout and attack parameters; they should not be generalized to real networks without additional validation.

## Quality check totals
- Broadcast observations: 405; full-delivery observations: 119/405 (29.4%).
- Broadcast observations without a recorded 90% threshold time: 2.
- Broadcasts with an instrumented T95 metric but no T95 timestamp: 18; older fixed-60-node broadcasts without T95 instrumentation: 78.
- Quality-check rows: 0 (some threshold-time fields are naturally absent when a broadcast did not reach the threshold; see `quality_checks.csv`).