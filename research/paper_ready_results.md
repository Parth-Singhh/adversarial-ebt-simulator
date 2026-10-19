# Paper-ready experimental findings

## Experimental dataset
The combined analysis uses 135 selected simulation repetitions and 405 broadcast observations. This comprises 110 sweep result files from `results_full_sweep.zip` plus 25 standalone files from one consistent fixed-60-node run set. Each repetition includes three broadcasts. Each experimental condition uses five repetitions (seed sets 0–4). The topology is complete and connected for each tested network size; the size conditions are 30, 60, and 100 nodes. The 60-node fixed-condition attack runs use a 10% malicious fraction; the baseline uses 0%. The malicious-fraction sweep tests 5%, 20%, and 30% at 60 nodes.

**Metric definitions.** Mean coverage is the mean percentage of nodes reached per broadcast, averaged over the three broadcasts within each repetition and then over five repetitions. Full-delivery rate is the percentage of individual broadcasts whose recorded `completionTime` is non-negative. Transmissions, drops, and malicious actions are reported as mean counts per broadcast. The T95 metrics are available only in the newer sweep result files; the older 60-node files did not record them, so those cells are intentionally blank.

## Malicious-fraction sweep (60 nodes)
| Malicious fraction | Attack | Mean coverage | Full delivery | Mean transmissions | Mean drops | Mean time to 95%* |
|---:|---|---:|---:|---:|---:|---:|
| 5% | Delay/Jitter | 98.2% | 40.0% | 235.73 | 0.00 | 50.31 ms |
| 5% | Drop-All | 97.9% | 13.3% | 223.47 | 14.33 | 56.80 ms |
| 5% | Isolation | 97.4% | 20.0% | 232.87 | 1.00 | 54.80 ms |
| 5% | Selective Forwarding | 97.9% | 33.3% | 228.80 | 6.33 | 54.00 ms |
| 20% | Delay/Jitter | 98.4% | 46.7% | 236.27 | 0.00 | 60.47 ms |
| 20% | Drop-All | 94.9% | 0.0% | 181.60 | 57.67 | 64.00 ms |
| 20% | Isolation | 97.8% | 20.0% | 230.13 | 4.53 | 57.60 ms |
| 20% | Selective Forwarding | 97.4% | 26.7% | 210.53 | 24.00 | 57.60 ms |
| 30% | Delay/Jitter | 98.4% | 46.7% | 236.27 | 0.00 | 67.43 ms |
| 30% | Drop-All | 95.0% | 0.0% | 159.73 | 85.33 | 66.50 ms |
| 30% | Isolation | 97.4% | 20.0% | 227.07 | 6.80 | 59.20 ms |
| 30% | Selective Forwarding | 96.2% | 13.3% | 195.40 | 36.87 | 60.80 ms |

*Mean T95 is conditional on the metric being recorded, and missing T95 timestamps indicate a broadcast did not reach that threshold in files where T95 was instrumented.

## Network-size sweep
| Nodes | Attack condition | Malicious fraction | Mean coverage | Full delivery | Mean transmissions | Mean drops |
|---:|---|---:|---:|---:|---:|---:|
| 30 | Baseline | 0.0% | 99.1% | 80.0% | 118.93 | 0.00 |
| 30 | Drop-All | 10.0% | 98.4% | 60.0% | 106.67 | 14.33 |
| 30 | Selective Forwarding | 10.0% | 98.4% | 60.0% | 111.00 | 7.53 |
| 30 | Delay/Jitter | 10.0% | 99.6% | 86.7% | 119.47 | 0.00 |
| 30 | Isolation | 10.0% | 99.1% | 80.0% | 117.60 | 1.33 |
| 60 | Baseline | 0.0% | 97.8% | 20.0% | 234.67 | 0.00 |
| 60 | Drop-All | 10.0% | 96.9% | 26.7% | 209.07 | 29.33 |
| 60 | Selective Forwarding | 10.0% | 97.9% | 26.7% | 222.20 | 13.20 |
| 60 | Delay/Jitter | 10.0% | 98.0% | 26.7% | 235.20 | 0.00 |
| 60 | Isolation | 10.0% | 97.4% | 20.0% | 231.53 | 2.33 |
| 100 | Baseline | 0.0% | 97.9% | 0.0% | 391.47 | 0.00 |
| 100 | Drop-All | 10.0% | 97.7% | 6.7% | 352.00 | 48.67 |
| 100 | Selective Forwarding | 10.0% | 98.1% | 6.7% | 373.80 | 19.07 |
| 100 | Delay/Jitter | 10.0% | 98.0% | 13.3% | 392.00 | 0.00 |
| 100 | Isolation | 10.0% | 98.1% | 0.0% | 387.80 | 4.73 |

## Main findings supported by the recorded results
1. **Drop-All has the strongest coverage and completion impact in the fraction sweep.** At 5% malicious peers, mean coverage is 97.89% and 13.3% of broadcasts reach every node. At 20% and 30%, mean coverage is 94.89% and 95.00%, and no broadcast in either condition achieves 100% delivery. Recorded drops rise from 14.33 to 57.67 and 85.33 per broadcast as the malicious fraction increases.
2. **Selective forwarding degrades progressively as malicious peers increase.** Mean coverage falls from 97.89% at 5% malicious peers to 96.22% at 30%; full delivery falls from 33.3% to 13.3% of broadcasts. Average recorded drops rise from 6.33 to 36.87 per broadcast.
3. **Delay/Jitter mostly affects timeliness rather than final coverage in this setup.** Mean coverage stays between 98.22% and 98.44% across the 5%–30% sweep, and no drops are recorded. Among broadcasts with T95 values, mean time to reach 95% rises from about 50.3 ms at 5% malicious peers to 67.4 ms at 30%. This indicates the need to discuss latency separately from coverage.
4. **Isolation shows a comparatively stable average-coverage result under the configured isolation policy.** Mean coverage varies between 97.44% and 97.78%, while the full-delivery rate remains 20% in all three fraction conditions. This is not evidence that isolation is harmless: the complete-delivery metric still shows missed nodes in most broadcasts.
5. **Larger networks are harder to complete perfectly even when average coverage remains high.** For the baseline, mean coverage is 99.11%, 97.78%, and 97.87% at 30, 60, and 100 nodes, respectively, while full-delivery rate is 80%, 20%, and 0%. At 100 nodes, all five conditions average roughly 97.7%–98.1% coverage, but full delivery ranges from 0% to 13.3%. Reporting only average coverage would therefore overstate practical completion reliability.
6. **Transmission volume increases with network size, while dropping attacks reduce useful dissemination.** Baseline mean transmissions per broadcast rise from 118.93 at 30 nodes to 234.67 at 60 and 391.47 at 100. In the 60-node fraction sweep, Drop-All transmissions fall from 223.47 at 5% malicious peers to 159.73 at 30%, alongside a steep increase in recorded drops.
7. **All 405 observations report `treeValid = 1`.** This confirms that the tree-structure validity check remained satisfied in the recorded runs, even when the reachability metric indicates that some nodes were not reached. Structural validity should not be described as equivalent to full dissemination.

## Limitations and reporting cautions
- The simulation uses a complete-graph topology, fixed fanout 4, and the current configured forwarding/gossip delays; results are not evidence for sparse or real-world network topologies.
- The malicious-fraction study has five repetitions per condition. Treat the results as an exploratory simulation study; avoid broad statistical-significance claims unless additional repetitions/tests are run.
- The fixed-60-node result files predate the `timeTo95pctReachable` scalar, so T95 is unavailable there. Do not fill those values using estimates.
- The result set does not establish an attack-independent optimal strategy. Results depend on the implemented policies and configuration (including the explicit isolation peer set).

## Figures
- `coverage_vs_malicious_fraction.png`
- `full_delivery_vs_malicious_fraction.png`
- `coverage_vs_network_size.png`
- `transmissions_and_drops_vs_fraction.png`
