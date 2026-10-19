# EBT Research Results and Reproducibility

This directory contains the derived metrics, research figures, and raw simulation-result archives for **Investigating the Resilience of Epidemic Broadcast Trees Against Malicious Behaviour**.

## Regenerate the analysis

From the repository root, using Python 3.10 or later:

```bash
python -m pip install -r research/requirements.txt
python research/scripts/analyze_results.py
```

The script reads only the committed input archives:

- `research/raw/results_full_sweep.zip` — 110 sweep `.sca` files for the malicious-fraction and network-size experiments.
- `research/raw/fixed60_core.zip` — 25 fixed 60-node `.sca` files used as the middle-size comparison.

It regenerates:

- `research/analysis/broadcast_metrics.csv` — one row per broadcast.
- `research/analysis/run_metrics.csv` — one row per simulation repetition/file.
- `research/analysis/condition_summary.csv` — condition-level averages and between-run standard deviations.
- `research/analysis/quality_checks.csv` — empty apart from its header when checks pass; non-empty output should be reviewed.
- Four PNGs under `research/figures/`.
- `research/paper_ready_results.md` — a results summary derived from the same analysis data.

The script uses only Python's standard library plus Matplotlib. It does not change the raw ZIP files. To process alternate archives, pass `--sweep-archive` and `--fixed-archive`; to write outputs to another clone/root, pass `--root`.

## Experiment design

- Complete graph topology; tested sizes: 30, 60, and 100 nodes.
- Fanout 4, forwarding delay 10 ms, gossip delay 1 ms, three broadcasts spaced 250 ms apart, simulated-time limit 20 s.
- Malicious-fraction sweep: 60 nodes, 5%, 20%, and 30% malicious peers; Drop-All, Selective Forwarding, Delay/Jitter, and Isolation.
- Network-size comparison: 30 and 100 nodes with baseline and four attack conditions; 60-node runs provide the intermediate comparison.
- Five repetitions (seed sets 0–4) per condition.

## Interpretation cautions

- Full delivery and mean coverage are different metrics. A high average coverage score does not imply every node received every broadcast.
- Tree-validity checks verify the recorded dissemination-tree structure; they do not imply complete reachability.
- T95 metrics are absent from the older fixed-60-node `.sca` files; the script preserves those missing values rather than imputing them.
- Results are conditional on these implementation choices and a complete graph; do not generalize them to sparse overlays without more experiments.
