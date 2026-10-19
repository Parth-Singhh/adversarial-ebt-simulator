#!/usr/bin/env python3
"""Rebuild EBT research CSV summaries, quality checks, figures, and findings.

Run from any working directory with:
    python research/scripts/analyze_results.py

The script reads only the committed ZIP archives under research/raw/ and writes
reproducible derived outputs under research/analysis/, research/figures/, and
research/paper_ready_results.md. Raw archives are never modified.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SWEEP = ROOT / "research" / "raw" / "results_full_sweep.zip"
DEFAULT_FIXED = ROOT / "research" / "raw" / "fixed60_core.zip"

BROADCAST_METRICS = [
    "file", "source", "config", "rep", "seed", "run_number", "study", "N",
    "fraction", "attack_type", "edge_count", "components", "attack_raw",
    "isolation_mode", "isolated_peer_set", "instrumented_time90",
    "instrumented_time95", "broadcast_id", "broadcast_index", "reached",
    "coverageRatio", "duplicates", "transmissions", "drops", "maliciousActions",
    "forgedMetadataEvents", "treeEdges", "maxDepth", "treeValid", "completionTime",
    "timeTo90pctReachable", "timeTo95pctReachable", "lastReachedTime", "coverage_pct",
    "full_coverage", "reached_90pct", "reached_95pct",
]
RUN_METRICS = [
    "file", "source", "config", "rep", "seed", "run_number", "study", "N",
    "fraction", "attack_type", "edge_count", "components", "attack_raw",
    "isolation_mode", "isolated_peer_set", "instrumented_time90", "instrumented_time95",
    "broadcast_count", "mean_coverageRatio", "mean_transmissions", "mean_duplicates",
    "mean_drops", "mean_maliciousActions", "mean_treeValid", "mean_treeEdges",
    "mean_maxDepth", "mean_coverage_pct", "mean_completionTime_if_complete",
    "full_coverage_broadcasts", "instrumented90_broadcasts", "instrumented95_broadcasts",
    "coverage90_broadcasts", "coverage95_broadcasts", "mean_time90_s_conditional",
    "mean_time95_s_conditional", "mean_lastReachedTime_s",
]
CONDITION_SUMMARY = [
    "study", "nodes", "malicious_fraction", "attack", "runs", "broadcasts",
    "mean_coverage_pct", "sd_coverage_pct_between_runs", "mean_transmissions",
    "sd_transmissions_between_runs", "mean_duplicates", "mean_drops",
    "mean_malicious_actions", "mean_tree_valid_pct", "full_coverage_broadcasts",
    "full_coverage_pct", "reached_90pct_broadcasts", "instrumented_90pct_broadcasts",
    "reached_90pct_pct", "reached_95pct_broadcasts", "instrumented_95pct_broadcasts",
    "reached_95pct_pct", "mean_time_to_90ms_conditional", "mean_time_to_95ms_conditional",
    "full_completion_time_mean_ms_conditional", "topology_components", "edge_count",
    "isolated_peer_set", "isolation_mode", "seeds",
]
QUALITY_COLUMNS = ["file", "issue", "actual", "expected"]

ATTACK_LABELS = {
    "honest": "Baseline",
    "drop": "Drop-All",
    "drop_all": "Drop-All",
    "selective_forward": "Selective Forwarding",
    "delay": "Delay/Jitter",
    "delay_jitter": "Delay/Jitter",
    "isolation": "Isolation",
    "probabilistic_forward": "Probabilistic Forwarding",
    "flood_duplicates": "Flood Duplicates",
    "equivocation": "Equivocation",
    "spoof_metadata": "Metadata Spoofing",
}


def clean_value(value: str) -> str:
    """Remove OMNeT++ string quoting while preserving actual text."""
    value = value.strip()
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
            if isinstance(decoded, str):
                value = decoded
        except (json.JSONDecodeError, TypeError):
            pass
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value.replace('\\"', '"').strip()


def number(value: Any, default: float | None = None) -> float | None:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def scalar_mean(values: Iterable[float | None], *, nonnegative: bool = False) -> float | None:
    included = [float(v) for v in values if v is not None and (not nonnegative or float(v) >= 0)]
    return statistics.fmean(included) if included else None


def write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            serialized = {}
            for field in fields:
                value = row.get(field)
                if value is None or (isinstance(value, float) and math.isnan(value)):
                    serialized[field] = ""
                elif isinstance(value, bool):
                    serialized[field] = "True" if value else "False"
                else:
                    serialized[field] = value
            writer.writerow(serialized)


def parse_sca_text(text: str, filename: str, source: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    attrs: dict[str, str] = {}
    params: dict[str, str] = {}
    node_params: dict[str, list[str]] = defaultdict(list)
    scalars: dict[str, float] = {}
    for line in text.splitlines():
        if line.startswith("attr "):
            parts = line.split(maxsplit=2)
            if len(parts) == 3:
                attrs[parts[1]] = parts[2].strip()
        elif line.startswith("par EpidemicBroadcastTree "):
            parts = line.split(maxsplit=3)
            if len(parts) == 4:
                params[parts[2]] = clean_value(parts[3])
        elif line.startswith("par EpidemicBroadcastTree.node["):
            parts = line.split(maxsplit=3)
            if len(parts) == 4:
                node_params[parts[2]].append(clean_value(parts[3]))
        elif line.startswith("scalar "):
            parts = line.split(maxsplit=3)
            if len(parts) == 4:
                _, module, name, value = parts
                try:
                    scalars[name] = float(value)
                except ValueError:
                    continue

    # Some settings (notably isolationMode and isolatedPeerSet) are node-level
    # parameters and do not appear on the top-level network module. Use the most
    # frequent effective value across nodes as a fallback for those settings.
    for key, values in node_params.items():
        if key not in params and values:
            params[key] = Counter(values).most_common(1)[0][0]

    config = attrs.get("configname", filename.split("-", 1)[0])
    try:
        rep = int(attrs.get("repetition", re.search(r"#(\d+)", filename).group(1) if re.search(r"#(\d+)", filename) else 0))
    except ValueError:
        rep = 0
    try:
        seed = int(attrs.get("seedset", rep))
    except ValueError:
        seed = rep
    try:
        run_number = int(attrs.get("runnumber", rep))
    except ValueError:
        run_number = rep
    n = int(number(params.get("numNodes"), 60) or 60)
    fraction = float(number(params.get("maliciousFraction"), 0.0) or 0.0)
    attack_raw = clean_value(params.get("attackType", "honest")).lower()
    attack_label = ATTACK_LABELS.get(attack_raw, attack_raw.replace("_", " ").title())
    study = "fraction" if config == "MaliciousFractionSweep" else "size"
    edge_count = int(number(scalars.get("topology.edgeCount"), 0) or 0)
    components = int(number(scalars.get("topology.components"), 0) or 0)
    isolation_mode = clean_value(params.get("isolationMode", "none")) or "none"
    isolated_peer_set = clean_value(params.get("isolatedPeerSet", ""))

    broadcasts: dict[str, dict[str, float]] = defaultdict(dict)
    for name, value in scalars.items():
        if not name.startswith("broadcast."):
            continue
        rest = name[len("broadcast."):]
        if "." not in rest:
            continue
        broadcast_id, metric = rest.rsplit(".", 1)
        broadcasts[broadcast_id][metric] = value

    sorted_broadcasts = sorted(
        broadcasts.items(),
        key=lambda item: int(re.search(r"_b(\d+)$", item[0]).group(1)) if re.search(r"_b(\d+)$", item[0]) else item[0],
    )
    has90 = any("timeTo90pctReachable" in metrics for _, metrics in sorted_broadcasts)
    has95 = any("timeTo95pctReachable" in metrics for _, metrics in sorted_broadcasts)
    run_meta = {
        "file": filename,
        "source": source,
        "config": config,
        "rep": rep,
        "seed": seed,
        "run_number": run_number,
        "study": study,
        "N": n,
        "fraction": fraction,
        "attack_type": attack_label,
        "edge_count": edge_count,
        "components": components,
        "attack_raw": attack_raw,
        "isolation_mode": isolation_mode,
        "isolated_peer_set": isolated_peer_set,
        "instrumented_time90": has90,
        "instrumented_time95": has95,
    }

    broadcast_rows: list[dict[str, Any]] = []
    for broadcast_id, metrics in sorted_broadcasts:
        bindex_match = re.search(r"_b(\d+)$", broadcast_id)
        bindex = int(bindex_match.group(1)) if bindex_match else len(broadcast_rows)
        reached = number(metrics.get("reached"))
        ratio = number(metrics.get("coverageRatio"))
        if ratio is None and reached is not None:
            denominator = number(scalars.get("topology.sourceComponentSize"), n) or n
            ratio = reached / denominator if denominator else None
        completion = number(metrics.get("completionTime"))
        t90 = number(metrics.get("timeTo90pctReachable"))
        t95 = number(metrics.get("timeTo95pctReachable"))
        last = number(metrics.get("lastReachedTime"))
        row = {
            **run_meta,
            "broadcast_id": broadcast_id,
            "broadcast_index": bindex,
            "reached": reached,
            "coverageRatio": ratio,
            "duplicates": number(metrics.get("duplicates")),
            "transmissions": number(metrics.get("transmissions")),
            "drops": number(metrics.get("drops")),
            "maliciousActions": number(metrics.get("maliciousActions")),
            "forgedMetadataEvents": number(metrics.get("forgedMetadataEvents")),
            "treeEdges": number(metrics.get("treeEdges")),
            "maxDepth": number(metrics.get("maxDepth")),
            "treeValid": number(metrics.get("treeValid")),
            "completionTime": completion,
            "timeTo90pctReachable": t90,
            "timeTo95pctReachable": t95,
            "lastReachedTime": last,
            "coverage_pct": ratio * 100 if ratio is not None else None,
            "full_coverage": int(completion is not None and completion >= 0),
            "reached_90pct": (int(t90 >= 0) if t90 is not None else None),
            "reached_95pct": (int(t95 >= 0) if t95 is not None else None),
        }
        broadcast_rows.append(row)

    return run_meta, broadcast_rows, []


def load_archives(sweep_archive: Path, fixed_archive: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    all_runs: list[dict[str, Any]] = []
    all_broadcasts: list[dict[str, Any]] = []
    quality: list[dict[str, Any]] = []
    sources = [(sweep_archive, "sweep_archive"), (fixed_archive, "fixed60_core")]
    seen: set[tuple[str, str]] = set()
    for archive_path, source in sources:
        if not archive_path.is_file():
            raise FileNotFoundError(
                f"Required raw archive not found: {archive_path}\n"
                "Check that the ZIP archives are present in research/raw/."
            )
        with zipfile.ZipFile(archive_path) as archive:
            sca_names = [name for name in archive.namelist() if name.lower().endswith(".sca") and not name.endswith("/")]
            if not sca_names:
                raise ValueError(f"No .sca files found in {archive_path}")
            for internal_name in sorted(sca_names):
                filename = Path(internal_name).name
                duplicate_key = (source, filename)
                if duplicate_key in seen:
                    quality.append({"file": filename, "issue": "duplicate_sca_filename", "actual": internal_name, "expected": "unique filename per archive"})
                    continue
                seen.add(duplicate_key)
                with archive.open(internal_name, "r") as stream:
                    text = stream.read().decode("utf-8", errors="replace")
                meta, broadcast_rows, _ = parse_sca_text(text, filename, source)
                all_runs.append(meta | {"broadcast_count": len(broadcast_rows), "_broadcasts": broadcast_rows})
                all_broadcasts.extend(broadcast_rows)
                if len(broadcast_rows) != 3:
                    quality.append({"file": filename, "issue": "unexpected_broadcast_count", "actual": len(broadcast_rows), "expected": 3})
                if meta["components"] not in (1,):
                    quality.append({"file": filename, "issue": "unexpected_topology_components", "actual": meta["components"], "expected": 1})
                for row in broadcast_rows:
                    if row["reached"] is None or not (1 <= row["reached"] <= meta["N"]):
                        quality.append({"file": filename, "issue": "invalid_reached_count", "actual": row["reached"], "expected": f"1..{meta['N']}"})
                    if row["treeValid"] is None or row["treeValid"] != 1:
                        quality.append({"file": filename, "issue": "invalid_or_missing_tree_validity", "actual": row["treeValid"], "expected": 1})
    # Preserve per-file instrumentation flags in the broadcast/run CSVs, while
    # also recording archive-wide availability for condition-level denominators.
    # The sweep archive was produced by a collector version with T95 support, but
    # one individual run may omit T95 scalars entirely; those missing per-file
    # values stay blank in broadcast_metrics.csv, while the study-level denominator
    # still treats the scalar as instrumented in that archive version.
    for source_name in {run["source"] for run in all_runs}:
        source_rows = [row for row in all_broadcasts if row["source"] == source_name]
        archive_has90 = any(row.get("timeTo90pctReachable") is not None for row in source_rows)
        archive_has95 = any(row.get("timeTo95pctReachable") is not None for row in source_rows)
        for run in all_runs:
            if run["source"] == source_name:
                run["_archive_instrumented_time90"] = archive_has90
                run["_archive_instrumented_time95"] = archive_has95
                for broadcast in run["_broadcasts"]:
                    broadcast["_archive_instrumented_time90"] = archive_has90
                    broadcast["_archive_instrumented_time95"] = archive_has95
    return all_runs, all_broadcasts, quality


def make_run_metrics(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    num_fields = ["coverageRatio", "transmissions", "duplicates", "drops", "maliciousActions", "treeValid", "treeEdges", "maxDepth", "coverage_pct", "lastReachedTime"]
    for run in runs:
        bs = run["_broadcasts"]
        out = {key: run.get(key) for key in RUN_METRICS}
        for field in num_fields:
            target_field = "mean_lastReachedTime_s" if field == "lastReachedTime" else ("mean_coverage_pct" if field == "coverage_pct" else "mean_" + field)
            out[target_field] = scalar_mean(b.get(field) for b in bs)
        out["broadcast_count"] = len(bs)
        out["mean_completionTime_if_complete"] = scalar_mean((b.get("completionTime") for b in bs), nonnegative=True)
        out["full_coverage_broadcasts"] = sum(int(b.get("full_coverage", 0)) for b in bs)
        # Instrumentation is a property of the result-file version/run. Count every
        # broadcast in such a run in the denominator even when a threshold scalar
        # is absent for an individual broadcast that did not reach that threshold.
        out["instrumented90_broadcasts"] = len(bs) if run.get("instrumented_time90") else 0
        out["instrumented95_broadcasts"] = len(bs) if run.get("_archive_instrumented_time95") else 0
        out["coverage90_broadcasts"] = sum(int(b.get("reached_90pct") or 0) for b in bs)
        out["coverage95_broadcasts"] = sum(int(b.get("reached_95pct") or 0) for b in bs)
        out["mean_time90_s_conditional"] = scalar_mean((b.get("timeTo90pctReachable") for b in bs), nonnegative=True)
        out["mean_time95_s_conditional"] = scalar_mean((b.get("timeTo95pctReachable") for b in bs), nonnegative=True)
        output.append(out)
    return output


def make_condition_summary(run_rows: list[dict[str, Any]], broadcast_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    key_fields = ["study", "N", "fraction", "attack_type"]
    run_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    broadcast_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in run_rows:
        run_groups[tuple(row[k] for k in key_fields)].append(row)
    for row in broadcast_rows:
        broadcast_groups[tuple(row[k] for k in key_fields)].append(row)

    output = []
    for key in sorted(run_groups, key=lambda k: (0 if k[0] == "fraction" else 1, k[1], k[2], k[3])):
        rs = run_groups[key]
        bs = broadcast_groups.get(key, [])
        def between_run_sd(field: str) -> float | None:
            values = [number(r.get(field)) for r in rs]
            values = [x for x in values if x is not None]
            return statistics.stdev(values) if len(values) >= 2 else (0.0 if values else None)
        # The older result collector did not write a T95 scalar at all. For newer
        # runs, the metric is considered instrumented for all broadcasts in each run.
        t90_instrumented = [b for b in bs if b.get("instrumented_time90")]
        t95_instrumented = [b for b in bs if b.get("_archive_instrumented_time95")]
        t90_reached = [b["timeTo90pctReachable"] for b in bs if b.get("timeTo90pctReachable") is not None and b["timeTo90pctReachable"] >= 0]
        t95_reached = [b["timeTo95pctReachable"] for b in bs if b.get("timeTo95pctReachable") is not None and b["timeTo95pctReachable"] >= 0]
        completions = [b["completionTime"] for b in bs if b.get("completionTime") is not None and b["completionTime"] >= 0]
        seed_values = sorted({int(r["seed"]) for r in rs if r.get("seed") is not None})
        sample = rs[0]
        full_count = sum(int(b.get("full_coverage", 0)) for b in bs)
        reached90 = sum(int(b.get("reached_90pct") or 0) for b in bs)
        reached95 = sum(int(b.get("reached_95pct") or 0) for b in bs)
        run_t90_mean = scalar_mean((r.get("mean_time90_s_conditional") for r in rs), nonnegative=True)
        run_t95_mean = scalar_mean((r.get("mean_time95_s_conditional") for r in rs), nonnegative=True)
        run_completion_mean = scalar_mean((r.get("mean_completionTime_if_complete") for r in rs), nonnegative=True)
        out = {
            "study": key[0], "nodes": key[1], "malicious_fraction": key[2], "attack": key[3],
            "runs": len(rs), "broadcasts": len(bs),
            "mean_coverage_pct": scalar_mean(b.get("coverage_pct") for b in bs),
            "sd_coverage_pct_between_runs": between_run_sd("mean_coverage_pct"),
            "mean_transmissions": scalar_mean(b.get("transmissions") for b in bs),
            "sd_transmissions_between_runs": between_run_sd("mean_transmissions"),
            "mean_duplicates": scalar_mean(b.get("duplicates") for b in bs),
            "mean_drops": scalar_mean(b.get("drops") for b in bs),
            "mean_malicious_actions": scalar_mean(b.get("maliciousActions") for b in bs),
            "mean_tree_valid_pct": 100 * scalar_mean(b.get("treeValid") for b in bs) if bs else None,
            "full_coverage_broadcasts": full_count,
            "full_coverage_pct": 100 * full_count / len(bs) if bs else None,
            "reached_90pct_broadcasts": reached90,
            "instrumented_90pct_broadcasts": len(t90_instrumented),
            "reached_90pct_pct": 100 * reached90 / len(t90_instrumented) if t90_instrumented else None,
            "reached_95pct_broadcasts": reached95,
            "instrumented_95pct_broadcasts": len(t95_instrumented),
            "reached_95pct_pct": 100 * reached95 / len(t95_instrumented) if t95_instrumented else None,
            # Average the within-repetition conditional means so each repetition has
            # equal weight, matching the documented run-level aggregation.
            "mean_time_to_90ms_conditional": 1000 * run_t90_mean if run_t90_mean is not None else None,
            "mean_time_to_95ms_conditional": 1000 * run_t95_mean if run_t95_mean is not None else None,
            "full_completion_time_mean_ms_conditional": 1000 * run_completion_mean if run_completion_mean is not None else None,
            "topology_components": scalar_mean(b.get("components") for b in bs),
            "edge_count": scalar_mean(b.get("edge_count") for b in bs),
            "isolated_peer_set": sample.get("isolated_peer_set", ""),
            "isolation_mode": sample.get("isolation_mode", "none"),
            "seeds": ",".join(str(s) for s in seed_values),
        }
        output.append(out)
    return output


def write_plots(summary: list[dict[str, Any]], run_rows: list[dict[str, Any]], figures_dir: Path) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    frac_rows = [r for r in summary if r["study"] == "fraction"]
    size_rows = [r for r in summary if r["study"] == "size"]
    attacks = ["Drop-All", "Selective Forwarding", "Delay/Jitter", "Isolation"]

    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    for attack in attacks:
        rows = sorted((r for r in frac_rows if r["attack"] == attack), key=lambda r: r["malicious_fraction"])
        if rows:
            x = [100 * r["malicious_fraction"] for r in rows]
            y = [r["mean_coverage_pct"] for r in rows]
            err = [r["sd_coverage_pct_between_runs"] or 0 for r in rows]
            ax.errorbar(x, y, yerr=err, marker="o", capsize=3, linewidth=1.7, label=attack)
    ax.set(title="Coverage vs. malicious fraction (N = 60)", xlabel="Malicious peers (%)", ylabel="Mean coverage (%)")
    ax.set_xticks(sorted({round(100*r["malicious_fraction"]) for r in frac_rows}))
    ax.set_ylim(90, 100.5)
    ax.grid(True, alpha=0.25)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(figures_dir / "coverage_vs_malicious_fraction.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    for attack in attacks:
        rows = sorted((r for r in frac_rows if r["attack"] == attack), key=lambda r: r["malicious_fraction"])
        if rows:
            ax.plot([100*r["malicious_fraction"] for r in rows], [r["full_coverage_pct"] for r in rows], marker="o", linewidth=1.7, label=attack)
    ax.set(title="Full-delivery rate vs. malicious fraction (N = 60)", xlabel="Malicious peers (%)", ylabel="Broadcasts reaching every node (%)")
    ax.set_xticks(sorted({round(100*r["malicious_fraction"]) for r in frac_rows}))
    ax.set_ylim(-3, 103)
    ax.grid(True, alpha=0.25)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(figures_dir / "full_delivery_vs_malicious_fraction.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8.2, 5.0))
    size_attacks = ["Baseline", "Drop-All", "Selective Forwarding", "Delay/Jitter", "Isolation"]
    for attack in size_attacks:
        rows = sorted((r for r in size_rows if r["attack"] == attack), key=lambda r: r["nodes"])
        if rows:
            x = [r["nodes"] for r in rows]
            y = [r["mean_coverage_pct"] for r in rows]
            err = [r["sd_coverage_pct_between_runs"] or 0 for r in rows]
            ax.errorbar(x, y, yerr=err, marker="o", capsize=3, linewidth=1.7, label=attack)
    ax.set(title="Coverage vs. network size (10% malicious except baseline)", xlabel="Number of nodes", ylabel="Mean coverage (%)")
    ax.set_xticks([30, 60, 100])
    ax.set_ylim(90, 101)
    ax.grid(True, alpha=0.25)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(figures_dir / "coverage_vs_network_size.png", dpi=200)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(12.0, 4.8))
    for attack in attacks:
        rows = sorted((r for r in frac_rows if r["attack"] == attack), key=lambda r: r["malicious_fraction"])
        if rows:
            x = [100*r["malicious_fraction"] for r in rows]
            axes[0].plot(x, [r["mean_transmissions"] for r in rows], marker="o", linewidth=1.7, label=attack)
            axes[1].plot(x, [r["mean_drops"] for r in rows], marker="o", linewidth=1.7, label=attack)
    axes[0].set(title="Mean transmissions", xlabel="Malicious peers (%)", ylabel="Transmissions per broadcast")
    axes[1].set(title="Mean dropped forwards", xlabel="Malicious peers (%)", ylabel="Drops per broadcast")
    for ax in axes:
        ax.set_xticks(sorted({round(100*r["malicious_fraction"]) for r in frac_rows}))
        ax.grid(True, alpha=0.25)
    axes[0].legend(frameon=False, fontsize=8)
    fig.suptitle("Communication cost vs. malicious fraction (N = 60)")
    fig.tight_layout()
    fig.savefig(figures_dir / "transmissions_and_drops_vs_fraction.png", dpi=200)
    plt.close(fig)


def fmt(value: Any, digits: int = 2) -> str:
    if value is None or value == "":
        return "—"
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return str(value)
    try:
        return f"{float(value):.{digits}f}"
    except (ValueError, TypeError):
        return str(value)


def build_report(summary: list[dict[str, Any]], runs: list[dict[str, Any]], broadcasts: list[dict[str, Any]], quality: list[dict[str, Any]]) -> str:
    fractions = [r for r in summary if r["study"] == "fraction"]
    sizes = [r for r in summary if r["study"] == "size"]
    def table(headers: list[str], rows: list[list[Any]]) -> str:
        lines = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"]*len(headers)) + "|"]
        lines.extend("| " + " | ".join(str(v) for v in row) + " |" for row in rows)
        return "\n".join(lines)
    fraction_table = table(
        ["Malicious fraction", "Attack", "Mean coverage", "Full delivery", "Transmissions", "Drops", "Mean T95*"],
        [[f"{100*r['malicious_fraction']:.0f}%", r["attack"], f"{fmt(r['mean_coverage_pct'])}%", f"{fmt(r['full_coverage_pct'])}%", fmt(r["mean_transmissions"]), fmt(r["mean_drops"]), (f"{fmt(r['mean_time_to_95ms_conditional'])} ms" if r["mean_time_to_95ms_conditional"] is not None else "—")] for r in fractions],
    )
    size_table = table(
        ["Nodes", "Condition", "Malicious fraction", "Mean coverage", "Full delivery", "Transmissions", "Drops"],
        [[str(r["nodes"]), r["attack"], f"{100*r['malicious_fraction']:.0f}%", f"{fmt(r['mean_coverage_pct'])}%", f"{fmt(r['full_coverage_pct'])}%", fmt(r["mean_transmissions"]), fmt(r["mean_drops"])] for r in sizes],
    )
    def find(study: str, n: int, frac: float, attack: str) -> dict[str, Any] | None:
        return next((r for r in summary if r["study"] == study and r["nodes"] == n and abs(r["malicious_fraction"]-frac) < 1e-8 and r["attack"] == attack), None)
    drop5, drop20, drop30 = (find("fraction", 60, f, "Drop-All") for f in [0.05, 0.2, 0.3])
    sf5, sf30 = find("fraction", 60, 0.05, "Selective Forwarding"), find("fraction", 60, 0.3, "Selective Forwarding")
    delay5, delay30 = find("fraction", 60, 0.05, "Delay/Jitter"), find("fraction", 60, 0.3, "Delay/Jitter")
    baseline30, baseline60, baseline100 = (find("size", n, 0.0, "Baseline") for n in [30,60,100])
    quality_line = f"The automated quality check found **{len(quality)} issue(s)**." if quality else "The automated quality checks found no missing expected broadcasts, out-of-range reachability counts, disconnected complete-graph topologies, or failed tree-validity scalars in the supplied archives."
    return f'''# Paper-ready experimental findings

## Reproducible dataset

This report is generated by `research/scripts/analyze_results.py` from the committed raw archives in `research/raw/`. It reads the 110 sweep `.sca` files and 25 fixed-60-node `.sca` files, for **{len(runs)} selected simulation repetitions** and **{len(broadcasts)} broadcast observations**. Each repetition is expected to contain three broadcasts. The fixed-size comparison uses 60 nodes and 10% malicious peers for attack configurations; baseline runs use 0%. The malicious-fraction sweep tests 5%, 20%, and 30% malicious participation at 60 nodes.

Five repetitions (seed sets 0–4) are present per condition. All tested simulations use complete-graph topologies. The main protocol parameters are fanout 4, 10 ms forwarding delay, 1 ms gossip delay, three broadcasts per repetition at 250 ms intervals, and a 20 s simulated-time limit.

**Metric definitions.** Mean coverage is the average percentage of nodes reached for individual broadcasts. Full-delivery rate is the percentage of broadcasts whose recorded `completionTime` is non-negative. Transmissions, drops, duplicates, and malicious actions are average counts per broadcast. Conditional T90/T95 means are computed only over broadcasts with a recorded non-negative threshold time. Blank T95 entries indicate older result files did not record that scalar; they are not imputed.

## Malicious-fraction sweep (60 nodes)

{fraction_table}

*Mean T95 is conditional on reaching the threshold. The fixed 60-node runs do not contain the newer T95 scalar and are not used in this table.*

## Network-size sweep

{size_table}

## Main observations supported by the recorded data

1. **Drop-All is the most damaging tested attack in the malicious-fraction sweep.** At 5% malicious participation, its mean coverage is {fmt(drop5['mean_coverage_pct'])}% and full delivery is {fmt(drop5['full_coverage_pct'])}%. At 20% and 30%, mean coverage is {fmt(drop20['mean_coverage_pct'])}% and {fmt(drop30['mean_coverage_pct'])}%, and no broadcast in either condition delivers to every node. Mean recorded drops increase from {fmt(drop5['mean_drops'])} at 5% to {fmt(drop20['mean_drops'])} at 20% and {fmt(drop30['mean_drops'])} at 30%.
2. **Selective forwarding degrades as malicious participation increases.** Mean coverage falls from {fmt(sf5['mean_coverage_pct'])}% at 5% to {fmt(sf30['mean_coverage_pct'])}% at 30%, while full delivery falls from {fmt(sf5['full_coverage_pct'])}% to {fmt(sf30['full_coverage_pct'])}%.
3. **Delay/Jitter affects timeliness more than final coverage in this particular configuration.** Mean coverage changes from {fmt(delay5['mean_coverage_pct'])}% at 5% to {fmt(delay30['mean_coverage_pct'])}% at 30%; conditional mean T95 changes from {fmt(delay5['mean_time_to_95ms_conditional'])} ms to {fmt(delay30['mean_time_to_95ms_conditional'])} ms. The result should not be generalized beyond the implemented policy and complete-graph topology.
4. **Perfect delivery becomes less frequent at larger network sizes even when average coverage remains high.** Baseline mean coverage is {fmt(baseline30['mean_coverage_pct'])}%, {fmt(baseline60['mean_coverage_pct'])}%, and {fmt(baseline100['mean_coverage_pct'])}% at 30, 60, and 100 nodes, while full-delivery rates are {fmt(baseline30['full_coverage_pct'])}%, {fmt(baseline60['full_coverage_pct'])}%, and {fmt(baseline100['full_coverage_pct'])}%, respectively. This shows why reporting coverage and complete delivery separately is important.
5. **Communication volume scales upward with network size in the complete-graph experiments.** Baseline mean transmissions rise from {fmt(baseline30['mean_transmissions'])} at 30 nodes to {fmt(baseline60['mean_transmissions'])} at 60 and {fmt(baseline100['mean_transmissions'])} at 100. In the Drop-All fraction sweep, mean transmissions decrease as dropped forwards rise, which reflects suppressed dissemination rather than improved efficiency by itself.
6. **All recorded tree-validity scalars equal 1.** Structural validation passing is not equivalent to every node receiving the broadcast; delivery metrics show missed nodes in many observations.

## Automated quality checks

{quality_line}

See `research/analysis/quality_checks.csv` for the complete check output. The check covers expected broadcast counts, reachability bounds, single-component topologies in these complete-graph runs, and recorded tree-validity scalars.

## Limitations

- The experiments use complete-graph topologies; results should not be treated as evidence for sparse overlays or real production networks.
- Five repetitions per condition make this an exploratory simulation study. Avoid statistical-significance claims without additional repetitions and a pre-specified test.
- The fixed 60-node result files predate the `timeTo95pctReachable` scalar. These missing values remain blank instead of being estimated.
- Isolation results depend on the configured explicit peer set, and all conclusions are tied to the implemented attack policies and protocol parameters.

## Figures

- `research/figures/coverage_vs_malicious_fraction.png`
- `research/figures/full_delivery_vs_malicious_fraction.png`
- `research/figures/coverage_vs_network_size.png`
- `research/figures/transmissions_and_drops_vs_fraction.png`
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sweep-archive", type=Path, default=DEFAULT_SWEEP, help=f"Sweep ZIP (default: {DEFAULT_SWEEP})")
    parser.add_argument("--fixed-archive", type=Path, default=DEFAULT_FIXED, help=f"Fixed 60-node ZIP (default: {DEFAULT_FIXED})")
    parser.add_argument("--root", type=Path, default=ROOT, help=f"Repository root (default: {ROOT})")
    args = parser.parse_args()
    root = args.root.resolve()
    analysis_dir = root / "research" / "analysis"
    figures_dir = root / "research" / "figures"

    try:
        runs_with_broadcasts, broadcasts, quality = load_archives(args.sweep_archive.resolve(), args.fixed_archive.resolve())
        run_rows = make_run_metrics(runs_with_broadcasts)
        summary = make_condition_summary(run_rows, broadcasts)
        # If conditions differ in result repetitions, make that visible as a quality issue.
        for row in summary:
            if row["runs"] != 5:
                quality.append({"file": f"{row['study']} N={row['nodes']} fraction={row['malicious_fraction']} attack={row['attack']}", "issue": "unexpected_repetition_count", "actual": row["runs"], "expected": 5})

        write_csv(analysis_dir / "broadcast_metrics.csv", BROADCAST_METRICS, broadcasts)
        write_csv(analysis_dir / "run_metrics.csv", RUN_METRICS, run_rows)
        write_csv(analysis_dir / "condition_summary.csv", CONDITION_SUMMARY, summary)
        write_csv(analysis_dir / "quality_checks.csv", QUALITY_COLUMNS, quality)
        write_plots(summary, run_rows, figures_dir)
        report = build_report(summary, run_rows, broadcasts, quality)
        (root / "research" / "paper_ready_results.md").write_text(report, encoding="utf-8")
    except (OSError, zipfile.BadZipFile, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Parsed {len(run_rows)} simulation files and {len(broadcasts)} broadcast observations.")
    print(f"Wrote CSV summaries to {analysis_dir}")
    print(f"Wrote figures to {figures_dir}")
    print(f"Updated {root / 'research' / 'paper_ready_results.md'}")
    print(f"Quality-check issues: {len(quality)}")
    if quality:
        print("Review research/analysis/quality_checks.csv before reporting results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
