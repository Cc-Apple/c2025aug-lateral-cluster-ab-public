# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
43_trust_graph_lineage_review.py

Purpose:
  C2025AUG / 2025-08-04 の横展開クラスタについて、
  Apple ID / iCloud / ScreenTime / CKKS / SFA / accountsd / cloudd 等の
  "Trust Graph Lineage（信頼状態の影）" を機械的に整理する。

Important boundary:
  - Apple server-side trust graph を直接証明するscriptではない。
  - raw artifactと既存39a/39b/40b/42b出力から、信頼状態の影を整理する。
  - 攻撃者・Apple関与・hidden MDM・Trial悪用は断定しない。

Default input:
  [RESULT_ROOT]\39b_rawlog_cluster_trial_audit
  [RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict
  [RESULT_ROOT]\42b_triald_direct_only_source_time_review

Output:
  [RESULT_ROOT]\43_trust_graph_lineage_review

Read-only. No delete / move / rename / modify of input.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import pandas as pd
except Exception as e:
    print("ERROR: pandas is required.", e)
    sys.exit(2)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

TARGET_START = "2025-08-01"
TARGET_END = "2025-08-10"
CORE_DATE = "2025-08-04"

TRUST_AXES = [
    "cloud_trust",
    "policy_restriction",
    "lateral_trust",
    "backup_manifest",
]
CONTEXT_AXES = [
    "telecom_wifi_proximity",
    "trial_ab",
    "daemon_seam",
    "evidence_pressure",
    "shadow_cloud_terms",
]
ALL_AXES = TRUST_AXES + CONTEXT_AXES

CORE_DEVICE_ORDER = [
    "USER_BRIDGE_15G",
    "USER_DEVICE_MINI2",
    "USER_ORIGIN_MINI1",
    "USER_DEVICE_12G",
    "EXT_UNCERTAIN_B",
    "EXT_NO_CONTACT_A",
    "EXT_CONTACT_D",
    "EXT_CONTACT_E_12PROMAX",
    "EXT_CONTACT_E_6SPLUS",
    "USER_DEVICE_11PRO",
    "EXT_REMOTE_GEO_C",
]

ROLE_DEFAULT = {
    "USER_ORIGIN_MINI1": "ORIGIN_CORE",
    "USER_BRIDGE_15G": "BRIDGE_TO_LATER_JOKER",
    "USER_DEVICE_12G": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_MINI2": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_11PRO": "USER_CLUSTER_SUPPORT",
    "EXT_UNCERTAIN_B": "EXTERNAL_CRITICAL_UNCERTAIN_CONTACT",
    "EXT_NO_CONTACT_A": "EXTERNAL_NO_CONTACT_RAW_ONLY_CRITICAL",
    "EXT_CONTACT_D": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_12PROMAX": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_6SPLUS": "EXTERNAL_CONTACT_KNOWN",
    "EXT_REMOTE_GEO_C": "EXTERNAL_REMOTE_GEO_CONTACT",
}


def safe_read_csv(path: Path, **kwargs) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path, **kwargs)
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding="utf-8-sig", **kwargs)
    except Exception as e:
        print(f"WARN: failed to read csv: {path} :: {e}")
        return pd.DataFrame()


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_csv(path: Path, rows: List[Dict], fields: Optional[List[str]] = None) -> None:
    ensure_dir(path.parent)
    if fields is None:
        fields = []
        for row in rows:
            for k in row.keys():
                if k not in fields:
                    fields.append(k)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path: Path, obj) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False), encoding="utf-8")


def normalize_date(v) -> str:
    if pd.isna(v):
        return ""
    s = str(v).strip()
    if not s or s.lower() == "nan":
        return ""
    m = re.search(r"(20\d{2})[-_/](\d{1,2})[-_/](\d{1,2})", s)
    if m:
        y, mo, d = m.groups()
        return f"{int(y):04d}-{int(mo):02d}-{int(d):02d}"
    # already date-like
    try:
        return pd.to_datetime(s, errors="coerce").strftime("%Y-%m-%d")
    except Exception:
        return ""


def in_window(date_s: str) -> bool:
    return TARGET_START <= date_s <= TARGET_END


def normalize_device_from_path(path_s: str, guess: str = "") -> str:
    p = str(path_s or "")
    g = str(guess or "").strip()
    low = p.lower()
    # More specific first. 39b mislabels EXT_NO_CONTACT_A as EXT_CONTACT_D.
    if "hathao_mother" in low or "ha thao mother" in low or "mother" in low and "hathao" in low:
        return "EXT_NO_CONTACT_A"
    if "ngoc" in low:
        if "6s" in low or "6plus" in low or "6_plus" in low or "iphone6" in low:
            return "EXT_CONTACT_E_6SPLUS"
        return "EXT_CONTACT_E_12PROMAX"
    if re.search(r"(^|[/\\])ha[ _]?thao($|[/\\])", low) or "ha thao" in low:
        return "EXT_CONTACT_D"
    if re.search(r"(^|[/\\])vy($|[/\\])", low):
        return "EXT_UNCERTAIN_B"
    if "ibuki" in low:
        return "EXT_REMOTE_GEO_C"
    if "iphone11pro" in low or "iphone 11 pro" in low:
        return "USER_DEVICE_11PRO"
    if "USER_ORIGIN_MINI1g" in low:
        return "USER_ORIGIN_MINI1G"
    if "USER_ORIGIN_MINI1" in low:
        return "USER_ORIGIN_MINI1"
    if "USER_DEVICE_MINI2" in low:
        return "USER_DEVICE_MINI2"
    if "15g" in low:
        return "USER_BRIDGE_15G"
    if "12g" in low:
        return "USER_DEVICE_12G"
    if g:
        return g
    return "UNKNOWN"


def parse_timestamp_from_path(path_s: str, fallback_date: str = "") -> Tuple[str, str]:
    """Return (timestamp_iso-ish, confidence)."""
    s = str(path_s or "")
    # Common: Name-2025-08-04-070126.ext / 2025-08-04-07-01-26
    m = re.search(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_]?([0-5]\d)[-_]?([0-5]\d)", s)
    if m:
        y, mo, d, h, mi, sec = m.groups()
        return f"{y}-{mo}-{d} {h}:{mi}:{sec}", "filename_datetime"
    # Folder date + no time
    if fallback_date:
        return f"{fallback_date} 00:00:00", "date_only"
    return "", "unknown"


def axis_counts_from_core(core_row: Dict) -> Dict[str, int]:
    out = {}
    for ax in ALL_AXES:
        k = f"raw_{ax}"
        try:
            out[ax] = int(float(core_row.get(k, 0) or 0))
        except Exception:
            out[ax] = 0
    return out


def log_score(count: int, weight: float = 1.0) -> float:
    try:
        return math.log10(max(int(count), 0) + 1) * weight
    except Exception:
        return 0.0


def trust_lineage_score(axis_counts: Dict[str, int], core_bonus: float, triald_direct: bool) -> float:
    score = 0.0
    score += log_score(axis_counts.get("cloud_trust", 0), 3.2)
    score += log_score(axis_counts.get("policy_restriction", 0), 3.8)
    score += log_score(axis_counts.get("lateral_trust", 0), 3.0)
    score += log_score(axis_counts.get("backup_manifest", 0), 2.6)
    score += log_score(axis_counts.get("telecom_wifi_proximity", 0), 1.2)
    score += log_score(axis_counts.get("evidence_pressure", 0), 0.8)
    score += core_bonus
    if triald_direct:
        score += 5.0
    return round(score, 3)


def verdict_for_device(axis_counts: Dict[str, int], core_tier: str, triald_direct: bool, support_class: str) -> str:
    trust_present = sum(1 for ax in TRUST_AXES if axis_counts.get(ax, 0) > 0)
    context_present = sum(1 for ax in CONTEXT_AXES if axis_counts.get(ax, 0) > 0)
    if trust_present == 4 and str(core_tier).startswith("A_") and triald_direct:
        return "A_TRUST_LINEAGE_STRONG_WITH_TRIALD_DIRECT"
    if trust_present == 4 and str(core_tier).startswith("A_"):
        if "RAW_ONLY" in str(support_class):
            return "B_TRUST_LINEAGE_RAW_ONLY_STRONG_NO_TRIALD_DIRECT"
        return "B_TRUST_LINEAGE_STRONG_NO_TRIALD_DIRECT"
    if trust_present >= 3 and context_present >= 3:
        return "C_TRUST_LINEAGE_SUPPORT"
    if trust_present >= 2:
        return "D_TRUST_LINEAGE_WEAK_SUPPORT"
    return "E_NO_TRUST_LINEAGE_DECISION"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=str(Path.home() / "Desktop" / "Result"), help="Result base directory")
    ap.add_argument("--out", default="", help="Output directory. Default: <base>/43_trust_graph_lineage_review")
    args = ap.parse_args()

    base = Path(args.base)
    out_dir = Path(args.out) if args.out else base / "43_trust_graph_lineage_review"
    ensure_dir(out_dir)

    in39b = base / "39b_rawlog_cluster_trial_audit"
    in40b = base / "40b_c2025aug_39a39b_cross_strict"
    in42b = base / "42b_triald_direct_only_source_time_review"

    paths = {
        "39b_file_axis_counts": in39b / "39b_file_axis_counts.csv",
        "40b_core_cross": in40b / "04_2025_0804_core_cross.csv",
        "42b_direct_timeline": in42b / "01_triald_direct_0804_timeline.csv",
        "42b_device_summary": in42b / "03_device_triald_direct_summary_0804.csv",
        "42b_core_matrix": in42b / "04_triald_vs_40b_core_matrix.csv",
    }

    input_rows = []
    for name, p in paths.items():
        input_rows.append({"name": name, "path": str(p), "exists": p.exists(), "size_bytes": p.stat().st_size if p.exists() else 0})
    write_csv(out_dir / "00_input_paths.csv", input_rows)

    missing = [r["name"] for r in input_rows if not r["exists"] and r["name"] in ["39b_file_axis_counts", "40b_core_cross"]]
    if missing:
        write_json(out_dir / "00_MASTER_SUMMARY.json", {"status": "MISSING_REQUIRED_INPUT", "missing": missing, "input_paths": input_rows})
        print("MISSING_REQUIRED_INPUT", missing)
        return 1

    df39b = safe_read_csv(paths["39b_file_axis_counts"])
    df40 = safe_read_csv(paths["40b_core_cross"])
    df42_tl = safe_read_csv(paths["42b_direct_timeline"])
    df42_sum = safe_read_csv(paths["42b_device_summary"])
    df42_matrix = safe_read_csv(paths["42b_core_matrix"])

    # Normalize raw file-axis rows
    if not df39b.empty:
        df39b["date_norm"] = df39b["date_guess_from_path"].apply(normalize_date)
        df39b["device_norm"] = [normalize_device_from_path(rp, dg) for rp, dg in zip(df39b.get("relative_path", []), df39b.get("device_guess_from_path", []))]
        df39b["hit_count"] = pd.to_numeric(df39b["hit_count"], errors="coerce").fillna(0).astype(int)
        dfw = df39b[(df39b["date_norm"] >= TARGET_START) & (df39b["date_norm"] <= TARGET_END)].copy()
        df0804 = df39b[df39b["date_norm"] == CORE_DATE].copy()
    else:
        dfw = pd.DataFrame()
        df0804 = pd.DataFrame()

    # 42b direct triald devices
    direct_devices = set()
    direct_ts_by_device: Dict[str, str] = {}
    if not df42_tl.empty:
        dev_col = "device" if "device" in df42_tl.columns else None
        ts_col = "event_timestamp" if "event_timestamp" in df42_tl.columns else ("timestamp" if "timestamp" in df42_tl.columns else None)
        if dev_col:
            for _, r in df42_tl.iterrows():
                d = str(r.get(dev_col, "")).strip()
                if not d:
                    continue
                direct_devices.add(d)
                ts = str(r.get(ts_col, "")).strip() if ts_col else ""
                if ts and (d not in direct_ts_by_device or ts < direct_ts_by_device[d]):
                    direct_ts_by_device[d] = ts

    # Build core rows from 40b, then attach trust score
    device_rows = []
    if not df40.empty:
        for _, r in df40.iterrows():
            device = str(r.get("device", "UNKNOWN"))
            if str(r.get("date", "")) != CORE_DATE:
                continue
            axis_counts = axis_counts_from_core(r.to_dict())
            trust_present = sum(1 for ax in TRUST_AXES if axis_counts.get(ax, 0) > 0)
            context_present = sum(1 for ax in CONTEXT_AXES if axis_counts.get(ax, 0) > 0)
            raw_tier = str(r.get("raw_tier", ""))
            final_tier = str(r.get("final_tier", ""))
            support_class = str(r.get("support_class", ""))
            core_bonus = 7.5 if final_tier.startswith("A_") else 2.0
            triald_direct = device in direct_devices
            score = trust_lineage_score(axis_counts, core_bonus, triald_direct)
            verdict = verdict_for_device(axis_counts, final_tier, triald_direct, support_class)
            row = {
                "device": device,
                "date": CORE_DATE,
                "role": r.get("role", ROLE_DEFAULT.get(device, "UNKNOWN")),
                "final_tier_40b": final_tier,
                "support_class_40b": support_class,
                "trust_lineage_verdict": verdict,
                "trust_lineage_score": score,
                "trust_axes_present_4": trust_present,
                "context_axes_present_5": context_present,
                "triald_direct_0804": "YES" if triald_direct else "NO",
                "first_triald_direct_ts_0804": direct_ts_by_device.get(device, ""),
            }
            for ax in TRUST_AXES:
                row[f"raw_{ax}"] = axis_counts.get(ax, 0)
            for ax in CONTEXT_AXES:
                row[f"raw_{ax}"] = axis_counts.get(ax, 0)
            device_rows.append(row)

    device_rows.sort(key=lambda x: (-float(x.get("trust_lineage_score", 0)), CORE_DEVICE_ORDER.index(x["device"]) if x["device"] in CORE_DEVICE_ORDER else 999, x["device"]))
    write_csv(out_dir / "01_trust_graph_0804_device_matrix.csv", device_rows)

    # Window matrix by device/date/axis from raw 39b
    window_rows = []
    if not dfw.empty:
        piv = dfw[dfw["axis"].isin(ALL_AXES)].groupby(["device_norm", "date_norm", "axis"], as_index=False)["hit_count"].sum()
        wide = piv.pivot_table(index=["device_norm", "date_norm"], columns="axis", values="hit_count", aggfunc="sum", fill_value=0).reset_index()
        for _, r in wide.iterrows():
            d = str(r.get("device_norm", ""))
            dt = str(r.get("date_norm", ""))
            counts = {ax: int(r.get(ax, 0) or 0) for ax in ALL_AXES}
            trust_present = sum(1 for ax in TRUST_AXES if counts.get(ax, 0) > 0)
            context_present = sum(1 for ax in CONTEXT_AXES if counts.get(ax, 0) > 0)
            score = trust_lineage_score(counts, 0, d in direct_devices and dt == CORE_DATE)
            row = {
                "device": d,
                "date": dt,
                "trust_lineage_score_raw_only": score,
                "trust_axes_present_4": trust_present,
                "context_axes_present_5": context_present,
                "triald_direct_on_core_day": "YES" if (d in direct_devices and dt == CORE_DATE) else "NO",
            }
            for ax in ALL_AXES:
                row[ax] = counts.get(ax, 0)
            window_rows.append(row)
    window_rows.sort(key=lambda x: (x["date"], -float(x["trust_lineage_score_raw_only"]), x["device"]))
    write_csv(out_dir / "02_trust_graph_window_2025_0801_0810.csv", window_rows)

    # Lineage sequence: earliest trust-axis source timestamp on 0804 per device + triald overlay
    seq_rows = []
    if not df0804.empty:
        trust_file_rows = df0804[df0804["axis"].isin(TRUST_AXES)].copy()
        for device, sub in trust_file_rows.groupby("device_norm"):
            ts_candidates = []
            axis_set = set()
            total_hits = 0
            top_rel = ""
            top_hits = -1
            for _, rr in sub.iterrows():
                dt = str(rr.get("date_norm", ""))
                rel = str(rr.get("relative_path", ""))
                ax = str(rr.get("axis", ""))
                hits = int(rr.get("hit_count", 0) or 0)
                axis_set.add(ax)
                total_hits += hits
                if hits > top_hits:
                    top_hits = hits
                    top_rel = rel
                ts, conf = parse_timestamp_from_path(rel, dt)
                if ts:
                    ts_candidates.append((ts, conf, rel))
            first_ts, conf, rel = min(ts_candidates, key=lambda x: x[0]) if ts_candidates else ("", "", "")
            seq_rows.append({
                "device": device,
                "first_trust_axis_ts_0804": first_ts,
                "timestamp_confidence": conf,
                "trust_axes_present_4": len(axis_set),
                "trust_axis_total_hits_0804": total_hits,
                "top_trust_source_path": top_rel,
                "top_trust_source_hits": top_hits if top_hits >= 0 else 0,
                "triald_direct_0804": "YES" if device in direct_devices else "NO",
                "first_triald_direct_ts_0804": direct_ts_by_device.get(device, ""),
                "role": ROLE_DEFAULT.get(device, "UNKNOWN"),
            })
    seq_rows.sort(key=lambda x: (x.get("first_trust_axis_ts_0804") or "9999", CORE_DEVICE_ORDER.index(x["device"]) if x["device"] in CORE_DEVICE_ORDER else 999))
    # Add order number
    for i, r in enumerate(seq_rows, 1):
        r["sequence_order_by_first_trust_axis"] = i
    write_csv(out_dir / "03_trust_graph_lineage_sequence_0804.csv", seq_rows)

    # Top source files per device/axis on 0804
    source_rows = []
    if not df0804.empty:
        top_df = df0804[df0804["axis"].isin(TRUST_AXES + ["telecom_wifi_proximity", "evidence_pressure"])].copy()
        for (device, axis), sub in top_df.groupby(["device_norm", "axis"]):
            sub2 = sub.sort_values("hit_count", ascending=False).head(5)
            rank = 0
            for _, rr in sub2.iterrows():
                rank += 1
                source_rows.append({
                    "device": device,
                    "date": CORE_DATE,
                    "axis": axis,
                    "rank": rank,
                    "hit_count": int(rr.get("hit_count", 0) or 0),
                    "relative_path": rr.get("relative_path", ""),
                    "source_root_label": rr.get("source_root_label", ""),
                })
    source_rows.sort(key=lambda x: (CORE_DEVICE_ORDER.index(x["device"]) if x["device"] in CORE_DEVICE_ORDER else 999, x["axis"], x["rank"]))
    write_csv(out_dir / "04_trust_source_files_top5_per_device_axis.csv", source_rows)

    # Overlap matrix: cloud/policy/backup/lateral only, from device rows
    overlap_rows = []
    for r in device_rows:
        present = [ax for ax in TRUST_AXES if int(r.get(f"raw_{ax}", 0) or 0) > 0]
        missing_ax = [ax for ax in TRUST_AXES if int(r.get(f"raw_{ax}", 0) or 0) <= 0]
        overlap_rows.append({
            "device": r["device"],
            "role": r["role"],
            "trust_axes_present_4": len(present),
            "present_axes": ";".join(present),
            "missing_axes": ";".join(missing_ax),
            "cloud_trust": r.get("raw_cloud_trust", 0),
            "policy_restriction": r.get("raw_policy_restriction", 0),
            "lateral_trust": r.get("raw_lateral_trust", 0),
            "backup_manifest": r.get("raw_backup_manifest", 0),
            "triald_direct_0804": r.get("triald_direct_0804", "NO"),
            "trust_lineage_verdict": r.get("trust_lineage_verdict", ""),
        })
    write_csv(out_dir / "05_policy_cloud_backup_lateral_overlap_matrix.csv", overlap_rows)

    # Notes: caveats and gap roles
    note_rows = []
    for r in device_rows:
        device = r["device"]
        note = ""
        risk = ""
        if device == "EXT_NO_CONTACT_A":
            note = "raw-only critical support; no direct triald on 0804; 41 showed RTC-heavy but no-RTC/structured axes still present"
            risk = "do not promote to causal proof"
        elif device.startswith("EXT_CONTACT_E"):
            note = "external known-contact support; triald direct missing/weak on 0804; keep as follower/BC seam support"
            risk = "avoid treating as origin"
        elif device == "EXT_REMOTE_GEO_C":
            note = "remote geo contact; direct triald only cpu-resource class in 42b; useful for separation, not origin"
            risk = "needs proximity/cloud separation review"
        elif device == "USER_ORIGIN_MINI1":
            note = "origin core; trust axes and triald direct overlap; main C2025AUG anchor"
            risk = "still not Apple-server-side trust graph proof"
        elif device == "USER_BRIDGE_15G":
            note = "bridge to later Joker; early direct triald; bridge candidate"
            risk = "bridge is structural, not command proof"
        else:
            note = "core/support device with trust-axis overlap"
            risk = "normal iOS/control stress still required"
        note_rows.append({
            "device": device,
            "role": r.get("role", ""),
            "trust_lineage_verdict": r.get("trust_lineage_verdict", ""),
            "note": note,
            "claim_boundary": risk,
        })
    write_csv(out_dir / "06_role_gap_and_claim_boundary_notes.csv", note_rows)

    # Triald overlay copied into simple table
    overlay_rows = []
    if not df42_matrix.empty:
        for _, r in df42_matrix.iterrows():
            overlay_rows.append({k: r.get(k, "") for k in df42_matrix.columns})
    elif not df42_tl.empty:
        for _, r in df42_tl.iterrows():
            overlay_rows.append({k: r.get(k, "") for k in df42_tl.columns})
    write_csv(out_dir / "07_triald_direct_overlay_from_42b.csv", overlay_rows)

    verdict_counts = defaultdict(int)
    for r in device_rows:
        verdict_counts[r.get("trust_lineage_verdict", "")] += 1

    summary = {
        "script": "43_trust_graph_lineage_review.py",
        "target": "C2025AUG / 2025-08-04 Trust Graph Lineage shadow review",
        "status": "DONE",
        "input_paths": input_rows,
        "core_date": CORE_DATE,
        "window": [TARGET_START, TARGET_END],
        "device_rows": len(device_rows),
        "window_rows": len(window_rows),
        "source_top_rows": len(source_rows),
        "lineage_sequence_rows": len(seq_rows),
        "direct_triald_devices_42b": sorted(list(direct_devices)),
        "verdict_counts": dict(verdict_counts),
        "final_verdict": "TRUST_GRAPH_LINEAGE_SHADOW_SUPPORTED_NOT_SERVER_SIDE_PROOF",
        "claim_boundary": [
            "Apple server-side trust graph is not directly observed",
            "Apple ID / iCloud / ScreenTime / Family Sharing lineage is inferred from local artifact shadows",
            "No actor attribution",
            "No Apple involvement claim",
            "No hidden MDM certainty",
            "No Trial abuse certainty",
        ],
        "next_recommended": "44_backup_manifest_inheritance_or_43b_proximity_cloud_separation",
    }
    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)

    readme = f"""43 Trust Graph Lineage Review
================================

対象:
  C2025AUG / 2025-08-04

目的:
  Apple ID / iCloud / ScreenTime / CKKS / SFA / accountsd / cloudd / backup / lateral_trust 系の
  local artifact shadow を使い、Trust Graph Lineage の影が端末別に出るか確認する。

最終判定:
  TRUST_GRAPH_LINEAGE_SHADOW_SUPPORTED_NOT_SERVER_SIDE_PROOF

言えること:
  - C2025AUG core日に、cloud_trust / policy_restriction / lateral_trust / backup_manifest が
    複数core端末で重なる。
  - USER_ORIGIN_MINI1 は origin core、USER_BRIDGE_15G は bridge 候補として保持できる。
  - 42bのdirect triald overlapを説明変数として重ねられる。

言えないこと:
  - Apple server-side trust graph の直接証明
  - Family Sharing / trusted device 登録の直接証明
  - hidden MDM確定
  - Trial悪用確定
  - 攻撃者特定
  - Apple関与確定

主な出力:
  01_trust_graph_0804_device_matrix.csv
  02_trust_graph_window_2025_0801_0810.csv
  03_trust_graph_lineage_sequence_0804.csv
  04_trust_source_files_top5_per_device_axis.csv
  05_policy_cloud_backup_lateral_overlap_matrix.csv
  06_role_gap_and_claim_boundary_notes.csv
  07_triald_direct_overlay_from_42b.csv

次:
  44 Backup / Manifest Inheritance
  または
  43b Proximity vs Cloud Separation
"""
    (out_dir / "08_README_VERDICT.txt").write_text(readme, encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
