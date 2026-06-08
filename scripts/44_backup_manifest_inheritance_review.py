# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
44_backup_manifest_inheritance_review.py
NO-PANDAS版 / 標準ライブラリのみ。

Purpose:
  C2025AUG / 2025-08-04 の横展開クラスタについて、
  Backup / Manifest / RTCR / Snapshot / iMazing workspace 系の
  "Backup / Manifest Inheritance（状態継承の影）" を機械的に整理する。

Important boundary:
  - backup / restore による感染・攻撃を直接証明するscriptではない。
  - raw artifactと既存39b/40b/43出力から、backup/manifest継承の影を整理する。
  - SAO確定、Manifest改ざん確定、復元汚染確定、攻撃者・Apple関与は断定しない。

Default input:
  [RESULT_ROOT]\39b_rawlog_cluster_trial_audit
  [RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict
  [RESULT_ROOT]\43_trust_graph_lineage_review

Output:
  [RESULT_ROOT]\44_backup_manifest_inheritance_review

Read-only. No delete / move / rename / modify of input.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

TARGET_START = "2025-08-01"
TARGET_END = "2025-08-10"
CORE_DATE = "2025-08-04"

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

CORE_DEVICE_ORDER = [
    "USER_ORIGIN_MINI1", "USER_BRIDGE_15G", "USER_DEVICE_12G", "USER_DEVICE_MINI2", "USER_DEVICE_11PRO",
    "EXT_UNCERTAIN_B", "EXT_NO_CONTACT_A", "EXT_CONTACT_D", "EXT_CONTACT_E_12PROMAX", "EXT_CONTACT_E_6SPLUS", "EXT_REMOTE_GEO_C",
]


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def read_csv_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.exists():
        return [], []
    encodings = ["utf-8-sig", "utf-8", "cp932", "cp1252"]
    last_err: Optional[Exception] = None
    for enc in encodings:
        try:
            with path.open("r", newline="", encoding=enc, errors="replace") as f:
                r = csv.DictReader(f)
                rows = [dict(row) for row in r]
                return rows, list(r.fieldnames or [])
        except Exception as e:
            last_err = e
    print(f"WARN: failed to read csv: {path} :: {last_err}")
    return [], []


def write_csv(path: Path, rows: List[Dict], fields: Optional[List[str]] = None) -> None:
    ensure_dir(path.parent)
    if fields is None:
        fields = []
        for row in rows:
            for k in row.keys():
                if k not in fields:
                    fields.append(k)
    with path.open("w", newline="", encoding="utf-8-sig", errors="replace") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path: Path, obj) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False), encoding="utf-8")


def to_int(v, default: int = 0) -> int:
    try:
        if v is None or str(v).strip() == "":
            return default
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default


def to_float(v, default: float = 0.0) -> float:
    try:
        if v is None or str(v).strip() == "":
            return default
        return float(str(v).replace(",", ""))
    except Exception:
        return default


def log_score(n: int, weight: float = 1.0) -> float:
    return math.log10(max(int(n), 0) + 1) * weight


def normalize_date(s: str) -> str:
    s = str(s or "")
    m = re.search(r"(20\d{2})[-_/](\d{1,2})[-_/](\d{1,2})", s)
    if m:
        y, mo, d = m.groups()
        return f"{int(y):04d}-{int(mo):02d}-{int(d):02d}"
    return ""


def in_window(date_s: str) -> bool:
    return TARGET_START <= date_s <= TARGET_END


def normalize_device_from_path(path_s: str, guess: str = "") -> str:
    p = str(path_s or "")
    g = str(guess or "").strip()
    low = p.lower().replace("\\", "/")

    # Specific first. 39b sometimes guesses EXT_CONTACT_D for EXT_NO_CONTACT_A.
    if "hathao_mother" in low or "ha thao mother" in low or ("hathao" in low and "mother" in low):
        return "EXT_NO_CONTACT_A"
    if "ngoc" in low:
        if "6s" in low or "6plus" in low or "6 plus" in low or "iphone6" in low:
            return "EXT_CONTACT_E_6SPLUS"
        return "EXT_CONTACT_E_12PROMAX"
    if re.search(r"(^|/)ha[ _]?thao($|/)", low) or "ha thao" in low:
        return "EXT_CONTACT_D"
    if re.search(r"(^|/)vy($|/)", low):
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
    if g and g not in ("CONTROL_OR_GENERIC_EXTERNAL", "UNKNOWN"):
        return g
    return g or "UNKNOWN"


def source_kind(path_s: str, source_root: str = "") -> str:
    low = str(path_s or "").lower().replace("\\", "/")
    root = str(source_root or "").lower()
    if "rtc" in low or "rtcreporting" in low:
        return "rtcr_reporting"
    if "manifest.db" in low:
        return "manifest_db"
    if "manifest.plist" in low:
        return "manifest_plist"
    if "status.plist" in low:
        return "status_plist"
    if "info.plist" in low:
        return "info_plist"
    if "snapshot" in low:
        return "snapshot"
    if "imazing" in low or "ddnabackup" in low or "backupchecksum" in low or "backup" in low:
        return "backup_workspace"
    if "analytics" in low:
        return "analytics_log"
    if "jetsam" in low:
        return "jetsam"
    if "reset" in low or "systemmemoryreset" in low:
        return "reset_memory"
    if "log-power" in low or "power" in low:
        return "power_session"
    if "stacks" in low:
        return "stacks"
    if "cloudd" in low or "cloud" in low:
        return "cloud_related_log"
    if "diskwrites" in low:
        return "diskwrites_resource"
    if "cpu_resource" in low or "signpost_reporter" in low:
        return "cpu_resource"
    if "manifest" in root:
        return "manifest_inventory_other"
    return "other"


def parse_timestamp_from_path(path_s: str, fallback_date: str = "") -> Tuple[str, str]:
    s = str(path_s or "")
    m = re.search(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_]?([0-5]\d)[-_]?([0-5]\d)", s)
    if m:
        y, mo, d, h, mi, sec = m.groups()
        return f"{y}-{mo}-{d} {h}:{mi}:{sec}", "filename_datetime"
    if fallback_date:
        return f"{fallback_date} 00:00:00", "date_only"
    return "", "unknown"


def find_input_file(base: Path, names: List[str]) -> Path:
    for n in names:
        p = base / n
        if p.exists():
            return p
    # recursive fallback
    for n in names:
        hits = list(base.rglob(n))
        if hits:
            return hits[0]
    return base / names[0]


def classify_device_0804(device: str, raw_backup: int, source_files: int, direct_manifest_files: int,
                         trust_verdict: str, support_class_40b: str) -> str:
    if raw_backup <= 0:
        return "E_NO_BACKUP_MANIFEST_SHADOW"
    if device == "EXT_NO_CONTACT_A" and source_files > 0:
        return "B_RAW_ONLY_BACKUP_MANIFEST_SHADOW"
    if support_class_40b == "RAW_ONLY" and source_files > 0:
        return "B_RAW_ONLY_BACKUP_MANIFEST_SHADOW"
    if "A_TRUST" in trust_verdict and raw_backup >= 50 and source_files >= 2:
        return "A_BACKUP_MANIFEST_SHADOW_WITH_TRUST_LINEAGE"
    if raw_backup >= 50 and source_files >= 2:
        return "B_BACKUP_MANIFEST_SHADOW_RAW_SUPPORTED"
    if raw_backup > 0:
        return "C_WEAK_BACKUP_MANIFEST_CONTEXT"
    return "E_NO_BACKUP_MANIFEST_SHADOW"


def main() -> int:
    parser = argparse.ArgumentParser(description="44 Backup / Manifest Inheritance Review (no pandas)")
    default_result = Path(r"[RESULT_ROOT]")
    parser.add_argument("--result-root", default=str(default_result))
    parser.add_argument("--input-39b", default="")
    parser.add_argument("--input-40b", default="")
    parser.add_argument("--input-43", default="")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    result_root = Path(args.result_root)
    input39b = Path(args.input_39b) if args.input_39b else result_root / "39b_rawlog_cluster_trial_audit"
    input40b = Path(args.input_40b) if args.input_40b else result_root / "40b_c2025aug_39a39b_cross_strict"
    input43 = Path(args.input_43) if args.input_43 else result_root / "43_trust_graph_lineage_review"
    out_dir = Path(args.out) if args.out else result_root / "44_backup_manifest_inheritance_review"
    ensure_dir(out_dir)

    file_axis_path = find_input_file(input39b, ["39b_file_axis_counts.csv"])
    manifest_inventory_path = find_input_file(input39b, ["39b_manifest_inventory.csv"])
    core40_path = find_input_file(input40b, ["04_2025_0804_core_cross.csv"])
    trust43_path = find_input_file(input43, ["01_trust_graph_0804_device_matrix.csv"])

    file_axis_rows, _ = read_csv_rows(file_axis_path)
    manifest_rows, _ = read_csv_rows(manifest_inventory_path)
    core40_rows, _ = read_csv_rows(core40_path)
    trust43_rows, _ = read_csv_rows(trust43_path)

    write_csv(out_dir / "00_input_paths.csv", [
        {"input": "39b_file_axis_counts", "path": str(file_axis_path), "exists": str(file_axis_path.exists())},
        {"input": "39b_manifest_inventory", "path": str(manifest_inventory_path), "exists": str(manifest_inventory_path.exists())},
        {"input": "40b_core_cross", "path": str(core40_path), "exists": str(core40_path.exists())},
        {"input": "43_trust_graph_matrix", "path": str(trust43_path), "exists": str(trust43_path.exists())},
    ])

    core_by_device: Dict[str, Dict[str, str]] = {}
    for r in core40_rows:
        d = str(r.get("device", "")).strip()
        if d:
            core_by_device[d] = r

    trust_by_device: Dict[str, Dict[str, str]] = {}
    for r in trust43_rows:
        d = str(r.get("device", "")).strip()
        if d:
            trust_by_device[d] = r

    # 39b backup_manifest raw source aggregation
    agg0804 = defaultdict(lambda: {
        "hit_count": 0, "source_files": set(), "source_kinds": defaultdict(int),
        "direct_manifest_files": set(), "backup_workspace_files": set(), "rtcr_files": set(),
        "top_files": defaultdict(int)
    })
    aggwin = defaultdict(lambda: defaultdict(lambda: {
        "hit_count": 0, "source_files": set(), "source_kinds": defaultdict(int), "top_files": defaultdict(int)
    }))

    for r in file_axis_rows:
        if str(r.get("axis", "")) != "backup_manifest":
            continue
        rel = r.get("relative_path", "")
        src_root = r.get("source_root_label", "")
        guessed = r.get("device_guess_from_path", "")
        dev = normalize_device_from_path(rel, guessed)
        date_s = normalize_date(r.get("date_guess_from_path", "") or rel)
        if not date_s or not in_window(date_s):
            continue
        hits = to_int(r.get("hit_count"))
        sk = source_kind(rel, src_root)
        key_file = rel
        rec = aggwin[dev][date_s]
        rec["hit_count"] += hits
        rec["source_files"].add(key_file)
        rec["source_kinds"][sk] += hits
        rec["top_files"][key_file] += hits
        if date_s == CORE_DATE:
            rec2 = agg0804[dev]
            rec2["hit_count"] += hits
            rec2["source_files"].add(key_file)
            rec2["source_kinds"][sk] += hits
            rec2["top_files"][key_file] += hits
            if sk in ("manifest_db", "manifest_plist", "status_plist", "info_plist", "snapshot"):
                rec2["direct_manifest_files"].add(key_file)
            if sk in ("backup_workspace", "manifest_db", "manifest_plist", "status_plist", "info_plist", "snapshot"):
                rec2["backup_workspace_files"].add(key_file)
            if sk == "rtcr_reporting":
                rec2["rtcr_files"].add(key_file)

    # Manifest inventory summary: not necessarily 0804; this is backup generation / ledger capability surface.
    inv_by_device = defaultdict(lambda: {
        "inventory_rows": 0, "manifest_db_count": 0, "manifest_plist_count": 0,
        "status_plist_count": 0, "info_plist_count": 0, "snapshot_count": 0,
        "checksum_count": 0, "backup_workspace_count": 0, "dates": set(),
        "total_size_bytes": 0, "large_manifest_db_count": 0,
        "sha_duplicate_pairs_hint": 0, "hashes": defaultdict(int), "top_files": []
    })
    for r in manifest_rows:
        rel = r.get("relative_path", "")
        dev = normalize_device_from_path(rel, r.get("device_guess_from_path", ""))
        if dev in ("UNKNOWN", "CONTROL_OR_GENERIC_EXTERNAL", ""):
            # keep external controls in inventory, but don't let generic label dominate core judgment
            dev = r.get("device_guess_from_path", "") or "UNKNOWN"
        sk = source_kind(rel, r.get("source_root_label", ""))
        date_s = normalize_date(r.get("date_guess_from_path", "") or rel)
        size = to_int(r.get("size_bytes"))
        rec = inv_by_device[dev]
        rec["inventory_rows"] += 1
        rec["total_size_bytes"] += size
        if date_s:
            rec["dates"].add(date_s)
        if sk == "manifest_db":
            rec["manifest_db_count"] += 1
            if size >= 50_000_000:
                rec["large_manifest_db_count"] += 1
        elif sk == "manifest_plist":
            rec["manifest_plist_count"] += 1
        elif sk == "status_plist":
            rec["status_plist_count"] += 1
        elif sk == "info_plist":
            rec["info_plist_count"] += 1
        elif sk == "snapshot":
            rec["snapshot_count"] += 1
        elif "checksum" in rel.lower():
            rec["checksum_count"] += 1
        elif sk == "backup_workspace":
            rec["backup_workspace_count"] += 1
        h = str(r.get("sha256_if_small", "") or "").strip()
        if h:
            rec["hashes"][h] += 1
        if len(rec["top_files"]) < 30:
            rec["top_files"].append({
                "relative_path": rel, "kind": sk, "size_bytes": size,
                "date": date_s, "scan_status": r.get("scan_status", "")
            })

    # Device matrix for core 0804
    device_set = set(CORE_DEVICE_ORDER) | set(core_by_device.keys()) | set(trust_by_device.keys()) | set(agg0804.keys())
    # keep generic labels but sort them low
    def dev_sort(d: str) -> Tuple[int, str]:
        if d in CORE_DEVICE_ORDER:
            return (0, f"{CORE_DEVICE_ORDER.index(d):02d}")
        return (1, d)

    matrix_rows = []
    for dev in sorted(device_set, key=dev_sort):
        if not dev or dev == "UNKNOWN":
            continue
        a = agg0804.get(dev, {})
        core = core_by_device.get(dev, {})
        trust = trust_by_device.get(dev, {})
        raw_backup_from_40b = to_int(core.get("raw_backup_manifest"))
        raw_backup_from_43 = to_int(trust.get("raw_backup_manifest"))
        source_hits = int(a.get("hit_count", 0) or 0)
        source_file_count = len(a.get("source_files", set()) or [])
        direct_manifest_count = len(a.get("direct_manifest_files", set()) or [])
        backup_workspace_count = len(a.get("backup_workspace_files", set()) or [])
        rtcr_count = len(a.get("rtcr_files", set()) or [])
        trust_verdict = trust.get("trust_lineage_verdict", "")
        support_class = core.get("support_class", core.get("support_class_40b", ""))
        # prefer direct 39b source sum; fall back to 40b/43 raw_backup.
        raw_backup_score_base = source_hits or raw_backup_from_40b or raw_backup_from_43
        verdict = classify_device_0804(dev, raw_backup_score_base, source_file_count, direct_manifest_count, trust_verdict, support_class)
        inv = inv_by_device.get(dev, {})
        inv_manifest_db = int(inv.get("manifest_db_count", 0) or 0)
        inv_status = int(inv.get("status_plist_count", 0) or 0)
        inv_info = int(inv.get("info_plist_count", 0) or 0)
        inv_dates = sorted(inv.get("dates", set()) or [])
        inheritance_score = (
            log_score(raw_backup_score_base, 8.0)
            + source_file_count * 0.7
            + len(a.get("source_kinds", {}) or {}) * 2.0
            + (6.0 if "A_TRUST" in trust_verdict else 3.0 if "B_TRUST" in trust_verdict else 0.0)
            + min(inv_manifest_db, 5) * 1.0
            + min(inv_status + inv_info, 10) * 0.4
            + (4.0 if rtcr_count else 0.0)
        )
        matrix_rows.append({
            "device": dev,
            "date": CORE_DATE,
            "role": core.get("role") or trust.get("role") or ROLE_DEFAULT.get(dev, ""),
            "backup_manifest_verdict": verdict,
            "inheritance_shadow_score": f"{inheritance_score:.3f}",
            "final_tier_40b": core.get("final_tier") or trust.get("final_tier_40b", ""),
            "support_class_40b": support_class or trust.get("support_class_40b", ""),
            "trust_lineage_verdict_43": trust_verdict,
            "raw_backup_manifest_from_40b": raw_backup_from_40b,
            "raw_backup_manifest_from_43": raw_backup_from_43,
            "backup_manifest_source_hits_39b": source_hits,
            "backup_manifest_source_files_0804": source_file_count,
            "source_kind_count_0804": len(a.get("source_kinds", {}) or {}),
            "rtcr_reporting_files_0804": rtcr_count,
            "backup_workspace_or_manifest_files_0804": backup_workspace_count,
            "direct_manifest_files_0804": direct_manifest_count,
            "manifest_inventory_db_count": inv_manifest_db,
            "manifest_inventory_status_plist_count": inv_status,
            "manifest_inventory_info_plist_count": inv_info,
            "manifest_inventory_date_count": len(inv_dates),
            "manifest_inventory_first_date": inv_dates[0] if inv_dates else "",
            "manifest_inventory_last_date": inv_dates[-1] if inv_dates else "",
            "claim_boundary": "local_artifact_shadow_not_restore_or_server_side_proof",
        })

    # window rows
    window_rows = []
    for dev in sorted(aggwin.keys(), key=dev_sort):
        for date_s in sorted(aggwin[dev].keys()):
            rec = aggwin[dev][date_s]
            window_rows.append({
                "device": dev,
                "date": date_s,
                "role": ROLE_DEFAULT.get(dev, ""),
                "backup_manifest_hits": rec["hit_count"],
                "source_files": len(rec["source_files"]),
                "source_kind_count": len(rec["source_kinds"]),
                "source_kinds": ";".join(f"{k}:{v}" for k, v in sorted(rec["source_kinds"].items(), key=lambda x: (-x[1], x[0]))),
                "window_flag": "CORE_DATE" if date_s == CORE_DATE else "WINDOW_SUPPORT",
            })

    # source top files
    top_source_rows = []
    for dev in sorted(agg0804.keys(), key=dev_sort):
        rec = agg0804[dev]
        for rank, (rel, hits) in enumerate(sorted(rec["top_files"].items(), key=lambda x: (-x[1], x[0]))[:10], 1):
            ts, ts_conf = parse_timestamp_from_path(rel, CORE_DATE)
            top_source_rows.append({
                "device": dev,
                "date": CORE_DATE,
                "rank": rank,
                "hit_count": hits,
                "source_kind": source_kind(rel),
                "timestamp_from_filename": ts,
                "timestamp_confidence": ts_conf,
                "relative_path": rel,
            })

    # Manifest inventory summary rows
    inv_rows = []
    for dev in sorted(inv_by_device.keys(), key=dev_sort):
        inv = inv_by_device[dev]
        dates = sorted(inv["dates"])
        dup_hash_count = sum(1 for h, c in inv["hashes"].items() if c > 1)
        inv_rows.append({
            "device": dev,
            "inventory_rows": inv["inventory_rows"],
            "date_count": len(dates),
            "first_date": dates[0] if dates else "",
            "last_date": dates[-1] if dates else "",
            "manifest_db_count": inv["manifest_db_count"],
            "large_manifest_db_count_ge_50mb": inv["large_manifest_db_count"],
            "manifest_plist_count": inv["manifest_plist_count"],
            "status_plist_count": inv["status_plist_count"],
            "info_plist_count": inv["info_plist_count"],
            "snapshot_count": inv["snapshot_count"],
            "checksum_count": inv["checksum_count"],
            "backup_workspace_count": inv["backup_workspace_count"],
            "total_size_bytes_inventory": inv["total_size_bytes"],
            "duplicate_small_file_hash_count_hint": dup_hash_count,
            "note": "inventory_only_not_0804_causality",
        })

    # Overlap with 43
    overlap_rows = []
    for row in matrix_rows:
        dev = row["device"]
        verdict = row["backup_manifest_verdict"]
        trust_v = row["trust_lineage_verdict_43"]
        if verdict.startswith("A_") and trust_v.startswith("A_"):
            combined = "A_BACKUP_AND_TRUST_STRONG_OVERLAP"
        elif verdict.startswith(("A_", "B_")) and trust_v.startswith(("A_", "B_")):
            combined = "B_BACKUP_AND_TRUST_SUPPORTED_OVERLAP"
        elif verdict.startswith(("A_", "B_")):
            combined = "C_BACKUP_ONLY_SHADOW"
        else:
            combined = "E_NOT_DECISION"
        overlap_rows.append({
            "device": dev,
            "role": row["role"],
            "combined_backup_trust_verdict": combined,
            "backup_manifest_verdict": verdict,
            "trust_lineage_verdict_43": trust_v,
            "raw_backup_manifest_from_40b": row["raw_backup_manifest_from_40b"],
            "backup_manifest_source_hits_39b": row["backup_manifest_source_hits_39b"],
            "backup_manifest_source_files_0804": row["backup_manifest_source_files_0804"],
            "claim_boundary": "combined_local_shadow_not_server_side_or_restore_proof",
        })

    # Notes
    notes = [
        {"level": "ADOPT", "item": "44 result", "detail": "Backup/Manifest inheritance shadow can be used as local artifact support."},
        {"level": "BOUNDARY", "item": "not proof", "detail": "This does not prove backup poisoning, restore inheritance, Apple server-side state, or attack attribution."},
        {"level": "CAUTION", "item": "RTC/stacks bias", "detail": "Some backup_manifest hits can be concentrated in RTCReporting/stacks/CoreTime/Jetsam. Treat as shadow support, not direct Manifest.db proof."},
        {"level": "NEXT", "item": "45", "detail": "Proximity vs Cloud Separation is the natural next step after Backup/Manifest inheritance shadow."},
    ]

    # Summary
    a_count = sum(1 for r in matrix_rows if str(r.get("backup_manifest_verdict", "")).startswith("A_"))
    b_count = sum(1 for r in matrix_rows if str(r.get("backup_manifest_verdict", "")).startswith("B_"))
    supported_devices = [r["device"] for r in matrix_rows if str(r.get("backup_manifest_verdict", "")).startswith(("A_", "B_"))]
    combined_supported = [r["device"] for r in overlap_rows if str(r.get("combined_backup_trust_verdict", "")).startswith(("A_", "B_"))]
    summary = {
        "status": "DONE",
        "variant": "NO_PANDAS_STD_LIB_ONLY",
        "target": "C2025AUG / 2025-08-04",
        "final_verdict": "BACKUP_MANIFEST_INHERITANCE_SHADOW_SUPPORTED_NOT_RESTORE_CAUSAL_PROOF",
        "input_files": {
            "39b_file_axis_counts": str(file_axis_path),
            "39b_manifest_inventory": str(manifest_inventory_path),
            "40b_core_cross": str(core40_path),
            "43_trust_graph_matrix": str(trust43_path),
        },
        "rows": {
            "device_rows": len(matrix_rows),
            "window_rows": len(window_rows),
            "source_top_rows": len(top_source_rows),
            "manifest_inventory_device_rows": len(inv_rows),
            "overlap_rows": len(overlap_rows),
        },
        "supported_counts": {
            "A_backup_manifest_strong": a_count,
            "B_backup_manifest_supported": b_count,
            "supported_A_or_B_total": a_count + b_count,
            "backup_trust_combined_A_or_B": len(combined_supported),
        },
        "supported_devices_A_or_B": supported_devices,
        "backup_trust_combined_supported_devices": combined_supported,
        "claim_boundary": [
            "local artifact shadow only",
            "not restore infection proof",
            "not Manifest.db tamper proof",
            "not Apple server-side proof",
            "not attribution proof",
        ],
    }

    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)
    write_csv(out_dir / "01_backup_manifest_0804_device_matrix.csv", matrix_rows)
    write_csv(out_dir / "02_backup_manifest_window_2025_0801_0810.csv", window_rows)
    write_csv(out_dir / "03_backup_source_files_top10_per_device.csv", top_source_rows)
    write_csv(out_dir / "04_manifest_inventory_device_summary.csv", inv_rows)
    write_csv(out_dir / "05_backup_manifest_overlap_with_43_trust.csv", overlap_rows)
    write_csv(out_dir / "06_claim_boundary_notes.csv", notes)

    readme = f"""44 Backup / Manifest Inheritance Review

Final verdict:
  {summary['final_verdict']}

Meaning:
  C2025AUG / 2025-08-04 において、backup_manifest axis は複数端末で確認できる。
  43 Trust Graph Lineage の cloud_trust / policy / lateral / backup_manifest とも重なる。

Supported A/B devices:
  {', '.join(supported_devices)}

Do not claim:
  - backup poisoning confirmed
  - restore inheritance confirmed
  - Manifest.db tampering confirmed
  - Apple server-side trust graph proof
  - hidden MDM confirmed
  - attacker / state / vendor attribution

Next recommended step:
  45 Proximity vs Cloud Separation.
"""
    (out_dir / "07_README_VERDICT.txt").write_text(readme, encoding="utf-8")

    print("44 Backup / Manifest Inheritance Review DONE")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
