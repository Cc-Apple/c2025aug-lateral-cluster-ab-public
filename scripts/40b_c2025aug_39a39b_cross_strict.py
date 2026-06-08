# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

# -*- coding: utf-8 -*-
r"""
40b_c2025aug_39a39b_cross_strict.py

Purpose:
  Cross-strict review for 39a_csv_result_cluster_trial_audit and
  39b_rawlog_cluster_trial_audit outputs.

  39a = prior CSV/result based discovery layer.
  39b = raw log / manifest based discovery layer.

  This script does NOT read one-year raw logs.
  It reads only the compact output CSVs from 39a and 39b.

Default input:
  [RESULT_ROOT]\39a_csv_result_cluster_trial_audit
  [RESULT_ROOT]\39b_rawlog_cluster_trial_audit

Default output:
  [RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict

CLI:
  python 40b_c2025aug_39a39b_cross_strict.py
  python 40b_c2025aug_39a39b_cross_strict.py <39a_dir> <39b_dir> <out_dir>
  python 40b_c2025aug_39a39b_cross_strict.py <result_root>
    where result_root contains both 39a_* and 39b_* folders.

Safety:
  read-only input. no delete / move / rename / edit.
"""

import csv
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_RESULT_ROOT = Path(r"[RESULT_ROOT]")
DEFAULT_39A_DIR = DEFAULT_RESULT_ROOT / "39a_csv_result_cluster_trial_audit"
DEFAULT_39B_DIR = DEFAULT_RESULT_ROOT / "39b_rawlog_cluster_trial_audit"
DEFAULT_OUT_DIR = DEFAULT_RESULT_ROOT / "40b_c2025aug_39a39b_cross_strict"

FOCUS_START = "2025-08-01"
FOCUS_END = "2025-08-10"
CORE_DATE = "2025-08-04"

AXES = [
    "trial_ab",
    "cloud_trust",
    "policy_restriction",
    "backup_manifest",
    "telecom_wifi_proximity",
    "daemon_seam",
    "evidence_pressure",
    "lateral_trust",
    "shadow_cloud_terms",
]

CORE_AXES = [
    "trial_ab",
    "cloud_trust",
    "telecom_wifi_proximity",
    "evidence_pressure",
]

AXIS_WEIGHTS = {
    "trial_ab": 1.20,
    "cloud_trust": 1.35,
    "policy_restriction": 1.45,
    "backup_manifest": 1.25,
    "telecom_wifi_proximity": 1.35,
    "daemon_seam": 1.00,
    "evidence_pressure": 1.20,
    "lateral_trust": 1.40,
    "shadow_cloud_terms": 0.30,
}

DEVICE_ORDER = [
    "USER_ORIGIN_MINI1",
    "USER_BRIDGE_15G",
    "USER_DEVICE_12G",
    "USER_DEVICE_MINI2",
    "USER_DEVICE_11PRO",
    "LOW_EXPOSURE_IPAD",
    "EXT_NO_CONTACT_A",
    "EXT_UNCERTAIN_B",
    "EXT_REMOTE_GEO_C",
    "EXT_CONTACT_D",
    "EXT_CONTACT_E_12PROMAX",
    "EXT_CONTACT_E_6SPLUS",
    "CONTROL_OR_GENERIC_EXTERNAL",
    "USER_ORIGIN_MINI1G",
    "UNKNOWN",
]

ROLE_MAP = {
    "USER_ORIGIN_MINI1": "ORIGIN_CORE",
    "USER_BRIDGE_15G": "BRIDGE_TO_LATER_JOKER",
    "USER_DEVICE_12G": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_MINI2": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_11PRO": "USER_CLUSTER_SUPPORT",
    "LOW_EXPOSURE_IPAD": "USER_CLUSTER_SUPPORT",
    "EXT_NO_CONTACT_A": "EXTERNAL_CRITICAL_NO_DIRECT_CONTACT",
    "EXT_UNCERTAIN_B": "EXTERNAL_CRITICAL_UNCERTAIN_CONTACT",
    "EXT_REMOTE_GEO_C": "EXTERNAL_GEO_SEPARATED",
    "EXT_CONTACT_D": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_12PROMAX": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_6SPLUS": "EXTERNAL_CONTACT_KNOWN",
    "CONTROL_OR_GENERIC_EXTERNAL": "GENERIC_EXTERNAL_LABEL_WEAK",
    "USER_ORIGIN_MINI1G": "LATER_BASELINE_NOT_C2025AUG",
    "UNKNOWN": "UNKNOWN",
}

DATE_RE = re.compile(r"(20\d{2})[-_/\.](\d{1,2})[-_/\.](\d{1,2})")


def mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_int(x, default=0):
    try:
        return int(float(str(x).strip() or "0"))
    except Exception:
        return default


def is_valid_date(s: str) -> bool:
    try:
        datetime.strptime(str(s), "%Y-%m-%d")
        return True
    except Exception:
        return False


def in_focus_window(s: str) -> bool:
    return is_valid_date(s) and FOCUS_START <= s <= FOCUS_END


def norm_path(s: str) -> str:
    return str(s or "").replace("\\", "/")


def detect_date_from_path(rel_path: str, fallback: str = "") -> str:
    p = norm_path(rel_path)

    matches = []
    for m in DATE_RE.finditer(p):
        y, mo, d = m.group(1), int(m.group(2)), int(m.group(3))
        cand = f"{y}-{mo:02d}-{d:02d}"
        if is_valid_date(cand):
            matches.append(cand)
    if matches:
        return matches[-1]

    parts = [x for x in p.split("/") if x]
    for i in range(len(parts) - 2):
        if re.fullmatch(r"20\d{2}", parts[i] or ""):
            try:
                cand = f"{int(parts[i]):04d}-{int(parts[i+1]):02d}-{int(parts[i+2]):02d}"
                if is_valid_date(cand):
                    return cand
            except Exception:
                pass

    fb = str(fallback or "").strip()
    if is_valid_date(fb):
        return fb
    return ""


def detect_device_from_path(rel_path: str, fallback: str = "UNKNOWN") -> str:
    p = norm_path(rel_path)
    low = p.lower()

    # Important: mother must be checked before generic EXT_CONTACT_D.
    if "hathao_mother" in low or "ha_thao_mother" in low or "ha thao mother" in low:
        return "EXT_NO_CONTACT_A"

    if low.startswith("ngoc/") or "/ngoc/" in low:
        if "iphone6s plus" in low or "iphone6splus" in low or "6s plus" in low:
            return "EXT_CONTACT_E_6SPLUS"
        if "iphone12 pro max" in low or "iphone12promax" in low or "12 pro max" in low:
            return "EXT_CONTACT_E_12PROMAX"
        return "EXT_CONTACT_E_12PROMAX"

    if low.startswith("ha thao/") or "/ha thao/" in low or low.startswith("hathao/") or "/hathao/" in low:
        return "EXT_CONTACT_D"
    if low.startswith("vy/") or "/vy/" in low:
        return "EXT_UNCERTAIN_B"
    if low.startswith("ibuki/") or "/ibuki/" in low:
        return "EXT_REMOTE_GEO_C"

    if "USER_ORIGIN_MINI1g" in low:
        return "USER_ORIGIN_MINI1G"
    if "mini-1" in low or "USER_ORIGIN_MINI1" in low:
        return "USER_ORIGIN_MINI1"
    if "mini-2" in low or "USER_DEVICE_MINI2" in low:
        return "USER_DEVICE_MINI2"
    if re.search(r"(^|/)15g(/|$)", low) or "15-g" in low:
        return "USER_BRIDGE_15G"
    if re.search(r"(^|/)12g(/|$)", low) or "12-g" in low:
        return "USER_DEVICE_12G"
    if "iphone11pro" in low or "iphone11 pro" in low or "11pro" in low:
        return "USER_DEVICE_11PRO"
    if re.search(r"(^|/)ipad(/|$)", low):
        return "LOW_EXPOSURE_IPAD"

    fb = str(fallback or "UNKNOWN").strip()
    if fb in ROLE_MAP:
        return fb
    return "UNKNOWN"


def read_csv_rows(path: Path):
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            yield row


def write_csv(path: Path, rows, fields=None) -> None:
    mkdir(path.parent)
    rows = list(rows)
    if fields is None:
        fields = []
        seen = set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    fields.append(k)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_json(path: Path, obj) -> None:
    mkdir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def axis_score(c: Counter, source_weight: float = 1.0) -> float:
    score = 0.0
    for a in AXES:
        v = c.get(a, 0)
        if v <= 0:
            continue
        score += min(math.log10(v + 1.0) * 10.0 * AXIS_WEIGHTS[a], 42.0) * source_weight
    axes_present = sum(1 for a in AXES if c.get(a, 0) > 0)
    if c.get("trial_ab", 0) > 0 and c.get("cloud_trust", 0) > 0:
        score += 7.0 * source_weight
    if c.get("trial_ab", 0) > 0 and (c.get("policy_restriction", 0) > 0 or c.get("backup_manifest", 0) > 0):
        score += 8.0 * source_weight
    if c.get("telecom_wifi_proximity", 0) > 0 and c.get("evidence_pressure", 0) > 0:
        score += 7.0 * source_weight
    if axes_present >= 6:
        score += 10.0 * source_weight
    if axes_present >= 8:
        score += 8.0 * source_weight
    return round(score, 3)


def classify_from_counts(c: Counter, date: str, device: str) -> str:
    axes_present = sum(1 for a in AXES if c.get(a, 0) > 0)
    core_ok = all(c.get(a, 0) > 0 for a in CORE_AXES)
    policy_or_backup = c.get("policy_restriction", 0) > 0 or c.get("backup_manifest", 0) > 0
    if date == CORE_DATE and axes_present >= 7 and core_ok and policy_or_backup and device != "CONTROL_OR_GENERIC_EXTERNAL":
        return "A_RAW_CORE_0804"
    if axes_present >= 7 and core_ok and policy_or_backup and device != "CONTROL_OR_GENERIC_EXTERNAL":
        return "B_RAW_WINDOW_SUPPORT"
    if axes_present >= 5 and core_ok:
        return "C_RAW_SUPPORT"
    return "D_WEAK_OR_GENERIC"


def load_39b_raw_strict(file_axis_path: Path):
    strict_counter = defaultdict(Counter)
    rows_seen = 0
    skipped = Counter()
    file_support = []

    for r in read_csv_rows(file_axis_path):
        rows_seen += 1
        axis = r.get("axis", "")
        if axis not in AXES:
            skipped["unknown_axis"] += 1
            continue
        count = safe_int(r.get("hit_count", 0))
        if count <= 0:
            skipped["zero_count"] += 1
            continue
        rel = r.get("relative_path", "")
        device = detect_device_from_path(rel, r.get("device_guess_from_path", "UNKNOWN"))
        date = detect_date_from_path(rel, r.get("date_guess_from_path", ""))
        if not in_focus_window(date):
            skipped["outside_focus_window"] += 1
            continue
        if device == "UNKNOWN":
            skipped["unknown_device"] += 1
            continue
        strict_counter[(device, date)][axis] += count
        file_support.append({
            "source": "39b_raw_file_axis",
            "device": device,
            "date": date,
            "axis": axis,
            "hit_count": count,
            "relative_path": rel,
            "source_root_label": r.get("source_root_label", ""),
            "original_device_guess": r.get("device_guess_from_path", ""),
            "original_date_guess": r.get("date_guess_from_path", ""),
        })

    matrix = []
    for (device, date), c in strict_counter.items():
        axes_present = sum(1 for a in AXES if c.get(a, 0) > 0)
        row = {
            "device": device,
            "date": date,
            "role": ROLE_MAP.get(device, "UNKNOWN"),
            "raw_total_axis_hits": sum(c.values()),
            "raw_axes_present": axes_present,
            "raw_score": axis_score(c, 1.0),
            "raw_tier": classify_from_counts(c, date, device),
        }
        for a in AXES:
            row["raw_" + a] = c.get(a, 0)
        matrix.append(row)
    matrix.sort(key=lambda r: (r["date"], DEVICE_ORDER.index(r["device"]) if r["device"] in DEVICE_ORDER else 999))
    return matrix, file_support, {"rows_seen": rows_seen, "skipped": dict(skipped)}


def load_39a_focus(pivot_path: Path):
    rows = []
    skipped = Counter()
    rows_seen = 0
    for r in read_csv_rows(pivot_path):
        rows_seen += 1
        device = str(r.get("device_guess", "UNKNOWN") or "UNKNOWN").strip() or "UNKNOWN"
        date = str(r.get("date", "") or "").strip()
        if device == "UNKNOWN":
            # keep UNKNOWN out of decision layer, because 39a is result-derived.
            skipped["unknown_device"] += 1
            continue
        if not in_focus_window(date):
            skipped["outside_focus_window"] += 1
            continue
        c = Counter({a: safe_int(r.get(a, 0)) for a in AXES})
        axes_present = sum(1 for a in AXES if c.get(a, 0) > 0)
        row = {
            "device": device,
            "date": date,
            "csv_total_hits": safe_int(r.get("total_hits", 0)),
            "csv_axes_present": axes_present,
            "csv_support_score": axis_score(c, 0.45),
        }
        for a in AXES:
            row["csv_" + a] = c.get(a, 0)
        rows.append(row)
    rows.sort(key=lambda r: (r["date"], DEVICE_ORDER.index(r["device"]) if r["device"] in DEVICE_ORDER else 999))
    return rows, {"rows_seen": rows_seen, "skipped": dict(skipped)}


def merge_cross(raw_rows, csv_rows):
    by_raw = {(r["device"], r["date"]): r for r in raw_rows}
    by_csv = {(r["device"], r["date"]): r for r in csv_rows}
    keys = sorted(set(by_raw.keys()) | set(by_csv.keys()), key=lambda k: (k[1], DEVICE_ORDER.index(k[0]) if k[0] in DEVICE_ORDER else 999, k[0]))
    out = []
    for device, date in keys:
        rr = by_raw.get((device, date), {})
        cr = by_csv.get((device, date), {})
        raw_tier = rr.get("raw_tier", "RAW_MISSING")
        raw_score = float(rr.get("raw_score", 0) or 0)
        csv_score = float(cr.get("csv_support_score", 0) or 0)
        raw_axes = int(rr.get("raw_axes_present", 0) or 0)
        csv_axes = int(cr.get("csv_axes_present", 0) or 0)
        has_raw = bool(rr)
        has_csv = bool(cr)

        support_class = "RAW_ONLY"
        if has_raw and has_csv:
            support_class = "RAW_AND_CSV_RESULT_SUPPORT"
        elif has_csv and not has_raw:
            support_class = "CSV_ONLY_WEAK_RESULT_ECHO"
        elif has_raw and not has_csv:
            support_class = "RAW_ONLY"

        combined_score = round(raw_score * 1.0 + csv_score * 0.35, 3)
        if date == CORE_DATE:
            combined_score += 8.0
        if device in {"EXT_NO_CONTACT_A", "EXT_UNCERTAIN_B", "EXT_REMOTE_GEO_C"}:
            combined_score += 8.0
        if device == "USER_BRIDGE_15G":
            combined_score += 5.0
        if device == "USER_ORIGIN_MINI1":
            combined_score += 5.0
        if support_class == "RAW_AND_CSV_RESULT_SUPPORT":
            combined_score += 6.0
        if device == "CONTROL_OR_GENERIC_EXTERNAL":
            combined_score *= 0.50

        if raw_tier == "A_RAW_CORE_0804" and support_class == "RAW_AND_CSV_RESULT_SUPPORT":
            final_tier = "A_CROSS_CORE_0804"
        elif raw_tier == "A_RAW_CORE_0804":
            final_tier = "A_RAW_CORE_0804_NO_CSV_ECHO"
        elif raw_tier == "B_RAW_WINDOW_SUPPORT" and support_class in {"RAW_AND_CSV_RESULT_SUPPORT", "RAW_ONLY"}:
            final_tier = "B_RAW_WINDOW_SUPPORT"
        elif raw_tier == "C_RAW_SUPPORT":
            final_tier = "C_RAW_SUPPORT"
        elif support_class == "CSV_ONLY_WEAK_RESULT_ECHO":
            final_tier = "D_CSV_ONLY_NOT_DECISION"
        else:
            final_tier = "D_WEAK_OR_GENERIC"

        row = {
            "device": device,
            "date": date,
            "role": ROLE_MAP.get(device, "UNKNOWN"),
            "final_tier": final_tier,
            "support_class": support_class,
            "combined_score": round(combined_score, 3),
            "raw_tier": raw_tier,
            "raw_score": rr.get("raw_score", 0),
            "raw_axes_present": raw_axes,
            "raw_total_axis_hits": rr.get("raw_total_axis_hits", 0),
            "csv_support_score": cr.get("csv_support_score", 0),
            "csv_axes_present": csv_axes,
            "csv_total_hits": cr.get("csv_total_hits", 0),
        }
        for a in AXES:
            row["raw_" + a] = rr.get("raw_" + a, 0)
            row["csv_" + a] = cr.get("csv_" + a, 0)
        out.append(row)
    out.sort(key=lambda r: (-float(r["combined_score"]), r["date"], r["device"]))
    return out


def build_lag_pairs(cross_rows):
    by_key = {(r["device"], r["date"]): r for r in cross_rows if not str(r["final_tier"]).startswith("D_CSV_ONLY")}
    pairs = []
    for r in cross_rows:
        if r["device"] != "USER_ORIGIN_MINI1":
            continue
        if str(r["final_tier"]).startswith("D"):
            continue
        d0 = datetime.strptime(r["date"], "%Y-%m-%d")
        for lag in range(0, 4):
            dd = (d0 + timedelta(days=lag)).strftime("%Y-%m-%d")
            for follower in DEVICE_ORDER:
                if follower in {"USER_ORIGIN_MINI1", "USER_ORIGIN_MINI1G", "UNKNOWN", "CONTROL_OR_GENERIC_EXTERNAL"}:
                    continue
                fr = by_key.get((follower, dd))
                if not fr:
                    continue
                pair_score = float(fr["combined_score"]) + float(r["combined_score"]) * 0.25
                if follower == "USER_BRIDGE_15G":
                    pair_score += 10
                if follower in {"EXT_NO_CONTACT_A", "EXT_UNCERTAIN_B", "EXT_REMOTE_GEO_C"}:
                    pair_score += 12
                if dd == CORE_DATE:
                    pair_score += 8
                pairs.append({
                    "origin_device": "USER_ORIGIN_MINI1",
                    "origin_date": r["date"],
                    "follower_device": follower,
                    "follower_date": dd,
                    "lag_days": lag,
                    "origin_final_tier": r["final_tier"],
                    "follower_final_tier": fr["final_tier"],
                    "origin_score": r["combined_score"],
                    "follower_score": fr["combined_score"],
                    "pair_score": round(pair_score, 3),
                    "follower_role": fr["role"],
                    "follower_raw_axes_present": fr["raw_axes_present"],
                    "follower_csv_axes_present": fr["csv_axes_present"],
                    "support_class": fr["support_class"],
                })
    pairs.sort(key=lambda r: (-float(r["pair_score"]), r["origin_date"], r["lag_days"], r["follower_device"]))
    return pairs


def find_inputs_from_args(argv):
    if len(argv) == 1:
        return DEFAULT_39A_DIR, DEFAULT_39B_DIR, DEFAULT_OUT_DIR
    if len(argv) == 2:
        root = Path(argv[1])
        return root / "39a_csv_result_cluster_trial_audit", root / "39b_rawlog_cluster_trial_audit", root / "40b_c2025aug_39a39b_cross_strict"
    if len(argv) >= 4:
        return Path(argv[1]), Path(argv[2]), Path(argv[3])
    print("Usage:")
    print("  python 40b_c2025aug_39a39b_cross_strict.py")
    print("  python 40b_c2025aug_39a39b_cross_strict.py <result_root>")
    print("  python 40b_c2025aug_39a39b_cross_strict.py <39a_dir> <39b_dir> <out_dir>")
    raise SystemExit(2)


def main() -> int:
    start = time.time()
    dir39a, dir39b, out_dir = find_inputs_from_args(sys.argv)
    mkdir(out_dir)

    path39a_pivot = dir39a / "39a_device_date_pivot.csv"
    path39b_file_axis = dir39b / "39b_file_axis_counts.csv"

    missing = [str(p) for p in [path39a_pivot, path39b_file_axis] if not p.exists()]
    if missing:
        print("ERROR: missing required files:")
        for m in missing:
            print(" -", m)
        return 2

    raw_matrix, file_support, raw_meta = load_39b_raw_strict(path39b_file_axis)
    csv_matrix, csv_meta = load_39a_focus(path39a_pivot)
    cross = merge_cross(raw_matrix, csv_matrix)
    focus_0804 = [r for r in cross if r["date"] == CORE_DATE]
    focus_0804.sort(key=lambda r: -float(r["combined_score"]))
    lag_pairs = build_lag_pairs(cross)

    top_support = []
    file_support.sort(key=lambda r: (r["date"], r["device"], -safe_int(r["hit_count"])))
    per_key = Counter()
    for r in file_support:
        key = (r["device"], r["date"], r["axis"])
        if per_key[key] >= 8:
            continue
        top_support.append(r)
        per_key[key] += 1

    gap_notes = []
    # Highlight CSV-only or raw-only mismatch.
    for r in cross:
        if r["support_class"] in {"CSV_ONLY_WEAK_RESULT_ECHO", "RAW_ONLY"}:
            gap_notes.append({
                "device": r["device"],
                "date": r["date"],
                "note_type": r["support_class"],
                "final_tier": r["final_tier"],
                "raw_score": r["raw_score"],
                "csv_support_score": r["csv_support_score"],
                "comment": "CSV-only cannot be used for decision; raw-only can be support but needs source-file review.",
            })

    fields_raw = ["device", "date", "role", "raw_tier", "raw_score", "raw_axes_present", "raw_total_axis_hits"] + ["raw_" + a for a in AXES]
    fields_csv = ["device", "date", "csv_support_score", "csv_axes_present", "csv_total_hits"] + ["csv_" + a for a in AXES]
    fields_cross = ["device", "date", "role", "final_tier", "support_class", "combined_score", "raw_tier", "raw_score", "raw_axes_present", "raw_total_axis_hits", "csv_support_score", "csv_axes_present", "csv_total_hits"]
    for a in AXES:
        fields_cross += ["raw_" + a, "csv_" + a]

    write_csv(out_dir / "01_raw39b_strict_device_date_matrix.csv", raw_matrix, fields_raw)
    write_csv(out_dir / "02_csv39a_focus_matrix.csv", csv_matrix, fields_csv)
    write_csv(out_dir / "03_39a39b_cross_device_date_matrix.csv", cross, fields_cross)
    write_csv(out_dir / "04_2025_0804_core_cross.csv", focus_0804, fields_cross)
    write_csv(out_dir / "05_USER_ORIGIN_MINI1_lag_pairs_cross.csv", lag_pairs)
    write_csv(out_dir / "06_raw_source_file_support_top8_per_axis.csv", top_support)
    write_csv(out_dir / "07_gap_and_noise_notes.csv", gap_notes)

    tier_counts = Counter(r["final_tier"] for r in cross)
    support_counts = Counter(r["support_class"] for r in cross)
    devices_0804 = [r["device"] for r in focus_0804 if not str(r["final_tier"]).startswith("D")]
    summary = {
        "created_at": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "script": "40b_c2025aug_39a39b_cross_strict.py",
        "policy": "read_only_input_no_delete_no_move_no_rename_no_edit",
        "input_39a_dir": str(dir39a),
        "input_39b_dir": str(dir39b),
        "output_dir": str(out_dir),
        "focus_window": {"start": FOCUS_START, "end": FOCUS_END, "core_date": CORE_DATE},
        "raw39b_meta": raw_meta,
        "csv39a_meta": csv_meta,
        "raw_strict_rows": len(raw_matrix),
        "csv_focus_rows": len(csv_matrix),
        "cross_rows": len(cross),
        "focus_0804_rows": len(focus_0804),
        "lag_pair_rows": len(lag_pairs),
        "tier_counts": dict(tier_counts),
        "support_counts": dict(support_counts),
        "non_weak_devices_on_2025_08_04": devices_0804,
        "decision": {
            "run_previous_40_as_is": False,
            "reason": "39a is result-derived support and 39b is raw-derived but broad; the correct next step is cross-strict 40b, not 39b-only 40 as final.",
            "use_40b_now": True,
            "claim_boundary": "Trial/AB is candidate cohort/feature-flag coupling only; not proof of Trial abuse, hidden MDM, Apple involvement, or remote command."
        },
        "elapsed_seconds": round(time.time() - start, 3),
    }
    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)

    readme = [
        "40b_c2025aug_39a39b_cross_strict verdict",
        "",
        "39a was checked before deciding whether to run 40.",
        "Decision: do NOT treat previous 40 as the final next run.",
        "Use this 40b instead because it compares 39a CSV-result support with 39b raw-derived strict rows.",
        "",
        "Meaning of sources:",
        "  39a = useful support, but result-derived and can echo/amplify old CSV counts.",
        "  39b = raw-derived, stronger, but broad keyword axis still needs strict filtering.",
        "",
        f"cross_rows: {len(cross)}",
        f"focus_0804_rows: {len(focus_0804)}",
        f"lag_pair_rows: {len(lag_pairs)}",
        f"tier_counts: {dict(tier_counts)}",
        "",
        "Claim boundary:",
        "  Do not claim Trial abuse / hidden MDM / Apple involvement / remote command from this alone.",
        "  This is a C2025AUG lateral trust cluster review layer only.",
    ]
    (out_dir / "08_README_VERDICT.txt").write_text("\n".join(readme), encoding="utf-8")

    print("=== 40b DONE ===")
    print("39a:", dir39a)
    print("39b:", dir39b)
    print("OUT:", out_dir)
    print("cross_rows:", len(cross))
    print("focus_0804_rows:", len(focus_0804))
    print("lag_pair_rows:", len(lag_pairs))
    print("tier_counts:", dict(tier_counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
