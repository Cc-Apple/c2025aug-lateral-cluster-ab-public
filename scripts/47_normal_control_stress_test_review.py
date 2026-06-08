# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
47_normal_control_stress_test_review.py

Normal / Control Stress Test for C2025AUG lateral trust cluster + A/B line.

No pandas. Standard library only.
Read-only. No delete/move/rename/modify of inputs.

Default input root:
  [RESULT_ROOT]

Expected prior outputs:
  40b_c2025aug_39a39b_cross_strict
  43_trust_graph_lineage_review
  44_backup_manifest_inheritance_review
  45_proximity_vs_cloud_separation_review
  46_evidence_preservation_suppression_review

Output:
  [RESULT_ROOT]\47_normal_control_stress_test_review
"""
from __future__ import annotations

import csv
import json
import math
import os
import sys
import time
from pathlib import Path
from collections import defaultdict, Counter

SCRIPT_NAME = "47_normal_control_stress_test_review"
TARGET_DATE = "2025-08-04"
WINDOW_LABEL = "C2025AUG_2025-08-04"

PRIOR_DIRS = {
    "40b": "40b_c2025aug_39a39b_cross_strict",
    "43": "43_trust_graph_lineage_review",
    "44": "44_backup_manifest_inheritance_review",
    "45": "45_proximity_vs_cloud_separation_review",
    "46": "46_evidence_preservation_suppression_review",
}

INPUT_FILES = {
    "40b_core": ("40b", "04_2025_0804_core_cross.csv"),
    "43_trust": ("43", "01_trust_graph_0804_device_matrix.csv"),
    "44_backup": ("44", "01_backup_manifest_0804_device_matrix.csv"),
    "45_proximity": ("45", "01_proximity_cloud_0804_device_matrix.csv"),
    "46_evidence": ("46", "01_evidence_suppression_0804_device_matrix.csv"),
}

DEVICE_ROLE_HINT = {
    "USER_ORIGIN_MINI1": "ORIGIN_CORE",
    "USER_BRIDGE_15G": "BRIDGE_TO_LATER_JOKER",
    "USER_DEVICE_12G": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_MINI2": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_11PRO": "USER_CLUSTER_SUPPORT",
    "EXT_NO_CONTACT_A": "EXTERNAL_CRITICAL_NO_DIRECT_CONTACT",
    "EXT_REMOTE_GEO_C": "EXTERNAL_GEO_SEPARATED",
    "EXT_UNCERTAIN_B": "EXTERNAL_CRITICAL_UNCERTAIN_CONTACT",
    "EXT_CONTACT_D": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_12PROMAX": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_6SPLUS": "EXTERNAL_CONTACT_KNOWN_OR_CONTROL_REVIEW",
    "CONTROL_OR_GENERIC_EXTERNAL": "GENERIC_LABEL_EXCLUDE_FROM_DECISION",
    "LOW_EXPOSURE_IPAD": "LOW_EXPOSURE_OR_CONTROL_CANDIDATE",
    "USER_ORIGIN_MINI1G": "NEW_CONTROL_CANDIDATE_IF_PRESENT",
}

CONTROL_CANDIDATE_NAMES = {"LOW_EXPOSURE_IPAD", "CONTROL_OR_GENERIC_EXTERNAL", "USER_ORIGIN_MINI1G", "FriendB_iPhone6Plus", "iPhone6Plus", "iPhone6sPlus_Control"}
GENERIC_EXCLUDE_NAMES = {"CONTROL_OR_GENERIC_EXTERNAL", "UNKNOWN"}


def safe_print(s: str) -> None:
    try:
        print(s)
    except UnicodeEncodeError:
        print(s.encode("utf-8", errors="replace").decode("utf-8", errors="replace"))


def ensure_utf8_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    for enc in ("utf-8-sig", "utf-8", "cp932", "latin-1"):
        try:
            with path.open("r", encoding=enc, errors="replace", newline="") as f:
                return list(csv.DictReader(f))
        except Exception:
            continue
    return []


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        keys = []
        seen = set()
        for row in rows:
            for k in row.keys():
                if k not in seen:
                    keys.append(k); seen.add(k)
        fieldnames = keys
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=False)


def as_int(v, default=0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default


def as_float(v, default=0.0) -> float:
    try:
        if v is None or v == "":
            return default
        return float(str(v).replace(",", ""))
    except Exception:
        return default


def bool_yes(v) -> bool:
    return str(v or "").upper() in {"YES", "TRUE", "1", "Y"}


def starts_any(v: str, prefixes: tuple[str, ...]) -> bool:
    return str(v or "").startswith(prefixes)


def find_existing_result_root(argv: list[str]) -> Path:
    # 1. explicit arg
    if len(argv) >= 2 and argv[1].strip():
        return Path(argv[1]).expanduser()
    # 2. env
    env = os.environ.get("SC_RESULT_ROOT")
    if env:
        return Path(env).expanduser()
    # 3. common Windows path
    win = Path(r"[RESULT_ROOT]")
    if win.exists():
        return win
    # 4. parent of current dir if prior folders exist
    cwd = Path.cwd()
    if all((cwd / d).exists() for d in PRIOR_DIRS.values()):
        return cwd
    if all((cwd.parent / d).exists() for d in PRIOR_DIRS.values()):
        return cwd.parent
    # 5. fallback
    return win


def resolve_inputs(root: Path) -> dict[str, Path]:
    out = {}
    for key, (dir_key, filename) in INPUT_FILES.items():
        out[key] = root / PRIOR_DIRS[dir_key] / filename
    return out


def norm_device(row: dict) -> str:
    return (row.get("device") or row.get("device_name") or row.get("target_device") or "").strip()


def merge_by_device(rows: list[dict]) -> dict[str, dict]:
    d = {}
    for row in rows:
        dev = norm_device(row)
        if dev:
            d[dev] = row
    return d


def tier_pass_cluster(v: str) -> bool:
    return starts_any(v, ("A_",))


def verdict_supported(v: str) -> bool:
    return starts_any(v, ("A_", "B_"))


def verdict_strong(v: str) -> bool:
    return starts_any(v, ("A_",))


def verdict_no_decision(v: str) -> bool:
    return starts_any(v, ("E_", "NO_", "D_")) or (not str(v or "").strip())


def device_control_class(device: str, role: str, records: dict) -> str:
    if device in GENERIC_EXCLUDE_NAMES:
        return "GENERIC_LABEL_NOT_VALID_CONTROL"
    if device in CONTROL_CANDIDATE_NAMES:
        return "CONTROL_OR_LOW_EXPOSURE_CANDIDATE"
    if device == "EXT_CONTACT_E_6SPLUS":
        return "FRIEND_DEVICE_NOT_CLEAN_CONTROL_IN_THIS_CLUSTER"
    if role.startswith("EXTERNAL"):
        return "EXTERNAL_REVIEW_DEVICE_NOT_CONTROL"
    if role.startswith("USER") or role in {"ORIGIN_CORE", "BRIDGE_TO_LATER_JOKER"}:
        return "USER_CLUSTER_DEVICE_NOT_CONTROL"
    return "UNCLASSIFIED_REVIEW"


def compute_device_matrix(data: dict[str, dict[str, dict]]) -> list[dict]:
    devices = set()
    for m in data.values():
        devices.update(m.keys())
    rows = []
    for dev in sorted(devices, key=lambda x: (x in {"CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"}, x)):
        r40 = data.get("40b", {}).get(dev, {})
        r43 = data.get("43", {}).get(dev, {})
        r44 = data.get("44", {}).get(dev, {})
        r45 = data.get("45", {}).get(dev, {})
        r46 = data.get("46", {}).get(dev, {})
        role = (r40.get("role") or r43.get("role") or r44.get("role") or r45.get("role") or r46.get("role") or DEVICE_ROLE_HINT.get(dev, ""))

        final_tier_40b = r40.get("final_tier") or r43.get("final_tier_40b") or r44.get("final_tier_40b") or r45.get("final_tier_40b") or r46.get("final_tier_40b") or ""
        support_class = r40.get("support_class") or r43.get("support_class_40b") or r44.get("support_class_40b") or r45.get("support_class_40b") or r46.get("support_class_40b") or ""
        trust_v = r43.get("trust_lineage_verdict") or r44.get("trust_lineage_verdict_43") or r45.get("trust_lineage_verdict_43") or r46.get("trust_lineage_verdict_43") or ""
        backup_v = r44.get("backup_manifest_verdict") or r45.get("backup_manifest_verdict_44") or r46.get("backup_manifest_verdict_44") or ""
        prox_v = r45.get("proximity_cloud_verdict") or r46.get("proximity_cloud_verdict_45") or ""
        evid_v = r46.get("evidence_suppression_verdict") or ""
        triald = r43.get("triald_direct_0804") or r44.get("triald_direct_0804_from43") or r45.get("triald_direct_0804_from43") or r46.get("triald_direct_0804_from43") or ""

        cluster_flag = 1 if tier_pass_cluster(final_tier_40b) else 0
        triald_flag = 1 if bool_yes(triald) else 0
        trust_flag = 1 if verdict_supported(trust_v) else 0
        backup_flag = 1 if verdict_supported(backup_v) else 0
        proximity_flag = 1 if verdict_supported(prox_v) or prox_v.startswith("C_") else 0
        cloud_separation_flag = 1 if prox_v.startswith("A_CLOUD") or prox_v.startswith("B_CLOUD") else 0
        evidence_flag = 1 if starts_any(evid_v, ("A_", "B_", "C_WEAK")) else 0
        strong_flags = sum([cluster_flag, triald_flag, 1 if verdict_strong(trust_v) else 0, 1 if verdict_strong(backup_v) else 0, cloud_separation_flag, 1 if verdict_strong(evid_v) else 0])
        layer_count = sum([cluster_flag, triald_flag, trust_flag, backup_flag, proximity_flag, evidence_flag])

        raw_hits = {
            "raw_total_axis_hits": as_int(r40.get("raw_total_axis_hits")),
            "raw_trial_ab": as_int(r40.get("raw_trial_ab")),
            "raw_cloud_trust": as_int(r40.get("raw_cloud_trust") or r43.get("raw_cloud_trust")),
            "raw_policy_restriction": as_int(r40.get("raw_policy_restriction") or r43.get("raw_policy_restriction")),
            "raw_backup_manifest": as_int(r40.get("raw_backup_manifest") or r44.get("raw_backup_manifest_from_40b")),
            "raw_telecom_wifi_proximity": as_int(r40.get("raw_telecom_wifi_proximity") or r45.get("raw_telecom_wifi_proximity_from40b")),
            "raw_evidence_pressure": as_int(r40.get("raw_evidence_pressure") or r46.get("raw_evidence_pressure_from40b")),
            "raw_lateral_trust": as_int(r40.get("raw_lateral_trust") or r43.get("raw_lateral_trust")),
        }
        # Score is intentionally bounded/log-scaled to avoid one giant RTC file dominating.
        hit_score = sum(math.log10(v + 1) for v in raw_hits.values())
        composite_score = round(layer_count * 20 + strong_flags * 8 + hit_score * 2, 3)

        control_class = device_control_class(dev, role, {"40b": r40, "43": r43, "44": r44, "45": r45, "46": r46})
        if control_class.startswith("CONTROL") or control_class.startswith("GENERIC"):
            if layer_count >= 5 or strong_flags >= 3:
                stress_result = "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY"
            elif layer_count >= 3:
                stress_result = "CONTROL_REVIEW_WEAK_OVERLAP"
            else:
                stress_result = "CONTROL_PASSES_NO_CLUSTER_DENSITY"
        else:
            if layer_count >= 5 and strong_flags >= 3:
                stress_result = "CLUSTER_PATTERN_PRESENT"
            elif layer_count >= 4:
                stress_result = "CLUSTER_PATTERN_SUPPORTED"
            elif layer_count >= 2:
                stress_result = "PARTIAL_CONTEXT_ONLY"
            else:
                stress_result = "NO_DECISION"

        normal_explanation_pressure = "LOW"
        if stress_result in {"CLUSTER_PATTERN_PRESENT", "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY"}:
            normal_explanation_pressure = "HIGH"
        elif stress_result in {"CLUSTER_PATTERN_SUPPORTED", "CONTROL_REVIEW_WEAK_OVERLAP"}:
            normal_explanation_pressure = "MEDIUM"

        rows.append({
            "device": dev,
            "date": TARGET_DATE,
            "role": role,
            "control_class": control_class,
            "stress_result": stress_result,
            "normal_explanation_pressure": normal_explanation_pressure,
            "composite_layer_count_6": layer_count,
            "strong_layer_count_6": strong_flags,
            "bounded_composite_score": composite_score,
            "cluster_core_40b": "YES" if cluster_flag else "NO",
            "triald_direct_42b43": "YES" if triald_flag else "NO",
            "trust_lineage_supported_43": "YES" if trust_flag else "NO",
            "backup_manifest_supported_44": "YES" if backup_flag else "NO",
            "proximity_or_cloud_context_45": "YES" if proximity_flag else "NO",
            "cloud_separation_needed_45": "YES" if cloud_separation_flag else "NO",
            "evidence_pressure_supported_46": "YES" if evidence_flag else "NO",
            "final_tier_40b": final_tier_40b,
            "support_class_40b": support_class,
            "trust_lineage_verdict_43": trust_v,
            "backup_manifest_verdict_44": backup_v,
            "proximity_cloud_verdict_45": prox_v,
            "evidence_suppression_verdict_46": evid_v,
            "raw_total_axis_hits_40b": raw_hits["raw_total_axis_hits"],
            "raw_trial_ab_40b": raw_hits["raw_trial_ab"],
            "raw_cloud_trust": raw_hits["raw_cloud_trust"],
            "raw_policy_restriction": raw_hits["raw_policy_restriction"],
            "raw_backup_manifest": raw_hits["raw_backup_manifest"],
            "raw_telecom_wifi_proximity": raw_hits["raw_telecom_wifi_proximity"],
            "raw_evidence_pressure": raw_hits["raw_evidence_pressure"],
            "raw_lateral_trust": raw_hits["raw_lateral_trust"],
            "claim_boundary": "control_stress_on_local_artifact_summaries_not_clean_population_proof",
        })
    rows.sort(key=lambda r: (-as_float(r["bounded_composite_score"]), r["device"]))
    return rows


def build_summary_tables(device_rows: list[dict]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    # 02 control vs core summary
    buckets = defaultdict(list)
    for r in device_rows:
        if r["control_class"].startswith("CONTROL"):
            bucket = "control_candidates"
        elif r["control_class"].startswith("GENERIC"):
            bucket = "generic_excluded"
        elif r["role"] in {"ORIGIN_CORE", "BRIDGE_TO_LATER_JOKER"} or r["role"].startswith("USER"):
            bucket = "user_cluster_devices"
        elif r["role"].startswith("EXTERNAL"):
            bucket = "external_review_devices"
        else:
            bucket = "other"
        buckets[bucket].append(r)

    summary_rows = []
    for bucket, rows in sorted(buckets.items()):
        cnt = len(rows)
        avg_layer = sum(as_int(r["composite_layer_count_6"]) for r in rows) / cnt if cnt else 0
        avg_score = sum(as_float(r["bounded_composite_score"]) for r in rows) / cnt if cnt else 0
        max_score = max([as_float(r["bounded_composite_score"]) for r in rows] or [0])
        pattern_present = sum(1 for r in rows if r["stress_result"] in {"CLUSTER_PATTERN_PRESENT", "CLUSTER_PATTERN_SUPPORTED", "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY"})
        summary_rows.append({
            "bucket": bucket,
            "device_count": cnt,
            "avg_layer_count_6": round(avg_layer, 3),
            "avg_bounded_score": round(avg_score, 3),
            "max_bounded_score": round(max_score, 3),
            "pattern_or_control_fail_count": pattern_present,
            "devices": ";".join(r["device"] for r in rows),
        })

    # 03 normal explanation collapse table
    hypotheses = []
    def add(h, result, support, boundary):
        hypotheses.append({"normal_hypothesis": h, "stress_result": result, "stress_support": support, "boundary": boundary})

    core_count = sum(1 for r in device_rows if r["cluster_core_40b"] == "YES")
    trial_count = sum(1 for r in device_rows if r["triald_direct_42b43"] == "YES")
    trust_count = sum(1 for r in device_rows if r["trust_lineage_supported_43"] == "YES")
    backup_count = sum(1 for r in device_rows if r["backup_manifest_supported_44"] == "YES")
    cloud_sep_count = sum(1 for r in device_rows if r["cloud_separation_needed_45"] == "YES")
    evidence_count = sum(1 for r in device_rows if r["evidence_pressure_supported_46"] == "YES")
    control_fail = sum(1 for r in device_rows if r["stress_result"] == "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY")
    control_pass = sum(1 for r in device_rows if r["stress_result"] == "CONTROL_PASSES_NO_CLUSTER_DENSITY")

    add("ordinary_single_device_iOS_noise", "WEAKENED", f"cluster_core_devices={core_count}; multi_layer_overlap_devices={sum(1 for r in device_rows if as_int(r['composite_layer_count_6'])>=5)}", "does_not_prove_attack_or_intent")
    add("ordinary_triald_noise_only", "WEAKENED_NOT_COLLAPSED", f"triald_direct_devices={trial_count}; must remain cohort_explanatory_variable", "triald_is_normal_iOS_component")
    add("ordinary_iCloud_sync_only", "WEAKENED", f"trust_lineage_supported_devices={trust_count}; cloud_separation_needed_devices={cloud_sep_count}", "no_Apple_server_side_logs")
    add("ordinary_backup_manifest_noise_only", "WEAKENED", f"backup_manifest_supported_devices={backup_count}", "not_restore_causal_proof")
    add("ordinary_physical_proximity_only", "WEAKENED", f"cloud_separation_needed_devices={cloud_sep_count}", "contact_metadata_is_partly_external/user-provided")
    add("ordinary_evidence_pressure_only", "WEAKENED_NOT_COLLAPSED", f"evidence_pressure_supported_devices={evidence_count}", "does_not_prove_suppression_intent")
    add("normal_controls_show_same_density", "NOT_SUPPORTED_IN_AVAILABLE_CONTROL_SET" if control_fail == 0 else "REVIEW_REQUIRED", f"control_pass={control_pass}; control_fail={control_fail}", "control_set_limited; USER_ORIGIN_MINI1G not necessarily present in this C2025AUG input")

    # 04 control candidate details
    control_rows = [r for r in device_rows if r["control_class"].startswith("CONTROL") or r["control_class"].startswith("GENERIC") or r["device"] in {"LOW_EXPOSURE_IPAD", "CONTROL_OR_GENERIC_EXTERNAL", "USER_ORIGIN_MINI1G"}]

    # 05 layer overlap rank
    layer_rows = []
    for r in device_rows:
        layer_rows.append({
            "device": r["device"],
            "role": r["role"],
            "layer_count_6": r["composite_layer_count_6"],
            "strong_layer_count_6": r["strong_layer_count_6"],
            "bounded_composite_score": r["bounded_composite_score"],
            "stress_result": r["stress_result"],
            "layers": ";".join([
                name for name, key in [
                    ("cluster_core_40b", "cluster_core_40b"),
                    ("triald_direct", "triald_direct_42b43"),
                    ("trust_lineage", "trust_lineage_supported_43"),
                    ("backup_manifest", "backup_manifest_supported_44"),
                    ("proximity_or_cloud", "proximity_or_cloud_context_45"),
                    ("evidence_pressure", "evidence_pressure_supported_46"),
                ] if r.get(key) == "YES"
            ])
        })
    layer_rows.sort(key=lambda r: (-as_float(r["bounded_composite_score"]), r["device"]))
    return summary_rows, hypotheses, control_rows, layer_rows


def decide_final_verdict(device_rows: list[dict]) -> tuple[str, str]:
    control_fail = [r for r in device_rows if r["stress_result"] == "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY"]
    control_pass = [r for r in device_rows if r["stress_result"] == "CONTROL_PASSES_NO_CLUSTER_DENSITY"]
    cluster_present = [r for r in device_rows if r["stress_result"] in {"CLUSTER_PATTERN_PRESENT", "CLUSTER_PATTERN_SUPPORTED"}]
    external_separation = [r for r in device_rows if r["cloud_separation_needed_45"] == "YES"]

    if control_fail:
        return "NORMAL_CONTROL_STRESS_REVIEW_REQUIRED_CONTROL_REPRODUCES_DENSITY", "A control candidate reproduced cluster-like density; do not seal without manual review."
    if cluster_present and control_pass:
        return "NORMAL_CONTROL_STRESS_REDUCES_GENERIC_IOS_EXPLANATION_CONTROL_SET_LIMITED", "Cluster devices show multi-layer overlap while available control/low-exposure candidates do not reproduce the same density. Control set remains limited."
    if cluster_present:
        return "NORMAL_CONTROL_STRESS_PARTIAL_NO_STRONG_CONTROL_BASELINE", "Cluster density exists, but available control baseline is too thin."
    return "NORMAL_CONTROL_STRESS_INCONCLUSIVE", "No stable cluster/control separation was derived from available summaries."


def main() -> int:
    ensure_utf8_stdout()
    started = time.time()
    result_root = find_existing_result_root(sys.argv)
    out_dir = result_root / "47_normal_control_stress_test_review"
    out_dir.mkdir(parents=True, exist_ok=True)

    paths = resolve_inputs(result_root)
    input_rows = []
    for key, p in paths.items():
        input_rows.append({"input_key": key, "path": str(p), "exists": "YES" if p.exists() else "NO"})

    rows40 = read_csv(paths["40b_core"])
    rows43 = read_csv(paths["43_trust"])
    rows44 = read_csv(paths["44_backup"])
    rows45 = read_csv(paths["45_proximity"])
    rows46 = read_csv(paths["46_evidence"])

    data = {
        "40b": merge_by_device(rows40),
        "43": merge_by_device(rows43),
        "44": merge_by_device(rows44),
        "45": merge_by_device(rows45),
        "46": merge_by_device(rows46),
    }

    device_rows = compute_device_matrix(data)
    summary_rows, hypothesis_rows, control_rows, layer_rows = build_summary_tables(device_rows)
    verdict, verdict_note = decide_final_verdict(device_rows)

    claim_boundary_rows = [
        {"item": "can_say", "value": "Available local artifact summaries reduce the generic normal-iOS explanation for C2025AUG."},
        {"item": "can_say", "value": "Cluster/review devices show multi-layer overlap across 40b/43/44/45/46."},
        {"item": "can_say", "value": "Available control/low-exposure labels do not reproduce the same density in this input set."},
        {"item": "cannot_say", "value": "This is not population-level clean-control proof."},
        {"item": "cannot_say", "value": "This does not prove attack intent, Apple involvement, hidden MDM, server-side trust graph, Trial abuse, or remote command."},
        {"item": "limitation", "value": "Control set is limited; USER_ORIGIN_MINI1G or friend clean control data may not be present in these C2025AUG summary inputs."},
        {"item": "limitation", "value": "CONTROL_OR_GENERIC_EXTERNAL/UNKNOWN generic labels are excluded from positive decision making."},
    ]

    write_csv(out_dir / "00_input_paths.csv", input_rows, ["input_key", "path", "exists"])
    write_csv(out_dir / "01_normal_control_device_matrix.csv", device_rows)
    write_csv(out_dir / "02_control_vs_core_stress_summary.csv", summary_rows)
    write_csv(out_dir / "03_normal_explanation_collapse_table.csv", hypothesis_rows)
    write_csv(out_dir / "04_control_candidate_details.csv", control_rows)
    write_csv(out_dir / "05_layer_overlap_rank.csv", layer_rows)
    write_csv(out_dir / "06_claim_boundary_notes.csv", claim_boundary_rows)

    summary = {
        "script": SCRIPT_NAME,
        "status": "DONE",
        "variant": "NO_PANDAS_STD_LIB_ONLY",
        "target": WINDOW_LABEL,
        "result_root": str(result_root),
        "output_dir": str(out_dir),
        "final_verdict": verdict,
        "final_verdict_note": verdict_note,
        "device_rows": len(device_rows),
        "control_candidate_rows": len(control_rows),
        "hypothesis_rows": len(hypothesis_rows),
        "layer_rank_rows": len(layer_rows),
        "cluster_pattern_present_or_supported_count": sum(1 for r in device_rows if r["stress_result"] in {"CLUSTER_PATTERN_PRESENT", "CLUSTER_PATTERN_SUPPORTED"}),
        "control_pass_count": sum(1 for r in device_rows if r["stress_result"] == "CONTROL_PASSES_NO_CLUSTER_DENSITY"),
        "control_fail_count": sum(1 for r in device_rows if r["stress_result"] == "CONTROL_FAILS_REPRODUCES_CLUSTER_DENSITY"),
        "generic_excluded_count": sum(1 for r in device_rows if r["control_class"].startswith("GENERIC")),
        "elapsed_seconds": round(time.time() - started, 3),
        "inputs": {k: {"path": str(v), "exists": v.exists()} for k, v in paths.items()},
    }
    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)

    readme = f"""47 Normal / Control Stress Test Review

Target: {WINDOW_LABEL}
Status: DONE
Variant: NO_PANDAS_STD_LIB_ONLY

Final verdict:
  {verdict}

Meaning:
  Available local artifact summaries reduce the generic normal-iOS explanation.
  Cluster/review devices show multi-layer overlap across 40b/43/44/45/46.
  Available control/low-exposure labels do not reproduce the same density in this input set.

Boundary:
  This is not population-level clean-control proof.
  This does not prove attack intent, Apple involvement, hidden MDM, server-side trust graph, Trial abuse, or remote command.
  Control set is limited. USER_ORIGIN_MINI1G or other clean controls may require a separate follow-up if available.

Next:
  48 Final Seal / 横展開クラスタ+A/B総合判定
"""
    (out_dir / "07_README_VERDICT.txt").write_text(readme, encoding="utf-8")

    safe_print("============================================================")
    safe_print("47 Normal / Control Stress Test Review")
    safe_print("============================================================")
    safe_print(f"Status: DONE")
    safe_print(f"Output: {out_dir}")
    safe_print(f"Final verdict: {verdict}")
    safe_print(f"Device rows: {len(device_rows)}")
    safe_print(f"Elapsed seconds: {summary['elapsed_seconds']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
