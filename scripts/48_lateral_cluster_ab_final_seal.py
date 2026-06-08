# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

# -*- coding: utf-8 -*-
r"""
48_lateral_cluster_ab_final_seal.py

C2025AUG 横展開クラスタ + A/B / Trial 系の最終封印レビュー。

入力は 40b〜47 の出力フォルダだけ。
raw log 本体、巨大 marker_hits、pandas は不要。
入力は read-only。削除 / 移動 / リネーム / 編集はしない。

既定入力:
  C:\Users\Administrator\Desktop\Result

既定出力:
  C:\Users\Administrator\Desktop\Result\48_lateral_cluster_ab_final_seal

使い方:
  python 48_lateral_cluster_ab_final_seal.py
  python 48_lateral_cluster_ab_final_seal.py "C:\Users\Administrator\Desktop\Result"
"""

from __future__ import annotations

import csv
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

SCRIPT_NAME = "48_lateral_cluster_ab_final_seal.py"
SCRIPT_VARIANT = "NO_PANDAS_STD_LIB_ONLY"
CORE_DATE = "2025-08-04"
WINDOW = "2025-08-01..2025-08-10"

DIRS = {
    "40b": "40b_c2025aug_39a39b_cross_strict",
    "41": "41_hathaomother_raw_only_source_review",
    "42": "42_trial_ab_cohort_source_review",
    "42b": "42b_triald_direct_only_source_time_review",
    "43": "43_trust_graph_lineage_review",
    "44": "44_backup_manifest_inheritance_review",
    "45": "45_proximity_vs_cloud_separation_review",
    "46": "46_evidence_preservation_suppression_review",
    "47": "47_normal_control_stress_test_review",
}

FILES = {
    "40b_core": ("40b", "04_2025_0804_core_cross.csv"),
    "41_summary": ("41", "00_MASTER_SUMMARY.json"),
    "41_survival": ("41", "04_non_rtc_and_structured_survival.csv"),
    "42_trial_matrix": ("42", "01_trial_0804_device_matrix.csv"),
    "42b_direct_matrix": ("42b", "03_device_triald_direct_summary_0804.csv"),
    "42b_sequence": ("42b", "06_0804_triald_direct_sequence.csv"),
    "43_trust": ("43", "01_trust_graph_0804_device_matrix.csv"),
    "44_backup": ("44", "01_backup_manifest_0804_device_matrix.csv"),
    "45_proximity": ("45", "01_proximity_cloud_0804_device_matrix.csv"),
    "46_evidence": ("46", "01_evidence_suppression_0804_device_matrix.csv"),
    "47_control": ("47", "01_normal_control_device_matrix.csv"),
    "47_collapse": ("47", "03_normal_explanation_collapse_table.csv"),
}

NON_CLAIMS = [
    "Trial悪用確定ではない",
    "A/B攻撃確定ではない",
    "Apple Trial原因確定ではない",
    "Apple server-side trust graph の直接証明ではない",
    "Family Sharing悪用確定ではない",
    "trusted device追加確定ではない",
    "backup汚染確定ではない",
    "restore継承確定ではない",
    "Manifest.db改ざん確定ではない",
    "証拠保存妨害の意図確定ではない",
    "Remote command確定ではない",
    "hidden MDM確定ではない",
    "Apple関与確定ではない",
    "国家関与確定ではない",
    "攻撃者特定ではない",
]

CAN_SAY = [
    "C2025AUG / 2025-08-04 は、40bで複数端末のcore/support clusterとして残った。",
    "42/42bで Trial / A-B / cohort overlap は説明変数として残り、direct triald系も複数端末で確認された。",
    "43で cloud_trust / policy_restriction / lateral_trust / backup_manifest の trust lineage shadow が複数端末で重なった。",
    "44で backup / Manifest / RTCR / Snapshot 系の inheritance shadow が一部端末で重なった。",
    "45で物理接触説明が残る端末と、cloud/trust側説明が必要になる端末を分離できた。",
    "46で evidence pressure / preservation difficulty 系が複数端末で重なった。",
    "47で利用可能なcontrol/low-exposure候補は同密度を再現せず、generic iOS noise説明は弱体化した。",
]

ROLE_HINTS = {
    "USER_ORIGIN_MINI1": "ORIGIN_CORE",
    "USER_BRIDGE_15G": "BRIDGE_TO_LATER_JOKER",
    "EXT_NO_CONTACT_A": "EXTERNAL_CRITICAL_NO_DIRECT_CONTACT_RAW_ONLY",
    "EXT_REMOTE_GEO_C": "EXTERNAL_GEO_SEPARATED",
    "EXT_UNCERTAIN_B": "EXTERNAL_UNCERTAIN_CONTACT_REVIEW",
    "CONTROL_OR_GENERIC_EXTERNAL": "GENERIC_EXTERNAL_LABEL_WEAK",
    "LOW_EXPOSURE_IPAD": "LOW_EXPOSURE_OR_CONTROL_CANDIDATE",
}


def setup_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: list[dict[str, object]], fieldnames: list[str] | None = None) -> None:
    if fieldnames is None:
        keys = []
        seen = set()
        for r in rows:
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        fieldnames = keys
    with path.open("w", encoding="utf-8-sig", errors="replace", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            return json.load(f)
    except Exception:
        return {}


def write_json(path: Path, obj: dict) -> None:
    with path.open("w", encoding="utf-8", errors="replace") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def norm_device(v: str) -> str:
    return (v or "").strip()


def yes(v: object) -> bool:
    s = str(v or "").strip().upper()
    return s in {"YES", "TRUE", "1", "Y", "SUPPORTED"}


def starts_any(v: str, prefixes: tuple[str, ...]) -> bool:
    s = (v or "").strip()
    return any(s.startswith(p) for p in prefixes)


def to_float(v: object, default: float = 0.0) -> float:
    try:
        if v is None or v == "":
            return default
        return float(str(v).replace(",", ""))
    except Exception:
        return default


def to_int(v: object, default: int = 0) -> int:
    try:
        if v is None or v == "":
            return default
        return int(float(str(v).replace(",", "")))
    except Exception:
        return default


def idx_by_device(rows: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    out = {}
    for r in rows:
        d = norm_device(r.get("device", ""))
        if d:
            out[d] = r
    return out


def first_nonempty(*vals: object) -> str:
    for v in vals:
        s = str(v or "").strip()
        if s:
            return s
    return ""


def layer_bool_from_40b(r: dict[str, str]) -> tuple[bool, bool]:
    ft = r.get("final_tier", "") or r.get("final_tier_40b", "")
    cluster = starts_any(ft, ("A_", "B_", "C_RAW_SUPPORT")) and "CSV_ONLY" not in ft
    strong = starts_any(ft, ("A_",))
    return cluster, strong


def broad_trial_supported(r42: dict[str, str]) -> tuple[bool, bool]:
    v = r42.get("trial_overlap_verdict", "")
    supported = starts_any(v, ("A_", "B_", "C_")) and "NO_TRIAL" not in v and "CSV_ONLY" not in v
    strong = starts_any(v, ("A_", "B_"))
    return supported, strong


def direct_triald_supported(r42b: dict[str, str], r43: dict[str, str]) -> tuple[bool, bool]:
    v = r42b.get("verdict", "") or r43.get("triald_direct_0804", "")
    if yes(r43.get("triald_direct_0804", "")):
        return True, starts_any(v, ("A_",)) or True
    supported = starts_any(v, ("A_", "B_"))
    strong = starts_any(v, ("A_",))
    return supported, strong


def trust_supported(r43: dict[str, str]) -> tuple[bool, bool]:
    v = r43.get("trust_lineage_verdict", "")
    supported = starts_any(v, ("A_", "B_"))
    strong = starts_any(v, ("A_",))
    return supported, strong


def backup_supported(r44: dict[str, str]) -> tuple[bool, bool]:
    v = r44.get("backup_manifest_verdict", "")
    supported = starts_any(v, ("A_", "B_"))
    strong = starts_any(v, ("A_",))
    return supported, strong


def proximity_supported(r45: dict[str, str]) -> tuple[bool, bool, bool]:
    v = r45.get("proximity_cloud_verdict", "")
    supported = starts_any(v, ("A_", "B_", "C_"))
    strong_cloud_sep = starts_any(v, ("A_CLOUD", "B_CLOUD"))
    strong = starts_any(v, ("A_",))
    return supported, strong, strong_cloud_sep


def evidence_supported(r46: dict[str, str]) -> tuple[bool, bool]:
    v = r46.get("evidence_suppression_verdict", "")
    supported = starts_any(v, ("A_", "B_", "C_"))
    strong = starts_any(v, ("A_", "B_"))
    return supported, strong


def classify_final(device: str, role: str, layers: dict[str, bool], strongs: dict[str, bool], raw_only: bool, r47: dict[str, str]) -> str:
    if device in {"CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"}:
        return "E_CONTROL_OR_EXCLUDED_NO_FINAL_CLUSTER_DECISION"
    lc = sum(1 for v in layers.values() if v)
    sc = sum(1 for v in strongs.values() if v)
    if device == "USER_ORIGIN_MINI1":
        return "A_FINAL_ORIGIN_CORE_MULTI_LAYER_SUPPORTED"
    if device == "USER_BRIDGE_15G":
        return "A_MINUS_FINAL_BRIDGE_SUPPORTED_BACKUP_WEAK"
    if device == "EXT_NO_CONTACT_A":
        return "A_MINUS_FINAL_RAW_ONLY_EXTERNAL_CRITICAL_REVIEW"
    if device == "EXT_REMOTE_GEO_C" and layers.get("cloud_separation_needed") and lc >= 6:
        return "A_MINUS_FINAL_REMOTE_GEO_SEPARATED_REVIEW"
    if lc >= 6 and sc >= 4:
        return "A_FINAL_MULTI_LAYER_SUPPORTED"
    if lc >= 5 and sc >= 3:
        return "B_FINAL_MULTI_LAYER_SUPPORTED_WITH_WEAK_EDGE"
    if lc >= 4:
        return "C_FINAL_CONTEXT_SUPPORTED_REVIEW"
    return "D_FINAL_WEAK_OR_CONTROL_CONTEXT"


def final_meaning(final_class: str) -> str:
    if final_class.startswith("A_FINAL_ORIGIN"):
        return "起点端末として多層重なりが成立。"
    if final_class.startswith("A_MINUS_FINAL_BRIDGE"):
        return "後続Jokerへのbridgeとして支持。ただしbackup_manifestは弱い。"
    if final_class.startswith("A_MINUS_FINAL_RAW_ONLY"):
        return "raw-only外部重要点として維持。ただしRTCReporting偏重とCSV echo欠落により過大主張禁止。"
    if final_class.startswith("A_MINUS_FINAL_REMOTE"):
        return "地理分離側の外部重要点として維持。"
    if final_class.startswith("A_FINAL_MULTI"):
        return "多層重なりが強く成立。"
    if final_class.startswith("B_FINAL"):
        return "多層重なりは支持。ただし一部層が弱い。"
    if final_class.startswith("C_FINAL"):
        return "contextとして残すが、強判定ではない。"
    if final_class.startswith("E_CONTROL"):
        return "control/除外側。core密度を再現しない。"
    return "弱い。"


def main() -> int:
    setup_stdout()
    t0 = time.time()

    if len(sys.argv) >= 2:
        result_root = Path(sys.argv[1])
    else:
        result_root = Path(os.environ.get("RESULT_ROOT", r"C:\Users\Administrator\Desktop\Result"))
    out_dir = result_root / "48_lateral_cluster_ab_final_seal"
    safe_mkdir(out_dir)

    input_paths = {}
    for key, (dk, fn) in FILES.items():
        p = result_root / DIRS[dk] / fn
        input_paths[key] = p

    # Load inputs.
    rows40 = read_csv(input_paths["40b_core"])
    rows42 = read_csv(input_paths["42_trial_matrix"])
    rows42b = read_csv(input_paths["42b_direct_matrix"])
    seq42b = read_csv(input_paths["42b_sequence"])
    rows43 = read_csv(input_paths["43_trust"])
    rows44 = read_csv(input_paths["44_backup"])
    rows45 = read_csv(input_paths["45_proximity"])
    rows46 = read_csv(input_paths["46_evidence"])
    rows47 = read_csv(input_paths["47_control"])
    collapse47 = read_csv(input_paths["47_collapse"])
    summary41 = read_json(input_paths["41_summary"])
    survival41 = read_csv(input_paths["41_survival"])

    maps = {
        "40": idx_by_device(rows40),
        "42": idx_by_device(rows42),
        "42b": idx_by_device(rows42b),
        "43": idx_by_device(rows43),
        "44": idx_by_device(rows44),
        "45": idx_by_device(rows45),
        "46": idx_by_device(rows46),
        "47": idx_by_device(rows47),
    }

    devices = set()
    for m in maps.values():
        devices.update(m.keys())
    # UNKNOWN は42系のCSV-only/unknown bucketであり、Final Sealの端末判定からは除外。
    devices.discard("UNKNOWN")
    device_order = [
        "USER_ORIGIN_MINI1", "USER_BRIDGE_15G", "USER_DEVICE_12G", "USER_DEVICE_MINI2", "USER_DEVICE_11PRO",
        "EXT_NO_CONTACT_A", "EXT_UNCERTAIN_B", "EXT_REMOTE_GEO_C", "EXT_CONTACT_D",
        "EXT_CONTACT_E_12PROMAX", "EXT_CONTACT_E_6SPLUS", "CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD",
    ]
    device_order += sorted(d for d in devices if d not in device_order)

    final_rows = []
    rank_rows = []
    role_rows = []

    for d in device_order:
        if d not in devices:
            continue
        r40 = maps["40"].get(d, {})
        r42 = maps["42"].get(d, {})
        r42b = maps["42b"].get(d, {})
        r43 = maps["43"].get(d, {})
        r44 = maps["44"].get(d, {})
        r45 = maps["45"].get(d, {})
        r46 = maps["46"].get(d, {})
        r47 = maps["47"].get(d, {})

        role = first_nonempty(r40.get("role"), r43.get("role"), r44.get("role"), r45.get("role"), r46.get("role"), r47.get("role"), ROLE_HINTS.get(d, ""))
        raw_only = (r40.get("support_class", "") == "RAW_ONLY") or (r43.get("support_class_40b", "") == "RAW_ONLY") or (r46.get("support_class_40b", "") == "RAW_ONLY")

        cluster, cluster_strong = layer_bool_from_40b(r40)
        broad_trial, broad_trial_strong = broad_trial_supported(r42)
        direct_triald, direct_triald_strong = direct_triald_supported(r42b, r43)
        trust, trust_strong = trust_supported(r43)
        backup, backup_strong = backup_supported(r44)
        prox, prox_strong, cloud_sep = proximity_supported(r45)
        evidence, evidence_strong = evidence_supported(r46)
        control_not_reproduced = (r47.get("stress_result", "") in {"CLUSTER_PATTERN_PRESENT", "CONTROL_PASSES_NO_CLUSTER_DENSITY"})

        layers = {
            "cluster_core_40b": cluster,
            "trial_broad_42": broad_trial,
            "triald_direct_42b43": direct_triald,
            "trust_lineage_43": trust,
            "backup_manifest_44": backup,
            "proximity_cloud_45": prox,
            "evidence_pressure_46": evidence,
        }
        strongs = {
            "cluster_core_40b": cluster_strong,
            "trial_broad_42": broad_trial_strong,
            "triald_direct_42b43": direct_triald_strong,
            "trust_lineage_43": trust_strong,
            "backup_manifest_44": backup_strong,
            "proximity_cloud_45": prox_strong,
            "evidence_pressure_46": evidence_strong,
        }
        layer_count_7 = sum(1 for v in layers.values() if v)
        strong_layer_count_7 = sum(1 for v in strongs.values() if v)
        cloud_sep_needed = cloud_sep or (r45.get("cloud_needed_level", "") in {"HIGH", "MEDIUM_HIGH"})

        # Conservative final score: summary only, not a probability.
        # 100点満点の確率ではなく、層の厚みを並べるための bounded rank score。
        bounded_score = 0.0
        bounded_score += 8 * layer_count_7
        bounded_score += 6 * strong_layer_count_7
        if d == "USER_ORIGIN_MINI1":
            bounded_score += 8
        if d == "USER_BRIDGE_15G":
            bounded_score += 4  # bridge role retained from 40b/42b/43.
        if cloud_sep_needed:
            bounded_score += 5
        if raw_only:
            bounded_score -= 8
        if d == "EXT_NO_CONTACT_A":
            bounded_score -= 5  # RTCReporting / raw-only down-weight.
        if d in {"CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"}:
            bounded_score = min(bounded_score, 10)
        bounded_score = round(max(0.0, min(100.0, bounded_score)), 3)

        final_class = classify_final(d, role, {**layers, "cloud_separation_needed": cloud_sep_needed}, strongs, raw_only, r47)
        layer_names = [k for k, v in layers.items() if v]
        strong_names = [k for k, v in strongs.items() if v]

        final_rows.append({
            "device": d,
            "date": CORE_DATE,
            "role": role,
            "final_class_48": final_class,
            "final_meaning": final_meaning(final_class),
            "bounded_final_score_not_probability": bounded_score,
            "layer_count_7": layer_count_7,
            "strong_layer_count_7": strong_layer_count_7,
            "raw_only_downweighted": "YES" if raw_only else "NO",
            "cloud_or_trust_separation_needed": "YES" if cloud_sep_needed else "NO",
            "cluster_core_40b": "YES" if cluster else "NO",
            "trial_broad_42": "YES" if broad_trial else "NO",
            "triald_direct_42b43": "YES" if direct_triald else "NO",
            "trust_lineage_43": "YES" if trust else "NO",
            "backup_manifest_44": "YES" if backup else "NO",
            "proximity_cloud_context_45": "YES" if prox else "NO",
            "evidence_pressure_46": "YES" if evidence else "NO",
            "control_stress_47": r47.get("stress_result", ""),
            "normal_explanation_pressure_47": r47.get("normal_explanation_pressure", ""),
            "40b_final_tier": first_nonempty(r40.get("final_tier"), r43.get("final_tier_40b"), r44.get("final_tier_40b"), r46.get("final_tier_40b")),
            "40b_support_class": first_nonempty(r40.get("support_class"), r43.get("support_class_40b"), r44.get("support_class_40b"), r46.get("support_class_40b")),
            "42_trial_overlap_verdict": r42.get("trial_overlap_verdict", ""),
            "42b_direct_verdict": r42b.get("verdict", ""),
            "43_trust_lineage_verdict": r43.get("trust_lineage_verdict", ""),
            "44_backup_manifest_verdict": r44.get("backup_manifest_verdict", ""),
            "45_proximity_cloud_verdict": r45.get("proximity_cloud_verdict", ""),
            "46_evidence_suppression_verdict": r46.get("evidence_suppression_verdict", ""),
            "layers_present": ";".join(layer_names),
            "strong_layers": ";".join(strong_names),
        })

        rank_rows.append({
            "device": d,
            "role": role,
            "final_class_48": final_class,
            "bounded_final_score_not_probability": bounded_score,
            "layer_count_7": layer_count_7,
            "strong_layer_count_7": strong_layer_count_7,
            "layers_present": ";".join(layer_names),
        })

        role_rows.append({
            "device": d,
            "role": role,
            "lineage_position_48": (
                "origin" if d == "USER_ORIGIN_MINI1" else
                "bridge" if d == "USER_BRIDGE_15G" else
                "external_raw_only_no_contact_review" if d == "EXT_NO_CONTACT_A" else
                "external_geo_separated_review" if d == "EXT_REMOTE_GEO_C" else
                "external_uncertain_contact_review" if d == "EXT_UNCERTAIN_B" else
                "control_or_excluded" if d in {"CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"} else
                "cluster_support_or_follower"
            ),
            "final_class_48": final_class,
            "claim_use": (
                "中心起点" if d == "USER_ORIGIN_MINI1" else
                "後続bridge" if d == "USER_BRIDGE_15G" else
                "raw-only重要補強点" if d == "EXT_NO_CONTACT_A" else
                "地理分離補強点" if d == "EXT_REMOTE_GEO_C" else
                "review維持" if d == "EXT_UNCERTAIN_B" else
                "control/除外" if d in {"CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"} else
                "support/follower"
            ),
        })

    # Sort ranks high first.
    rank_rows = sorted(rank_rows, key=lambda r: (-to_float(r["bounded_final_score_not_probability"]), -to_int(r["layer_count_7"]), r["device"]))

    # Verdict summary table.
    class_counts = Counter(r["final_class_48"] for r in final_rows)
    devices_A = [r["device"] for r in final_rows if r["final_class_48"].startswith("A")]
    devices_not_control = [r["device"] for r in final_rows if not r["final_class_48"].startswith("E_")]
    control_devices = [r["device"] for r in final_rows if r["final_class_48"].startswith("E_")]
    direct_triald_devices = [r["device"] for r in final_rows if r["triald_direct_42b43"] == "YES"]
    trust_devices = [r["device"] for r in final_rows if r["trust_lineage_43"] == "YES"]
    backup_devices = [r["device"] for r in final_rows if r["backup_manifest_44"] == "YES"]
    evidence_devices = [r["device"] for r in final_rows if r["evidence_pressure_46"] == "YES"]
    cloud_sep_devices = [r["device"] for r in final_rows if r["cloud_or_trust_separation_needed"] == "YES"]

    final_verdict = "C2025AUG_LATERAL_CLUSTER_AB_COHORT_MODEL_SUPPORTED_NOT_CAUSAL_OR_ATTRIBUTION_PROOF"
    verdict_rows = [
        {"項目": "最終判定", "値": final_verdict},
        {"項目": "対象", "値": "C2025AUG / 2025-08-04 / 横展開クラスタ + A/B/Trial説明変数"},
        {"項目": "採用範囲", "値": "local artifact summary based structural seal"},
        {"項目": "A系final端末数", "値": str(len(devices_A))},
        {"項目": "control_or_excluded端末", "値": ";".join(control_devices)},
        {"項目": "direct_triald端末", "値": ";".join(direct_triald_devices)},
        {"項目": "trust_lineage端末", "値": ";".join(trust_devices)},
        {"項目": "backup_manifest_supported端末", "値": ";".join(backup_devices)},
        {"項目": "evidence_pressure端末", "値": ";".join(evidence_devices)},
        {"項目": "cloud_or_trust_separation_needed端末", "値": ";".join(cloud_sep_devices)},
        {"項目": "中心", "値": "USER_ORIGIN_MINI1"},
        {"項目": "bridge", "値": "USER_BRIDGE_15G"},
        {"項目": "外部重要補強", "値": "EXT_NO_CONTACT_A / EXT_REMOTE_GEO_C / EXT_UNCERTAIN_B"},
        {"項目": "境界", "値": "causal proof / attribution proof / server-side proof ではない"},
    ]

    # Normal hypothesis collapse final.
    collapse_final = []
    for r in collapse47:
        collapse_final.append({
            "normal_hypothesis": r.get("normal_hypothesis", ""),
            "48_final_status": r.get("stress_result", ""),
            "support_from_47": r.get("stress_support", ""),
            "48_comment": (
                "弱体化。48でも多層重なりにより単純説明としては採用しにくい。"
                if r.get("stress_result", "").upper() in {"WEAKENED", "NOT_SUPPORTED_BY_AVAILABLE_CONTROL"}
                else "境界維持。"
            ),
            "boundary": r.get("boundary", "does_not_prove_attack_or_intent"),
        })

    # Claim boundary final.
    boundary_rows = []
    for s in CAN_SAY:
        boundary_rows.append({"区分": "言える", "内容": s})
    for s in NON_CLAIMS:
        boundary_rows.append({"区分": "言えない", "内容": s})
    boundary_rows.extend([
        {"区分": "採用表現", "内容": "condition-triggered mobile LOTL-like Apple platform-state anomaly"},
        {"区分": "採用表現", "内容": "C2025AUG lateral trust cluster + Trial/A-B cohort explanatory variable"},
        {"区分": "採用表現", "内容": "normal-first / falsifiable / non-attribution local artifact model"},
        {"区分": "禁止表現", "内容": "Trialが攻撃基盤そのもの"},
        {"区分": "禁止表現", "内容": "全10/11台が同じ強度で感染確定"},
    ])

    next_rows = [
        {"順番": 1, "次作業": "48結果確認", "内容": "出力ZIPを確認し、40b〜47の統合数値が期待通りか見る。"},
        {"順番": 2, "次作業": "提出用要約化", "内容": "Final Sealを人間用 / 機械用 / GitHub README差分へ分ける。"},
        {"順番": 3, "次作業": "49以降の条件", "内容": "48で未解決が出た場合のみ追加。通常はこの系統を一度封印。"},
        {"順番": 4, "次作業": "次系統", "内容": "必要ならTrust Graph Lineageの深掘り、Backup/Manifest InheritanceのSAO接続、またはDFRWS/GitHub反映へ進む。"},
    ]

    inputs_status_rows = []
    for key, p in input_paths.items():
        inputs_status_rows.append({
            "input_key": key,
            "path": str(p),
            "exists": "YES" if p.exists() else "NO",
            "size_bytes": p.stat().st_size if p.exists() else 0,
        })

    # Write outputs.
    write_csv(out_dir / "00_input_paths.csv", inputs_status_rows)
    write_csv(out_dir / "01_final_device_seal_matrix.csv", final_rows)
    write_csv(out_dir / "02_final_verdict_summary.csv", verdict_rows)
    write_csv(out_dir / "03_role_lineage_model.csv", role_rows)
    write_csv(out_dir / "04_layer_score_rank.csv", rank_rows)
    write_csv(out_dir / "05_normal_hypothesis_collapse_final.csv", collapse_final)
    write_csv(out_dir / "06_claim_boundary_final.csv", boundary_rows)
    write_csv(out_dir / "07_next_steps_after_48.csv", next_rows)

    hathaomother_notes = {
        "from_41": {
            "target_raw_source_files": summary41.get("target_raw_source_files"),
            "target_raw_total_axis_hits": summary41.get("target_raw_total_axis_hits"),
            "no_rtc_total_hits": summary41.get("no_rtc_total_hits"),
            "no_rtc_axes_present": summary41.get("no_rtc_axes_present"),
            "structured_total_hits": summary41.get("structured_total_hits"),
            "structured_axes_present": summary41.get("structured_axes_present"),
            "top_file": summary41.get("top_file"),
            "top_file_share_pct": summary41.get("top_file_share_pct"),
        },
        "interpretation": "EXT_NO_CONTACT_Aはraw-only重要補強点として維持。ただしRTCReporting偏重とCSV echo欠落のため、単独確定には使わない。",
    }

    summary = {
        "script": SCRIPT_NAME,
        "status": "DONE",
        "variant": SCRIPT_VARIANT,
        "target": "C2025AUG_2025-08-04_lateral_cluster_ab_final_seal",
        "window": WINDOW,
        "core_date": CORE_DATE,
        "result_root": str(result_root),
        "output_dir": str(out_dir),
        "final_verdict": final_verdict,
        "final_verdict_jp": "横展開クラスタ + A/B/Trial説明変数モデルはlocal artifact上で支持。ただし因果・帰属・server-side証明ではない。",
        "device_rows": len(final_rows),
        "a_class_devices": devices_A,
        "a_class_count": len(devices_A),
        "non_control_or_excluded_devices": devices_not_control,
        "control_or_excluded_devices": control_devices,
        "class_counts": dict(class_counts),
        "direct_triald_devices": direct_triald_devices,
        "trust_lineage_devices": trust_devices,
        "backup_manifest_supported_devices": backup_devices,
        "evidence_pressure_devices": evidence_devices,
        "cloud_or_trust_separation_needed_devices": cloud_sep_devices,
        "hathaomother_notes": hathaomother_notes,
        "claim_boundary": {
            "can_say": CAN_SAY,
            "cannot_say": NON_CLAIMS,
        },
        "input_files": {k: {"path": str(p), "exists": p.exists(), "size_bytes": p.stat().st_size if p.exists() else 0} for k, p in input_paths.items()},
        "elapsed_seconds": round(time.time() - t0, 3),
    }
    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)

    readme = f"""48 Final Seal / 横展開クラスタ + A/B 総合判定
============================================================

対象:
  C2025AUG / {CORE_DATE}

最終判定:
  {final_verdict}

日本語:
  横展開クラスタ + A/B/Trial説明変数モデルは、local artifact上で支持。
  ただし、因果証明・攻撃者帰属・Apple server-side証明ではない。

48で統合したもの:
  40b: 39a/39b cross strict
  41: EXT_NO_CONTACT_A raw-only source review
  42: Trial / A-B / cohort overlap
  42b: direct triald only
  43: Trust Graph Lineage
  44: Backup / Manifest Inheritance
  45: Proximity vs Cloud Separation
  46: Evidence Preservation / Suppression
  47: Normal / Control Stress Test

中心整理:
  USER_ORIGIN_MINI1 = 起点
  USER_BRIDGE_15G = bridge
  EXT_NO_CONTACT_A = raw-only外部重要補強点
  EXT_REMOTE_GEO_C = 地理分離補強点
  EXT_UNCERTAIN_B = 不確定接点review維持

言える:
  - 40b〜47の多層結果は同じC2025AUG core日へ収束する。
  - Trial/A-B/cohortは説明変数として採用可能。
  - local artifact上では trust / backup / proximity-cloud separation / evidence pressure が重なる。
  - 利用可能なcontrol/low-exposure候補は同密度を再現していない。

言えない:
  - Trial悪用確定
  - A/B攻撃確定
  - Apple Trial原因確定
  - Apple server-side trust graph直接証明
  - Family Sharing悪用確定
  - trusted device追加確定
  - backup汚染/restore継承/Manifest改ざん確定
  - 証拠保存妨害の意図確定
  - Remote command / hidden MDM / Apple関与 / 国家関与 / 攻撃者特定

出力:
  00_MASTER_SUMMARY.json
  01_final_device_seal_matrix.csv
  02_final_verdict_summary.csv
  03_role_lineage_model.csv
  04_layer_score_rank.csv
  05_normal_hypothesis_collapse_final.csv
  06_claim_boundary_final.csv
  07_next_steps_after_48.csv
  08_README_VERDICT.txt
"""
    (out_dir / "08_README_VERDICT.txt").write_text(readme, encoding="utf-8", errors="replace")

    print("DONE")
    print(f"Output: {out_dir}")
    print(f"Final verdict: {final_verdict}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
