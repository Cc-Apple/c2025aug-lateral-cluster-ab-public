# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
45_proximity_vs_cloud_separation_review.py
NO-PANDAS版 / 標準ライブラリのみ。

目的:
  C2025AUG / 2025-08-04 の横展開クラスタについて、
  Proximity vs Cloud Separation を整理する。

見ること:
  - Wi-Fi / BSSID / RSSI / Channel / CommCenter / Baseband / power / network系の proximity痕跡
  - 既知の人間接点・端末接触・地理分離の前提
  - 43 Trust Graph Lineage と 44 Backup / Manifest Inheritance との重なり

重要境界:
  - BSSID/RSSIが直接残ることを保証するscriptではない。
  - cloud/trust graphを直接証明するscriptではない。
  - 物理接触説で説明できる部分と、説明が苦しい部分を分離するだけ。
  - 攻撃者、Apple関与、hidden MDM、Trial悪用、Family Sharing悪用は断定しない。

Default input:
  [RESULT_ROOT]\39b_rawlog_cluster_trial_audit
  [RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict
  [RESULT_ROOT]\43_trust_graph_lineage_review
  [RESULT_ROOT]\44_backup_manifest_inheritance_review

Output:
  [RESULT_ROOT]\45_proximity_vs_cloud_separation_review

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

CORE_DEVICE_ORDER = [
    "USER_ORIGIN_MINI1", "USER_BRIDGE_15G", "USER_DEVICE_12G", "USER_DEVICE_MINI2", "USER_DEVICE_11PRO",
    "EXT_UNCERTAIN_B", "EXT_NO_CONTACT_A", "EXT_CONTACT_D", "EXT_CONTACT_E_12PROMAX", "EXT_CONTACT_E_6SPLUS", "EXT_REMOTE_GEO_C",
]

ROLE_DEFAULT = {
    "USER_ORIGIN_MINI1": "ORIGIN_CORE",
    "USER_BRIDGE_15G": "BRIDGE_TO_LATER_JOKER",
    "USER_DEVICE_12G": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_MINI2": "USER_CLUSTER_SUPPORT",
    "USER_DEVICE_11PRO": "USER_CLUSTER_SUPPORT",
    "EXT_UNCERTAIN_B": "EXTERNAL_UNCERTAIN_NO_DIRECT_CONTACT_EXPECTED",
    "EXT_NO_CONTACT_A": "EXTERNAL_NO_CONTACT_CRITICAL",
    "EXT_CONTACT_D": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_12PROMAX": "EXTERNAL_CONTACT_KNOWN",
    "EXT_CONTACT_E_6SPLUS": "EXTERNAL_CONTACT_KNOWN",
    "EXT_REMOTE_GEO_C": "EXTERNAL_REMOTE_GEO_CONTACT",
}

CONTACT_MODEL = {
    "USER_ORIGIN_MINI1": {
        "contact_class": "USER_DEVICE_LOCAL_CONTEXT",
        "human_contact": "SELF",
        "device_contact": "SELF",
        "geo_status": "VN_USER_SIDE",
        "proximity_explanation_strength": "HIGH_FOR_USER_SIDE",
        "cloud_needed_level": "LOW_FOR_THIS_DEVICE_ALONE",
    },
    "USER_BRIDGE_15G": {
        "contact_class": "USER_DEVICE_LOCAL_CONTEXT",
        "human_contact": "SELF",
        "device_contact": "SELF",
        "geo_status": "VN_USER_SIDE",
        "proximity_explanation_strength": "HIGH_FOR_USER_SIDE",
        "cloud_needed_level": "LOW_FOR_THIS_DEVICE_ALONE",
    },
    "USER_DEVICE_12G": {
        "contact_class": "USER_DEVICE_LOCAL_CONTEXT",
        "human_contact": "SELF",
        "device_contact": "SELF",
        "geo_status": "USER_ECOSYSTEM_SIDE",
        "proximity_explanation_strength": "MEDIUM_HIGH_FOR_USER_DEVICE",
        "cloud_needed_level": "LOW_MEDIUM",
    },
    "USER_DEVICE_MINI2": {
        "contact_class": "USER_DEVICE_LOCAL_CONTEXT",
        "human_contact": "SELF",
        "device_contact": "SELF",
        "geo_status": "USER_ECOSYSTEM_SIDE",
        "proximity_explanation_strength": "MEDIUM_HIGH_FOR_USER_DEVICE",
        "cloud_needed_level": "LOW_MEDIUM",
    },
    "USER_DEVICE_11PRO": {
        "contact_class": "USER_DEVICE_LOCAL_CONTEXT",
        "human_contact": "SELF",
        "device_contact": "SELF",
        "geo_status": "USER_ECOSYSTEM_SIDE",
        "proximity_explanation_strength": "MEDIUM_HIGH_FOR_USER_DEVICE",
        "cloud_needed_level": "LOW_MEDIUM",
    },
    "EXT_CONTACT_D": {
        "contact_class": "EXTERNAL_KNOWN_CONTACT_DEVICE_CONTACT_POSSIBLE",
        "human_contact": "YES",
        "device_contact": "YES_OR_POSSIBLE",
        "geo_status": "VN_CONTACT_SIDE",
        "proximity_explanation_strength": "MEDIUM_POSSIBLE",
        "cloud_needed_level": "MEDIUM",
    },
    "EXT_CONTACT_E_12PROMAX": {
        "contact_class": "EXTERNAL_KNOWN_CONTACT_DEVICE_CONTACT_POSSIBLE",
        "human_contact": "YES",
        "device_contact": "YES_OR_POSSIBLE",
        "geo_status": "VN_CONTACT_SIDE",
        "proximity_explanation_strength": "MEDIUM_POSSIBLE",
        "cloud_needed_level": "MEDIUM",
    },
    "EXT_CONTACT_E_6SPLUS": {
        "contact_class": "EXTERNAL_KNOWN_CONTACT_DEVICE_CONTACT_POSSIBLE",
        "human_contact": "YES",
        "device_contact": "YES_OR_POSSIBLE",
        "geo_status": "VN_CONTACT_SIDE",
        "proximity_explanation_strength": "MEDIUM_POSSIBLE",
        "cloud_needed_level": "MEDIUM",
    },
    "EXT_REMOTE_GEO_C": {
        "contact_class": "EXTERNAL_REMOTE_GEO_NO_PHYSICAL_DEVICE_CONTACT_AT_TIME",
        "human_contact": "YES_CONTACTABLE",
        "device_contact": "NO_PHYSICAL_AT_2025_0804",
        "geo_status": "TH_WHILE_USER_VN",
        "proximity_explanation_strength": "LOW_FOR_PHYSICAL_PROXIMITY",
        "cloud_needed_level": "HIGH",
    },
    "EXT_UNCERTAIN_B": {
        "contact_class": "EXTERNAL_UNCERTAIN_OR_NO_DIRECT_CONTACT",
        "human_contact": "UNKNOWN_OR_NO_DIRECT_CONTACT",
        "device_contact": "UNCERTAIN_LOW",
        "geo_status": "UNKNOWN_EXPECTED_EXTERNAL",
        "proximity_explanation_strength": "LOW_MEDIUM_UNCERTAIN",
        "cloud_needed_level": "MEDIUM_HIGH",
    },
    "EXT_NO_CONTACT_A": {
        "contact_class": "EXTERNAL_NO_HUMAN_CONTACT_NO_DEVICE_CONTACT",
        "human_contact": "NO",
        "device_contact": "NO",
        "geo_status": "EXTERNAL_NO_DIRECT_CONTACT",
        "proximity_explanation_strength": "LOW",
        "cloud_needed_level": "HIGH",
    },
    "CONTROL_OR_GENERIC_EXTERNAL": {
        "contact_class": "GENERIC_EXTERNAL_LABEL_NOT_DECISION",
        "human_contact": "UNKNOWN",
        "device_contact": "UNKNOWN",
        "geo_status": "UNKNOWN",
        "proximity_explanation_strength": "NO_DECISION",
        "cloud_needed_level": "NO_DECISION",
    },
    "LOW_EXPOSURE_IPAD": {
        "contact_class": "LOW_EXPOSURE_OR_NO_CORE_DECISION",
        "human_contact": "SELF_OR_CONTROL",
        "device_contact": "SELF_OR_CONTROL",
        "geo_status": "LOW_EXPOSURE",
        "proximity_explanation_strength": "NO_CORE_DECISION",
        "cloud_needed_level": "NO_CORE_DECISION",
    },
}


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


def proximity_source_kind(path_s: str, source_root: str = "") -> str:
    low = str(path_s or "").lower().replace("\\", "/")
    if "wificonnectionquality" in low or "wifi" in low or "bssid" in low or "rssi" in low:
        return "wifi_bssid_rssi"
    if "commcenter" in low:
        return "commcenter"
    if "baseband" in low or "cellular" in low or "plmn" in low or "noservice" in low:
        return "baseband_cellular"
    if "log-power" in low or "power" in low or "battery" in low:
        return "power_radio_context"
    if "network" in low or "configd" in low or "symptomsd" in low:
        return "network_config"
    if "location" in low or "gps" in low:
        return "location_context"
    if "bluetooth" in low or "awdl" in low or "airdrop" in low or "rapportd" in low or "sharingd" in low:
        return "nearby_apple_connectivity"
    if "rtcreporting" in low or "rtc" in low:
        return "rtcr_context"
    if "analytics" in low:
        return "analytics_context"
    if "session" in low:
        return "session_context"
    return "other_proximity_context"


def parse_timestamp_from_path(path_s: str, fallback_date: str = "") -> Tuple[str, str]:
    s = str(path_s or "")
    m = re.search(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_]?([0-5]\d)[-_]?([0-5]\d)", s)
    if m:
        y, mo, d, hh, mi, ss = m.groups()
        date_s = f"{y}-{mo}-{d}"
        return date_s, f"{date_s} {hh}:{mi}:{ss}"
    date_s = normalize_date(s) or fallback_date
    return date_s, f"{date_s} 00:00:00" if date_s else ""


def row_get(row: Dict[str, str], *keys: str) -> str:
    for k in keys:
        if k in row and str(row.get(k, "")).strip() != "":
            return str(row.get(k, "")).strip()
    return ""


def load_40b_core(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / "04_2025_0804_core_cross.csv")
    out: Dict[str, Dict[str, str]] = {}
    for r in rows:
        dev = r.get("device", "")
        if dev:
            out[dev] = r
    return out


def load_43(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / "01_trust_graph_0804_device_matrix.csv")
    return {r.get("device", ""): r for r in rows if r.get("device")}


def load_44(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / "01_backup_manifest_0804_device_matrix.csv")
    return {r.get("device", ""): r for r in rows if r.get("device")}


def gather_proximity_sources(file_axis_csv: Path) -> Tuple[Dict[str, Dict], List[Dict], Dict[str, Dict[str, Dict]]]:
    rows, _ = read_csv_rows(file_axis_csv)
    per_dev = defaultdict(lambda: {
        "proximity_source_files_0804": set(),
        "proximity_source_hits_0804": 0,
        "proximity_kinds_0804": defaultdict(int),
        "window_source_files": set(),
        "window_source_hits": 0,
    })
    top_candidates: Dict[Tuple[str, str], Dict] = {}
    date_kind_map: Dict[str, Dict[str, Dict]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for r in rows:
        axis = str(r.get("axis", ""))
        if axis != "telecom_wifi_proximity":
            continue
        rel = r.get("relative_path", "")
        dev = normalize_device_from_path(rel, r.get("device_guess_from_path", ""))
        date_s = normalize_date(r.get("date_guess_from_path", "")) or parse_timestamp_from_path(rel)[0]
        if not date_s or not in_window(date_s):
            continue
        hits = to_int(r.get("hit_count", 0))
        kind = proximity_source_kind(rel, r.get("source_root_label", ""))
        ts_date, ts = parse_timestamp_from_path(rel, date_s)
        p = per_dev[dev]
        p["window_source_files"].add(rel)
        p["window_source_hits"] += hits
        date_kind_map[dev][date_s][kind] += hits

        if date_s == CORE_DATE:
            p["proximity_source_files_0804"].add(rel)
            p["proximity_source_hits_0804"] += hits
            p["proximity_kinds_0804"][kind] += hits
            key = (dev, rel)
            prev = top_candidates.get(key)
            if prev:
                prev["hit_count"] += hits
            else:
                top_candidates[key] = {
                    "device": dev,
                    "date": date_s,
                    "timestamp_guess": ts,
                    "source_kind": kind,
                    "hit_count": hits,
                    "relative_path": rel,
                    "source_root_label": r.get("source_root_label", ""),
                }

    top_rows = sorted(top_candidates.values(), key=lambda x: (x["device"], -to_int(x["hit_count"]), x["relative_path"]))
    return per_dev, top_rows, date_kind_map


def classify_device(dev: str, core: Dict[str, str], trust: Dict[str, str], backup: Dict[str, str], prox: Dict) -> Tuple[str, float, str]:
    model = CONTACT_MODEL.get(dev, {})
    contact_class = model.get("contact_class", "UNKNOWN")
    final_tier = core.get("final_tier", core.get("final_tier_40b", ""))
    raw_axes = to_int(core.get("raw_axes_present", 0))
    raw_total = to_int(core.get("raw_total_axis_hits", 0))
    raw_prox = to_int(core.get("raw_telecom_wifi_proximity", trust.get("raw_telecom_wifi_proximity", 0)))
    prox_hits = int(prox.get("proximity_source_hits_0804", 0))
    kind_count = len(prox.get("proximity_kinds_0804", {}))
    trust_score = to_float(trust.get("trust_lineage_score", 0))
    backup_score = to_float(backup.get("inheritance_shadow_score", 0))
    triald = str(trust.get("triald_direct_0804", "")).upper() == "YES"

    score = 0.0
    score += log_score(raw_prox or prox_hits, 7.0)
    score += kind_count * 2.5
    score += min(trust_score, 60.0) * 0.30
    score += min(backup_score, 70.0) * 0.15
    score += raw_axes * 1.5
    score += log_score(raw_total, 2.5)
    if triald:
        score += 3.0
    if dev in ("EXT_NO_CONTACT_A", "EXT_REMOTE_GEO_C"):
        score += 10.0
    elif dev == "EXT_UNCERTAIN_B":
        score += 6.0
    elif dev in ("CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD"):
        score -= 30.0

    reason_bits = []
    if raw_prox or prox_hits:
        reason_bits.append("proximity_artifact_present")
    if trust.get("trust_lineage_verdict"):
        reason_bits.append("trust_lineage_overlay")
    if backup.get("backup_manifest_verdict"):
        reason_bits.append("backup_manifest_overlay")
    if triald:
        reason_bits.append("triald_direct_overlay")
    reason_bits.append(contact_class)

    if dev in ("CONTROL_OR_GENERIC_EXTERNAL", "LOW_EXPOSURE_IPAD") or not final_tier or final_tier.startswith("D_"):
        verdict = "E_NO_PROXIMITY_CLOUD_DECISION"
    elif dev == "EXT_NO_CONTACT_A":
        verdict = "A_CLOUD_TRUST_SEPARATION_STRONG_NO_DIRECT_CONTACT"
    elif dev == "EXT_REMOTE_GEO_C":
        verdict = "A_CLOUD_TRUST_SEPARATION_STRONG_REMOTE_GEO"
    elif dev == "EXT_UNCERTAIN_B":
        verdict = "B_CLOUD_TRUST_SEPARATION_REVIEW_UNCERTAIN_CONTACT"
    elif dev in ("EXT_CONTACT_D", "EXT_CONTACT_E_12PROMAX", "EXT_CONTACT_E_6SPLUS"):
        verdict = "C_PROXIMITY_POSSIBLE_BUT_TRUST_BACKUP_OVERLAP"
    elif dev in ("USER_ORIGIN_MINI1", "USER_BRIDGE_15G", "USER_DEVICE_12G", "USER_DEVICE_MINI2", "USER_DEVICE_11PRO"):
        verdict = "C_USER_DEVICE_LOCAL_OR_TRUST_CONTEXT"
    else:
        verdict = "D_WEAK_OR_GENERIC_CONTEXT"
    return verdict, round(score, 3), ";".join(reason_bits)


def main() -> int:
    ap = argparse.ArgumentParser(description="45 Proximity vs Cloud Separation Review / no pandas")
    ap.add_argument("--in39b", default=r"[RESULT_ROOT]\39b_rawlog_cluster_trial_audit")
    ap.add_argument("--in40b", default=r"[RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict")
    ap.add_argument("--in43", default=r"[RESULT_ROOT]\43_trust_graph_lineage_review")
    ap.add_argument("--in44", default=r"[RESULT_ROOT]\44_backup_manifest_inheritance_review")
    ap.add_argument("--out", default=r"[RESULT_ROOT]\45_proximity_vs_cloud_separation_review")
    args = ap.parse_args()

    in39b = Path(args.in39b)
    in40b = Path(args.in40b)
    in43 = Path(args.in43)
    in44 = Path(args.in44)
    out = Path(args.out)
    ensure_dir(out)

    input_rows = [
        {"name": "in39b", "path": str(in39b), "exists": str(in39b.exists())},
        {"name": "in40b", "path": str(in40b), "exists": str(in40b.exists())},
        {"name": "in43", "path": str(in43), "exists": str(in43.exists())},
        {"name": "in44", "path": str(in44), "exists": str(in44.exists())},
        {"name": "out", "path": str(out), "exists": "CREATED"},
    ]
    write_csv(out / "00_input_paths.csv", input_rows)

    core40 = load_40b_core(in40b)
    trust43 = load_43(in43)
    backup44 = load_44(in44)
    prox_per_dev, prox_top_rows_all, date_kind_map = gather_proximity_sources(in39b / "39b_file_axis_counts.csv")

    all_devices = []
    for d in CORE_DEVICE_ORDER + sorted(set(core40) | set(trust43) | set(backup44) | set(prox_per_dev)):
        if d and d not in all_devices:
            all_devices.append(d)

    device_rows: List[Dict] = []
    for dev in all_devices:
        core = core40.get(dev, {})
        trust = trust43.get(dev, {})
        backup = backup44.get(dev, {})
        prox = prox_per_dev.get(dev, {})
        model = CONTACT_MODEL.get(dev, {})
        verdict, score, reason = classify_device(dev, core, trust, backup, prox)
        kinds = prox.get("proximity_kinds_0804", {}) or {}
        row = {
            "device": dev,
            "date": CORE_DATE,
            "role": core.get("role", ROLE_DEFAULT.get(dev, "UNKNOWN")),
            "contact_class": model.get("contact_class", "UNKNOWN"),
            "human_contact": model.get("human_contact", "UNKNOWN"),
            "device_contact": model.get("device_contact", "UNKNOWN"),
            "geo_status": model.get("geo_status", "UNKNOWN"),
            "proximity_explanation_strength": model.get("proximity_explanation_strength", "UNKNOWN"),
            "cloud_needed_level": model.get("cloud_needed_level", "UNKNOWN"),
            "proximity_cloud_verdict": verdict,
            "separation_score": score,
            "reason_flags": reason,
            "final_tier_40b": core.get("final_tier", ""),
            "support_class_40b": core.get("support_class", ""),
            "trust_lineage_verdict_43": trust.get("trust_lineage_verdict", ""),
            "backup_manifest_verdict_44": backup.get("backup_manifest_verdict", ""),
            "triald_direct_0804_from43": trust.get("triald_direct_0804", ""),
            "first_triald_direct_ts_0804_from43": trust.get("first_triald_direct_ts_0804", ""),
            "raw_telecom_wifi_proximity_from40b": core.get("raw_telecom_wifi_proximity", trust.get("raw_telecom_wifi_proximity", "0")),
            "proximity_source_hits_39b_0804": int(prox.get("proximity_source_hits_0804", 0)),
            "proximity_source_files_39b_0804": len(prox.get("proximity_source_files_0804", set())),
            "proximity_source_kind_count_0804": len(kinds),
            "wifi_bssid_rssi_hits_0804": int(kinds.get("wifi_bssid_rssi", 0)),
            "commcenter_hits_0804": int(kinds.get("commcenter", 0)),
            "baseband_cellular_hits_0804": int(kinds.get("baseband_cellular", 0)),
            "power_radio_context_hits_0804": int(kinds.get("power_radio_context", 0)),
            "network_config_hits_0804": int(kinds.get("network_config", 0)),
            "nearby_apple_connectivity_hits_0804": int(kinds.get("nearby_apple_connectivity", 0)),
            "rtcr_context_hits_0804": int(kinds.get("rtcr_context", 0)),
            "claim_boundary": "separation_model_not_cloud_server_or_physical_contact_proof",
        }
        device_rows.append(row)

    device_rows.sort(key=lambda r: (str(r["proximity_cloud_verdict"]), -to_float(r["separation_score"]), r["device"]))
    write_csv(out / "01_proximity_cloud_0804_device_matrix.csv", device_rows)

    # top source files per device
    top_rows: List[Dict] = []
    by_dev = defaultdict(list)
    for r in prox_top_rows_all:
        by_dev[r["device"]].append(r)
    for dev in all_devices:
        dev_rows = sorted(by_dev.get(dev, []), key=lambda x: -to_int(x.get("hit_count")))[:10]
        for rank, r in enumerate(dev_rows, 1):
            rr = dict(r)
            rr["rank_in_device"] = rank
            top_rows.append(rr)
    write_csv(out / "02_proximity_source_files_top10_per_device.csv", top_rows)

    contact_rows = []
    for dev in all_devices:
        model = CONTACT_MODEL.get(dev, {})
        contact_rows.append({
            "device": dev,
            "role": core40.get(dev, {}).get("role", ROLE_DEFAULT.get(dev, "UNKNOWN")),
            "contact_class": model.get("contact_class", "UNKNOWN"),
            "human_contact": model.get("human_contact", "UNKNOWN"),
            "device_contact": model.get("device_contact", "UNKNOWN"),
            "geo_status": model.get("geo_status", "UNKNOWN"),
            "proximity_explanation_strength": model.get("proximity_explanation_strength", "UNKNOWN"),
            "cloud_needed_level": model.get("cloud_needed_level", "UNKNOWN"),
            "notes": {
                "EXT_NO_CONTACT_A": "no human/contact/device contact premise; raw-only critical",
                "EXT_REMOTE_GEO_C": "contactable person but physical device contact not possible at 2025-08-04 because TH vs VN premise",
                "EXT_UNCERTAIN_B": "uncertain; expected external and low direct contact",
                "EXT_CONTACT_D": "known human/device contact; physical explanation remains possible",
                "EXT_CONTACT_E_12PROMAX": "known contact; physical explanation remains possible",
                "EXT_CONTACT_E_6SPLUS": "known contact; physical explanation remains possible",
            }.get(dev, ""),
        })
    write_csv(out / "03_contact_separation_matrix.csv", contact_rows)

    overlap_rows = []
    for r in device_rows:
        overlap_rows.append({
            "device": r["device"],
            "role": r["role"],
            "proximity_cloud_verdict": r["proximity_cloud_verdict"],
            "separation_score": r["separation_score"],
            "final_tier_40b": r["final_tier_40b"],
            "trust_lineage_verdict_43": r["trust_lineage_verdict_43"],
            "backup_manifest_verdict_44": r["backup_manifest_verdict_44"],
            "triald_direct_0804_from43": r["triald_direct_0804_from43"],
            "proximity_source_files_39b_0804": r["proximity_source_files_39b_0804"],
            "proximity_source_kind_count_0804": r["proximity_source_kind_count_0804"],
            "physical_explanation": r["proximity_explanation_strength"],
            "cloud_needed_level": r["cloud_needed_level"],
        })
    write_csv(out / "04_proximity_trust_backup_overlap_matrix.csv", overlap_rows)

    # sequence-like rows from top sources and triald timestamp for context.
    sequence_rows = []
    for r in device_rows:
        dev = r["device"]
        first_src_ts = ""
        if by_dev.get(dev):
            first_src_ts = sorted(by_dev[dev], key=lambda x: str(x.get("timestamp_guess", "")))[0].get("timestamp_guess", "")
        sequence_rows.append({
            "device": dev,
            "role": r["role"],
            "first_proximity_source_ts_0804_guess": first_src_ts,
            "first_triald_direct_ts_0804_from43": r["first_triald_direct_ts_0804_from43"],
            "proximity_cloud_verdict": r["proximity_cloud_verdict"],
            "contact_class": r["contact_class"],
            "trust_lineage_verdict_43": r["trust_lineage_verdict_43"],
            "backup_manifest_verdict_44": r["backup_manifest_verdict_44"],
        })
    sequence_rows.sort(key=lambda r: (r.get("first_proximity_source_ts_0804_guess") or "9999", r["device"]))
    write_csv(out / "05_sequence_proximity_cloud_0804.csv", sequence_rows)

    notes = [
        {
            "note_type": "CAN_SAY",
            "content": "C2025AUG core日に、proximity系artifactとtrust/backup overlapを分離して評価できる。",
        },
        {
            "note_type": "CAN_SAY",
            "content": "EXT_NO_CONTACT_A / EXT_REMOTE_GEO_C / EXT_UNCERTAIN_B は、単純な物理接触説明では苦しい側として優先review対象に残る。",
        },
        {
            "note_type": "CAN_SAY",
            "content": "EXT_CONTACT_D / EXT_CONTACT_E系は既知接触があるため、物理説明を完全排除せず、trust/backup重なりのsupport扱いにする。",
        },
        {
            "note_type": "CANNOT_SAY",
            "content": "cloud/trust graph伝播、Family Sharing悪用、trusted device追加、Apple server-side状態を直接証明したとは言わない。",
        },
        {
            "note_type": "CANNOT_SAY",
            "content": "BSSID/RSSI同一、物理近接、攻撃者接近をこのscriptだけで断定しない。",
        },
        {
            "note_type": "NEXT",
            "content": "46 Evidence Preservation / Suppression Modelへ進み、保存妨害構造を見る。",
        },
    ]
    write_csv(out / "06_claim_boundary_notes.csv", notes)

    verdict_counts = defaultdict(int)
    for r in device_rows:
        verdict_counts[r["proximity_cloud_verdict"]] += 1

    high_cloud = [r["device"] for r in device_rows if str(r["proximity_cloud_verdict"]).startswith("A_CLOUD")]
    review_cloud = [r["device"] for r in device_rows if str(r["proximity_cloud_verdict"]).startswith("B_CLOUD")]
    physical_possible = [r["device"] for r in device_rows if str(r["proximity_cloud_verdict"]).startswith("C_")]

    summary = {
        "status": "DONE",
        "variant": "NO_PANDAS_STD_LIB_ONLY",
        "target_window": f"{TARGET_START}..{TARGET_END}",
        "core_date": CORE_DATE,
        "final_verdict": "PROXIMITY_CLOUD_SEPARATION_SUPPORTED_NOT_SERVER_SIDE_PROOF",
        "device_rows": len(device_rows),
        "proximity_source_top_rows": len(top_rows),
        "contact_rows": len(contact_rows),
        "overlap_rows": len(overlap_rows),
        "sequence_rows": len(sequence_rows),
        "verdict_counts": dict(verdict_counts),
        "high_cloud_separation_devices": high_cloud,
        "cloud_review_devices": review_cloud,
        "physical_or_local_possible_devices": physical_possible,
        "important_boundary": [
            "physical proximity explanation is separated, not disproven globally",
            "cloud/trust graph is inferred from local artifact overlap, not server-side proof",
            "no attribution / no hidden MDM / no Apple involvement claim",
        ],
        "input_paths": input_rows,
    }
    write_json(out / "00_MASTER_SUMMARY.json", summary)

    readme = f"""45 Proximity vs Cloud Separation Review
============================================================

Final verdict:
  {summary['final_verdict']}

Meaning:
  C2025AUG / 2025-08-04 について、物理接触・同一Wi-Fiで説明しやすい端末と、cloud/trust graph側の説明が必要になる端末を分離した。

High cloud/trust separation:
  {', '.join(high_cloud) if high_cloud else '(none)'}

Cloud/trust review:
  {', '.join(review_cloud) if review_cloud else '(none)'}

Physical/local explanation still possible:
  {', '.join(physical_possible) if physical_possible else '(none)'}

Claim boundary:
  - Apple server-side trust graph の直接証明ではない。
  - Family Sharing / trusted device 追加の直接証明ではない。
  - BSSID/RSSI同一や物理接近を断定しない。
  - proximity artifact と trust/backup overlap を分離整理するscript。

Next:
  46 Evidence Preservation / Suppression Model
"""
    (out / "07_README_VERDICT.txt").write_text(readme, encoding="utf-8")

    print("DONE")
    print(f"Output: {out}")
    print(f"Final verdict: {summary['final_verdict']}")
    print(f"device_rows: {len(device_rows)}")
    print(f"high_cloud_separation_devices: {', '.join(high_cloud) if high_cloud else '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
