# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

# -*- coding: utf-8 -*-
r"""
42_trial_ab_cohort_source_review.py

目的:
  39a / 39b / 40b の結果だけを使い、C2025AUG / 2025-08-04 の
  Trial / A-B / cohort 系が、横展開クラスタの core 日にどの程度重なるかを確認する。

重要:
  - これは raw 1年分ログを読まない。
  - 39b_file_axis_counts.csv と 40b の core 結果を主に読む。
  - 39b_raw_marker_hits.csv が存在する場合だけ、sample行を限定抽出する。
  - Trial / A-B を攻撃基盤と断定しない。
  - cohort差分 / 発火条件 / feature flag 的な説明変数として扱う。

既定入力:
  [RESULT_ROOT]\39a_csv_result_cluster_trial_audit
  [RESULT_ROOT]\39b_rawlog_cluster_trial_audit
  [RESULT_ROOT]\40b_c2025aug_39a39b_cross_strict

既定出力:
  [RESULT_ROOT]\42_trial_ab_cohort_source_review

実行:
  python 42_trial_ab_cohort_source_review.py
  python 42_trial_ab_cohort_source_review.py <Result_root>
  python 42_trial_ab_cohort_source_review.py <39a_dir> <39b_dir> <40b_dir> <out_dir>

安全:
  input read-only. delete / move / rename / edit なし。
"""

import csv
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_RESULT_ROOT = Path(r"[RESULT_ROOT]")
DEFAULT_39A_DIR = DEFAULT_RESULT_ROOT / "39a_csv_result_cluster_trial_audit"
DEFAULT_39B_DIR = DEFAULT_RESULT_ROOT / "39b_rawlog_cluster_trial_audit"
DEFAULT_40B_DIR = DEFAULT_RESULT_ROOT / "40b_c2025aug_39a39b_cross_strict"
DEFAULT_OUT_DIR = DEFAULT_RESULT_ROOT / "42_trial_ab_cohort_source_review"

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

TRIAL_KEYWORDS = [
    "triald",
    "com.apple.trial",
    "trial",
    "proactive_event_tracker",
    "experiment",
    "treatment",
    "rollout",
    "eligibility",
    "deployment",
    "factor",
    "asset",
    "cohort",
    "app_cohort",
    "beta",
    "abtest",
    "a/b",
]

DATE_RE = re.compile(r"(20\d{2})[-_/\.](\d{1,2})[-_/\.](\d{1,2})")
TIME_RE = re.compile(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})(\d{2})(\d{2})")


def mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_int(x, default=0):
    try:
        return int(float(str(x).strip() or "0"))
    except Exception:
        return default


def safe_float(x, default=0.0):
    try:
        return float(str(x).strip() or "0")
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


def detect_time_from_path(rel_path: str) -> str:
    p = norm_path(rel_path)
    m = TIME_RE.search(p)
    if not m:
        return ""
    try:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)}:{m.group(6)}"
    except Exception:
        return ""


def detect_device_from_path(rel_path: str, fallback: str = "UNKNOWN") -> str:
    p = norm_path(rel_path)
    low = p.lower()

    # Mother must be checked before generic EXT_CONTACT_D.
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


def file_kind(rel_path: str) -> str:
    low = norm_path(rel_path).lower()
    base = low.split("/")[-1]
    if "proactive_event_tracker" in low or "triald" in low or "com_apple_trial" in low or "com.apple.trial" in low:
        return "triald_direct"
    if "analytics" in base:
        return "analytics"
    if "log-power" in base or base.endswith(".session"):
        return "power_session"
    if "rtc" in low or "rtcreporting" in low:
        return "rtc_reporting"
    if "jetsam" in base:
        return "jetsam"
    if "cpu_resource" in base or "signpost" in base:
        return "cpu_resource"
    if "wifi" in base:
        return "wifi_quality"
    if "sfa" in base or "ckks" in base or "cloudservices" in base:
        return "sfa_cloud"
    if "commcenter" in base or "baseband" in base:
        return "commcenter_baseband"
    if base.endswith(".ips") or ".ips." in base:
        return "ips_other"
    if base.endswith(".json"):
        return "json_other"
    return "other"


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


def write_text(path: Path, text: str) -> None:
    mkdir(path.parent)
    path.write_text(text, encoding="utf-8")


def resolve_paths(argv):
    if len(argv) >= 5:
        return Path(argv[1]), Path(argv[2]), Path(argv[3]), Path(argv[4])
    if len(argv) == 2:
        root = Path(argv[1])
        return (
            root / "39a_csv_result_cluster_trial_audit",
            root / "39b_rawlog_cluster_trial_audit",
            root / "40b_c2025aug_39a39b_cross_strict",
            root / "42_trial_ab_cohort_source_review",
        )
    return DEFAULT_39A_DIR, DEFAULT_39B_DIR, DEFAULT_40B_DIR, DEFAULT_OUT_DIR


def find_marker_hits_file(result_root: Path, dir39b: Path) -> Path:
    candidates = [
        dir39b / "39b_raw_marker_hits.csv",
        dir39b.parent / "39b_raw_marker_hits.csv",
        dir39b.parent / "39b_raw_marker_hits" / "39b_raw_marker_hits.csv",
        result_root / "39b_raw_marker_hits.csv",
        result_root / "39b_raw_marker_hits" / "39b_raw_marker_hits.csv",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return c
    return Path("")


def load_40b_core(dir40b: Path):
    path = dir40b / "04_2025_0804_core_cross.csv"
    core = {}
    if not path.exists():
        return core
    for r in read_csv_rows(path):
        dev = r.get("device") or "UNKNOWN"
        core[dev] = r
    return core


def load_axis_counts(path: Path, source_label: str):
    rows = []
    if not path.exists():
        return rows
    for r in read_csv_rows(path):
        rel = r.get("relative_path", "")
        dev = detect_device_from_path(rel, r.get("device_guess_from_path") or r.get("device_guess") or "UNKNOWN")
        date = detect_date_from_path(rel, r.get("date_guess_from_path") or r.get("date_guess") or "")
        axis = r.get("axis", "")
        hit = safe_int(r.get("hit_count", 0))
        rows.append({
            "source": source_label,
            "device": dev,
            "date": date,
            "axis": axis,
            "hit_count": hit,
            "relative_path": rel,
            "source_root_label": r.get("source_root_label", ""),
            "time_from_filename": detect_time_from_path(rel),
            "file_kind": file_kind(rel),
        })
    return rows


def verdict_trial(row):
    raw_trial = safe_int(row.get("raw_trial_ab", 0))
    csv_trial = safe_int(row.get("csv_trial_ab", 0))
    direct_files = safe_int(row.get("triald_direct_file_count", 0))
    trial_files = safe_int(row.get("raw_trial_source_file_count", 0))
    raw_total = safe_int(row.get("raw_total_axis_hits", 0))
    share = safe_float(row.get("raw_trial_share_pct", 0.0))
    tier = row.get("final_tier", "")

    if raw_trial <= 0 and csv_trial <= 0:
        return "NO_TRIAL_SUPPORT"
    if tier.startswith("A_") and raw_trial > 0 and csv_trial > 0 and direct_files > 0:
        return "A_TRIAL_COHORT_STRONG_OVERLAP"
    if tier.startswith("A_") and raw_trial > 0 and direct_files > 0:
        return "B_RAW_TRIAL_DIRECT_OVERLAP"
    if tier.startswith("A_") and raw_trial > 0 and csv_trial > 0:
        return "B_RAW_CSV_TRIAL_OVERLAP"
    if raw_trial > 0 and trial_files > 0:
        return "C_RAW_TRIAL_PRESENT_WEAK_CONTEXT"
    if csv_trial > 0 and raw_trial == 0:
        return "D_CSV_ONLY_TRIAL_NOT_DECISION"
    if share > 25:
        return "D_TRIAL_RATIO_HIGH_BUT_SOURCE_WEAK"
    return "D_WEAK_OR_GENERIC_TRIAL"


def main():
    t0 = time.time()
    dir39a, dir39b, dir40b, out_dir = resolve_paths(sys.argv)
    result_root = dir39b.parent
    mkdir(out_dir)

    input_rows = [
        {"name": "39a_dir", "path": str(dir39a), "exists": dir39a.exists()},
        {"name": "39b_dir", "path": str(dir39b), "exists": dir39b.exists()},
        {"name": "40b_dir", "path": str(dir40b), "exists": dir40b.exists()},
        {"name": "out_dir", "path": str(out_dir), "exists": out_dir.exists()},
    ]
    write_csv(out_dir / "00_input_paths.csv", input_rows, ["name", "path", "exists"])

    core = load_40b_core(dir40b)

    raw_axis_path = dir39b / "39b_file_axis_counts.csv"
    csv_axis_path = dir39a / "39a_file_axis_counts.csv"
    raw_rows = load_axis_counts(raw_axis_path, "39b_raw")
    csv_rows = load_axis_counts(csv_axis_path, "39a_csv")

    # Focus raw/csv rows.
    raw_focus = [r for r in raw_rows if in_focus_window(r["date"])]
    csv_focus = [r for r in csv_rows if in_focus_window(r["date"])]
    raw_0804 = [r for r in raw_rows if r["date"] == CORE_DATE]
    csv_0804 = [r for r in csv_rows if r["date"] == CORE_DATE]

    # Raw trial source files on 2025-08-04.
    raw_trial_0804 = [r for r in raw_0804 if r["axis"] == "trial_ab"]
    trial_by_dev = defaultdict(list)
    for r in raw_trial_0804:
        trial_by_dev[r["device"]].append(r)

    # All axes by device for 0804 from raw.
    raw_counts = defaultdict(Counter)
    raw_files_by_dev_axis = defaultdict(set)
    for r in raw_0804:
        raw_counts[r["device"]][r["axis"]] += r["hit_count"]
        raw_files_by_dev_axis[(r["device"], r["axis"])].add(r["relative_path"])

    csv_counts = defaultdict(Counter)
    for r in csv_0804:
        csv_counts[r["device"]][r["axis"]] += r["hit_count"]

    # Per device core matrix.
    matrix = []
    device_set = set(core.keys()) | set(raw_counts.keys()) | set(csv_counts.keys())
    def dev_sort_key(d):
        return (DEVICE_ORDER.index(d) if d in DEVICE_ORDER else 999, d)

    for dev in sorted(device_set, key=dev_sort_key):
        c40 = core.get(dev, {})
        # Prefer 40b cross-strict values when present because 39a support is already normalized there.
        raw_trial_local = raw_counts[dev]["trial_ab"]
        csv_trial_local = csv_counts[dev]["trial_ab"]
        raw_total_local = sum(raw_counts[dev].values())
        csv_total_local = sum(csv_counts[dev].values())
        raw_trial = safe_int(c40.get("raw_trial_ab", raw_trial_local)) if c40 else raw_trial_local
        csv_trial = safe_int(c40.get("csv_trial_ab", csv_trial_local)) if c40 else csv_trial_local
        raw_total = safe_int(c40.get("raw_total_axis_hits", raw_total_local)) if c40 else raw_total_local
        csv_total = safe_int(c40.get("csv_total_hits", csv_total_local)) if c40 else csv_total_local
        trial_files = trial_by_dev.get(dev, [])
        direct_count = sum(1 for r in trial_files if r["file_kind"] == "triald_direct")
        direct_hits = sum(r["hit_count"] for r in trial_files if r["file_kind"] == "triald_direct")
        file_kind_counts = Counter(r["file_kind"] for r in trial_files)
        top_files = sorted(trial_files, key=lambda x: x["hit_count"], reverse=True)[:5]
        row = {
            "device": dev,
            "date": CORE_DATE,
            "role": c40.get("role", ROLE_MAP.get(dev, "UNKNOWN")),
            "final_tier": c40.get("final_tier", "NO_40B_CORE_ROW"),
            "support_class": c40.get("support_class", ""),
            "raw_trial_ab": raw_trial,
            "csv_trial_ab": csv_trial,
            "raw_total_axis_hits": raw_total,
            "csv_total_hits": csv_total,
            "raw_trial_share_pct": round((raw_trial / raw_total * 100.0), 3) if raw_total else 0.0,
            "csv_trial_share_pct": round((csv_trial / csv_total * 100.0), 3) if csv_total else 0.0,
            "raw_trial_source_file_count": len({r["relative_path"] for r in trial_files}),
            "triald_direct_file_count": direct_count,
            "triald_direct_hits": direct_hits,
            "trial_file_kind_counts": ";".join(f"{k}:{v}" for k, v in sorted(file_kind_counts.items())),
            "top_trial_files": " | ".join(f"{r['hit_count']}:{r['relative_path']}" for r in top_files),
        }
        row["trial_overlap_verdict"] = verdict_trial(row)
        matrix.append(row)

    write_csv(out_dir / "01_trial_0804_device_matrix.csv", matrix, [
        "device", "date", "role", "final_tier", "support_class",
        "trial_overlap_verdict", "raw_trial_ab", "csv_trial_ab",
        "raw_total_axis_hits", "csv_total_hits",
        "raw_trial_share_pct", "csv_trial_share_pct",
        "raw_trial_source_file_count", "triald_direct_file_count", "triald_direct_hits",
        "trial_file_kind_counts", "top_trial_files",
    ])

    # Source file table.
    source_file_rows = []
    for dev, rows in trial_by_dev.items():
        for r in sorted(rows, key=lambda x: x["hit_count"], reverse=True):
            source_file_rows.append({
                "device": dev,
                "date": r["date"],
                "hit_count": r["hit_count"],
                "file_kind": r["file_kind"],
                "time_from_filename": r["time_from_filename"],
                "relative_path": r["relative_path"],
                "source_root_label": r["source_root_label"],
            })
    write_csv(out_dir / "02_trial_0804_source_files.csv", source_file_rows, [
        "device", "date", "hit_count", "file_kind", "time_from_filename", "relative_path", "source_root_label"
    ])

    # Window timeline: raw trial hits by device/date and direct triald count.
    timeline_counts = defaultdict(Counter)
    timeline_files = defaultdict(set)
    timeline_direct_files = defaultdict(set)
    for r in raw_focus:
        if r["axis"] != "trial_ab":
            continue
        key = (r["device"], r["date"])
        timeline_counts[key]["raw_trial_ab"] += r["hit_count"]
        timeline_files[key].add(r["relative_path"])
        if r["file_kind"] == "triald_direct":
            timeline_direct_files[key].add(r["relative_path"])
    timeline_rows = []
    for (dev, date), cnt in sorted(timeline_counts.items(), key=lambda kv: (kv[0][1], dev_sort_key(kv[0][0]))):
        timeline_rows.append({
            "device": dev,
            "date": date,
            "role": ROLE_MAP.get(dev, "UNKNOWN"),
            "raw_trial_ab": cnt["raw_trial_ab"],
            "trial_source_file_count": len(timeline_files[(dev, date)]),
            "triald_direct_file_count": len(timeline_direct_files[(dev, date)]),
            "is_core_date": "YES" if date == CORE_DATE else "NO",
        })
    write_csv(out_dir / "03_trial_window_timeline_2025_0801_0810.csv", timeline_rows, [
        "device", "date", "role", "raw_trial_ab", "trial_source_file_count", "triald_direct_file_count", "is_core_date"
    ])

    # File-kind breakdown.
    fk_rows = []
    fk_counter = defaultdict(Counter)
    fk_hits = defaultdict(Counter)
    for r in raw_trial_0804:
        key = r["device"]
        fk_counter[key][r["file_kind"]] += 1
        fk_hits[key][r["file_kind"]] += r["hit_count"]
    for dev in sorted(fk_counter.keys(), key=dev_sort_key):
        for kind in sorted(fk_counter[dev]):
            fk_rows.append({
                "device": dev,
                "file_kind": kind,
                "source_file_rows": fk_counter[dev][kind],
                "hit_count": fk_hits[dev][kind],
            })
    write_csv(out_dir / "04_trial_file_kind_breakdown_0804.csv", fk_rows, [
        "device", "file_kind", "source_file_rows", "hit_count"
    ])

    # Optional marker samples.
    # 39b_raw_marker_hits.csv can be very large. Do NOT parse every CSV row.
    # First perform cheap line filtering, then parse only candidate lines.
    marker_path = find_marker_hits_file(result_root, dir39b)
    sample_rows = []
    keyword_rows = []
    marker_scanned = 0
    marker_candidate_lines = 0
    marker_matched = 0
    keyword_counts = defaultdict(Counter)
    per_dev_sample_limit = 40
    sample_count_dev = Counter()

    scan_marker = ("--scan-marker" in sys.argv) or (os.environ.get("SCAN_MARKER", "").strip() == "1")
    marker_skipped_reason = ""
    if marker_path and marker_path.exists() and not scan_marker:
        marker_skipped_reason = "skipped_by_default_large_optional_marker_scan; set SCAN_MARKER=1 or add --scan-marker to parse"
    if marker_path and marker_path.exists() and scan_marker:
        date_tokens = ["2025-08-04", "/2025/08/4/", "/2025/08/04/", "/08/4/", "/08/04/"]
        with marker_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
            header_line = f.readline()
            marker_scanned += 1
            try:
                header = next(csv.reader([header_line]))
            except Exception:
                header = ["source_root_label", "relative_path", "line_no", "device_guess", "date_guess", "axes", "sample"]
            for line in f:
                marker_scanned += 1
                # Cheap string filter first. This keeps 559MB marker files usable.
                if "trial_ab" not in line:
                    continue
                norm_line = line.replace("\\", "/")
                if not any(tok in norm_line for tok in date_tokens):
                    continue
                marker_candidate_lines += 1
                try:
                    vals = next(csv.reader([line]))
                except Exception:
                    continue
                if len(vals) < len(header):
                    vals += [""] * (len(header) - len(vals))
                row = dict(zip(header, vals))
                axes = str(row.get("axes", ""))
                if "trial_ab" not in axes:
                    continue
                rel = row.get("relative_path", "")
                date = detect_date_from_path(rel, row.get("date_guess", ""))
                if date != CORE_DATE:
                    continue
                dev = detect_device_from_path(rel, row.get("device_guess", "UNKNOWN"))
                sample = str(row.get("sample", ""))[:600]
                low_sample = sample.lower()
                marker_matched += 1
                for kw in TRIAL_KEYWORDS:
                    if kw.lower() in low_sample or kw.lower() in norm_path(rel).lower():
                        keyword_counts[dev][kw] += 1
                if sample_count_dev[dev] < per_dev_sample_limit:
                    sample_count_dev[dev] += 1
                    sample_rows.append({
                        "device": dev,
                        "date": date,
                        "line_no": row.get("line_no", ""),
                        "axes": axes,
                        "source_root_label": row.get("source_root_label", ""),
                        "relative_path": rel,
                        "sample": sample,
                    })

    for dev in sorted(keyword_counts.keys(), key=dev_sort_key):
        total = sum(keyword_counts[dev].values())
        for kw in TRIAL_KEYWORDS:
            if keyword_counts[dev][kw]:
                keyword_rows.append({
                    "device": dev,
                    "keyword": kw,
                    "count": keyword_counts[dev][kw],
                    "device_keyword_total": total,
                })

    write_csv(out_dir / "05_marker_trial_samples_0804_if_available.csv", sample_rows, [
        "device", "date", "line_no", "axes", "source_root_label", "relative_path", "sample"
    ])
    write_csv(out_dir / "06_trial_keyword_breakdown_from_samples.csv", keyword_rows, [
        "device", "keyword", "count", "device_keyword_total"
    ])

    # Verdict notes.
    verdict_counter = Counter(r["trial_overlap_verdict"] for r in matrix)
    strong_devices = [r["device"] for r in matrix if r["trial_overlap_verdict"] == "A_TRIAL_COHORT_STRONG_OVERLAP"]
    direct_devices = [r["device"] for r in matrix if r["triald_direct_file_count"] and r["final_tier"].startswith("A_")]
    raw_devices = [r["device"] for r in matrix if safe_int(r["raw_trial_ab"]) > 0 and r["final_tier"].startswith("A_")]

    notes = [
        {
            "項目": "採用判定",
            "内容": "Trial/A-B/cohortはC2025AUG core日に広く重なる。ただし攻撃基盤とは断定しない。cohort差分・発火条件の説明変数として採用。",
        },
        {
            "項目": "強い点",
            "内容": "USER_ORIGIN_MINI1はraw+csvかつtriald_directがあり、origin core上でTrial overlapが強い。複数外部端末にもraw trial_abが存在。",
        },
        {
            "項目": "弱い点",
            "内容": "trial_ab軸にはAnalytics/log-power内のapp_cohortやbeta等の汎用語も入る。Trial悪用・Apple Trial原因・A/B攻撃確定とは言わない。",
        },
        {
            "項目": "EXT_NO_CONTACT_A",
            "内容": "raw-only coreとして残るが、trial_abは小さい。41同様にraw-only重要点であり単独決定打ではない。",
        },
        {
            "項目": "次段階",
            "内容": "43ではTrust Graph Lineage、または42bでtriald_directファイルだけに絞った時刻順source reviewを行う。",
        },
    ]
    write_csv(out_dir / "07_verdict_notes.csv", notes, ["項目", "内容"])

    summary = {
        "script": "42_trial_ab_cohort_source_review.py",
        "status": "OK",
        "purpose": "C2025AUG / 2025-08-04 Trial-A/B-cohort overlap review",
        "input_39a_dir": str(dir39a),
        "input_39b_dir": str(dir39b),
        "input_40b_dir": str(dir40b),
        "out_dir": str(out_dir),
        "core_date": CORE_DATE,
        "raw_focus_rows": len(raw_focus),
        "csv_focus_rows": len(csv_focus),
        "raw_0804_rows": len(raw_0804),
        "csv_0804_rows": len(csv_0804),
        "trial_0804_source_file_rows": len(source_file_rows),
        "trial_0804_total_hits": sum(r["hit_count"] for r in source_file_rows),
        "devices_with_raw_trial_0804": len([r for r in matrix if safe_int(r.get("raw_trial_ab")) > 0]),
        "devices_with_csv_trial_0804": len([r for r in matrix if safe_int(r.get("csv_trial_ab")) > 0]),
        "devices_with_triald_direct_0804": len([r for r in matrix if safe_int(r.get("triald_direct_file_count")) > 0]),
        "strong_overlap_devices": strong_devices,
        "a_core_devices_with_raw_trial": raw_devices,
        "a_core_devices_with_triald_direct": direct_devices,
        "verdict_counts": dict(verdict_counter),
        "marker_hits_file": str(marker_path) if marker_path else "",
        "marker_scan_enabled": scan_marker,
        "marker_skipped_reason": marker_skipped_reason,
        "marker_scanned_rows": marker_scanned,
        "marker_candidate_lines": marker_candidate_lines,
        "marker_matched_trial_0804_rows": marker_matched,
        "elapsed_sec": round(time.time() - t0, 3),
        "final_verdict": "TRIAL_COHORT_OVERLAP_SUPPORTED_AS_EXPLANATORY_VARIABLE_NOT_CAUSAL_PROOF",
        "non_claims": [
            "Trial悪用確定ではない",
            "A/B攻撃確定ではない",
            "Apple Trial原因確定ではない",
            "Remote command確定ではない",
            "hidden MDM確定ではない",
            "攻撃者特定ではない",
        ],
    }
    write_json(out_dir / "00_MASTER_SUMMARY.json", summary)

    readme = f"""42 Trial / A-B / Cohort Source Review

対象:
  C2025AUG / {CORE_DATE}

結論:
  Trial / A-B / cohort 系は、C2025AUG core日に広く重なる。
  ただし、これは攻撃基盤の証明ではない。
  現段階では cohort差分・発火条件・feature flag 的な説明変数として扱う。

主な出力:
  00_MASTER_SUMMARY.json
  01_trial_0804_device_matrix.csv
  02_trial_0804_source_files.csv
  03_trial_window_timeline_2025_0801_0810.csv
  04_trial_file_kind_breakdown_0804.csv
  05_marker_trial_samples_0804_if_available.csv
  06_trial_keyword_breakdown_from_samples.csv
  07_verdict_notes.csv

重要な読み方:
  A_TRIAL_COHORT_STRONG_OVERLAP:
    raw + csv + triald_direct がcore device上で揃う。

  B_RAW_TRIAL_DIRECT_OVERLAP:
    raw + triald_direct はあるが、csv echoが弱い/無い。

  B_RAW_CSV_TRIAL_OVERLAP:
    raw + csv はあるが、triald direct sourceが弱い。

  D_CSV_ONLY_TRIAL_NOT_DECISION:
    csv側だけ。主判定に使わない。

禁止表現:
  Trial悪用確定
  A/B攻撃確定
  Apple Trial原因確定
  Remote command確定
  hidden MDM確定

次:
  43 Trust Graph Lineage
  または
  42b triald_direct only source-time review
"""
    write_text(out_dir / "08_README_VERDICT.txt", readme)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
