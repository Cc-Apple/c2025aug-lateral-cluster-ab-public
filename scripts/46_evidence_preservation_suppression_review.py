# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r'''
46_evidence_preservation_suppression_review.py
NO-PANDAS版 / 標準ライブラリのみ。

目的:
  C2025AUG / 2025-08-04 の横展開クラスタについて、
  Evidence Preservation / Suppression Model を整理する。

見ること:
  - jetsam / memory pressure
  - diskwrites / storage pressure
  - logd / deleted / LogRetirement / rejected-config
  - ResetTelemetry / watchdog / SystemMemoryReset / panic
  - cpu_resource / signpost_reporter
  - sysdiagnose / stacks / spin
  - backup failure / manifest / snapshot 周辺
  - screen capture / recording failure 周辺
  - 40b core / 43 trust / 44 backup / 45 proximity との重なり

重要境界:
  - 証拠保存妨害の意図を直接証明するscriptではない。
  - screenshot/recording failure の直接証拠が必ず出るとは限らない。
  - storage pressure / jetsam / log pressure と core cluster の重なりを整理するだけ。
  - 攻撃者、Apple関与、hidden MDM、Trial悪用、Remote command は断定しない。

Default input:
  C:\Users\Administrator\Desktop\Result\39b_rawlog_cluster_trial_audit
  C:\Users\Administrator\Desktop\Result\40b_c2025aug_39a39b_cross_strict
  C:\Users\Administrator\Desktop\Result\43_trust_graph_lineage_review
  C:\Users\Administrator\Desktop\Result\44_backup_manifest_inheritance_review
  C:\Users\Administrator\Desktop\Result\45_proximity_vs_cloud_separation_review

Output:
  C:\Users\Administrator\Desktop\Result\46_evidence_preservation_suppression_review

Read-only. No delete / move / rename / modify of input.
'''

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

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

TARGET_START = '2025-08-01'
TARGET_END = '2025-08-10'
CORE_DATE = '2025-08-04'

CORE_DEVICE_ORDER = [
    'USER_ORIGIN_MINI1', 'USER_BRIDGE_15G', 'USER_DEVICE_12G', 'USER_DEVICE_MINI2', 'USER_DEVICE_11PRO',
    'EXT_UNCERTAIN_B', 'EXT_NO_CONTACT_A', 'EXT_CONTACT_D', 'EXT_CONTACT_E_12PROMAX', 'EXT_CONTACT_E_6SPLUS', 'EXT_REMOTE_GEO_C',
]

ROLE_DEFAULT = {
    'USER_ORIGIN_MINI1': 'ORIGIN_CORE',
    'USER_BRIDGE_15G': 'BRIDGE_TO_LATER_JOKER',
    'USER_DEVICE_12G': 'USER_CLUSTER_SUPPORT',
    'USER_DEVICE_MINI2': 'USER_CLUSTER_SUPPORT',
    'USER_DEVICE_11PRO': 'USER_CLUSTER_SUPPORT',
    'EXT_UNCERTAIN_B': 'EXTERNAL_UNCERTAIN_NO_DIRECT_CONTACT_EXPECTED',
    'EXT_NO_CONTACT_A': 'EXTERNAL_NO_CONTACT_CRITICAL',
    'EXT_CONTACT_D': 'EXTERNAL_CONTACT_KNOWN',
    'EXT_CONTACT_E_12PROMAX': 'EXTERNAL_CONTACT_KNOWN',
    'EXT_CONTACT_E_6SPLUS': 'EXTERNAL_CONTACT_KNOWN',
    'EXT_REMOTE_GEO_C': 'EXTERNAL_REMOTE_GEO_CONTACT',
}


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def read_csv_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.exists():
        return [], []
    encodings = ['utf-8-sig', 'utf-8', 'cp932', 'cp1252']
    last_err: Optional[Exception] = None
    for enc in encodings:
        try:
            with path.open('r', newline='', encoding=enc, errors='replace') as f:
                r = csv.DictReader(f)
                rows = [dict(row) for row in r]
                return rows, list(r.fieldnames or [])
        except Exception as e:
            last_err = e
    print(f'WARN: failed to read csv: {path} :: {last_err}')
    return [], []


def write_csv(path: Path, rows: List[Dict], fields: Optional[List[str]] = None) -> None:
    ensure_dir(path.parent)
    if fields is None:
        fields = []
        for row in rows:
            for k in row.keys():
                if k not in fields:
                    fields.append(k)
    with path.open('w', newline='', encoding='utf-8-sig', errors='replace') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_json(path: Path, obj) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False), encoding='utf-8')


def to_int(v, default: int = 0) -> int:
    try:
        if v is None or str(v).strip() == '':
            return default
        return int(float(str(v).replace(',', '')))
    except Exception:
        return default


def to_float(v, default: float = 0.0) -> float:
    try:
        if v is None or str(v).strip() == '':
            return default
        return float(str(v).replace(',', ''))
    except Exception:
        return default


def log_score(n: int, weight: float = 1.0) -> float:
    return math.log10(max(int(n), 0) + 1) * weight


def normalize_date(s: str) -> str:
    s = str(s or '')
    m = re.search(r'(20\d{2})[-_/](\d{1,2})[-_/](\d{1,2})', s)
    if m:
        y, mo, d = m.groups()
        return f'{int(y):04d}-{int(mo):02d}-{int(d):02d}'
    return ''


def in_window(date_s: str) -> bool:
    return TARGET_START <= date_s <= TARGET_END


def normalize_device_from_path(path_s: str, guess: str = '') -> str:
    p = str(path_s or '')
    g = str(guess or '').strip()
    low = p.lower().replace('\\', '/')

    if 'hathao_mother' in low or 'ha thao mother' in low or ('hathao' in low and 'mother' in low):
        return 'EXT_NO_CONTACT_A'
    if 'ngoc' in low:
        if '6s' in low or '6plus' in low or '6 plus' in low or 'iphone6' in low:
            return 'EXT_CONTACT_E_6SPLUS'
        return 'EXT_CONTACT_E_12PROMAX'
    if re.search(r'(^|/)ha[ _]?thao($|/)', low) or 'ha thao' in low:
        return 'EXT_CONTACT_D'
    if re.search(r'(^|/)vy($|/)', low):
        return 'EXT_UNCERTAIN_B'
    if 'ibuki' in low:
        return 'EXT_REMOTE_GEO_C'
    if 'iphone11pro' in low or 'iphone 11 pro' in low:
        return 'USER_DEVICE_11PRO'
    if 'USER_ORIGIN_MINI1g' in low:
        return 'USER_ORIGIN_MINI1G'
    if 'USER_ORIGIN_MINI1' in low:
        return 'USER_ORIGIN_MINI1'
    if 'USER_DEVICE_MINI2' in low:
        return 'USER_DEVICE_MINI2'
    if '15g' in low:
        return 'USER_BRIDGE_15G'
    if '12g' in low:
        return 'USER_DEVICE_12G'
    if g and g not in ('CONTROL_OR_GENERIC_EXTERNAL', 'UNKNOWN'):
        return g
    return g or 'UNKNOWN'


def parse_timestamp_from_path(path_s: str, fallback_date: str = '') -> Tuple[str, str]:
    s = str(path_s or '')
    m = re.search(r'(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_]?([0-5]\d)[-_]?([0-5]\d)', s)
    if m:
        y, mo, d, hh, mi, ss = m.groups()
        date_s = f'{y}-{mo}-{d}'
        return date_s, f'{date_s} {hh}:{mi}:{ss}'
    date_s = normalize_date(s) or fallback_date
    return date_s, f'{date_s} 00:00:00' if date_s else ''


def evidence_source_kind(path_s: str, source_root: str = '') -> str:
    low = str(path_s or '').lower().replace('\\', '/')
    if 'jetsam' in low or 'memorystatus' in low or 'memory' in low:
        return 'jetsam_memory_pressure'
    if 'diskwrites' in low or 'logwritingusage' in low or 'storage' in low or 'fileprovider' in low or 'cloudphotod' in low or 'photolibrary' in low:
        return 'diskwrites_storage_pressure'
    if 'logretirement' in low or 'rejected-config' in low or '/deleted' in low or 'deleted.' in low or 'logd' in low:
        return 'logd_deleted_retirement'
    if 'resettelemetry' in low or 'systemmemoryreset' in low or 'watchdog' in low or 'wdog' in low or 'panic' in low or 'forcereset' in low or 'reset' in low:
        return 'reset_watchdog_failure'
    if 'cpu_resource' in low or 'signpost_reporter.cpu' in low or 'cpu' in low:
        return 'cpu_resource_pressure'
    if 'sysdiagnose' in low or 'stacks' in low or 'spin' in low:
        return 'sysdiagnose_stacks_context'
    if 'log-power' in low or 'droop' in low or 'vacvoltagelimit' in low or 'thermal' in low or 'battery' in low or 'power' in low:
        return 'power_thermal_evidence_context'
    if 'backup' in low or 'manifest' in low or 'snapshot' in low or 'imazing' in low or 'status.plist' in low or 'info.plist' in low:
        return 'backup_manifest_failure_context'
    if 'screenshot' in low or 'screenrecord' in low or 'recording' in low or 'capture' in low:
        return 'screen_capture_recording_context'
    if 'rtcreporting' in low or '/rtc' in low or 'rtc' in low:
        return 'rtcr_reporting_context'
    if 'analytics' in low:
        return 'analytics_evidence_context'
    if 'session' in low:
        return 'session_evidence_context'
    return 'other_evidence_pressure_context'


def load_40b_core(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / '04_2025_0804_core_cross.csv')
    return {r.get('device', ''): r for r in rows if r.get('device')}


def load_43(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / '01_trust_graph_0804_device_matrix.csv')
    return {r.get('device', ''): r for r in rows if r.get('device')}


def load_44(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / '01_backup_manifest_0804_device_matrix.csv')
    return {r.get('device', ''): r for r in rows if r.get('device')}


def load_45(path: Path) -> Dict[str, Dict[str, str]]:
    rows, _ = read_csv_rows(path / '01_proximity_cloud_0804_device_matrix.csv')
    return {r.get('device', ''): r for r in rows if r.get('device')}


def gather_evidence_sources(file_axis_csv: Path) -> Tuple[Dict[str, Dict], List[Dict], Dict[str, Dict[str, Dict]]]:
    rows, _ = read_csv_rows(file_axis_csv)
    per_dev = defaultdict(lambda: {
        'evidence_source_files_0804': set(),
        'evidence_source_hits_0804': 0,
        'evidence_kinds_0804': defaultdict(int),
        'window_source_files': set(),
        'window_source_hits': 0,
        'window_kinds': defaultdict(int),
    })
    top_candidates: Dict[Tuple[str, str], Dict] = {}
    date_kind_map: Dict[str, Dict[str, Dict]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for r in rows:
        axis = str(r.get('axis', ''))
        if axis != 'evidence_pressure':
            continue
        rel = r.get('relative_path', '')
        dev = normalize_device_from_path(rel, r.get('device_guess_from_path', ''))
        date_s = normalize_date(r.get('date_guess_from_path', '')) or parse_timestamp_from_path(rel)[0]
        if not date_s or not in_window(date_s):
            continue
        hits = to_int(r.get('hit_count', 0))
        kind = evidence_source_kind(rel, r.get('source_root_label', ''))
        ts_date, ts = parse_timestamp_from_path(rel, date_s)
        p = per_dev[dev]
        p['window_source_files'].add(rel)
        p['window_source_hits'] += hits
        p['window_kinds'][kind] += hits
        date_kind_map[dev][date_s][kind] += hits

        if date_s == CORE_DATE:
            p['evidence_source_files_0804'].add(rel)
            p['evidence_source_hits_0804'] += hits
            p['evidence_kinds_0804'][kind] += hits
            key = (dev, rel)
            prev = top_candidates.get(key)
            if prev:
                prev['hit_count'] += hits
            else:
                top_candidates[key] = {
                    'device': dev,
                    'date': date_s,
                    'timestamp_guess': ts,
                    'source_kind': kind,
                    'hit_count': hits,
                    'relative_path': rel,
                    'source_root_label': r.get('source_root_label', ''),
                }
    top_rows = sorted(top_candidates.values(), key=lambda x: (x['device'], -to_int(x['hit_count']), x['relative_path']))
    return per_dev, top_rows, date_kind_map


def classify_device(dev: str, core: Dict[str, str], trust: Dict[str, str], backup: Dict[str, str], prox: Dict[str, str], ev: Dict) -> Tuple[str, float, str]:
    final_tier = core.get('final_tier', '')
    raw_axes = to_int(core.get('raw_axes_present', 0))
    raw_total = to_int(core.get('raw_total_axis_hits', 0))
    raw_ev = to_int(core.get('raw_evidence_pressure', trust.get('raw_evidence_pressure', 0)))
    ev_hits = int(ev.get('evidence_source_hits_0804', 0))
    kinds = ev.get('evidence_kinds_0804', {}) or {}
    kind_count = len(kinds)
    trust_score = to_float(trust.get('trust_lineage_score', 0))
    backup_score = to_float(backup.get('inheritance_shadow_score', 0))
    separation_score = to_float(prox.get('separation_score', 0))
    triald = str(trust.get('triald_direct_0804', '')).upper() == 'YES'

    # category signals
    jetsam = to_int(kinds.get('jetsam_memory_pressure', 0))
    disk = to_int(kinds.get('diskwrites_storage_pressure', 0))
    logd = to_int(kinds.get('logd_deleted_retirement', 0))
    reset = to_int(kinds.get('reset_watchdog_failure', 0))
    cpu = to_int(kinds.get('cpu_resource_pressure', 0))
    sysdiag = to_int(kinds.get('sysdiagnose_stacks_context', 0))
    backup_fail = to_int(kinds.get('backup_manifest_failure_context', 0))

    score = 0.0
    score += log_score(raw_ev or ev_hits, 10.0)
    score += kind_count * 2.2
    score += log_score(raw_total, 2.0)
    score += min(trust_score, 60.0) * 0.15
    score += min(backup_score, 70.0) * 0.12
    score += min(separation_score, 80.0) * 0.10
    if jetsam: score += 4.0
    if disk: score += 4.0
    if logd: score += 5.0
    if reset: score += 4.0
    if cpu: score += 3.0
    if sysdiag: score += 1.0   # self-debug可能性があるので重み低め
    if backup_fail: score += 3.0
    if triald: score += 2.0
    if dev == 'EXT_NO_CONTACT_A': score += 8.0
    if dev == 'USER_ORIGIN_MINI1': score += 6.0
    if dev in ('CONTROL_OR_GENERIC_EXTERNAL', 'LOW_EXPOSURE_IPAD'): score -= 30.0

    reason_bits = []
    if raw_ev or ev_hits: reason_bits.append('evidence_pressure_present')
    if jetsam: reason_bits.append('jetsam_memory')
    if disk: reason_bits.append('diskwrites_storage')
    if logd: reason_bits.append('logd_deleted_retirement')
    if reset: reason_bits.append('reset_watchdog')
    if cpu: reason_bits.append('cpu_resource')
    if sysdiag: reason_bits.append('sysdiagnose_stacks_self_debug_possible')
    if trust.get('trust_lineage_verdict'): reason_bits.append('trust_lineage_overlay')
    if backup.get('backup_manifest_verdict'): reason_bits.append('backup_manifest_overlay')
    if prox.get('proximity_cloud_verdict'): reason_bits.append('proximity_cloud_overlay')
    if triald: reason_bits.append('triald_direct_overlay')

    if dev in ('CONTROL_OR_GENERIC_EXTERNAL', 'LOW_EXPOSURE_IPAD') or not final_tier or final_tier.startswith('D_'):
        verdict = 'E_NO_EVIDENCE_SUPPRESSION_DECISION'
    elif raw_ev >= 5000 and kind_count >= 5 and (trust or backup or prox):
        verdict = 'A_EVIDENCE_SUPPRESSION_SHADOW_STRONG'
    elif raw_ev >= 1000 and kind_count >= 4:
        verdict = 'A_EVIDENCE_SUPPRESSION_SHADOW_SUPPORTED'
    elif raw_ev >= 250 and kind_count >= 2:
        verdict = 'B_EVIDENCE_PRESSURE_CONTEXT_SUPPORTED'
    elif raw_ev > 0:
        verdict = 'C_WEAK_EVIDENCE_PRESSURE_CONTEXT'
    else:
        verdict = 'D_NO_EVIDENCE_PRESSURE_CONTEXT'
    return verdict, round(score, 3), ';'.join(reason_bits)


def main() -> int:
    ap = argparse.ArgumentParser(description='46 Evidence Preservation / Suppression Review / no pandas')
    ap.add_argument('--in39b', default=r'C:\Users\Administrator\Desktop\Result\39b_rawlog_cluster_trial_audit')
    ap.add_argument('--in40b', default=r'C:\Users\Administrator\Desktop\Result\40b_c2025aug_39a39b_cross_strict')
    ap.add_argument('--in43', default=r'C:\Users\Administrator\Desktop\Result\43_trust_graph_lineage_review')
    ap.add_argument('--in44', default=r'C:\Users\Administrator\Desktop\Result\44_backup_manifest_inheritance_review')
    ap.add_argument('--in45', default=r'C:\Users\Administrator\Desktop\Result\45_proximity_vs_cloud_separation_review')
    ap.add_argument('--out', default=r'C:\Users\Administrator\Desktop\Result\46_evidence_preservation_suppression_review')
    args = ap.parse_args()

    in39b = Path(args.in39b)
    in40b = Path(args.in40b)
    in43 = Path(args.in43)
    in44 = Path(args.in44)
    in45 = Path(args.in45)
    out = Path(args.out)
    ensure_dir(out)

    input_rows = [
        {'name': 'in39b', 'path': str(in39b), 'exists': str(in39b.exists())},
        {'name': 'in40b', 'path': str(in40b), 'exists': str(in40b.exists())},
        {'name': 'in43', 'path': str(in43), 'exists': str(in43.exists())},
        {'name': 'in44', 'path': str(in44), 'exists': str(in44.exists())},
        {'name': 'in45', 'path': str(in45), 'exists': str(in45.exists())},
        {'name': 'out', 'path': str(out), 'exists': 'CREATED'},
    ]
    write_csv(out / '00_input_paths.csv', input_rows)

    core40 = load_40b_core(in40b)
    trust43 = load_43(in43)
    backup44 = load_44(in44)
    prox45 = load_45(in45)
    ev_per_dev, ev_top_rows_all, date_kind_map = gather_evidence_sources(in39b / '39b_file_axis_counts.csv')

    all_devices = []
    for d in CORE_DEVICE_ORDER + sorted(set(core40) | set(trust43) | set(backup44) | set(prox45) | set(ev_per_dev)):
        if d and d not in all_devices:
            all_devices.append(d)

    device_rows: List[Dict] = []
    for dev in all_devices:
        core = core40.get(dev, {})
        trust = trust43.get(dev, {})
        backup = backup44.get(dev, {})
        prox = prox45.get(dev, {})
        ev = ev_per_dev.get(dev, {})
        kinds = ev.get('evidence_kinds_0804', {}) or {}
        verdict, score, reason = classify_device(dev, core, trust, backup, prox, ev)
        row = {
            'device': dev,
            'date': CORE_DATE,
            'role': core.get('role', ROLE_DEFAULT.get(dev, 'UNKNOWN')),
            'evidence_suppression_verdict': verdict,
            'evidence_suppression_score': score,
            'reason_flags': reason,
            'final_tier_40b': core.get('final_tier', ''),
            'support_class_40b': core.get('support_class', ''),
            'trust_lineage_verdict_43': trust.get('trust_lineage_verdict', ''),
            'backup_manifest_verdict_44': backup.get('backup_manifest_verdict', ''),
            'proximity_cloud_verdict_45': prox.get('proximity_cloud_verdict', ''),
            'triald_direct_0804_from43': trust.get('triald_direct_0804', ''),
            'raw_evidence_pressure_from40b': core.get('raw_evidence_pressure', trust.get('raw_evidence_pressure', '0')),
            'csv_evidence_pressure_from40b': core.get('csv_evidence_pressure', '0'),
            'evidence_source_hits_39b_0804': int(ev.get('evidence_source_hits_0804', 0)),
            'evidence_source_files_39b_0804': len(ev.get('evidence_source_files_0804', set())),
            'evidence_source_kind_count_0804': len(kinds),
            'jetsam_memory_pressure_hits_0804': int(kinds.get('jetsam_memory_pressure', 0)),
            'diskwrites_storage_pressure_hits_0804': int(kinds.get('diskwrites_storage_pressure', 0)),
            'logd_deleted_retirement_hits_0804': int(kinds.get('logd_deleted_retirement', 0)),
            'reset_watchdog_failure_hits_0804': int(kinds.get('reset_watchdog_failure', 0)),
            'cpu_resource_pressure_hits_0804': int(kinds.get('cpu_resource_pressure', 0)),
            'sysdiagnose_stacks_context_hits_0804': int(kinds.get('sysdiagnose_stacks_context', 0)),
            'power_thermal_evidence_context_hits_0804': int(kinds.get('power_thermal_evidence_context', 0)),
            'backup_manifest_failure_context_hits_0804': int(kinds.get('backup_manifest_failure_context', 0)),
            'screen_capture_recording_context_hits_0804': int(kinds.get('screen_capture_recording_context', 0)),
            'rtcr_reporting_context_hits_0804': int(kinds.get('rtcr_reporting_context', 0)),
            'claim_boundary': 'local_evidence_pressure_overlap_not_intent_or_suppression_proof',
        }
        device_rows.append(row)

    device_rows.sort(key=lambda r: (str(r['evidence_suppression_verdict']), -to_float(r['evidence_suppression_score']), r['device']))
    write_csv(out / '01_evidence_suppression_0804_device_matrix.csv', device_rows)

    # top source files per device
    top_rows: List[Dict] = []
    by_dev = defaultdict(list)
    for r in ev_top_rows_all:
        by_dev[r['device']].append(r)
    for dev in all_devices:
        dev_rows = sorted(by_dev.get(dev, []), key=lambda x: -to_int(x.get('hit_count')))[:12]
        for rank, r in enumerate(dev_rows, 1):
            rr = dict(r)
            rr['rank_in_device'] = rank
            top_rows.append(rr)
    write_csv(out / '02_evidence_source_files_top12_per_device.csv', top_rows)

    # kind summary
    kind_rows = []
    for dev in all_devices:
        ev = ev_per_dev.get(dev, {})
        kinds = ev.get('evidence_kinds_0804', {}) or {}
        for kind, hits in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0])):
            kind_rows.append({
                'device': dev,
                'date': CORE_DATE,
                'source_kind': kind,
                'hit_count': int(hits),
                'role': core40.get(dev, {}).get('role', ROLE_DEFAULT.get(dev, 'UNKNOWN')),
            })
    write_csv(out / '03_evidence_kind_breakdown_0804.csv', kind_rows)

    overlap_rows = []
    for r in device_rows:
        overlap_rows.append({
            'device': r['device'],
            'role': r['role'],
            'evidence_suppression_verdict': r['evidence_suppression_verdict'],
            'evidence_suppression_score': r['evidence_suppression_score'],
            'final_tier_40b': r['final_tier_40b'],
            'trust_lineage_verdict_43': r['trust_lineage_verdict_43'],
            'backup_manifest_verdict_44': r['backup_manifest_verdict_44'],
            'proximity_cloud_verdict_45': r['proximity_cloud_verdict_45'],
            'triald_direct_0804_from43': r['triald_direct_0804_from43'],
            'raw_evidence_pressure_from40b': r['raw_evidence_pressure_from40b'],
            'evidence_source_kind_count_0804': r['evidence_source_kind_count_0804'],
            'jetsam_memory_pressure_hits_0804': r['jetsam_memory_pressure_hits_0804'],
            'diskwrites_storage_pressure_hits_0804': r['diskwrites_storage_pressure_hits_0804'],
            'logd_deleted_retirement_hits_0804': r['logd_deleted_retirement_hits_0804'],
            'reset_watchdog_failure_hits_0804': r['reset_watchdog_failure_hits_0804'],
            'cpu_resource_pressure_hits_0804': r['cpu_resource_pressure_hits_0804'],
        })
    write_csv(out / '04_evidence_trust_backup_proximity_overlap_matrix.csv', overlap_rows)

    sequence_rows = []
    for r in device_rows:
        dev = r['device']
        first_src_ts = ''
        if by_dev.get(dev):
            first_src_ts = sorted(by_dev[dev], key=lambda x: str(x.get('timestamp_guess', '')))[0].get('timestamp_guess', '')
        sequence_rows.append({
            'device': dev,
            'role': r['role'],
            'first_evidence_source_ts_0804_guess': first_src_ts,
            'triald_direct_0804_from43': r['triald_direct_0804_from43'],
            'evidence_suppression_verdict': r['evidence_suppression_verdict'],
            'trust_lineage_verdict_43': r['trust_lineage_verdict_43'],
            'backup_manifest_verdict_44': r['backup_manifest_verdict_44'],
            'proximity_cloud_verdict_45': r['proximity_cloud_verdict_45'],
        })
    sequence_rows.sort(key=lambda r: (r.get('first_evidence_source_ts_0804_guess') or '9999', r['device']))
    write_csv(out / '05_sequence_evidence_pressure_0804.csv', sequence_rows)

    notes = [
        {'note_type': 'CAN_SAY', 'content': 'C2025AUG core日に、evidence pressure と trust/backup/proximity overlapを端末別に整理できる。'},
        {'note_type': 'CAN_SAY', 'content': 'jetsam / diskwrites / logd-deleted / reset-watchdog / cpu_resource などの保存困難化に関係する周辺artifactを抽出する。'},
        {'note_type': 'CAN_SAY', 'content': 'EXT_NO_CONTACT_Aはraw-onlyだが、evidence pressureでも強く残る場合はreview対象として維持する。'},
        {'note_type': 'CANNOT_SAY', 'content': '証拠保存妨害の意図、攻撃者、Apple関与、hidden MDM、Remote commandはこのscriptでは断定しない。'},
        {'note_type': 'CANNOT_SAY', 'content': 'sysdiagnose/stacksはセルフデバッグ付随の可能性があるため、単独主証拠にしない。'},
        {'note_type': 'NEXT', 'content': '47 Normal / Control Stress Testへ進み、普通のiOSでも同じ密度で出るかを潰す。'},
    ]
    write_csv(out / '06_claim_boundary_notes.csv', notes)

    verdict_counts = defaultdict(int)
    for r in device_rows:
        verdict_counts[r['evidence_suppression_verdict']] += 1

    strong = [r['device'] for r in device_rows if str(r['evidence_suppression_verdict']).startswith('A_EVIDENCE_SUPPRESSION_SHADOW_STRONG')]
    supported = [r['device'] for r in device_rows if str(r['evidence_suppression_verdict']).startswith('A_EVIDENCE_SUPPRESSION_SHADOW_SUPPORTED')]
    context = [r['device'] for r in device_rows if str(r['evidence_suppression_verdict']).startswith('B_') or str(r['evidence_suppression_verdict']).startswith('C_')]

    summary = {
        'status': 'DONE',
        'variant': 'NO_PANDAS_STD_LIB_ONLY',
        'target_window': f'{TARGET_START}..{TARGET_END}',
        'core_date': CORE_DATE,
        'final_verdict': 'EVIDENCE_PRESERVATION_SUPPRESSION_SHADOW_SUPPORTED_NOT_INTENT_PROOF',
        'device_rows': len(device_rows),
        'source_top_rows': len(top_rows),
        'kind_breakdown_rows': len(kind_rows),
        'overlap_rows': len(overlap_rows),
        'sequence_rows': len(sequence_rows),
        'verdict_counts': dict(verdict_counts),
        'strong_evidence_suppression_shadow_devices': strong,
        'supported_evidence_suppression_shadow_devices': supported,
        'evidence_pressure_context_devices': context,
        'important_boundary': [
            'evidence pressure overlap is not proof of intentional suppression',
            'sysdiagnose/stacks may be self-debug related and should be down-weighted',
            'no attribution / no hidden MDM / no Apple involvement claim',
        ],
        'input_paths': input_rows,
    }
    write_json(out / '00_MASTER_SUMMARY.json', summary)

    readme = f'''46 Evidence Preservation / Suppression Review
============================================================

Final verdict:
  {summary['final_verdict']}

Meaning:
  C2025AUG / 2025-08-04 について、証拠保存・ログ保持・容量圧迫・reset/jetsam/logd/deleted周辺のpressureが、
  40b core / 43 trust / 44 backup / 45 proximity とどう重なるかを整理した。

Strong shadow:
  {', '.join(strong) if strong else '(none)'}

Supported shadow:
  {', '.join(supported) if supported else '(none)'}

Context:
  {', '.join(context) if context else '(none)'}

Claim boundary:
  - 証拠保存妨害の意図を直接証明しない。
  - screenshot / recording failure の直接証明ではない。
  - sysdiagnose / stacks はセルフデバッグ付随の可能性を考慮する。
  - 攻撃者 / Apple関与 / hidden MDM / Remote command は断定しない。

Next:
  47 Normal / Control Stress Test
'''
    (out / '07_README_VERDICT.txt').write_text(readme, encoding='utf-8')

    print('DONE')
    print(f'Output: {out}')
    print(f"Final verdict: {summary['final_verdict']}")
    print(f'device_rows: {len(device_rows)}')
    print(f"strong_evidence_suppression_shadow_devices: {', '.join(strong) if strong else '(none)'}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
