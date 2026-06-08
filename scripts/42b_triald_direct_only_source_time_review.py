# Public sanitized template
# Device/person labels and local absolute paths are redacted for public release.
# Raw logs are not included in this repository package.

# -*- coding: utf-8 -*-
r'''
42b_triald_direct_only_source_time_review.py

目的:
  42で広く拾った Trial / A-B / cohort 軸を、さらに狭める。
  39b_file_axis_counts.csv から、C2025AUG / 2025-08-04 前後の
  triald direct 系ファイルだけを抽出し、時刻順・端末順・40b coreとの整合を確認する。

見る対象:
  - proactive_event_tracker-com_apple_Trial-com_apple_triald-*.ips
  - triald.cpu_resource-*.ips

重要:
  - raw 1年分ログ本体は読まない。
  - 39b_raw_marker_hits.csv も読まない。
  - 39b_file_axis_counts.csv と 40b core 結果だけを読む。
  - Trial悪用 / A-B攻撃 / Apple Trial原因 は断定しない。
  - 42bは「direct trialdがC2025AUG core日に実在するか」の確認。

既定入力:
  C:\Users\Administrator\Desktop\Result\39b_rawlog_cluster_trial_audit
  C:\Users\Administrator\Desktop\Result\40b_c2025aug_39a39b_cross_strict

既定出力:
  C:\Users\Administrator\Desktop\Result\42b_triald_direct_only_source_time_review

実行:
  python 42b_triald_direct_only_source_time_review.py
  python 42b_triald_direct_only_source_time_review.py <Result_root>
  python 42b_triald_direct_only_source_time_review.py <39b_dir> <40b_dir> <out_dir>

安全:
  input read-only. delete / move / rename / edit なし。
'''

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
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

DEFAULT_RESULT_ROOT = Path(r'C:\Users\Administrator\Desktop\Result')
DEFAULT_39B_DIR = DEFAULT_RESULT_ROOT / '39b_rawlog_cluster_trial_audit'
DEFAULT_40B_DIR = DEFAULT_RESULT_ROOT / '40b_c2025aug_39a39b_cross_strict'
DEFAULT_OUT_DIR = DEFAULT_RESULT_ROOT / '42b_triald_direct_only_source_time_review'

FOCUS_START = '2025-08-01'
FOCUS_END = '2025-08-10'
CORE_DATE = '2025-08-04'

DEVICE_ORDER = [
    'USER_ORIGIN_MINI1',
    'USER_BRIDGE_15G',
    'USER_DEVICE_12G',
    'USER_DEVICE_MINI2',
    'USER_DEVICE_11PRO',
    'LOW_EXPOSURE_IPAD',
    'EXT_NO_CONTACT_A',
    'EXT_UNCERTAIN_B',
    'EXT_REMOTE_GEO_C',
    'EXT_CONTACT_D',
    'EXT_CONTACT_E_12PROMAX',
    'EXT_CONTACT_E_6SPLUS',
    'CONTROL_OR_GENERIC_EXTERNAL',
    'USER_ORIGIN_MINI1G',
    'UNKNOWN',
]

ROLE_MAP = {
    'USER_ORIGIN_MINI1': 'ORIGIN_CORE',
    'USER_BRIDGE_15G': 'BRIDGE_TO_LATER_JOKER',
    'USER_DEVICE_12G': 'USER_CLUSTER_SUPPORT',
    'USER_DEVICE_MINI2': 'USER_CLUSTER_SUPPORT',
    'USER_DEVICE_11PRO': 'USER_CLUSTER_SUPPORT',
    'LOW_EXPOSURE_IPAD': 'USER_CLUSTER_SUPPORT',
    'EXT_NO_CONTACT_A': 'EXTERNAL_CRITICAL_NO_DIRECT_CONTACT',
    'EXT_UNCERTAIN_B': 'EXTERNAL_CRITICAL_UNCERTAIN_CONTACT',
    'EXT_REMOTE_GEO_C': 'EXTERNAL_GEO_SEPARATED',
    'EXT_CONTACT_D': 'EXTERNAL_CONTACT_KNOWN',
    'EXT_CONTACT_E_12PROMAX': 'EXTERNAL_CONTACT_KNOWN',
    'EXT_CONTACT_E_6SPLUS': 'EXTERNAL_CONTACT_KNOWN',
    'CONTROL_OR_GENERIC_EXTERNAL': 'GENERIC_EXTERNAL_LABEL_WEAK',
    'USER_ORIGIN_MINI1G': 'LATER_BASELINE_NOT_C2025AUG',
    'UNKNOWN': 'UNKNOWN',
}

DATE_RE = re.compile(r'(20\d{2})[-_/\.](\d{1,2})[-_/\.](\d{1,2})')
FILE_TS_RE = re.compile(r'(20\d{2})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})')


def mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_int(x, default=0):
    try:
        return int(float(str(x).strip() or '0'))
    except Exception:
        return default


def is_valid_date(s: str) -> bool:
    try:
        datetime.strptime(str(s), '%Y-%m-%d')
        return True
    except Exception:
        return False


def in_focus_window(s: str) -> bool:
    return is_valid_date(s) and FOCUS_START <= s <= FOCUS_END


def norm_path(s: str) -> str:
    return str(s or '').replace('\\', '/')


def basename(rel_path: str) -> str:
    return norm_path(rel_path).split('/')[-1]


def detect_filename_timestamp(rel_path: str) -> str:
    p = basename(rel_path)
    m = FILE_TS_RE.search(p)
    if not m:
        m = FILE_TS_RE.search(norm_path(rel_path))
    if not m:
        return ''
    return f'{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)}:{m.group(6)}'


def detect_filename_date(rel_path: str) -> str:
    ts = detect_filename_timestamp(rel_path)
    if ts:
        return ts[:10]
    return ''


def detect_date_from_path(rel_path: str, fallback: str = '') -> str:
    # filename date first. This fixes paths like ID移植後の挙動-2025-0731_0808/2025-08-04/...
    fd = detect_filename_date(rel_path)
    if is_valid_date(fd):
        return fd

    p = norm_path(rel_path)
    matches = []
    for m in DATE_RE.finditer(p):
        y, mo, d = m.group(1), int(m.group(2)), int(m.group(3))
        cand = f'{y}-{mo:02d}-{d:02d}'
        if is_valid_date(cand):
            matches.append(cand)
    if matches:
        return matches[-1]

    parts = [x for x in p.split('/') if x]
    for i in range(len(parts) - 2):
        if re.fullmatch(r'20\d{2}', parts[i] or ''):
            try:
                cand = f'{int(parts[i]):04d}-{int(parts[i+1]):02d}-{int(parts[i+2]):02d}'
                if is_valid_date(cand):
                    return cand
            except Exception:
                pass

    fb = str(fallback or '').strip()
    if is_valid_date(fb):
        return fb
    return ''


def detect_device_from_path(rel_path: str, fallback: str = 'UNKNOWN') -> str:
    p = norm_path(rel_path)
    low = p.lower()

    if 'hathao_mother' in low or 'ha_thao_mother' in low or 'ha thao mother' in low:
        return 'EXT_NO_CONTACT_A'

    if low.startswith('ngoc/') or '/ngoc/' in low:
        if 'iphone6s plus' in low or 'iphone6splus' in low or '6s plus' in low:
            return 'EXT_CONTACT_E_6SPLUS'
        if 'iphone12 pro max' in low or 'iphone12promax' in low or '12 pro max' in low:
            return 'EXT_CONTACT_E_12PROMAX'
        return 'EXT_CONTACT_E_12PROMAX'

    if low.startswith('ha thao/') or '/ha thao/' in low or low.startswith('hathao/') or '/hathao/' in low:
        return 'EXT_CONTACT_D'
    if low.startswith('vy/') or '/vy/' in low:
        return 'EXT_UNCERTAIN_B'
    if low.startswith('ibuki/') or '/ibuki/' in low:
        return 'EXT_REMOTE_GEO_C'

    if 'USER_ORIGIN_MINI1g' in low:
        return 'USER_ORIGIN_MINI1G'
    if 'mini-1' in low or 'USER_ORIGIN_MINI1' in low:
        return 'USER_ORIGIN_MINI1'
    if 'mini-2' in low or 'USER_DEVICE_MINI2' in low:
        return 'USER_DEVICE_MINI2'
    if re.search(r'(^|/)15g(/|$)', low) or '15-g' in low:
        return 'USER_BRIDGE_15G'
    if re.search(r'(^|/)12g(/|$)', low) or '12-g' in low:
        return 'USER_DEVICE_12G'
    if 'iphone11pro' in low or 'iphone11 pro' in low or '11pro' in low:
        return 'USER_DEVICE_11PRO'
    if re.search(r'(^|/)ipad(/|$)', low):
        return 'LOW_EXPOSURE_IPAD'

    fb = str(fallback or 'UNKNOWN').strip()
    if fb in ROLE_MAP:
        return fb
    return 'UNKNOWN'


def direct_triald_kind(rel_path: str) -> str:
    low = norm_path(rel_path).lower()
    base = basename(rel_path).lower()
    # Main strict target.
    if 'proactive_event_tracker' in low and ('com_apple_trial' in low or 'com.apple.trial' in low) and 'triald' in low:
        return 'PROACTIVE_TRIALD_DIRECT'
    # Still direct to triald, but not the same as proactive_event_tracker.
    if 'triald.cpu_resource' in base or ('triald' in base and 'cpu_resource' in base):
        return 'TRIALD_CPU_RESOURCE_DIRECT'
    return ''


def is_direct_triald(rel_path: str) -> bool:
    return bool(direct_triald_kind(rel_path))


def preferred_path(paths):
    # Prefer non-退避, shortest clean path.
    paths = list(paths)
    paths.sort(key=lambda p: (1 if '退避フォルダ' in p else 0, len(p), p))
    return paths[0] if paths else ''


def read_csv_rows(path: Path):
    with path.open('r', encoding='utf-8-sig', errors='replace', newline='') as f:
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
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def write_json(path: Path, obj) -> None:
    mkdir(path.parent)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def write_text(path: Path, text: str) -> None:
    mkdir(path.parent)
    path.write_text(text, encoding='utf-8')


def resolve_paths(argv):
    if len(argv) >= 4:
        return Path(argv[1]), Path(argv[2]), Path(argv[3])
    if len(argv) == 2:
        root = Path(argv[1])
        return (
            root / '39b_rawlog_cluster_trial_audit',
            root / '40b_c2025aug_39a39b_cross_strict',
            root / '42b_triald_direct_only_source_time_review',
        )
    return DEFAULT_39B_DIR, DEFAULT_40B_DIR, DEFAULT_OUT_DIR


def dev_sort_key(d):
    return (DEVICE_ORDER.index(d) if d in DEVICE_ORDER else 999, d)


def load_40b_core(dir40b: Path):
    path = dir40b / '04_2025_0804_core_cross.csv'
    core = {}
    if not path.exists():
        return core
    for r in read_csv_rows(path):
        dev = r.get('device') or 'UNKNOWN'
        core[dev] = r
    return core


def load_direct_triald_events(dir39b: Path):
    path = dir39b / '39b_file_axis_counts.csv'
    if not path.exists():
        return [], []

    # aggregate by direct event key to avoid duplicated paths under 退避フォルダ.
    events = {}
    duplicate_rows = []
    total_axis_rows_seen = 0
    direct_axis_rows_seen = 0

    for r in read_csv_rows(path):
        total_axis_rows_seen += 1
        rel = r.get('relative_path', '')
        kind = direct_triald_kind(rel)
        if not kind:
            continue
        date = detect_date_from_path(rel, r.get('date_guess_from_path') or r.get('date_guess') or '')
        if not in_focus_window(date):
            continue

        direct_axis_rows_seen += 1
        dev = detect_device_from_path(rel, r.get('device_guess_from_path') or r.get('device_guess') or 'UNKNOWN')
        ts = detect_filename_timestamp(rel)
        axis = r.get('axis', '')
        hit = safe_int(r.get('hit_count', 0))
        base = basename(rel)
        source_root_label = r.get('source_root_label', '')
        event_key = (dev, ts or date, base, kind)

        ev = events.setdefault(event_key, {
            'device': dev,
            'date': date,
            'timestamp': ts,
            'event_kind': kind,
            'basename': base,
            'source_root_label': source_root_label,
            'axis_hits': Counter(),
            'paths': set(),
            'path_axis_hits': defaultdict(Counter),
            'raw_axis_rows': 0,
        })
        # max per axis avoids double-counting same copied file in multiple paths.
        if hit > ev['axis_hits'][axis]:
            ev['axis_hits'][axis] = hit
        ev['paths'].add(rel)
        ev['path_axis_hits'][rel][axis] += hit
        ev['raw_axis_rows'] += 1

    output = []
    dup_rows = []
    for key, ev in events.items():
        paths = sorted(ev['paths'])
        pref = preferred_path(paths)
        axis_hits = ev['axis_hits']
        output.append({
            'device': ev['device'],
            'date': ev['date'],
            'timestamp': ev['timestamp'],
            'event_kind': ev['event_kind'],
            'role': ROLE_MAP.get(ev['device'], 'UNKNOWN'),
            'trial_ab_hits': axis_hits.get('trial_ab', 0),
            'daemon_seam_hits': axis_hits.get('daemon_seam', 0),
            'evidence_pressure_hits': axis_hits.get('evidence_pressure', 0),
            'cloud_trust_hits': axis_hits.get('cloud_trust', 0),
            'axis_count': len([a for a, v in axis_hits.items() if v > 0]),
            'axis_summary': ';'.join(f'{a}:{axis_hits[a]}' for a in sorted(axis_hits)),
            'duplicate_path_count': len(paths),
            'preferred_path': pref,
            'all_paths': ' | '.join(paths),
            'basename': ev['basename'],
            'source_root_label': ev['source_root_label'],
            'raw_axis_rows': ev['raw_axis_rows'],
        })
        if len(paths) > 1:
            for p in paths:
                dup_rows.append({
                    'device': ev['device'],
                    'date': ev['date'],
                    'timestamp': ev['timestamp'],
                    'event_kind': ev['event_kind'],
                    'basename': ev['basename'],
                    'duplicate_path_count': len(paths),
                    'path': p,
                    'axis_summary_for_path': ';'.join(f'{a}:{v}' for a, v in sorted(ev['path_axis_hits'][p].items())),
                    'preferred': 'YES' if p == pref else 'NO',
                })

    output.sort(key=lambda r: (r['date'], r['timestamp'] or r['date'], dev_sort_key(r['device']), r['event_kind']))
    dup_rows.sort(key=lambda r: (r['date'], r['timestamp'] or r['date'], dev_sort_key(r['device']), r['path']))
    meta = {
        'total_axis_rows_seen': total_axis_rows_seen,
        'direct_axis_rows_seen': direct_axis_rows_seen,
        'dedup_event_count': len(output),
        'duplicate_event_count': len([r for r in output if safe_int(r['duplicate_path_count']) > 1]),
    }
    return output, dup_rows, meta


def direct_verdict(dev, core_row, events_0804):
    event_kinds = {e['event_kind'] for e in events_0804}
    has_proactive = 'PROACTIVE_TRIALD_DIRECT' in event_kinds
    has_cpu = 'TRIALD_CPU_RESOURCE_DIRECT' in event_kinds
    tier = core_row.get('final_tier', '') if core_row else ''

    if tier.startswith('A_') and has_proactive:
        return 'A_CORE_WITH_PROACTIVE_TRIALD_DIRECT'
    if tier.startswith('A_') and has_cpu:
        return 'B_CORE_WITH_TRIALD_CPU_DIRECT_ONLY'
    if tier.startswith('A_') and not events_0804:
        return 'C_CORE_NO_TRIALD_DIRECT_0804'
    if events_0804 and has_proactive:
        return 'C_NONCORE_PROACTIVE_TRIALD_DIRECT'
    if events_0804:
        return 'D_NONCORE_TRIALD_DIRECT_CONTEXT'
    return 'NO_TRIALD_DIRECT_0804'


def main():
    t0 = time.time()
    dir39b, dir40b, out_dir = resolve_paths(sys.argv)
    mkdir(out_dir)

    input_rows = [
        {'name': '39b_dir', 'path': str(dir39b), 'exists': dir39b.exists()},
        {'name': '40b_dir', 'path': str(dir40b), 'exists': dir40b.exists()},
        {'name': 'out_dir', 'path': str(out_dir), 'exists': out_dir.exists()},
    ]
    write_csv(out_dir / '00_input_paths.csv', input_rows, ['name', 'path', 'exists'])

    core = load_40b_core(dir40b)
    events, dup_rows, meta = load_direct_triald_events(dir39b)
    events_0804 = [e for e in events if e['date'] == CORE_DATE]

    write_csv(out_dir / '01_triald_direct_0804_timeline.csv', events_0804, [
        'timestamp', 'date', 'device', 'role', 'event_kind',
        'trial_ab_hits', 'daemon_seam_hits', 'evidence_pressure_hits', 'cloud_trust_hits',
        'axis_count', 'axis_summary', 'duplicate_path_count',
        'preferred_path', 'all_paths', 'basename', 'source_root_label', 'raw_axis_rows',
    ])

    write_csv(out_dir / '02_triald_direct_window_2025_0801_0810.csv', events, [
        'timestamp', 'date', 'device', 'role', 'event_kind',
        'trial_ab_hits', 'daemon_seam_hits', 'evidence_pressure_hits', 'cloud_trust_hits',
        'axis_count', 'axis_summary', 'duplicate_path_count',
        'preferred_path', 'all_paths', 'basename', 'source_root_label', 'raw_axis_rows',
    ])

    # device summary on core date.
    by_dev_0804 = defaultdict(list)
    for e in events_0804:
        by_dev_0804[e['device']].append(e)

    device_set = set(core.keys()) | set(by_dev_0804.keys())
    summary_rows = []
    for dev in sorted(device_set, key=dev_sort_key):
        evs = by_dev_0804.get(dev, [])
        kind_counter = Counter(e['event_kind'] for e in evs)
        first_ts = min([e['timestamp'] for e in evs if e['timestamp']] or [''])
        last_ts = max([e['timestamp'] for e in evs if e['timestamp']] or [''])
        core_row = core.get(dev, {})
        summary_rows.append({
            'device': dev,
            'date': CORE_DATE,
            'role': core_row.get('role', ROLE_MAP.get(dev, 'UNKNOWN')),
            '40b_final_tier': core_row.get('final_tier', 'NO_40B_CORE_ROW'),
            '40b_support_class': core_row.get('support_class', ''),
            'direct_event_count': len(evs),
            'proactive_triald_event_count': kind_counter.get('PROACTIVE_TRIALD_DIRECT', 0),
            'triald_cpu_resource_event_count': kind_counter.get('TRIALD_CPU_RESOURCE_DIRECT', 0),
            'trial_ab_hits': sum(safe_int(e['trial_ab_hits']) for e in evs),
            'daemon_seam_hits': sum(safe_int(e['daemon_seam_hits']) for e in evs),
            'evidence_pressure_hits': sum(safe_int(e['evidence_pressure_hits']) for e in evs),
            'cloud_trust_hits': sum(safe_int(e['cloud_trust_hits']) for e in evs),
            'first_timestamp': first_ts,
            'last_timestamp': last_ts,
            'event_kind_summary': ';'.join(f'{k}:{v}' for k, v in sorted(kind_counter.items())),
            'verdict': direct_verdict(dev, core_row, evs),
            'top_paths': ' | '.join(e['preferred_path'] for e in evs[:5]),
        })

    write_csv(out_dir / '03_device_triald_direct_summary_0804.csv', summary_rows, [
        'device', 'date', 'role', '40b_final_tier', '40b_support_class', 'verdict',
        'direct_event_count', 'proactive_triald_event_count', 'triald_cpu_resource_event_count',
        'trial_ab_hits', 'daemon_seam_hits', 'evidence_pressure_hits', 'cloud_trust_hits',
        'first_timestamp', 'last_timestamp', 'event_kind_summary', 'top_paths',
    ])

    # direct vs 42 broad expectation style notes.
    comparison_rows = []
    for r in summary_rows:
        dev = r['device']
        comparison_rows.append({
            'device': dev,
            'role': r['role'],
            '40b_final_tier': r['40b_final_tier'],
            '42b_direct_verdict': r['verdict'],
            'meaning': (
                'direct proactive trialdあり。42の広いTrial overlapをdirect側で補強。'
                if r['verdict'] == 'A_CORE_WITH_PROACTIVE_TRIALD_DIRECT'
                else 'triald.cpu_resourceのみ。proactive_event_trackerではないため補助扱い。'
                if r['verdict'] == 'B_CORE_WITH_TRIALD_CPU_DIRECT_ONLY'
                else '40b coreだがdirect trialdなし。42の広いTrial supportは非direct由来として扱う。'
                if r['verdict'] == 'C_CORE_NO_TRIALD_DIRECT_0804'
                else '主判定外。'
            ),
        })
    write_csv(out_dir / '04_triald_vs_40b_core_matrix.csv', comparison_rows, [
        'device', 'role', '40b_final_tier', '42b_direct_verdict', 'meaning'
    ])

    write_csv(out_dir / '05_duplicate_path_audit.csv', dup_rows, [
        'device', 'date', 'timestamp', 'event_kind', 'basename', 'duplicate_path_count',
        'preferred', 'path', 'axis_summary_for_path'
    ])

    # sequence summary.
    seq_rows = []
    for idx, e in enumerate(events_0804, 1):
        seq_rows.append({
            'seq': idx,
            'timestamp': e['timestamp'],
            'device': e['device'],
            'role': e['role'],
            'event_kind': e['event_kind'],
            'trial_ab_hits': e['trial_ab_hits'],
            'daemon_seam_hits': e['daemon_seam_hits'],
            'preferred_path': e['preferred_path'],
        })
    write_csv(out_dir / '06_0804_triald_direct_sequence.csv', seq_rows, [
        'seq', 'timestamp', 'device', 'role', 'event_kind', 'trial_ab_hits', 'daemon_seam_hits', 'preferred_path'
    ])

    notes = [
        {
            '項目': '採用判定',
            '内容': '42bは採用。C2025AUG core日にはtriald direct系ファイルが複数端末で存在する。',
        },
        {
            '項目': '強い点',
            '内容': 'proactive_event_tracker-com_apple_Trial-com_apple_triald が USER_ORIGIN_MINI1 / USER_BRIDGE_15G / USER_DEVICE_12G / USER_DEVICE_MINI2 / USER_DEVICE_11PRO / EXT_UNCERTAIN_B / EXT_CONTACT_D に出る。',
        },
        {
            '項目': 'EXT_REMOTE_GEO_C',
            '内容': 'EXT_REMOTE_GEO_Cはproactive_event_trackerではなく triald.cpu_resource。direct triald補助だが、proactive directとは分ける。',
        },
        {
            '項目': 'EXT_NO_CONTACT_A / EXT_CONTACT_E',
            '内容': '40b core / 42 broad support はあるが、42b direct trialdでは出ない。非direct Trial supportまたは別seam由来として扱う。',
        },
        {
            '項目': '禁止表現',
            '内容': 'Trial悪用確定 / A-B攻撃確定 / Apple Trial原因確定 / Remote command確定とは言わない。',
        },
        {
            '項目': '次段階',
            '内容': '次は43 Trust Graph Lineage、または42cでdirect trialdファイルの中身サンプルをraw_marker_hitsから限定抽出する。',
        },
    ]
    write_csv(out_dir / '07_verdict_notes.csv', notes, ['項目', '内容'])

    verdict_counts = Counter(r['verdict'] for r in summary_rows)
    proactive_devices = [r['device'] for r in summary_rows if safe_int(r['proactive_triald_event_count']) > 0]
    direct_devices = [r['device'] for r in summary_rows if safe_int(r['direct_event_count']) > 0]
    core_no_direct = [r['device'] for r in summary_rows if r['verdict'] == 'C_CORE_NO_TRIALD_DIRECT_0804']

    summary = {
        'script': '42b_triald_direct_only_source_time_review.py',
        'status': 'OK',
        'purpose': 'C2025AUG / 2025-08-04 direct triald source-time review',
        'input_39b_dir': str(dir39b),
        'input_40b_dir': str(dir40b),
        'out_dir': str(out_dir),
        'focus_start': FOCUS_START,
        'focus_end': FOCUS_END,
        'core_date': CORE_DATE,
        'direct_axis_rows_seen': meta.get('direct_axis_rows_seen', 0),
        'dedup_direct_event_count_window': len(events),
        'dedup_direct_event_count_0804': len(events_0804),
        'proactive_triald_direct_event_count_0804': len([e for e in events_0804 if e['event_kind'] == 'PROACTIVE_TRIALD_DIRECT']),
        'triald_cpu_resource_direct_event_count_0804': len([e for e in events_0804 if e['event_kind'] == 'TRIALD_CPU_RESOURCE_DIRECT']),
        'devices_with_direct_triald_0804': direct_devices,
        'devices_with_proactive_triald_0804': proactive_devices,
        'core_devices_without_direct_triald_0804': core_no_direct,
        'verdict_counts': dict(verdict_counts),
        'duplicate_event_count': meta.get('duplicate_event_count', 0),
        'final_verdict': 'DIRECT_TRIALD_OVERLAP_SUPPORTED_BUT_NOT_CAUSAL_PROOF',
        'elapsed_sec': round(time.time() - t0, 3),
        'non_claims': [
            'Trial悪用確定ではない',
            'A/B攻撃確定ではない',
            'Apple Trial原因確定ではない',
            'Remote command確定ではない',
            'hidden MDM確定ではない',
            '攻撃者特定ではない',
        ],
    }
    write_json(out_dir / '00_MASTER_SUMMARY.json', summary)

    readme = f'''42b triald direct only source-time review

対象:
  C2025AUG / {CORE_DATE}

目的:
  42で広く拾った Trial / A-B / cohort 軸から、
  direct triald sourceだけを分離する。

見る対象:
  - proactive_event_tracker-com_apple_Trial-com_apple_triald
  - triald.cpu_resource

結論:
  direct triald overlap は確認できる。
  ただし、Trial悪用やA-B攻撃の証明ではない。

出力:
  00_MASTER_SUMMARY.json
  01_triald_direct_0804_timeline.csv
  02_triald_direct_window_2025_0801_0810.csv
  03_device_triald_direct_summary_0804.csv
  04_triald_vs_40b_core_matrix.csv
  05_duplicate_path_audit.csv
  06_0804_triald_direct_sequence.csv
  07_verdict_notes.csv

読み方:
  A_CORE_WITH_PROACTIVE_TRIALD_DIRECT:
    40b core端末で proactive_event_tracker Trial/triald がある。

  B_CORE_WITH_TRIALD_CPU_DIRECT_ONLY:
    40b core端末で triald.cpu_resource だけがある。

  C_CORE_NO_TRIALD_DIRECT_0804:
    40b coreだが direct triald は無い。
    42の広いTrial supportは非direct由来として扱う。

禁止:
  Trial悪用確定
  A-B攻撃確定
  Apple Trial原因確定
  Remote command確定
  hidden MDM確定
'''
    write_text(out_dir / '08_README_VERDICT.txt', readme)

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
