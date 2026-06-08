42b triald direct only source-time review

対象:
  C2025AUG / 2025-08-04

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
