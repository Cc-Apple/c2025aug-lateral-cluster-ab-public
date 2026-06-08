42 Trial / A-B / Cohort Source Review

対象:
  C2025AUG / 2025-08-04

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
