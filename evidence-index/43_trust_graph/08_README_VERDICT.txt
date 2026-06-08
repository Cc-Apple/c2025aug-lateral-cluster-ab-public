43 Trust Graph Lineage Review
================================

対象:
  C2025AUG / 2025-08-04

版:
  NO-PANDAS / 標準ライブラリのみ

目的:
  Apple ID / iCloud / ScreenTime / CKKS / SFA / accountsd / cloudd / backup / lateral_trust 系の
  local artifact shadow を使い、Trust Graph Lineage の影が端末別に出るか確認する。

最終判定:
  TRUST_GRAPH_LINEAGE_SHADOW_SUPPORTED_NOT_SERVER_SIDE_PROOF

言えること:
  - C2025AUG core日に、cloud_trust / policy_restriction / lateral_trust / backup_manifest が
    複数core端末で重なる。
  - USER_ORIGIN_MINI1 は origin core、USER_BRIDGE_15G は bridge 候補として保持できる。
  - 42bのdirect triald overlapを説明変数として重ねられる。

言えないこと:
  - Apple server-side trust graph の直接証明
  - Family Sharing / trusted device 登録の直接証明
  - hidden MDM確定
  - Trial悪用確定
  - 攻撃者特定
  - Apple関与確定

主な出力:
  01_trust_graph_0804_device_matrix.csv
  02_trust_graph_window_2025_0801_0810.csv
  03_trust_graph_lineage_sequence_0804.csv
  04_trust_source_files_top5_per_device_axis.csv
  05_policy_cloud_backup_lateral_overlap_matrix.csv
  06_role_gap_and_claim_boundary_notes.csv
  07_triald_direct_overlay_from_42b.csv

次:
  44 Backup / Manifest Inheritance
  または
  43b Proximity vs Cloud Separation
