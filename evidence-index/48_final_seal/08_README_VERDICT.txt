48 Final Seal / 横展開クラスタ + A/B 総合判定
============================================================

対象:
  C2025AUG / 2025-08-04

最終判定:
  C2025AUG_LATERAL_CLUSTER_AB_COHORT_MODEL_SUPPORTED_NOT_CAUSAL_OR_ATTRIBUTION_PROOF

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
