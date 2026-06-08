# C2025AUG Lateral Cluster + A/B-Cohort Public Evidence Pack

This package is a public, sanitized GitHub-ready evidence pack for the **C2025AUG / 2025-08-04 lateral-cluster + A/B/Trial explanatory-variable review**.

## Final verdict

`C2025AUG_LATERAL_CLUSTER_AB_COHORT_MODEL_SUPPORTED_NOT_CAUSAL_OR_ATTRIBUTION_PROOF`

Japanese reading:

> 横展開クラスタ + A/B/Trial説明変数モデルは local artifact 上で支持。ただし因果・帰属・server-side 証明ではない。

## Scope

This package contains:

- sanitized CSV / JSON / TXT outputs from review stages **40b–48**
- public scripts used to generate the staged outputs, sanitized as templates
- SHA256 hash registers for source/output ZIP packages
- public claim boundaries
- public device-role aliasing

This package does **not** contain:

- raw iOS logs
- raw sysdiagnose archives
- raw Manifest.db files
- raw Snapshot content
- Apple ID material
- OTP / financial data
- BSSID / MAC-level private material
- private file-system paths
- private person/device labels

## Review chain

| Stage | Purpose |
|---|---|
| 40b | Cross-strict review of 39a CSV-derived results and 39b raw-derived results |
| 41 | Raw-only source review for external no-contact critical device alias |
| 42 | Trial / A-B / cohort overlap review |
| 42b | Direct `triald` source-time review |
| 43 | Trust Graph Lineage shadow review |
| 44 | Backup / Manifest inheritance shadow review |
| 45 | Proximity vs Cloud separation review |
| 46 | Evidence preservation / suppression pressure review |
| 47 | Normal / control stress test |
| 48 | Final seal / integrated verdict |

## Public device aliasing

Private device/person labels are redacted. Use `machine/DEVICE_ALIAS_MAP_PUBLIC.csv` for public role labels.

## Claim boundary

This package can support a falsifiable forensic model of a mobile-native Apple platform-state anomaly cluster. It does **not** prove Trial abuse, Apple involvement, hidden MDM, remote command, attacker attribution, server-side trust-graph manipulation, backup poisoning, restore inheritance, or intent.

## Integrity

See:

- `source-package-hashes/SOURCE_PACKAGE_HASH_REGISTER.csv`
- `manifests/PUBLIC_PACKAGE_FILE_MANIFEST.csv`
- `manifests/PUBLIC_PACKAGE_SHA256.txt`
