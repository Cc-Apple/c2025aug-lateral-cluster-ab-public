# Raw Manifest private review plan

This file documents the private-review direction for raw Manifest / backup-ledger material.

## Public boundary

Raw Manifest.db files, raw Snapshot content, raw iOS logs, raw sysdiagnose archives, private paths, Apple ID material, device identifiers, BSSID/MAC material, OTP/financial data, and private person labels are intentionally excluded from the public repository.

Public output should contain only:
- sanitized summaries
- CSV/JSON/TXT review outputs
- scripts
- SHA256 hash registers
- public claim boundaries
- non-identifying inventory statistics

## Private review goals

The private review should test whether backup / Manifest / Snapshot / RTCR state shows inheritance-like or finalization-related anomalies around the C2025AUG review window.

Primary checks:

1. Manifest.db SQLite validity
   - SQLite header
   - openability
   - integrity_check
   - table list
   - Files table presence
   - row counts

2. Manifest / Status / Info plist consistency
   - BackupState
   - SnapshotState
   - IsFullBackup
   - backup dates
   - tmp/final plist pair behavior
   - generation-to-generation consistency

3. Backup generation lineage
   - file count deltas
   - domain deltas
   - disappearing domains
   - sudden domain/file growth
   - same-hash and changed-hash comparison

4. RTCR / Snapshot coupling
   - RTCR timing
   - Snapshot finalization state
   - Info.plist.tmp presence
   - backup-finalization failure or incomplete state

5. Encrypted / unencrypted backup comparison
   - whether encrypted backups show non-SQLite Manifest behavior
   - whether unencrypted backups show normal SQLite behavior
   - whether the difference repeats across generations or devices

## Claim boundary

This private review may support backup-ledger or Manifest-state anomaly findings.

It must not claim:
- backup poisoning is proven
- restore inheritance is proven
- Manifest.db tampering is proven
- Apple server-side causation is proven
- hidden MDM is proven
- attacker attribution is proven

unless independent evidence directly supports those claims.
