# Public evidence boundary

Included:
- sanitized derived CSV / JSON / TXT outputs
- sanitized public scripts/templates
- SHA256 hashes for source packages and generated public files
- claim-boundary notes

Excluded:
- raw iOS logs
- raw Manifest.db / Snapshot / sysdiagnose content
- personal identifiers
- private absolute paths
- BSSID/MAC/OTP/financial/message content

Reason:
The goal is public reproducibility boundary and expert triage, not disclosure of private raw artifacts.
