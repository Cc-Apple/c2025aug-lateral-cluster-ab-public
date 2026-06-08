# Reproducibility guide

Raw logs are not included. Public reproduction is therefore limited to verifying the staged public outputs and file hashes.

Steps:
1. Verify `source-package-hashes/SOURCE_PACKAGE_HASH_REGISTER.csv` against private held ZIPs, if available.
2. Verify `manifests/PUBLIC_PACKAGE_FILE_MANIFEST.csv` against this package.
3. Review stages in order: 40b -> 41 -> 42 -> 42b -> 43 -> 44 -> 45 -> 46 -> 47 -> 48.
4. Use the scripts as sanitized templates. Private labels and paths were redacted.

For full expert review, private raw artifacts must be compared against the hash register under a controlled disclosure process.
