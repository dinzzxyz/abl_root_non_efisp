# Repository working guide

Read README.md, HANDOFF.md, LAPORAN.md, and RESEARCH_CONTINUED.md before making
technical conclusions. Preserve original evidence and hash/version boundaries.
For the newer CN candidate and OEM diagnostics, also read BOOTSTATE_FINDINGS.md.
For the live Tools FV/FAT12/stock-log capture, read LIVE_BOOT_FINDINGS.md.
For indirect platform callbacks and native Ebl file/RAM routes, also read
ENTRY_FINDINGS.md. Early hotkey checking is not the later setup-app launch.

This repository contains static analysis, exact reconstruction of a supplied
EFI payload, and read-only stock boot-log observations. It does not contain a
verified SM8750 SuperFastboot port.
Do not describe static marker matches as successful device execution.

Use absolute file offsets, PE RVA, and decompressed-buffer offsets explicitly;
do not mix those address spaces. Fixed offsets apply only to identified hashes.

Keep firmware, EDL loaders, credentials, and device identifiers outside Git.
Record hashes and private input acquisition notes instead of embedding secrets.
Do not create a firmware flashing step from an unverified assumption.

For changes affecting extraction or patch reproduction, run the documented
offline analysis and verification against the original input archive. Update
evidence only when an intentional analysis change requires it. New claims need
their source, bytes/offsets, method, and remaining uncertainty documented.

Keep useful work in Git commits. Update HANDOFF.md and HISTORY.md when a
research milestone changes what the next contributor should do.
