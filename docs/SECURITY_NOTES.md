# Security notes

- The SHA-256 lookup feed currently contains zero production threat hashes. No match is **not** a clean bill of health.
- Permission combinations are heuristic warnings, not evidence of malware.
- Ed25519 signature verification helper is not a complete updater. A production updater additionally requires a pinned trust key, monotonic version enforcement, secure transport, atomic installation and recovery.
- The Android 10 cryptographic provider's support for Ed25519 needs device testing.
- The DNS/VPN toggle must remain disabled until end-to-end packet forwarding and DNS filtering work.
- No real malware is executed by the application.
