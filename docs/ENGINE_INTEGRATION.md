# Engine integration and release blockers

## AdGuard DNSLib
Official Android build documentation: https://github.com/AdguardTeam/DnsLibs/blob/master/docs/android.md

The upstream project includes an Android AAR and TUN test application. Integrate a pinned upstream revision, build its native dependencies and verify the packet path on physical Android devices. Do not start a VPN or claim DNS protection until the complete data path preserves ordinary traffic, IPv6 and network changes.

## YARA-X
Official project: https://github.com/VirusTotal/yara-x

Android JNI packaging, signed rule distribution, memory limits and representative benign test fixtures are pending. Never report rule matches as definitive malware classification without supporting evidence.

## Threat feeds
The bundled threat hash list is intentionally empty. A production feed requires a lawful redistributable source, provenance, updates, signature verification, expiry and rollback protection.

## Release blockers
- Production DNS engine and packet forwarding not integrated.
- YARA-X not integrated.
- No real threat signature feed.
- No signed rule updates.
- No physical-device verification.
- No signed release APK or AAB.
- No Play policy review or publication.
