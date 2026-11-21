# EUM SECURITY PRO

Android security application development repository.

## Current status
Early prototype. APK metadata inspection and SHA-256 hashing are under development. VPN ad blocking, production threat intelligence, YARA-X integration, signed updates, release builds and device verification are **not yet implemented or verified**.

## Release policy
Do not publish to Google Play or claim active malware protection until real engine integration, independent tests, privacy and permission reviews, and signed AAB build are complete.

## Planned modules
- Android Kotlin + Jetpack Compose
- DNS filtering via VpnService and verified packet forwarding
- APK static inspection and SHA-256 matching
- Signed threat rule updates
- CI and device testing
