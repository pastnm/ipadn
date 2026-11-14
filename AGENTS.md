# iPadn 2.1.1 B39 upstream synchronization

- User requested syncing upstream settings-crash fix and retaining B38 VPN connection.
- Upstream main b8eaa07fc1f78881ace1c8be8c97362db49dcc7c; v2.1.1 code commit c4052f41506ff8e0d5412dd953eaca1c96dfccfe. Main differs from the tag only in AltStore release metadata.
- Keep every NativeInstall file, Cargo dependencies/lock, NativeInstaller.swift and legacy transport, TLS, heartbeat, application query/install logic byte-identical to B38. Keep exact LocalDevVPN/Loon policy and interface binding.
- Retain all iOS16 compatibility, full native/Mac PKG/Unicorn/SAPRuntime/widget/Live Activities components and existing bundle identifiers; version2.1.1(39), app16.0 extension16.1.
- Sync all upstream2.1.1 application changes: safe help link, App Store URL handling, adaptive date-range filter, upstream tests. Preserve B38 traditional certificate pairing support. No credential migration or new pairing required.
- Build locally and verify full IPA, host tests, upstream synchronization and byte identity against B38. XCTest build is not execution. Existing simulator runtime failures are recorded in prior environment logs. Real device behavior remains untested in this run.
- No system pairing database reads, device installation, trust/VPN configuration changes, messages or upstream publication. Deliver IPA/source/patches/report/logs into existing iCloud Drive/iPadn folder and verify hashes, preserving history.
