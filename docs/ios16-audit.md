# iOS 16.3.1 compatibility audit

## Baseline and delivery status

Audited upstream `main` at `0940a2f796feaedaa53308895580314379e6ecd5`. The release tag `v2.0.0` points to `1d4018d`; only the AltStore source metadata differs from HEAD. The checked app/extension version is 2.0.0, build 28.

**Status: uncompiled source fixes and legacy lockdown integration in progress. No rebuilt IPA, installed replacement, or verified iOS 16 native installation.** The original project in another workspace was not modified. The private destination https://github.com/pastnm/ipadn-ios16-fix.git already exists; the parent conversation records confirmation for source submission and GitHub Actions cloud compilation. The earlier statement that repository name/visibility and push authorization were pending was stale. The destination is now connected as `cloud`, while `origin` remains upstream. The first source-only repair was pushed to the private repair repository and triggered a cloud build; that run stopped at generated-files consistency before compilation (details below). No release, device pairing access, or app installation has been performed from this workspace.

## Installation Settings crash

`iPadn-iOS/iPadn/Views/InstallationSettingsView.swift` constructs its help Link unconditionally while building the Form. The original destination was `URL(string: "https://github.com/mengangs/ipadn#安装下载的应用")!`. That makes failure happen when entering the page, before tapping the help link and before its `.task` error handler can run.

A small signed Objective-C/Foundation probe was compiled and executed on this iOS 16.3.1 device. Results:

- `NSURL URLWithString:` returns nil for the original raw Chinese-fragment URL.
- It returns a valid URL for the percent-encoded equivalent.
- Setting `URLComponents.fragment` produces the same encoded address.
- The patched Swift source contains that safe encoded address.

The patch changes only the literal to its percent-encoded equivalent, preserving the help destination and Chinese anchor. This reproduces the underlying Foundation failure and establishes a concrete force-unwrap crash path. It is not a Swift execution test or a reproduction of the complete app page. A matching main-app `.ips` is still needed to attribute every reported crash to it; the extension report below is separate.

No direct crash cause was found in the normal NavigationLink/environment-object route. Certificate errors are caught; OnDevicePairing construction does not start pairing, audio, or a Live Activity. Button(systemImage:) is not an iOS 17 violation: SDK 17.4 declares the relevant client-emitted overloads for iOS 14/15. A wrapper elsewhere already guards newer design-system APIs.

## Live Activity extension crash

The supplied crash summary identifies `iPadnLiveActivity`, not the main app: DYLD missing `_$s7SwiftUI28ContainerBackgroundPlacementVMa`, with an image built for iOS 17 running on iOS 16.3.1.

The source matches this report:

- Generator and checked-in extension Debug/Release configurations target iOS 17.0, despite the main app targeting 16.0.
- Three widget branches call `containerBackground(for: .widget)` without an availability check.
- The registered SDK declares ContainerBackgroundPlacement and containerBackground as iOS 17 APIs. ActivityConfiguration is available from iOS 16.1; the numericText() overload used here is available from iOS 16.0.

Source patch:

- Set extension minimum deployment to 16.1 in both generator and project.
- Route all three widget backgrounds through a ViewBuilder helper, using containerBackground only in an iOSApplicationExtension 17.0 branch.
- On iOS 16 use ordinary background, with 16-point padding for home-screen widgets and no extra padding for the circular accessory.
- Keep the widget bundle, both Live Activities and all shortcut links.

This must be rebuilt, not implemented by editing the MinimumOSVersion plist of a prebuilt binary. The final Mach-O imports/minimum OS and extension launch have not been checked. The extension is not intended for iOS 16.0, where ActivityKit is unavailable; the investigated device is 16.3.1.

## Native installation on iOS 16

### Upstream baseline is not compatible

`NativeInstaller.swift:validatePairingFile` rejects records containing HostCertificate or DeviceCertificate and requires 32-byte RPPairing keys. Rust `NativeInstall/src/lib.rs:connect/open_tunnel` exclusively uses RpPairingFile, RemotePairingClient, a PSK tunnel, RSD and `connect_rsd` services. The script also builds the static library with an iOS 17.0 deployment target. Its Swift `isAvailable` checks C symbols only, not runtime support.

The upstream README limits this route to iOS 17.4+. Lowering deployment targets or bypassing the validation alone would not provide the missing protocol. No entry was hidden and no web-install substitution was made.

### Working-tree integration (not compiled or validated)

- Swift detects certificate records versus RPPairing records, rejects mixed/incomplete structures, and sends explicit `legacy_lockdown` or `remote_pairing` in every native lookup/list/install request. Legacy uses 62078 without Bonjour discovery; iOS 16–17.3 rejects remote records before connecting with instructions for a trusted traditional record.
- `InstalledAppsView` no longer hard-blocks iOS 16 behind 17.4 when a native listing symbol is present. This is capability exposure, not proof it works.
- The native library deployment target is 16.0 and requires a real rebuild. The main app/widget fixes remain in place; no extension is removed.
- Installation results no longer count `after: null`, a missing app or a placeholder as success. `verify` errors instruct users to inspect installed apps/App Store status before retrying, because the system may already have performed the install.
- XCTest source now covers both record structures, invalid/mixed records, modern/legacy routing and post-install verification failure. These tests have NOT run. Swift validation checks structure only; Rust must validate the crypto material.
- Rust integration is being prepared separately in `NativeInstall/src/legacy.rs` and related files, reusing the MIT pinned idevice dependency, with TLS/session/StartService and shared AFC/installation_proxy flows. Its exact TLS peer-authentication guarantees still require review; do not treat a trusted route warning as proof of peer identity.
- New legacy guidance/errors are Chinese source text; translations into the other shipped languages have not been supplied. Existing localization catalogs have not been removed.

### Protocol requirements and evidence

iOS 16 does have the older computer-style installation path: legacy lockdown pairing, TLS, AFC upload and installation_proxy. SideStore documents iOS 14+ support and a local VPN/lockdown approach; minimuxer's source connects to lockdownd through port 62078, stages an IPA with AFC and requests installation through an installation-proxy client. This establishes that the iOS 17.4 requirement belongs to the current RPPairing route, not to all computer-style installation protocols.

A suitable implementation would need:

1. A trusted certificate-based pairing record for this device, generated with the device owner's consent, normally from a computer after a trust confirmation. The current on-device iOS 27 pairing flow is not an iOS 16 replacement.
2. A compatible VPN/loopback route that makes the device's lockdown and service ports reachable. Existing RPPairing connectivity alone does not validate this. A VPN embedded in the app needs Network Extension provisioning; an external appropriately configured VPN can supply the route without granting that entitlement to iPadn itself. No VPN was inspected or configured here.
3. Separate parsing/storage for legacy and remote pairing credentials; never send a legacy file to RpPairingFile. Protect private keys, avoid logging/export/backup, validate that the record matches the intended device and do not silently re-pair.
4. TLS lockdown session and StartService support, AFC upload and cleanup, installation_proxy lookup/install/progress/cancellation, and metadata/data-preservation regression checks. This is a new backend integration, not just a UI patch.
5. An iOS 16-compatible native library and Swift app build, plus real-device testing. Package signatures, ownership/licensing and the system's downgrade/upgrade policies still apply. A native transport does not bypass them.

The already pinned MIT `idevice` 0.1.68 includes a `TcpProvider` accepting a legacy `PairingFile`, suggesting reuse without importing AGPL minimuxer code. Exact service API integration still requires code/test work. SideStore success with developer-signed applications alone does not prove this app's App Store package metadata/data-preservation requirements; that must be tested on an authorized target app.

Sources read (not integrated as code):

- https://raw.githubusercontent.com/SideStore/SideStore/develop/README.md
- https://raw.githubusercontent.com/osy/Jitterbug/master/README.md
- https://raw.githubusercontent.com/jkcoxson/minimuxer/master/src/device.rs
- https://raw.githubusercontent.com/jkcoxson/minimuxer/master/src/muxer.rs
- https://raw.githubusercontent.com/jkcoxson/minimuxer/master/src/install.rs
- https://docs.rs/idevice/0.1.68/src/idevice/provider.rs.html

No pairing credential or Apple account was read or requested. No claim is made that this device currently has the required pairing or route.

## Build and test evidence

- `git diff v2.0.0 HEAD --stat`: only AltStore metadata differs.
- `bash scripts/build_unsigned_ipa.sh` from `iPadn-iOS`: exits 1 at the explicit Xcode requirement check, before compiling or changing build products.
- Tool checks: Swift/Swift compiler, Xcode, Rust/cargo/rustup, Go, Python 3, Node and ditto unavailable.
- Objective-C probe: compiled with the prepared clang, signed with ldid and executed successfully on iOS 16.3.1; source-linked URL regression passes.
- `git diff --check`: passes.
- Swift compilation, Python project verification, XCTest, UI tests, full IPA verification, extension launch and real installation: NOT RUN.

The complete upstream build also includes ZIPFoundation via SPM, the vendored signing runtime, Rust native-install support and a Go Mac-PKG bridge. A new toolchain assumption must not silently skip these features. Use both REQUIRE flags for any eventual full IPA build. `BUILDING.md` contains stale 1.9.2/iOS 17 text; the project/generator/workflow were checked directly rather than relying on that line.

Source repair `fdbfa26` has now been pushed to the authorized private `cloud/main`, triggering Actions run `43241537429`. The supplied failure summary identifies the generated-files check, before IPA compilation/tests. Local read-only comparisons confirm that all five scanned file groups (73 app Swift files, 24 icon files, 8 test Swift files, 1 test fixture, 6 extension Swift files) already match case-insensitive ordering, but not the default POSIX app ordering. The generator now explicitly uses a stable case-folded key; CI runs Windows/POSIX regression tests before retaining the original full generated-output comparison. No `.pbxproj` membership or application behavior was changed by this follow-up. Python regeneration and the new Python tests cannot run on this device (Python is unavailable); cloud CI must validate them. No IPA/deb has yet been produced. Installation and real native-install acceptance still require separate authorization.
