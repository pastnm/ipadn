#!/usr/bin/env python3
"""Verify the unsigned universal device IPA, including both icon idioms."""
import hashlib
import json
import os
import plistlib
import sys
import zipfile
from pathlib import Path
from macho_audit import audit_macho, deployment_errors, is_macho, maximum_for_member, version_tuple
ALTERNATE_ICONS = ['AppIconAuto', 'AppIconFlat', 'AppIconLight', 'AppIconDark', 'AppIconFlatLight', 'AppIconFlatDark']

ROOT = Path(__file__).resolve().parents[1]
ipa = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'build/iPadn-unsigned.ipa'
prefix = 'Payload/iPadn.app/'
with zipfile.ZipFile(ipa) as archive:
    corrupt = archive.testzip()
    if corrupt is not None:
        raise ValueError('Corrupt IPA entry: ' + corrupt)
    names = archive.namelist()
    assert len(names) == len(set(names)), 'Duplicate ZIP members are not allowed'
    info = plistlib.loads(archive.read(prefix + 'Info.plist'))
    extension = prefix + 'PlugIns/iPadnLiveActivity.appex/'
    assert extension + 'Info.plist' in names, 'Full IPA requires the Live Activity/widget extension'
    extension_info = plistlib.loads(archive.read(extension + 'Info.plist'))
    assert extension_info['CFBundleIdentifier'] == 'app.local.iPadn.LiveActivity', 'Unexpected extension identifier'
    required_executables = set()
    for bundle, metadata in [(prefix, info), (extension, extension_info)]:
        executable_name = metadata['CFBundleExecutable']
        assert executable_name and '/' not in executable_name and executable_name not in ('.', '..'), 'Invalid bundle executable name'
        executable_path = bundle + executable_name
        assert executable_path in names, 'Missing bundle executable: ' + executable_path
        required_executables.add(executable_path)
    assert info.get('NSSupportsLiveActivities') is True, 'Live Activities not declared'
    assert info['CFBundleDisplayName'] == 'iPadn', 'Unexpected application name'
    assert info['CFBundleIdentifier'] == 'app.local.iPadn', 'Unexpected bundle identifier'
    assert set(info['UIDeviceFamily']) == {1, 2}, 'Both iPhone and iPad must be supported'
    for key in ['CFBundleIcons', 'CFBundleIcons~ipad']:
        icons = info[key]
        assert icons['CFBundlePrimaryIcon']['CFBundleIconName'] == 'AppIcon', key
        for name in ALTERNATE_ICONS:
            alternate = icons['CFBundleAlternateIcons'][name]
            assert alternate['CFBundleIconFiles'], 'Missing standalone alternate icon declaration: ' + key + ' ' + name
    for name in ALTERNATE_ICONS:
        for suffix in ['60x60@2x.png', '60x60@3x.png', '76x76@2x~ipad.png', '83x83@2x~ipad.png']:
            assert prefix + name + suffix in archive.namelist(), 'Missing alternate icon PNG: ' + name + suffix
    manifest = json.loads((ROOT / 'vendor/SAPRuntime/manifest.json').read_text())['files']
    for filename, expected in manifest.items():
        actual = hashlib.sha256(archive.read(prefix + 'SAPRuntime/' + filename)).hexdigest()
        assert actual == expected, 'Bundled runtime hash mismatch: ' + filename
    assert not any('localhost-test-only' in name or name.endswith('.p12') for name in archive.namelist()), 'Unexpected test or TLS private identity in IPA'
    macpkg = (prefix + 'Unicorn-GPL-2.0.txt') in archive.namelist()
    if macpkg or os.environ.get('IPADN_REQUIRE_MACPKG') == '1':
        executable = archive.read(prefix + info['CFBundleExecutable'])
        for symbol in [b'_iPadnMacPKGDecrypt', b'_iPadnMacPKGStatus', b'_uc_emu_start']:
            assert symbol in executable, 'Mac PKG bridge symbol missing: ' + symbol.decode()
        assert macpkg and prefix + 'ipatool-MIT.txt' in archive.namelist(), 'Missing Mac PKG bridge license notices'
    native = (prefix + 'idevice-MIT.txt') in archive.namelist()
    if native or os.environ.get('IPADN_REQUIRE_NATIVE') == '1':
        executable = archive.read(prefix + info['CFBundleExecutable'])
        for symbol in [b'_iPadnNativeInstall', b'_iPadnNativeLookup', b'_iPadnNativeList', b'_iPadnNativeCancel', b'_iPadnNativeFree',
                       b'_iPadnNativePair', b'_iPadnNativePairCancel']:
            assert symbol in executable, 'Native installation symbol missing: ' + symbol.decode()
        assert native, 'Missing native installation license notice'
        for service in ['_remotepairing._tcp', '_remotepairing-pairable-host._tcp']:
            assert service in info.get('NSBonjourServices', []), 'Missing Bonjour service declaration: ' + service
    assert prefix + 'embedded.mobileprovision' not in archive.namelist(), 'Unexpected provisioning profile'
    assert not any(name.startswith(prefix + '_CodeSignature/') for name in archive.namelist()), 'Unexpected signing envelope'

    # Inspect every embedded Mach-O, not just CFBundleExecutable or plists.
    # Imports are evidence for a later iOS 16 symbol audit, not proof that every
    # strong symbol exists on iOS 16 or that a weak symbol is guarded correctly.
    macho_results = []
    static_errors = []
    for name in names:
        if not name.startswith(prefix) or name.endswith('/'):
            continue
        if '..' in name.split('/'):
            static_errors.append('Unexpected parent traversal in ZIP member: ' + name)
            continue
        if name.endswith('/Info.plist'):
            metadata = plistlib.loads(archive.read(name))
            maximum = maximum_for_member(name)
            minimum = metadata.get('MinimumOSVersion')
            if name in (prefix + 'Info.plist', extension + 'Info.plist') and minimum is None:
                static_errors.append(name + ': missing MinimumOSVersion')
            if minimum is not None:
                try:
                    if version_tuple(minimum) > version_tuple(maximum):
                        static_errors.append(name + ': plist minimum %s exceeds %s' % (minimum, maximum))
                except ValueError as error:
                    static_errors.append(name + ': ' + str(error))
        with archive.open(name) as stream:
            magic = stream.read(4)
        if not is_macho(magic):
            if name in required_executables:
                static_errors.append(name + ': required executable is not Mach-O')
            continue
        maximum = maximum_for_member(name)
        result = {'path': name, 'maximum_os': maximum}
        try:
            result['slices'] = audit_macho(archive.read(name))
            result['errors'] = deployment_errors(result['slices'], maximum)
        except (ValueError, OverflowError) as error:
            result['slices'] = []
            result['errors'] = [str(error)]
        static_errors.extend(name + ': ' + error for error in result['errors'])
        macho_results.append(result)
    for executable_path in required_executables:
        if not any(item['path'] == executable_path for item in macho_results):
            static_errors.append('Required executable was not audited: ' + executable_path)

report = {
    'passed': not static_errors,
    'version': info['CFBundleShortVersionString'],
    'build': info['CFBundleVersion'],
    'bundle_id': info['CFBundleIdentifier'],
    'checks': ['ZIP CRC integrity', 'iPadn identity', 'phone/pad primary and alternate icon metadata',
               'vendored runtime SHA-256', 'no provisioning profile or signing envelope',
               'Mac PKG bridge linked' if macpkg else 'Mac PKG bridge not linked',
               'full Live Activity/widget extension present',
               'Mach-O minimum OS/platform checked for every embedded device slice',
               'native installation linked' if native else 'native installation not linked'],
    'macho_files_checked': len(macho_results),
    'macho_import_report': 'macho-audit.json',
    'errors': static_errors,
    'not_run': ['iOS 16 launch and UI tests', 'iOS 16 system-export comparison for strong imports',
                'weak-import call-site guard validation', 'legacy native transport interoperability',
                'Apple authorization', 'real-device installation', 'launch animation'],
}
(ROOT / 'build').mkdir(exist_ok=True)
(ROOT / 'build/macho-audit.json').write_text(json.dumps({
    'passed': not static_errors,
    'scope': 'Static Mach-O commands and import records; not runtime compatibility proof',
    'binaries': macho_results,
    'errors': static_errors,
}, ensure_ascii=False, indent=2) + '\n')
(ROOT / 'build/ipa-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False, indent=2))
if static_errors:
    sys.exit(1)
