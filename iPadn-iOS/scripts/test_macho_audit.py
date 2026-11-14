#!/usr/bin/env python3
"""Offline, synthetic Mach-O tests. No Apple SDK, device, signing or network."""
import json
import os
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from macho_audit import (audit_macho, bind_imports, deployment_errors, is_macho,
                         maximum_for_member, version_tuple)


def deployment(major=16, minor=0, platform=2, endian='<'):
    return struct.pack(endian + '6I', 0x32, 24, platform,
                       (major << 16) | (minor << 8), 27 << 16, 0)


def macho(commands, tail=b'', endian='<', wide=True, cpu=0x100000C, subtype=0):
    size = sum(len(command) for command in commands)
    fields = [0xFEEDFACF if wide else 0xFEEDFACE, cpu, subtype, 2, len(commands), size, 0]
    if wide:
        fields.append(0)
    return struct.pack(endian + ('8I' if wide else '7I'), *fields) + b''.join(commands) + tail


def dylib(name, weak=False):
    encoded = name.encode() + b'\0'
    size = (24 + len(encoded) + 7) & ~7
    return (struct.pack('<6I', 0x80000018 if weak else 0xC, size, 24, 0, 0, 0)
            + encoded + b'\0' * (size - 24 - len(encoded)))


class MachOAuditTests(unittest.TestCase):
    def test_build_version_uses_minimum_not_sdk(self):
        result = audit_macho(macho([deployment()]))
        self.assertEqual(result[0]['deployment'][0]['minimum_os'], '16.0.0')
        self.assertEqual(result[0]['deployment'][0]['sdk'], '27.0.0')
        self.assertEqual(deployment_errors(result, '16.0'), [])

    def test_legacy_minimum_command(self):
        command = struct.pack('<4I', 0x25, 16, (16 << 16) | (1 << 8), 17 << 16)
        result = audit_macho(macho([command]))
        self.assertEqual(deployment_errors(result, '16.1'), [])
        self.assertTrue(deployment_errors(result, '16.0'))

    def test_newer_minimum_fails(self):
        self.assertTrue(deployment_errors(audit_macho(macho([deployment(17)])), '16.0'))

    def test_missing_deployment_fails(self):
        self.assertTrue(deployment_errors(audit_macho(macho([])), '16.0'))

    def test_simulator_platform_fails_even_for_arm64(self):
        self.assertTrue(deployment_errors(audit_macho(macho([deployment(platform=7)])), '16.0'))

    def test_x86_legacy_slice_fails(self):
        legacy = struct.pack('<4I', 0x25, 16, 16 << 16, 17 << 16)
        self.assertTrue(deployment_errors(audit_macho(macho([legacy], cpu=0x1000007)), '16.0'))

    def test_every_fat_slice_is_checked(self):
        first = macho([deployment()])
        second = macho([deployment(17)], subtype=2)
        start = 48
        fat = (struct.pack('>2I', 0xCAFEBABE, 2)
               + struct.pack('>5I', 0x100000C, 0, start, len(first), 0)
               + struct.pack('>5I', 0x100000C, 2, start + len(first), len(second), 0)
               + first + second)
        result = audit_macho(fat)
        self.assertEqual(len(result), 2)
        self.assertTrue(any('slice 1' in error for error in deployment_errors(result, '16.0')))

    def test_fat64_little_endian(self):
        thin = macho([deployment()])
        fat = (struct.pack('<2I', 0xCAFEBABF, 1)
               + struct.pack('<IIQQII', 0x100000C, 0, 40, len(thin), 0, 0) + thin)
        self.assertEqual(deployment_errors(audit_macho(fat), '16.0'), [])

    def test_fat_bounds_are_checked(self):
        fat = struct.pack('>2I', 0xCAFEBABE, 1) + struct.pack('>5I', 0x100000C, 0, 999, 80, 0)
        with self.assertRaises(ValueError):
            audit_macho(fat)

    def test_fat_architecture_must_match(self):
        thin = macho([deployment()])
        fat = (struct.pack('>2I', 0xCAFEBABE, 1)
               + struct.pack('>5I', 12, 0, 28, len(thin), 0) + thin)
        with self.assertRaises(ValueError):
            audit_macho(fat)

    def test_32_bit_and_big_endian_headers(self):
        for endian, wide, cpu in [('<', False, 12), ('>', True, 0x100000C)]:
            with self.subTest(endian=endian, wide=wide):
                result = audit_macho(macho([deployment(endian=endian)], endian=endian, wide=wide, cpu=cpu))
                self.assertEqual(deployment_errors(result, '16.0'), [])

    def test_dylib_linkage_is_reported(self):
        result = audit_macho(macho([deployment(), dylib('/usr/lib/libSystem.B.dylib'),
                                    dylib('/System/Library/Frameworks/Translation.framework/Translation', weak=True)]))[0]
        self.assertEqual([item['linkage'] for item in result['dylib_dependencies']], ['strong', 'weak'])

    def test_symbol_table_weak_reference_flag(self):
        strings = b'\0_strong\0_weak\0'
        symoff = 32 + 24 + 24
        command = struct.pack('<6I', 2, 24, symoff, 2, symoff + 32, len(strings))
        symbols = struct.pack('<IBBHQ', 1, 1, 0, 0, 0) + struct.pack('<IBBHQ', 9, 1, 0, 0x40, 0)
        result = audit_macho(macho([deployment(), command], symbols + strings))[0]
        self.assertEqual(result['strong_imports'], ['_strong'])
        self.assertEqual(result['weak_imports'], ['_weak'])

    def test_bind_stream_imports(self):
        stream = b'\x11\x40_strong\0\x51\x70\x00\x90\x41_weak\0\x90\x00'
        start = 32 + 24 + 48
        command = struct.pack('<12I', 0x80000022, 48, 0, 0, start, len(stream), 0, 0, 0, 0, 0, 0)
        result = audit_macho(macho([deployment(), command], stream))[0]
        self.assertEqual(result['strong_imports'], ['_strong'])
        self.assertEqual(result['weak_imports'], ['_weak'])

    def test_bind_stream_operand_skipping(self):
        stream = b'\x20\x81\x00\x60\x7f\x80\x01\xa0\x01\xc0\x01\x01\xd0\x01\xd1\x40_name\0\x90\x00'
        self.assertEqual(bind_imports(stream), {('_name', False)})
        with self.assertRaises(ValueError):
            bind_imports(b'\x40_no_terminator')

    def test_chained_import_records(self):
        for kind, word, entry in [(1, 1 << 8, '<I'), (2, 1 << 8, '<Ii'), (3, 1 << 16, '<Qq')]:
            with self.subTest(kind=kind):
                record = struct.pack(entry, word, 0) if kind != 1 else struct.pack(entry, word)
                fixups = struct.pack('<7I', 0, 0, 28, 28 + len(record), 1, kind, 0) + record + b'_weak\0'
                start = 32 + 24 + 16
                command = struct.pack('<4I', 0x80000034, 16, start, len(fixups))
                result = audit_macho(macho([deployment(), command], fixups))[0]
                self.assertEqual(result['weak_imports'], ['_weak'])

    def test_malformed_commands_fail_closed(self):
        for command in [struct.pack('<2I', 0x32, 0), struct.pack('<2I', 0x32, 80),
                        struct.pack('<2I', 0x32, 8)]:
            with self.subTest(command=command), self.assertRaises(ValueError):
                audit_macho(macho([command]))

    def test_truncated_bind_operands_fail(self):
        with self.assertRaises(ValueError):
            bind_imports(b'\x20\x80')
        with self.assertRaises(ValueError):
            bind_imports(b'\xf0')

    def test_limits_follow_extension_ownership_including_frameworks(self):
        self.assertEqual(maximum_for_member('Payload/iPadn.app/Frameworks/F.framework/F'), '16.0')
        self.assertEqual(maximum_for_member('Payload/iPadn.app/PlugIns/X.appex/Frameworks/F.framework/F'), '16.1')
        self.assertEqual(maximum_for_member('Payload/iPadn.app/Resources/X.appexlike/F'), '16.0')

    def test_non_macho_and_bad_versions(self):
        self.assertFalse(is_macho(b'PK\x03\x04'))
        with self.assertRaises(ValueError):
            audit_macho(b'not a binary')
        self.assertEqual(version_tuple('16.1'), (16, 1, 0))
        for value in ['16.beta', '16.0.0.1', '-1', '１６.０']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                version_tuple(value)


class IPAIntegrationTests(unittest.TestCase):
    """Exercise the real verifier in an isolated temporary repository layout."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        scripts = self.root / 'scripts'
        scripts.mkdir()
        for name in ['verify_ipa.py', 'macho_audit.py']:
            (scripts / name).write_bytes((Path(__file__).resolve().parent / name).read_bytes())
        manifest = self.root / 'vendor/SAPRuntime'
        manifest.mkdir(parents=True)
        (manifest / 'manifest.json').write_text('{"files": {}}')
        self.prefix = 'Payload/iPadn.app/'
        self.extension = self.prefix + 'PlugIns/iPadnLiveActivity.appex/'
        icons = ['AppIconAuto', 'AppIconFlat', 'AppIconLight', 'AppIconDark', 'AppIconFlatLight', 'AppIconFlatDark']
        icon_metadata = {'CFBundlePrimaryIcon': {'CFBundleIconName': 'AppIcon'},
                         'CFBundleAlternateIcons': {name: {'CFBundleIconFiles': [name]} for name in icons}}
        self.info = {'CFBundleDisplayName': 'iPadn', 'CFBundleIdentifier': 'app.local.iPadn',
                     'CFBundleExecutable': 'iPadn', 'UIDeviceFamily': [1, 2],
                     'MinimumOSVersion': '16.0', 'CFBundleShortVersionString': '2.0.0', 'CFBundleVersion': '28',
                     'NSSupportsLiveActivities': True, 'CFBundleIcons': icon_metadata,
                     'CFBundleIcons~ipad': icon_metadata}
        self.extension_info = {'CFBundleIdentifier': 'app.local.iPadn.LiveActivity',
                               'CFBundleExecutable': 'iPadnLiveActivity', 'MinimumOSVersion': '16.1'}
        self.entries = {self.prefix + 'iPadn': macho([deployment()]),
                        self.extension + 'iPadnLiveActivity': macho([deployment(16, 1)])}
        for name in icons:
            for suffix in ['60x60@2x.png', '60x60@3x.png', '76x76@2x~ipad.png', '83x83@2x~ipad.png']:
                self.entries[self.prefix + name + suffix] = b'fixture icon'

    def run_verifier(self, include_extension=True):
        entries = dict(self.entries)
        entries[self.prefix + 'Info.plist'] = plistlib.dumps(self.info)
        if include_extension:
            entries[self.extension + 'Info.plist'] = plistlib.dumps(self.extension_info)
        ipa = self.root / 'fixture.ipa'
        with zipfile.ZipFile(ipa, 'w') as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        environment = dict(os.environ, IPADN_REQUIRE_MACPKG='0', IPADN_REQUIRE_NATIVE='0')
        return subprocess.run([sys.executable, str(self.root / 'scripts/verify_ipa.py'), str(ipa)],
                              env=environment, capture_output=True, text=True, check=False)

    def test_full_fixture_passes_and_reports_all_binaries(self):
        process = self.run_verifier()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        report = json.loads((self.root / 'build/macho-audit.json').read_text())
        self.assertTrue(report['passed'])
        self.assertEqual(len(report['binaries']), 2)

    def test_full_verifier_rejects_missing_extension(self):
        process = self.run_verifier(include_extension=False)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('requires the Live Activity/widget extension', process.stderr)

    def test_plist_16_does_not_hide_binary_17(self):
        self.entries[self.prefix + 'iPadn'] = macho([deployment(17)])
        process = self.run_verifier()
        self.assertNotEqual(process.returncode, 0)
        report = json.loads((self.root / 'build/ipa-verification.json').read_text())
        self.assertFalse(report['passed'])
        self.assertTrue(any('minimum 17.0.0 exceeds 16.0' in error for error in report['errors']))

    def test_framework_binary_is_not_skipped(self):
        self.entries[self.prefix + 'Frameworks/F.framework/F'] = macho([deployment(17)])
        process = self.run_verifier()
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('Frameworks/F.framework/F', process.stdout)

    def test_extension_framework_uses_16_1_limit(self):
        self.entries[self.extension + 'Frameworks/F.framework/F'] = macho([deployment(16, 1)])
        process = self.run_verifier()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)

    def test_extension_binary_minimum_is_checked(self):
        self.entries[self.extension + 'iPadnLiveActivity'] = macho([deployment(17)])
        process = self.run_verifier()
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('minimum 17.0.0 exceeds 16.1', process.stdout)

    def test_bundle_plist_minimum_is_also_checked(self):
        self.info['MinimumOSVersion'] = '17.0'
        process = self.run_verifier()
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('plist minimum 17.0 exceeds 16.0', process.stdout)

    def test_non_macho_required_executable_fails(self):
        self.entries[self.prefix + 'iPadn'] = b'not an executable'
        process = self.run_verifier()
        self.assertNotEqual(process.returncode, 0)
        self.assertIn('required executable is not Mach-O', process.stdout)


if __name__ == '__main__':
    unittest.main()
