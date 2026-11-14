#!/usr/bin/env python3
"""Offline regression tests for cross-platform Xcode project ordering."""
import re
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath

from project_paths import sorted_project_paths


class ProjectPathTests(unittest.TestCase):
    def test_windows_and_posix_have_identical_order(self):
        names = [
            'Services/AppLock.swift', 'App/ToolStore.swift',
            'Services/AppleService.swift', 'App/iPadnApp.swift',
            'Services/AppReleaseFeed.swift', 'App/Localization.swift',
            'Services/AppleAuthentication.swift', 'App/ToolIntents.swift',
            'Services/AppUpdateService.swift', 'Services/ApplePropertyList.swift',
        ]
        expected = [
            'App/iPadnApp.swift', 'App/Localization.swift',
            'App/ToolIntents.swift', 'App/ToolStore.swift',
            'Services/AppleAuthentication.swift', 'Services/ApplePropertyList.swift',
            'Services/AppleService.swift', 'Services/AppLock.swift',
            'Services/AppReleaseFeed.swift', 'Services/AppUpdateService.swift',
        ]
        for path_type in (PurePosixPath, PureWindowsPath):
            for inputs in (names, list(reversed(names))):
                actual = sorted_project_paths(path_type(name) for name in inputs)
                self.assertEqual([path.as_posix() for path in actual], expected)

    def test_case_only_ties_do_not_depend_on_enumeration(self):
        names = ['A.swift', 'a.swift', 'B.swift', 'b.swift']
        for path_type in (PurePosixPath, PureWindowsPath):
            for inputs in (names, list(reversed(names))):
                actual = sorted_project_paths(path_type(name) for name in inputs)
                self.assertEqual([path.as_posix() for path in actual], names)

    def test_committed_app_order_matches_generator(self):
        root = Path(__file__).resolve().parents[1]
        project = (root / 'iPadn.xcodeproj/project.pbxproj').read_text(encoding='utf-8')
        references = re.findall(r'path = "([^"\n]+/[^"\n]+\.swift)";', project)
        expected = [p.relative_to(root / 'iPadn').as_posix()
                    for p in sorted_project_paths((root / 'iPadn').rglob('*.swift'))]
        self.assertTrue(expected, 'No app source files found')
        self.assertEqual(references, expected)


if __name__ == '__main__':
    unittest.main()
