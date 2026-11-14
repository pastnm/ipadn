"""Stable project ordering shared by Windows and POSIX generators."""


def sorted_project_paths(paths):
    # PureWindowsPath compares case-insensitively; PurePosixPath does not.
    # Spell the ordering explicitly to preserve the committed Windows order
    # on macOS/Linux too. The original spelling breaks case-only ties without
    # depending on directory enumeration order or the machine's locale.
    return sorted(paths, key=lambda path: (path.as_posix().casefold(), path.as_posix()))
