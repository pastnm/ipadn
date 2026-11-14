#!/usr/bin/env python3
"""Writes altstore-source.json from the published GitHub releases.

AltStore, SideStore, Feather and similar signing tools read this file to
list iPadn and offer its updates. Run after a release is published:

    python3 iPadn-iOS/scripts/generate_altstore_source.py

Uses GH_TOKEN or GITHUB_TOKEN when set (CI), else anonymous requests.
"""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

REPO = "pastnm/ipadn"
RAW = "https://raw.githubusercontent.com/" + REPO + "/main/"
ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "altstore-source.json"
KEEP = 10
DESCRIPTION = (
    "iOS 16 VPN compatibility fork maintained by pastnm, based on mengangs/ipadn. "
    "Keeps traditional lockdown pairing and B38 LocalDevVPN / Loon loopback support, "
    "alongside the full app, widgets and Live Activities.\n\n"
    "由 pastnm 维护，基于 mengangs/ipadn 的 iOS 16 VPN 兼容分支。保留传统 lockdown 配对、"
    "B38 的 LocalDevVPN / Loon 回环连接及完整功能、小组件和实时活动。"
)
SCREENSHOTS = ["01-search", "02-detail", "03-versions", "04-prices", "05-downloads", "06-purchased", "07-native-install"]


def fetch(url):
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "iPadn-source"})
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        request.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def notes(body):
    """Release notes without the build's verification line."""
    lines = [line for line in (body or "").replace("\r\n", "\n").split("\n") if not line.startswith("验证：")]
    return "\n".join(lines).strip()


def version_entry(release):
    """One source entry for a published release, or None when it has no package."""
    tag = release.get("tag_name", "")
    match = re.fullmatch(r"v?(\d+\.\d+\.\d+)(?:-b([1-9]\d*))?", tag)
    if release.get("draft") or release.get("prerelease") or match is None:
        return None
    assets = {asset["name"]: asset for asset in release.get("assets", [])}
    # The standard package (with the extension); the lite one is for App ID-limited signing.
    package = next((asset for name, asset in assets.items() if name.endswith("-unsigned.ipa") and "-lite-" not in name), None)
    if package is None:
        return None
    version = match[1]
    build, minimum = match[2] or version, "17.0"
    info = assets.get("build-info.json")
    if info is not None:
        try:
            details = json.loads(fetch(info["browser_download_url"]))
            declared_minimum = details.get("minimum_ios_app") or details.get("minimum_ios")
            if match[2] and (details.get("version") != version
                             or str(details.get("build")) != match[2] or not declared_minimum):
                raise ValueError("Incomplete or mismatched build-info.json for " + tag)
            build = str(details.get("build") or build)
            minimum = str(declared_minimum or minimum)
        except Exception as error:  # Keep the fallback only for older release tags.
            print("build-info for " + tag + ": " + str(error), file=sys.stderr)
            if match[2]:
                raise  # A fork build must not silently publish incorrect OS requirements.
    elif match[2]:
        raise ValueError("Missing build-info.json for " + tag)
    return {
        "version": version,
        "buildVersion": build,
        "date": release["published_at"],
        "localizedDescription": notes(release.get("body")),
        "downloadURL": package["browser_download_url"],
        "size": package["size"],
        "minOSVersion": minimum,
    }


def source(releases):
    versions = [entry for entry in (version_entry(release) for release in releases) if entry]
    versions.sort(key=lambda entry: (
        tuple(int(part) for part in entry["version"].split(".")),
        int(entry["buildVersion"]) if entry["buildVersion"].isdigit() else 0,
    ), reverse=True)
    versions = versions[:KEEP]
    if not versions:
        raise SystemExit("No published release with a package")
    latest = versions[0]
    return {
        "name": "iPadn · iOS 16 VPN",
        "identifier": "app.local.iPadn.pastnm.source",
        "subtitle": "iOS 16 VPN compatibility fork by pastnm",
        "description": DESCRIPTION,
        "iconURL": RAW + "docs/images/icon.png",
        "website": "https://github.com/" + REPO,
        "tintColor": "#111111",
        "featuredApps": ["app.local.iPadn"],
        "apps": [{
            "name": "iPadn",
            "bundleIdentifier": "app.local.iPadn",
            "developerName": "mengangs (upstream) / pastnm (compatibility fork)",
            "subtitle": "iOS 16 VPN compatibility fork by pastnm",
            "localizedDescription": DESCRIPTION,
            "iconURL": RAW + "docs/images/icon.png",
            "tintColor": "#111111",
            "category": "utilities",
            "screenshots": [RAW + "docs/images/en/" + name + ".jpg" for name in SCREENSHOTS],
            "versions": versions,
            "appPermissions": {
                "entitlements": [],
                "privacy": {
                    "NSLocalNetworkUsageDescription": "Loads signing resources and serves installation packages over this device's loopback address, and finds this device's installation service."
                },
            },
            # Fields older clients read instead of "versions".
            "version": latest["version"],
            "versionDate": latest["date"],
            "versionDescription": latest["localizedDescription"],
            "downloadURL": latest["downloadURL"],
            "size": latest["size"],
        }],
        "news": [],
    }


def main():
    releases = json.loads(fetch("https://api.github.com/repos/" + REPO + "/releases?per_page=30"))
    text = json.dumps(source(releases), ensure_ascii=False, indent=2) + "\n"
    OUTPUT.write_text(text, encoding="utf-8")
    print("Wrote " + str(OUTPUT.relative_to(ROOT)) + " with " + str(text.count('"buildVersion"')) + " versions")


if __name__ == "__main__":
    main()
