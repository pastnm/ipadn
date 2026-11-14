<div align="center">

<img src="docs/images/icon.png" width="120" alt="iPadn">

# iPadn · iOS 16 VPN compatibility fork

**Search, download and install the apps you own, on iPhone and iPad.**
Works with iPhone, iPad, Apple TV and Mac apps, including older versions and apps removed from sale.

[![Latest release](https://img.shields.io/github/v/release/pastnm/ipadn?label=latest&color=111111)](https://github.com/pastnm/ipadn/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/pastnm/ipadn/total?label=downloads&color=111111)](https://github.com/pastnm/ipadn/releases)
![Requires](https://img.shields.io/badge/iOS%20%2F%20iPadOS-16%2B-111111)
[![License](https://img.shields.io/github/license/pastnm/ipadn?label=license&color=111111)](LICENSE)

[简体中文](README.md) · **English**

[Download](https://github.com/pastnm/ipadn/releases/latest) · [Install a download](#installing-a-downloaded-app) · [FAQ](#frequently-asked-questions) · [Report a problem](https://github.com/pastnm/ipadn/issues) · [Support iPadn](#support-ipadn)

</div>

Maintained by [pastnm](https://github.com/pastnm), based on [mengangs/ipadn](https://github.com/mengangs/ipadn). The current release is **2.1.1 B39**, retaining B38 traditional pairing, LocalDevVPN / Loon loopback support and the full app. Upstream authorship, screenshots and component licenses are preserved.

> **Download this fork:** [B39 full IPA and source](https://github.com/pastnm/ipadn/releases/tag/2.1.1-b39). B39's in-app update check still reads upstream releases. Update this fork through this repository's Releases or the signing-tool source below to keep its compatibility changes.

<p align="center">
  <img src="docs/images/en/01-search.jpg" width="24%" alt="Search">
  <img src="docs/images/en/02-detail.jpg" width="24%" alt="App details">
  <img src="docs/images/en/03-versions.jpg" width="24%" alt="Version history and release notes">
  <img src="docs/images/en/04-prices.jpg" width="24%" alt="Regional price comparison">
</p>

<p align="center">
  <img src="docs/images/en/05-downloads.jpg" width="24%" alt="Downloads">
  <img src="docs/images/en/06-purchased.jpg" width="24%" alt="Purchases">
  <img src="docs/images/en/07-native-install.jpg" width="24%" alt="Native Install">
  <img src="docs/images/en/08-languages.jpg" width="24%" alt="Arabic interface">
</p>

---

## What’s new in 2.1.1 B39

- Sync upstream **2.1.1**: the Installation settings crash fix, safe App Store links and improved date-range filter layout.
- Retain **B38's connection implementation**: traditional lockdown pairing, LocalDevVPN / Loon loopback compatibility, and interface-bound heartbeat and dynamic installation services.
- **iOS 16 through 17.3 can use traditional pairing files.** Existing valid files remain usable. Upstream's “old format” message does not mean the file has expired or needs conversion to RPPairing.
- This fork currently publishes the **unsigned full package** with native install, Mac PKG, widgets and Live Activities. No lite package is published here. The app requires iOS 16.0, the extension requires iOS 16.1, and conventional signing needs two App IDs.
- Full Release compilation, IPA checks, 55 Rust host tests, 31 Python tests and four macOS pairing/help-link tests passed. iOS test targets compiled; B39 device connections, actual installation and data preservation still require device validation.

See [B39 changes and pairing formats](docs/local-v2.1.1-b39-upstream.md) and the [release verification report](https://github.com/pastnm/ipadn/releases/tag/2.1.1-b39).

## 2.1.0 highlights

- **Clearer version history**: each row shows its own package icon, IPA size and version details, making activity badges easy to compare without downloading the full package. Asset-catalog-only icons are not yet supported; unavailable icons use placeholders.
- **Find versions by date**: select inclusive start/end dates, with progress, cancellation and explicit unknown-date counts. Histories load in batches, with on-demand icons and a bounded decoded-image cache. Package dates can differ from store release dates.
- **More complete download controls**: swipe to delete/share, outside-tap dismissal, a five-second Undo countdown, completion transitions, and sequential automatic installation with the native method.
- **Inspectable installed apps**: view local version and Bundle ID even without store details, distinguish missing regional listings from lookup failures, and retry store details independently.
- Fixes clipped swipe edges, slow closing animations after dropped frames, duplicate installation queuing and wrapped search-chip corners. This fork retains these upstream features and currently publishes the full package only.

## What it does

| | |
| --- | --- |
| 🔍 **Search & discover** | Search by app name, App ID or App Store link, and switch storefront region and platform (iPhone / iPad / Apple TV / Mac). Recent searches appear as chips. Discover can be turned off in Settings; when enabled it shows Top Free, Top Paid and Top Grossing for any region, by category. App pages show screenshots, customer reviews and other apps by the same developer. |
| 🌐 **Translation** | Descriptions and release notes in another language can be replaced with the system translation (iOS 17.4 or later). |
| 🕘 **Older versions** | See each version's number, date, IPA package size, version-specific icon and release notes and download older versions, or enter a version ID directly. Long-press a row to copy its version number or ID; accessibility text sizes use a vertical layout. Unavailable sizes show “—”, never the latest version's size. Primary icon PNGs are read on demand from each version's IPA and cached separately. Unavailable icons use a placeholder, never current store artwork; asset-catalog-only icons are not yet supported. Downloaded apps can “Keep this version” to stop update reminders. |
| ⬇️ **Downloads** | Background downloads you can pause, resume and retry, with live speed and time remaining, also on the Lock Screen and in the Dynamic Island. Download over Wi‑Fi only and install automatically when a download finishes if you like. Swipe cards to delete or share; tap elsewhere to close the actions. Exported filenames include the app name and version. Deletion offers a five-second Undo countdown, and completion changes the progress ring to a checkmark and Install. Long-press uses the system menu; tap the selected tab again to scroll to the top. Task details show the permissions, extensions and languages a package declares. |
| 🔔 **Update alerts** | Downloaded apps with a newer version are marked in the list, and background checks send a notification. |
| ⬆️ **iPadn updates** | B39's built-in check still reads upstream. Update this compatibility fork through this repository's Releases or its signing-tool source below. |
| 👀 **Follow apps** | Get notified about new versions, price drops, free promotions or removals, with a price history. |
| 🌏 **Regional prices** | Compare app and in-app purchase prices (including subscriptions) across regions, converted to your chosen currency and sorted from lowest. You pick the regions. |
| 📲 **One-tap install** | Tap “Install” when a download finishes. No profile or certificate needed, with live progress. |
| 🧩 **Native install** | Installs through the system's own installation service, with the same result as installing from a computer: the App Store recognizes and updates the app, and an App Store copy can be replaced in place with its data kept. You can also block App Store updates for the app. From iOS 27, pairing is done on the device without a computer. |
| 📱 **Apps on this device** | Lists the apps installed on your phone and updates every app with a newer App Store version in one go. Apps without a store listing still open their on-device version, bundle ID and other available information. Missing regional listings and failed requests are distinguished, with a separate store-query retry. |
| 💻 **Wi‑Fi transfer** | Download finished packages in a browser on a computer on the same Wi‑Fi, only while the page is open. |
| 💻 **Mac apps** | Download PKG installers of Mac App Store apps and install them on a Mac. |
| 🛍️ **Purchases** | Sync every app you've acquired, find them by name or date, and download several at once. Find removed apps that can still be downloaded and back them all up; export the list as a spreadsheet. |
| 📦 **Removed apps** | If you acquired an app once, you can find it by App ID and download it even after it's removed from sale. |
| 👥 **Multiple accounts** | Save several Apple Accounts (email or phone number) and switch with one tap. |
| 🎮 **Apple Arcade** | Accounts subscribed to Apple Arcade can download Arcade games. |
| 🔒 **App lock** | Lock iPadn with Face ID, Touch ID or your passcode; its content is hidden in the app switcher too. |
| 🧭 **Widgets & Shortcuts** | Home Screen and Lock Screen widgets open Search, Downloads, Purchased or the update check; Shortcuts actions download apps, check for updates, report download progress, follow apps and more. |
| 🧰 **Pro mode** | Browse and extract files inside a package, compare two downloaded versions of an app, and view account tokens and the device identifier (off by default). |

The interface follows the App Store's design. Appearance follows the system and the icon is dark by default (both can be changed in Settings), with Dynamic Type, the iPad sidebar and alternate app icons.

**Languages:** English, Simplified Chinese, Traditional Chinese, Japanese, Korean, Russian, Spanish, French, German, Portuguese (Brazil) and Arabic, with a right-to-left layout for Arabic. iPadn follows the system language; to choose a different one for iPadn only, use Settings › iPadn › Language. English was refined by a community contributor and the other languages are machine-assisted translations; corrections are welcome in [Issues](https://github.com/pastnm/ipadn/issues) or a pull request.

## Getting started

> Requires **iOS / iPadOS 16** or later.

1. Download `iPadn-2.1.1-b39-iOS16-20261114-185014-unsigned.ipa` from the [B39 release](https://github.com/pastnm/ipadn/releases/tag/2.1.1-b39). It is the full package with widgets and Live Activities; conventional signing needs two App IDs. This fork currently has no lite package.
2. Sign it with your usual signing tool and install it on your device.
3. Open iPadn and sign in to your Apple Account under Account. If two-factor authentication is on, enter the 6-digit code shown on your trusted device.

> iPadn isn't on the App Store. Releases are unsigned, so you need to sign them yourself.

### Add the source to your signing tool

SideStore, AltStore, Feather and other tools that support AltStore sources can add the address below. You can then install iPadn from the tool and update it there when a new version is out, without downloading the package by hand.

```
https://raw.githubusercontent.com/pastnm/ipadn/main/altstore-source.json
```

This source only lists published packages from `pastnm/ipadn`, currently version 2.1.1 (build 39), and excludes upstream packages. After publishing a new release, run `python3 iPadn-iOS/scripts/generate_altstore_source.py` to refresh it; automatic refresh after publication is not configured. The app bundle identifier stays `app.local.iPadn`.

## Downloading an app

1. In **Search**, enter an app name, App ID or App Store link.
2. Tap “Get” to download the latest version, or open the app page and choose an older version under **Version history**.
3. Follow the progress in **Downloads**, then tap “Install” or the share button.

**Tips**

- For Apple TV or iPad versions, switch the platform below the search field.
- Can't find a removed app? Search for its App ID.
- When signed in, app pages load the full version list from Apple; apps your account hasn't acquired show the public version details.
- Touch and hold a download card to see details, export the file or delete the task.
- To download several purchases at once, tap “Select” in Purchased, tick them and tap “Download selected”.
- Packages taking too much space? Delete older versions in one go under Account › Settings › Storage.
- Version history incomplete? In the version source list under Account › Settings, tap “Check All Sources” to see whether each source works. In an endpoint URL, `{id}` or `{appId}` stands for the App ID.

## Installing a downloaded app

For a manual install, tap “Install” on the download card and follow the selected method. Web installation methods require confirmation in the system prompt; keep iPadn open until they finish.

With “Install When Downloaded” enabled and Native install selected, completed downloads install sequentially without another confirmation. Pair beforehand and keep LocalDevVPN or a supported Loon loopback connection active. Silent audio keeps the app running from downloading through installation; Lock Screen and Dynamic Island activities can show downloading, processing and installation states (standard package, with Live Activities enabled). iOS still controls background execution, so work cannot be guaranteed after the system terminates the app; reopening iPadn resumes pending work. Other methods still need iPadn in the foreground and their installation page and system prompts.

Choose the install method under Account › Settings › Installation settings:

| Method | For | What you need |
| --- | --- | --- |
| **One-tap install** (recommended) | Everyone | Nothing to set up; a network connection while installing |
| **Native install** | Getting App Store recognition and updates, or replacing an App Store copy | A valid pairing file and LocalDevVPN or Loon loopback configuration, see below |
| **Local certificate** | When one-tap install shows no prompt (for example inside LiveContainer) | Create a certificate in Installation settings, install its profile, and enable trust under Settings › General › About › Certificate Trust Settings |
| **Proxy service** | People already using Surge, Loon and similar tools | Your own manifest service address and proxy rules |

With a local certificate, the system asks “ipadn.localtest.me would like to install…”: that's the installation service iPadn runs on your device. With Surge, Loon, Shadowrocket or another proxy, you don't need to turn it off; add a DIRECT rule instead: `api.palera.in` for one-tap install, `ipadn.localtest.me` for a local certificate.

Installation shows its progress: the system starting, the package transfer percentage, and the transfer finishing. If no system prompt appears after tapping “Install”, tap “Install in Safari”, confirm there, then return to iPadn and wait.

One-tap install, local certificate and proxy service use the system's web installation channel, which can't replace an App Store copy of the same app. Use native install for that.

### Native install

One-tap install, local certificate and proxy service all go through the system's web installation channel. Apps installed that way aren't shown as installed in the App Store and can't be updated there; desktop tools such as 3uTools list them as “shared”; and they can't replace an App Store copy of the same app. Native install uses the installation service desktop tools use instead, with the same result as installing from a computer: the App Store recognizes and updates the app, and an App Store copy is replaced in place with its data kept. Packages never leave your device.

**1. Prepare a loopback VPN**

- **LocalDevVPN:** get [LocalDevVPN](https://apps.apple.com/app/localdevvpn/id6755608044) from the App Store and connect before native installation. Users have reported successful connection checks; it is a useful starting point for validating pairing and connectivity.
- **Loon:** B38 loopback compatibility is retained. Use a loopback-capable version (3.5.3 build 1007 or later), enable the appropriate loopback plugin and retain an existing working configuration. A route for `10.7.0.1/32` alone is insufficient: forward lockdown port 62078 and the dynamic service ports returned by the device. Loon compatibility is based on observed interfaces and host tests; complete authentication, heartbeat and installation still need device validation.

Connect one of these VPNs at a time. B39 does not create or modify your VPN configuration.

**2. Choose pairing for your system**

| System | Pairing method |
| --- | --- |
| **iOS / iPadOS 16 through 17.3** | Connect to a computer, trust it, export the traditional **lockdown pairing file** containing certificates, then import it under Installation settings › Native install. Existing valid files can be reused. |
| **iOS / iPadOS 17.4 through 26** | The upstream remote pairing method remains available: generate an **RPPairing** file with [idevice_pair](https://github.com/jkcoxson/idevice_pair) on a computer and import it. Existing valid traditional files continue to use lockdown. |
| **iOS / iPadOS 27 or later** | The upstream “Pair on This Device” flow remains available with Developer Mode enabled. Follow the app's guide to enter its pairing code in system Settings. |

Traditional files contain certificate and host information such as `HostCertificate`, `HostPrivateKey` and `HostID`; RPPairing uses remote pairing values such as `public_key`, `private_key` and `identifier`. **Renaming the extension or copying fields cannot convert between them.** Upstream's “old format” message reflects its remote-only validator. B39 accepts traditional files, so iOS 16 users need not pair again because of that message.

Tap “Import Pairing File”, or place the file in Files › On My iPhone › iPadn and open the Native install page to import it automatically. Pairing files contain sensitive keys; never upload them to GitHub, cloud storage or a bug report.

**3. Check the connection**

Unlock the device, connect the chosen loopback VPN, return to iPadn and tap “Check Connection”. After it succeeds, validate installation, in-place updates and App Store recognition. B39 retains B38's protocol and route implementation; not every system, VPN configuration or app has been verified.

Updating to B39 alone does not require a new pairing file. If a trust change or system restore invalidates authentication, export a new file from a trusted computer. For route failures, check the VPN first; importing the pairing file again cannot fix the route.

You can also tap the share button to hand the package to another installation tool.

## Mac apps

1. Switch the platform below the search field to **Mac**.
2. Open the app page and tap “Get PKG”.
3. When the download finishes, tap the share button and send it to your Mac with AirDrop or Files to install it.

The first Mac download fetches about 47 MB of extra components, which are reused afterwards. DMG / PKG / ZIP installers the developer offers on their website can also be downloaded from the app page.

## Pro mode

After turning on Pro mode under Account › Settings:

- Download task details offer “Browse package contents”, where you can view and extract any file and preview text and images.
- Package info can compare a download with other downloaded versions of the same app: version, permissions, extensions, frameworks and more.
- Settings shows “Account & device identifier”, with account tokens and the option to change the device identifier. Tokens give direct access to your Apple Account, so never share them; after changing the device identifier, accounts may need to sign in again.

## Your data

- Account details are stored only on your device; verification codes are never saved.
- Downloaded packages stay on your device and are never uploaded anywhere. Wi‑Fi transfer runs only while its page is open, uses an address with a random key, answers only devices on your local network and stops when you leave the page.
- Price comparison fetches reference exchange rates from open.er-api.com; requests contain no account information.
- Removing an account doesn't delete downloaded packages. Deleting a download task also deletes its file, after a confirmation.

## Frequently asked questions

<details>
<summary><b>Why can't I download a certain app or version?</b></summary>

Apple only lets you download apps your account holds a license for. A version may also have been removed or not be offered in the current region. Try another version, switch storefront region, or switch to an account that owns the app.
</details>

<details>
<summary><b>Nothing happens after tapping “Install”?</b></summary>

Make sure the device is online, and tap “Install” in the system prompt. If no prompt appears, tap “Install in Safari”, or switch to “Local certificate” in Installation settings (especially inside LiveContainer). If it still doesn't work, share the package with another installation tool, or export diagnostics under Settings › Maintenance and send them to us.
</details>

<details>
<summary><b>In LiveContainer, files can't be imported or exported, or one-tap install does nothing?</b></summary>

In LiveContainer, long-press iPadn and turn on “Fix File Picker” in its settings. Importing and exporting packages and diagnostics then works, and one-tap install can show the system install prompt.
</details>

<details>
<summary><b>“Already installed, delete it and try again”?</b></summary>

One-tap install, local certificate and proxy service use the system's web installation channel, and iOS doesn't let that channel replace an App Store copy of the same app. Use native install instead: it replaces the app directly and keeps its data. Native install is still refused when the version you're installing is older than the installed one (iOS doesn't allow downgrades), or when the installed copy came from TestFlight or another signing tool.
</details>

<details>
<summary><b>Why does the App Store show a cloud icon and no update, and desktop tools list the app as “shared”?</b></summary>

The app was installed with one-tap install, local certificate or proxy service. The system's web installation channel drops the purchase record inside the package, so the App Store and desktop tools don't recognize it. Install it once more with native install to fix it; its data is kept.
</details>

<details>
<summary><b>Why does pairing need a computer below iOS 27? Is it only once?</b></summary>

Native install uses the system's own installation service, the same one a computer uses to install apps, and it only accepts paired, trusted connections. Before iOS 27, Apple only lets a computer start that pairing over a cable (you tap “Trust This Computer” and enter your passcode); an app on the phone can't start it, so the pairing file has to be made on a computer first. iOS 27 added on-device pairing under Developer Mode, which is what “Pair on This Device” uses.

B39 uses traditional lockdown pairing on iOS 16 through 17.3 and keeps RPPairing on iOS 17.4 or later. Existing valid files remain usable; export a new one if a trust change or system restore invalidates authentication. Updating to B39 alone does not require pairing again.
</details>

<details>
<summary><b>Native install says it can't reach the installation service?</b></summary>

- Unlock the device and connect LocalDevVPN or a supported Loon loopback configuration; do not run both VPNs at once.
- Loon needs full loopback forwarding. A route for `10.7.0.1/32` alone does not provide the installation services. Other proxy tools are not guaranteed substitutes.
- Distinguish route, pairing, heartbeat and installation-service failures before replacing credentials. Export a new file only for confirmed pairing failures. If it still fails, copy diagnostics under Account › Settings › Maintenance; never attach the pairing file.
</details>

<details>
<summary><b>No pairing code, or no “Pair with iPadn” in Settings?</b></summary>

- On-device pairing needs iOS / iPadOS 27 or later, with Developer Mode on.
- Tap “Pair on This Device” first, then go to Settings; iPadn keeps running in the background while pairing. The code appears in the Dynamic Island, on the Lock Screen and in a notification. Allow notifications and Live Activities under Settings › iPadn.
- Pairing stops after 5 minutes of waiting; tap “Pair on This Device” again.
</details>

<details>
<summary><b>Downloading or getting an app asks for a verification code, but none arrives?</b></summary>

- iPadn asks Apple to send the code for you. Codes only go to an iPhone, iPad or Mac signed in to the same Apple Account, never by text message. When “Apple Account Sign-In Requested” appears on that device, tap Allow.
- If it doesn't appear, get a code on that device under Settings › [your name] › Sign-In & Security › Get Verification Code; it works the same.
- You can tap “Resend Code”. Apple may stop sending for a while after many requests.
- If getting free apps also asks for verification, the Apple Account usually requires a password for free downloads. On a device signed in to the account, open Settings › Media & Purchases › Password Settings and turn it off; the option isn't there when Face ID is used for purchases.
- Apple sometimes asks for verification again based on its own risk checks. That's up to Apple; the download continues automatically after you verify.
</details>

<details>
<summary><b>Tapping “Get” takes a while before the download starts?</b></summary>

Each request first needs the signature Apple requires, made on your device. Right after opening iPadn, or after more than 5 minutes idle, the signing component takes a few seconds to load; apps you've never downloaded also need a license claimed first, which takes two more requests to Apple. iPadn prepares the signing component when you open an app page, and your downloads go ahead of background work.
</details>

<details>
<summary><b>A download reaches 100% and then starts over?</b></summary>

With some signing methods, the system's background download service can't save files into iPadn, so the download has to run again inside the app. On the first launch after each install, iPadn tests this with a tiny file and switches straight to in-app downloading if needed, so nothing downloads twice. Keep iPadn in the foreground during in-app downloads; they pause about 30 seconds after it goes to the background. After re-signing, tap “Try Background Downloads Again” under Settings › Downloads.
</details>

<details>
<summary><b>How do I find an app that was removed from the store?</b></summary>

Search for its App ID. As long as your account acquired the app once, you can still download it, and its icon is remembered after the first download.
</details>

<details>
<summary><b>What if a download stalls?</b></summary>

Check the connection, then pause and resume. A failed download can be retried directly and isn't added twice.
</details>

<details>
<summary><b>Can I download TestFlight builds?</b></summary>

Not currently. Existing IPA files can be imported with the “+” button on the Downloads page.
</details>

<details>
<summary><b>Why do regional prices show only China's in-app purchases?</b></summary>

On mainland Chinese networks Apple redirects other regions' App Store pages to China, so their in-app prices can't be read (the app's own price is unaffected). Route apps.apple.com through your proxy, then pull to refresh.
</details>

<details>
<summary><b>Does removing an account delete downloaded apps?</b></summary>

No. Removing an account only clears that account's sign-in details and purchase records.
</details>

## Support iPadn

The following support channels belong to **upstream author mengangs**. They retain the upstream payment details and do not collect funds for this fork's maintainer.

<div align="center">

<sub>❤️ ❤️ ❤️</sub>

iPadn will always be **free, open source and ad-free**.<br>
If it saves you time or you simply enjoy it, you're welcome to buy the author a coffee ☕<br>
Your support keeps the updates coming.

<a href="https://afdian.com/a/mengangs"><img src="https://img.shields.io/badge/Afdian-Buy%20me%20a%20coffee-946ce6?style=for-the-badge&logo=buymeacoffee&logoColor=white" alt="Afdian"></a>
<img src="https://img.shields.io/badge/USDT-BEP20-26a17b?style=for-the-badge&logo=tether&logoColor=white" alt="USDT BEP20">

| Afdian (Alipay, WeChat Pay) | USDT (BNB Smart Chain / BEP20) |
| :---: | :---: |
| [**afdian.com/a/mengangs**](https://afdian.com/a/mengangs)<br><sub>Monthly or one-time</sub> | <img src="docs/images/usdt-bep20.png" width="180" alt="USDT QR code"><br><code>0x5f0cff7587b9fc305f9fa626135789bd5100818e</code> |

<sub>Before sending USDT, check that the network is BEP20 and the address matches exactly; funds sent on another network or in another token may be lost.<br>You can also scan or copy the address in iPadn under Account › Settings › Support iPadn.<br>Starring the repo, reporting problems and improving translations help just as much.</sub>

</div>

## Contributing

- **Translations:** every interface string lives in [`Localizable.xcstrings`](iPadn-iOS/iPadn/Resources/Localizable.xcstrings); open it in Xcode to edit entries one by one. Pull requests that improve a language or add a new one are welcome.
- **Bug reports:** describe your device, system version and steps in [Issues](https://github.com/pastnm/ipadn/issues). If you can, attach the file from Account › Settings › Export diagnostics; it contains no account names or credentials.
- **Building:** see [BUILDING.md](iPadn-iOS/BUILDING.md).

## Acknowledgements

- The original project [mengangs/ipadn](https://github.com/mengangs/ipadn) is developed by mengangs; pastnm maintains this repository's iOS 16 VPN compatibility changes.

- [kylefmohr](https://github.com/kylefmohr) contributed the English translation ([#35](https://github.com/mengangs/ipadn/pull/35)).
- Thanks to everyone who reported problems and suggested ideas, and to the open-source projects iPadn uses, listed in [Third-party components and licenses](iPadn-iOS/THIRD_PARTY_NOTICES.md).

## More

- [B39 changes and pairing formats](docs/local-v2.1.1-b39-upstream.md)
- [Upstream 2.1.1 release notes](RELEASE_NOTES.md)
- [Building from source](iPadn-iOS/BUILDING.md)
- [Third-party components and licenses](iPadn-iOS/THIRD_PARTY_NOTICES.md)

## License

iPadn is released under [GPL-2.0-or-later](LICENSE): you may use, modify and redistribute it, and modified versions must be released under the same license.

<sub>iPadn is not affiliated with Apple Inc. Only download apps you are legally licensed to use.</sub>
