## Arc Exporter (macOS)

Export Arc Browser profiles into cross‑browser importable artifacts, with optional direct import into Chrome/Chromium. Also includes optional helpers for Firefox/Zen.

### Features
- Exports per‑profile, cross‑browser artifacts under `arc-export/`:
  - bookmarks HTML (NETSCAPE format; importable by most browsers)
  - passwords CSV (widely importable)
  - cards CSV (reference only)
  - optional cookies.sqlite for Firefox/Zen (`--import-cookies`)
  - optional extensions report and suggested `policies.json` for Firefox/Zen (experimental)
- Optional: copies Arc profiles into new Chrome/Chromium profiles (non‑destructive), including:
  - passwords/cards merged into the Chrome profile (re‑encrypted with Chrome key)
  - extensions copied and registered so Chrome installs from the Web Store on launch (themes skipped)

### Requirements
- macOS
- Python 3.9+
- Arc and Google Chrome installed
- OpenSSL CLI available (for Chromium v10 decryption)

### Quick start
1) Fully quit Chrome (Cmd+Q).
2) Run:
```bash
python3 main.py
```
This writes portable exports to `arc-export/` and, by default, also creates new Chrome profiles (e.g., `Profile 1`, `Profile 2`, …). Use the flags below to tailor behavior.

### Common flags
```bash
# Only copy profiles + extensions into Chrome (skip exports)
python3 main.py --no-passwords --no-cards --no-bookmarks

# Only export artifacts (no Chrome profiles)
python3 main.py --no-copy-profiles

# Experimental: build AMO mapping + policies.json per profile (Firefox/Zen)
python3 main.py --experimental-amo-mapping

# Experimental: export cookies.sqlite per profile (Firefox/Zen)
python3 main.py --import-cookies
```

### Outputs
- Cross‑browser exports: `arc-export/profiles/<ArcProfileName>/`
  - `bookmarks_<ts>.html` (NETSCAPE)
  - `passwords_<ts>.csv`
  - `cards_<ts>.csv`
  - optional `extensions_report_<ts>.json` and `policies_<ts>.json` (Firefox/Zen)
  - optional `cookies_<ts>.sqlite` (Firefox/Zen)
- Chrome/Chromium (optional): `~/Library/Application Support/Google/Chrome/Profile N`

### Troubleshooting
- Extensions not showing in Chrome (when using Chrome import):
  - Ensure Chrome was fully closed before running.
  - Relaunch Chrome and switch to the newly created profile. Give it a minute; external descriptors will trigger installs.
  - If still missing, quit Chrome and remove the target profile’s `Secure Preferences` file, then relaunch. Check `chrome://policy` for blocks.
- Profiles too large:
  - The tool skips heavy site-data (Cache, Code Cache, GPUCache, IndexedDB, Storage, File System, Media Cache, etc.). New Chrome profiles should be a few hundred MB, not multi‑GB.
- Passwords/cards merge errors (Chrome import):
  - macOS Keychain access for “Arc Safe Storage”/“Chrome Safe Storage” may be required.

### Scope and formats
- By default, exports are generic/portable and not Firefox‑specific.
- Firefox/Zen‑specific artifacts are only created when you use the optional flags:
  - `--import-cookies` → produces Firefox‑format `cookies.sqlite`
  - `--experimental-amo-mapping` → suggests Firefox/Zen `policies.json`
  - No direct extension install to Firefox/Zen is performed.

### Notes
- The script is non-destructive: existing Chrome profiles are untouched; new ones are created with the next free index.
- All outputs are written in paths ignored by `.gitignore`.
- This project is licensed under the MIT License.
