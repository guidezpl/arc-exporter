## Arc Exporter (macOS)

Export Arc Browser profiles into cross‑browser importable artifacts, with optional direct import into Chrome/Chromium. Also includes optional helpers for Firefox/Zen.

### Features
- Exports per‑profile, cross‑browser artifacts under `arc-export/`:
  - bookmarks HTML (NETSCAPE format; importable by most browsers)
  - passwords CSV (widely importable)
  - cards CSV (reference only)
- Copies Arc profiles into new Chrome/Chromium profiles (non‑destructive), including:
  - passwords/cards merged into the Chrome profile (re‑encrypted with Chrome key)
  - extensions install is EXPERIMENTAL and disabled by default (see below)

### Requirements
- macOS
- Python 3.9+
- Arc and Google Chrome installed
- OpenSSL CLI available (for Chromium v10 decryption)

### Quick start
1) Fully quit Chrome and Arc (Cmd+Q).
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

# Experimental: attempt per‑profile Chrome extension install (UNSTABLE)
python3 main.py --experimental-extensions
```

### Outputs
- Cross‑browser exports: `arc-export/profiles/<ArcProfileName>/`
  - `bookmarks_<ts>.html` (NETSCAPE)
  - `passwords_<ts>.csv`
  - `cards_<ts>.csv`
  - optional `extensions_report_<ts>.json` and `policies_<ts>.json` (Firefox/Zen)
  - optional `cookies_<ts>.sqlite` (Firefox/Zen)
- Chrome/Chromium (optional): `~/Library/Application Support/Google/Chrome/Profile N`

### Scope and formats
- By default, exports are generic/portable and not Firefox‑specific.
- Firefox/Zen‑specific artifacts are only created when you use the optional flags:
  - `--import-cookies` → produces Firefox‑format `cookies.sqlite`
  - `--experimental-amo-mapping` → suggests Firefox/Zen `policies.json`
  - No direct extension install to Firefox/Zen is performed.

### Experimental features (status: currently broken)
- `--experimental-extensions`: Per‑profile extension preinstall for Chrome. Due to Chrome integrity checks and policy scope, automated installs may not complete or may require manual confirmation in each profile.
- `--experimental-amo-mapping`: Tries to map Chrome extensions to AMO and write suggested policies.
- `--import-cookies`: Exports Arc cookies into a Firefox‑format database.

### Contribution
Contributions are welcome! Please feel free to submit a pull request. This project is licensed under the MIT License.