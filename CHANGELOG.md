# Changelog

## 0.3.1

### Added

- **Modern WPF GUI** (`gui/`, .NET 8). Replaced the WinForms front end with a
  dark, Malwarebytes-inspired interface: sidebar navigation (Scan / Quarantine /
  Categories), card-based findings with severity and category badges, preselect
  checkboxes driven by the category policy, and quarantine / allow actions.
- **Shipping installer** (`installer/feather.iss` + `installer/build.ps1`, Inno
  Setup 6). Self-contained .NET 8 build, ~46 MB, includes the scanner, GUI,
  docs and rules. Installs to `Program Files\Feather`, optional PATH entry,
  Start Menu + optional desktop shortcut. Built in CI and uploaded as an
  artifact.

### Changed

- GUI target changed from WinForms to WPF (no runtime dependency beyond the
  bundled .NET 8).
- `Scanner.FindExecutable` now also checks `{app}\bin\feather.exe` (installed
  layout) in addition to the development layout.

## 0.3.0

### Added

- **Categories.** Every finding carries a `Category` (`hacktool`, `adware`,
  `pua`, `injector`, `stealer`, `trojan`, ...) alongside its tier. ClamAV
  signature names and built-in rules map onto the same vocabulary, so
  "PUA.HackTool.OnlineFix" becomes `unwanted` / `hacktool`, not a nameless
  alarm. See `docs/CATEGORIES.md`.
- **Desktop GUI** (`gui/`, WPF, .NET 8). Dark, Malwarebytes-inspired theme:
  sidebar navigation, card-based findings with severity/category badges,
  preselect checkboxes driven by the category policy, quarantine and allow
  actions. It runs `feather.exe` and parses its JSON; it contains no detection
  code and cannot invent an action.
- **Quarantine** (`feather quarantine`, `quarantine-list`, `restore`). Copy,
  re-hash the copy, then remove the original. Objects are stored as
  `<sha256>.q`; every action is recorded in `manifest.tsv`. Nothing in a scan
  calls it. See `docs/QUARANTINE.md`.
- `--category` and `--reason` flags, and an optional category word in IOC files
  (`sha256 <hash> adware label`).
- JSON gained `category`, `categoryLabel` and `hits[].category`; text output
  shows the category next to the verdict.
- GUI build and artifact upload in CI; smoke test covers categories, quarantine
  and restore.

### Changed

- `Signal` and `RuleHit` carry `Category`; `Finding` exposes the category of the
  strongest signal.
- `Engine::applyExclusions` is public so cached findings can be re-filtered
  without re-reading the file.

## 0.2.0

### Added

- **Fusion layer.** Detection sources return `Signal`s; `verdict/fusion.h` owns
  the final tier. Sources no longer decide anything, which is what makes
  third-party engines usable without inheriting their judgement.
- **ClamAV adapter.** Optional `--clamd host:port` source speaking the
  documented `INSTREAM` protocol over a socket. No `libclamav` linkage, so the
  repository stays MIT and ClamAV stays optional.
- **Signature reclassification.** ClamAV `PUA.*` / `Tool.*` / `HackTool` /
  `Heuristics.*` detections are mapped to `unwanted`. Named families remain
  `malicious`.
- **Per-file warnings.** A failing source (clamd down, timeout) is reported on
  the file instead of being silently treated as clean.
- `tests/clamd.ps1` + `tests/mock-clamd.ps1`: adapter tested against a mock
  daemon, so no ClamAV install and no GPL code are needed in CI.

### Changed

- `Engine` now takes an `EngineConfig` (IOC database, exclusions, optional
  clamd endpoint) instead of positional arguments.
- JSON output gained `hits[].source` and `warnings[]`.
- Text output shows the originating source for every hit.

### Fixed

- 1 MiB hash buffer was allocated on the stack, overflowing the default thread
  stack and crashing on the first file.
- Cached verdicts are now scoped to the active source set. Enabling `--clamd`
  after a plain scan no longer reuses a stale `clean` result: the cache key
  includes a source fingerprint (`rules+ioc` vs `rules+ioc+clamav@host:port`).
- Exclusions are re-applied to cache hits, so adding or removing an allow rule
  takes effect immediately instead of requiring a cache wipe.

## 0.1.0

- Initial engine and CLI scanner: SHA-256, bounds-checked PE parser, hash IOC
  database, exclusions, four-tier verdict model, hash cache, JSON output,
  smoke tests, Windows CI.
