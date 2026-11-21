# feather

A lightweight Windows file scanner that **classifies instead of condemning**.

Most scanners collapse "this is a game fix" and "this is a stealer" into a single
red popup and delete both. feather keeps them apart, tells you what it actually
found, and never deletes anything behind your back.

> **Status: alpha.** The detection engine, CLI scanner, desktop GUI, explicit
> quarantine and the optional ClamAV adapter work today. On-access protection
> exists too, but it needs a self-signed kernel driver: **Secure Boot must be
> disabled** and test signing enabled before it can load. Until then feather is
> an on-demand scanner, and the dashboard says so honestly. It is not a
> replacement for Defender.

## What it looks like

Run `gui\bin\Release\net8.0-windows\Feather.exe` (or `dotnet run --project gui`):

- It scans a folder and lists only what it flagged, with the **category** each
  finding belongs to: `HackTool`, `Adware`, `PUA`, `Injector`, `Stealer`, ...
- Every row has a checkbox. Your category policy only *preselects* rows: mark
  `Adware` as auto-select and `HackTool` as manual, and the box state follows
  that. You still press the button.
- **Quarantine checked** copies the files (verifying the copy by hash) and only
  then removes the originals. **Allow checked** writes a hash exclusion instead,
  so the file stays where it is and stops being flagged.
- The details pane shows every signal, its source and its reason. No verdict is
  unexplained.

Nothing is deleted by a scan. The optional real-time layer quarantines (never
wipes) a detection, and every such action is recorded and shown on the dashboard.

## Architecture: sources in, one verdict out

```
sources/                 each source is an adapter, not a decider
  rules/                 built-in static heuristics
  ioc/                   known-bad SHA-256 lookup
  clamav/                optional clamd client (INSTREAM over TCP)
        |
        v  Signal{ source, id, severity, category, detail }
verdict/fusion            strongest signal wins; exclusions applied
        |
        v
     Finding              one file, one tier, one category, every reason attached
        |
        +--> CLI          text / JSON
        +--> GUI          WPF dashboard: checkbox per finding, category policy
        +--> feathersvc   SYSTEM service: verdicts for on-access opens
                 ^
                 | FltSendMessage / FilterReplyMessage
        +--> featherflt   minifilter: blocks executable opens on a bad verdict
```

No source controls the verdict. That is what lets ClamAV's
`PUA.HackTool.*` signatures become `unwanted` without touching ClamAV itself:

| ClamAV signature | feather tier |
|---|---|
| `PUA.*`, `Tool.*`, contains `HackTool` | `unwanted` |
| `Heuristics.*` | `unwanted` |
| `Win.Trojan.*`, `Win.Ransomware.*`, `Eicar-*`, everything else | `malicious` |

If a source fails (clamd is down, a socket times out), the file is still
scanned by the other sources, and the failure is reported as a per-file
warning. It never silently becomes "clean".

### Using ClamAV

Install ClamAV separately and run `clamd`; feather never bundles it (ClamAV is
GPL-2.0, feather is MIT, and keeping them as separate programs keeps that
boundary honest):

```powershell
.\build\Release\feather.exe scan C:\Downloads --clamd 127.0.0.1:3310
```

That gives you ClamAV's signature coverage and feather's classification. Replacing
a ClamAV PUA deletion with a warning is the whole point.

For real-time protection, `tools\setup-clamav.ps1` (run elevated) writes Feather's
own `clamd.conf`/`freshclam.conf` under `%PROGRAMDATA%\Feather\clamav`, downloads
signatures and registers `clamd` on `127.0.0.1:3310`. It is optional: without it
the local rules still work and the dashboard shows ClamAV as unreachable.

## Verdict model

Tiers describe **how sure** the scanner is. Categories describe **what kind of
thing** it found — the part you actually need in order to decide.

| Verdict | Meaning | Example | Suggested action |
| --- | --- | --- | --- |
| `malicious` | known-bad SHA-256, spoofed filename, or a named malware family from ClamAV | stealer, miner, ransomware | block |
| `unwanted` | holds a **capability** associated with malware, but that capability is not proof | process injector, memory dumper, ClamAV PUA/HackTool, double extension | warn, you decide |
| `info` | structural oddity worth noting | packed/high-entropy section, large overlay | note only |
| `clean` | nothing known | — | — |

Categories sit next to that verdict: `hacktool`, `adware`, `pua`, `packer`,
`injector`, `dropper`, `spyware`, `stealer`, `miner`, `ransomware`, `trojan`,
`worm`, `virus`, `suspicious`, `test`, `malware`. See
[docs/CATEGORIES.md](docs/CATEGORIES.md) for the full mapping and the policy
file format.

A scan never quarantines anything. Quarantine is either an explicit CLI command /
GUI button, or an automatic, restorable move by the optional real-time service.
There is no automatic wipe: permanent deletion only happens when you explicitly
choose **Remove selected** on a `malicious` finding or run `feather wipe`.
Quarantine copies first, re-hashes the copy, and only removes the original after
the copy verifies.

## Why cracks do not get swiped

Deliberately **not** treated as evidence of anything:

- **Packer / cryptor detected.** Cracks are packed by definition.
- **Unsigned binary.** Most game fixes and indie tools are unsigned.
- **Low prevalence / "rare file."** Rare is not bad.
- **HackTool, PUA, "possibly unwanted" heuristics.** That is the entire category
  this project refuses to moralize about.
- **High entropy.** Reported as `info`, never escalated.

Kept as signals, because they describe **behaviour or provenance** rather than
appearance: known-bad hashes, filename extension spoofing, injection-capable
imports, process-memory-dumping imports.

The honest caveat: repacked "cracks" are a major malware delivery vector. That
is exactly why the answer is *classify by capability* rather than *trust by
category*. If a game fix grows an LSASS reader, it stops being a game fix.

See [docs/VERDICT-MODEL.md](docs/VERDICT-MODEL.md) for the full rules.

## Build

Requirements: Windows, Visual Studio 2022 (Desktop C++ workload) or Build Tools,
CMake 3.20+, and the .NET 8 SDK for the GUI.

```powershell
# if you do not have a C++ toolchain yet:
winget install --id Microsoft.VisualStudio.2022.BuildTools `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.CMake.Project --includeRecommended"

cmake -S . -B build
cmake --build build --config Release

# GUI
dotnet build gui/Feather.Gui.csproj -c Release
```

The binary lands in `build/Release/feather.exe`; the GUI in
`gui\bin\Release\net8.0-windows\Feather.exe`. The GUI finds the scanner in
`build\Release`, `build\Debug` or on `PATH`; `File > Locate feather.exe`
overrides that.

### Building the installer

```powershell
powershell -ExecutionPolicy Bypass -File installer/build.ps1
```

Requires Inno Setup 6 (installed automatically by the script's lookup; if
missing, install with `winget install JRSoftware.InnoSetup`). Output:
`installer/output/feather-setup-0.4.0.exe` (~46 MB, self-contained). The installer
ships `feathersvc.exe` and starts `FeatherRT`; the kernel driver is staged but
must be activated separately with `driver\install-driver.ps1`.

## Use

```powershell
# scan a folder, using the sample known-bad list
.\build\Release\feather.exe scan C:\Users\me\Downloads --ioc rules\ioc.sample.txt

# show informational findings too, and honour your own tolerance list
.\build\Release\feather.exe scan D:\ --ioc rules\ioc.sample.txt --allow rules\allow.sample.txt --all

# machine-readable output
.\build\Release\feather.exe scan C:\ --json out\results.json --quiet
```

Exit codes: `0` clean, `2` unwanted or malicious found, `1` usage or IO error.
That makes it usable in scripts and CI.

Second scans are fast: unchanged files with a known verdict are skipped via a
hash cache in `%LOCALAPPDATA%\Feather\cache.tsv`. Use `--no-cache` to disable.
Cache entries are tied to the active source set, so enabling `--clamd` later
does not reuse pre-ClamAV results.

### The GUI

```powershell
gui\bin\Release\net8.0-windows\Feather.exe
```

The **Dashboard** opens to a Quick Scan card, Protection Advisor and Security
Status panels, and Protection Updates. Click **Scan** there to scan drive C
immediately. The **Scan** page has the same big Scan button plus a `...` menu
for a specific folder. Tick what you want gone, then choose **Remove
selected** or **Allow selected**. Malware (`malicious` verdict) is wiped
permanently — overwritten with zeros before deletion — while `unwanted` and
`info` findings are quarantined and stay restorable. Nothing is removed
without this explicit confirmation. The `Categories` tab is where "Adware:
auto-select, HackTool: ask me" is configured; it writes
`%LOCALAPPDATA%\Feather\policy.json`. Allow-listed hashes go to
`%LOCALAPPDATA%\Feather\allow.txt`, which is the same file format the CLI takes
with `--allow`.

The dashboard shows the **actual** real-time state: Active, Degraded or Inactive.
It reads status written by `FeatherRT` and never claims protection that is not
running. It also lists quarantine from both your profile and the SYSTEM service.

### Real-time protection (optional)

`driver/featherflt` is an on-access minifilter. On an executable open it asks the
`FeatherRT` SYSTEM service for a verdict over a private communication port. A
`malicious` or `unwanted` verdict denies the open (`STATUS_ACCESS_DENIED`) and the
service moves the file into `%PROGRAMDATA%\Feather\quarantine` **before** it
replies. Nothing is wiped in real time. `info` and `clean` opens proceed.

```powershell
# Build (needs WDK 10.0.26100 + VS 2022 C++ tools):
powershell -ExecutionPolicy Bypass -File driver\build-driver.ps1

# Activate (elevated). DISABLE SECURE BOOT IN UEFI FIRST:
powershell -ExecutionPolicy Bypass -File driver\install-driver.ps1

# Verify after activation (elevated):
fltmc filters
Get-Service FeatherRT,featherflt
```

The script signs the driver with a local test certificate, installs the filter
instance and starts both services. If Secure Boot is on, test signing is blocked
and the filter will not load — the script reports that instead of pretending,
and opens fail open until it loads. See [docs/REALTIME.md](docs/REALTIME.md) for
configuration, the failure policy and the honest limitations.

### Quarantine / wipe from the CLI

```powershell
.\build\Release\feather.exe quarantine .\suspicious.exe --category adware --reason "came with an installer"
.\build\Release\feather.exe quarantine-list
.\build\Release\feather.exe restore <sha256>

# Permanent removal — overwrites with zeros, then deletes, and audits to wipe-log.tsv:
.\build\Release\feather.exe wipe .\confirmed-malware.exe --reason "confirmed by user"
```

Quarantine defaults to `%LOCALAPPDATA%\Feather\quarantine`; use
`--quarantine-dir` to override it. The real-time service uses
`%PROGRAMDATA%\Feather\quarantine`; the GUI shows both vaults and restores from
either. Files are stored as `<sha256>.q`, so they are not executable from inside
the vault, and every entry is recorded in `manifest.tsv` with the original path,
size and category.

### Verifying it actually detects something

Download the harmless EICAR test file and scan it:

```powershell
curl.exe -o "$env:TEMP\eicar.com" https://www.eicar.org/download/eicar.com.txt
.\build\Release\feather.exe scan "$env:TEMP\eicar.com" --ioc rules\ioc.sample.txt
```

It should report `[malicious]` with `hash.known_bad`. Windows Defender will
probably quarantine the file first; that is expected.

## Rules

- `rules/ioc.sample.txt` — known-bad SHA-256 list. Hash-only by design. An
  optional category word sits between the hash and the label:
  `sha256 <hash> adware bundled installer`.
- `rules/allow.sample.txt` — your exclusions. Can lower `unwanted` to `clean`,
  can **never** override `malicious`.

## Design rules

1. The engine is OS-independent and has no driver dependency.
2. The driver contains **zero detection logic** — it is enforcement, nothing else.
3. The CLI, the GUI, `feathersvc` and the driver all use the same engine.
4. An unsigned build must always remain fully usable, minus enforcement.
5. A scan may classify. Only a person may remove — except that the real-time
   service may **quarantine** (never wipe) a detection before an executable open.

## Roadmap

- [x] Detection engine: hashing, PE parsing, verdict tiers, exclusions
- [x] CLI scanner with cache and JSON output
- [x] Fusion layer: sources emit signals, one verdict comes out
- [x] ClamAV adapter over clamd (optional, no GPL code in this repo)
- [x] Categories (`hacktool`, `adware`, `stealer`, ...) on every finding
- [x] Explicit, copy-then-verify quarantine with restore
- [x] Desktop GUI: pick from the unwanted, per-category preselect policy
- [x] Shipping installer (Inno Setup, self-contained .NET 8)
- [ ] YARA adapter (libyara, per-rule severity in metadata)
- [ ] MFT/USN enumeration for fast full-disk scans
- [ ] AMSI provider for script coverage (`IAntimalwareProvider`) — no driver needed
- [x] On-access minifilter (C, WDK) + verdict service — calls the same engine
- [ ] ETW-TI behavioural sensor (requires signing + MVI registration)

## Limitations

Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) before trusting this with
anything. Short version: static analysis of a file cannot prove intent; this
project has no emulator, no cloud reputation and no behavioural data yet, so
it will miss things and it will occasionally warn about things that are fine.

## Not that kind of project

feather does not provide, host, link to or endorse cracked software. It does
not attempt to defeat DRM. It classifies files by capability so that users can
make an informed decision about software they already have.

## License

MIT. See [LICENSE](LICENSE).

The optional ClamAV adapter talks to a `clamd` daemon over a socket; it does not
link `libclamav` or bundle ClamAV, which is GPL-2.0. You install and license
ClamAV separately. That keeps this repository MIT, and keeps ClamAV optional.
