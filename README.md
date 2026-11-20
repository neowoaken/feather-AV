# feather

A lightweight Windows file scanner that **classifies instead of condemning**.

Most scanners collapse "this is a game fix" and "this is a stealer" into a single
red popup and delete both. feather keeps them apart, tells you what it actually
found, and never deletes anything.

> **Status: alpha.** The detection engine, CLI scanner and the optional ClamAV
> adapter work today. The kernel driver does not exist yet — see
> [roadmap](#roadmap). This is a scanner, not a full antivirus, and it is not a
> replacement for Defender.

## Architecture: sources in, one verdict out

```
sources/                 each source is an adapter, not a decider
  rules/                 built-in static heuristics
  ioc/                   known-bad SHA-256 lookup
  clamav/                optional clamd client (INSTREAM over TCP)
        |
        v  Signal{ source, id, severity, detail }
verdict/fusion            strongest signal wins; exclusions applied
        |
        v
     Finding              one file, one tier, every reason attached
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

## Verdict model

| Verdict | Meaning | Example | Suggested action |
| --- | --- | --- | --- |
| `malicious` | known-bad SHA-256, spoofed filename, or a named malware family from ClamAV | stealer, miner, ransomware | block |
| `unwanted` | holds a **capability** associated with malware, but that capability is not proof | process injector, memory dumper, ClamAV PUA/HackTool, double extension | warn, you decide |
| `info` | structural oddity worth noting | packed/high-entropy section, large overlay | note only |
| `clean` | nothing known | — | — |

Nothing is auto-quarantined. There is no "delete" code path yet, on purpose.

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
CMake 3.20+.

```powershell
# if you do not have a C++ toolchain yet:
winget install --id Microsoft.VisualStudio.2022.BuildTools `
  --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.CMake.Project --includeRecommended"

cmake -S . -B build
cmake --build build --config Release
```

The binary lands in `build/Release/feather.exe`.

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

### Verifying it actually detects something

Download the harmless EICAR test file and scan it:

```powershell
curl.exe -o "$env:TEMP\eicar.com" https://www.eicar.org/download/eicar.com.txt
.\build\Release\feather.exe scan "$env:TEMP\eicar.com" --ioc rules\ioc.sample.txt
```

It should report `[malicious]` with `hash.known_bad`. Windows Defender will
probably quarantine the file first; that is expected.

## Rules

- `rules/ioc.sample.txt` — known-bad SHA-256 list. Hash-only by design.
- `rules/allow.sample.txt` — your exclusions. Can lower `unwanted` to `clean`,
  can **never** override `malicious`.

## Design rules

1. The engine is OS-independent and has no driver dependency.
2. The driver (later) contains **zero detection logic** — it is sensors and
   enforcement, nothing else.
3. The CLI, the AMSI provider and the driver all call the same engine.
4. An unsigned build must always remain fully usable, minus enforcement.

## Roadmap

- [x] Detection engine: hashing, PE parsing, verdict tiers, exclusions
- [x] CLI scanner with cache and JSON output
- [x] Fusion layer: sources emit signals, one verdict comes out
- [x] ClamAV adapter over clamd (optional, no GPL code in this repo)
- [ ] MFT/USN enumeration for fast full-disk scans
- [ ] YARA adapter (libyara, per-rule severity in metadata)
- [ ] AMSI provider for script coverage (`IAntimalwareProvider`) — no driver needed
- [ ] On-access minifilter (C, WDK, signed) — calls the same engine
- [ ] ETW-TI behavioural sensor (requires signing + MVI registration)
- [ ] Quarantine (explicit, user-confirmed, never automatic)

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
