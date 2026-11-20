# feather

A lightweight Windows file scanner that **classifies instead of condemning**.

Most scanners collapse "this is a game fix" and "this is a stealer" into a single
red popup and delete both. feather keeps them apart, tells you what it actually
found, and never deletes anything.

> **Status: alpha.** The detection engine and CLI scanner work today. The
> kernel driver does not exist yet — see [roadmap](#roadmap). This is a
> scanner, not a full antivirus, and it is not a replacement for Defender.

## The verdict model

| Verdict | Meaning | Example | Suggested action |
|---|---|---|---|
| `malicious` | known-bad SHA-256, or filename spoofing | stealer, miner, ransomware | block |
| `unwanted` | holds a **capability** associated with malware, but that capability is not proof | process injector, memory dumper, double extension | warn, you decide |
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
- [ ] MFT/USN enumeration for fast full-disk scans
- [ ] YARA rule support (optional, loaded at runtime)
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
