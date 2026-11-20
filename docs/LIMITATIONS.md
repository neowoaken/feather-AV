# Limitations

Read this before trusting feather with anything important. It is short and it
is not marketing.

## What feather is not

- **Not an antivirus.** No real-time protection, no driver, no AMSI, no cloud.
  It cannot stop malware from running. It looks at files you ask it to look at.
- **Not a Defender replacement.** Defender has a decade of telemetry, an
  emulator, a cloud backend and a signed kernel driver. Keep it enabled.
- **Not a guarantee.** `clean` means "none of the rules fired", not "safe".

## Static analysis cannot prove intent

Every current rule inspects bytes at rest. A file that decrypts its payload at
runtime, downloads it, or only misbehaves when a specific process is running
will look `clean`. This is a fundamental limit, not a bug to patch.

In particular:

- **Packed malware** with a trivial stub will pass, because we refuse to treat
  "packed" as evidence.
- **Signed malware** (stolen certificates) will pass, because signatures are not
  a trust signal here.
- **Scripts** (PowerShell, JS, VBS, LNK) are barely inspected at all until the
  AMSI provider exists.
- **Living-off-the-land attacks** involve no suspicious file at all.

## Known false negatives

- Anything not in your IOC list and not PE-shaped.
- Malicious documents and installers that need execution to reveal intent.
- Malware delivered as a legitimate signed binary plus a config file.
- Encrypted archives.

## Known false positives

- Legitimate injection tools (debuggers, mod loaders, game overlay hooks) will
  report `unwanted` via `pe.injection_capable`.
- Crash reporters that import `MiniDumpWriteDump` report `unwanted`.
- Any file deliberately named `something.jpg.exe`.

`unwanted` is a warning tier. It is designed to be noisier than `malicious` so
that `malicious` can stay quiet.

## Performance

- Full scans are **I/O bound**. The cache makes repeat scans fast, not first
  scans.
- Enumeration currently uses a recursive directory walk. Large trees with many
  small files are slower than they need to be until MFT/USN enumeration lands.
- PE parsing reads up to 32 MiB per file. Files larger than that are analysed
  on their prefix only.
- Files locked by another process with no read sharing are reported as errors,
  not scanned.

## The optional ClamAV adapter

- Requires a **separate** ClamAV installation and a running `clamd`. feather
  does not bundle it, download it, or start it.
- Coverage is broad but shallow: ClamAV's database is huge and heavily weighted
  toward known families. It is weak against modern packed, scripted and
  signed malware — do not read "clamd said OK" as safe.
- Each file is read twice when ClamAV is enabled: once for hashing, once for the
  clamd stream. Cached files skip both.
- If `clamd` is unreachable or times out, files are still scanned by the local
  sources and the failure appears as a per-file warning. It never becomes a
  silent "clean".
- ClamAV's PUA/HackTool/Heuristic detections are deliberately downgraded to
  `unwanted`. A named trojan family stays `malicious`.

## Security of the tool itself

- No code signing. Windows SmartScreen and Defender may flag the built binary,
  especially since it reads the whole disk.
- The IOC and exclusion files are plain text and are not verified. If someone
  can modify them, they can hide malware from you: treat them as security-
  sensitive, and review changes.
- Open-source detection logic is readable by malware authors. Rule IDs and
  details are therefore kept generic; do not expect them to stay secret, and do
  not put anything sensitive in the repository.

## Legal

feather classifies files you already have. It does not download software, does
not circumvent DRM, and does not provide or endorse cracked games. Nothing in
this project is legal advice.
