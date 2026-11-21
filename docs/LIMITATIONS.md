# Limitations

Read this before trusting feather with anything important. It is short and it
is not marketing.

## What feather is not

- **Not a full antivirus.** There is no AMSI, no cloud reputation, no emulator
  and no behavioural engine. The optional kernel filter checks executable opens
  against static rules; it does not watch what a running process does.
- **Not a Defender replacement.** Defender has a decade of telemetry, an
  emulator, a cloud backend and a properly signed kernel driver. Keep it enabled.
  Feather's driver is self-signed and only loads with Secure Boot disabled.
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
- **Scripts** (PowerShell, JS, VBS, LNK) are extension-matched by the filter but
  barely inspected by the rules until an AMSI provider exists.
- **Living-off-the-land attacks** involve no suspicious file at all.
- **Fileless and already-running malware** never triggers an `IRP_MJ_CREATE`
  check. The filter sees opens, not behaviour.

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

## Real-time protection

- **Fail-open by design.** If `FeatherRT` is not running, the port is not
  connected, or a scan cannot complete, the open is allowed and a degraded
  counter is incremented. A blue-screen-free machine is worth more than a filter
  that silently wedges every launch. The dashboard shows the degraded state.
- **Trusted processes are skipped.** `feathersvc` and Feather's own executables
  are excluded from scanning to avoid recursion. Anything running from the
  Feather install directory is trusted for the duration of its cached PID entry.
- **Verdicts are cached** by path, size and mtime for 10 minutes by default. A
  file changed in place is re-scanned; a metadata-preserving rewrite within the
  same timestamp granularity can slip through until the TTL expires.
- **Only executable-looking extensions are checked.** Documents, archives and
  other data files are not scanned on access.
- **Quarantine is not a kill switch.** A process that already holds a handle to a
  file can keep using it after the file is moved. Real-time protection reduces
  exposure; it does not clean an infected machine.
- **Secure Boot must be off** for the self-signed driver. Test signing widens the
  machine's trust configuration; this is a deliberate trade, not a recommendation
  for production endpoints.

## Security of the tool itself

- No code signing. Windows SmartScreen and Defender may flag the built binary,
  especially since it reads the whole disk.
- The IOC and exclusion files are plain text and are not verified. If someone
  can modify them, they can hide malware from you: treat them as security-
  sensitive, and review changes.
- Open-source detection logic is readable by malware authors. Rule IDs and
  details are therefore kept generic; do not expect them to stay secret, and do
  not put anything sensitive in the repository.
- **Quarantine is not encrypted.** Both `%LOCALAPPDATA%\Feather\quarantine` and
  the service's `%PROGRAMDATA%\Feather\quarantine` are plain files. Anyone who can
  read those directories can read the vaulted bytes. Treat them as "out of the
  way", not as a secure sample store.
- The GUI is a front end, not the protection service. It runs one on-demand scan
  at a time, has no tray icon and no scheduler; it reads status from `FeatherRT`.

## Legal

feather classifies files you already have. It does not download software, does
not circumvent DRM, and does not provide or endorse cracked games. Nothing in
this project is legal advice.
