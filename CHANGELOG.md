# Changelog

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
