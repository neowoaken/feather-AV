# Architecture

```
                 +-----------------------------+
                 |        feather_engine       |
                 |  portable C++20, no OS APIs |
                 |  hash / PE / fusion         |
                 +--------------+--------------+
                                |
      +-----------------+-----------+--------------+--------------+
      |                 |           |              |              |
 +----v----+     +------v------+ +--v--------+ +---v------+ +-----v------+
 |   CLI   |     |     GUI     | |    AMSI   | |minifilter| |  ETW-TI    |
 | scanner |     |  WinForms   | | (planned) | |(planned) | | (planned)  |
 | C++/std |     |   .NET 8    | | C++ / COM | |  C / WDK | | user-mode  |
 +---------+     +-------------+ +-----------+ +----------+ +------------+

Detection sources (behind the engine):

   rules/     built-in static heuristics
   ioc/       known-bad SHA-256 database
   clamav/    optional clamd client (socket, no libclamav)
   yara/      planned
```

## Modules

| Path | Responsibility |
|---|---|
| `engine/sha256.*` | Self-contained SHA-256. No OpenSSL/CNG, so the engine builds and tests anywhere. |
| `engine/pe.*` | Bounds-checked PE parser: sections, entropy, imports, exports, overlay, Authenticode presence. Never executes or maps anything. |
| `engine/ioc.*` | Hash-only known-bad database. |
| `engine/exclusions.*` | User tolerance list (hash or path glob). Cannot override `malicious`. |
| `engine/engine.*` | Orchestrator: hash once, parse PE once, run sources, fuse, apply exclusions. |
| `sources/source.h` | `FileFacts`, `SignalSource`, `SourceResult` — the adapter contract. |
| `sources/rules_source.*` | Built-in heuristics. |
| `sources/ioc_source.*` | Hash lookup. |
| `sources/clamav_source.*` | clamd `INSTREAM` client and ClamAV-to-tier classification. |
| `verdict/signal.h` | `Severity`, `Category` and `Signal` — the only thing sources may produce. |
| `verdict/fusion.h` | Aggregation: strongest signal wins. |
| `cli/walk.*` | File enumeration. Does not follow directory symlinks. |
| `cli/cache.*` | `(path, size, mtime, source scope) -> (sha256, verdict)` cache. |
| `cli/quarantine.*` | Copy-then-verify vault, manifest, restore. Never called by a scan. |
| `cli/main.cpp` | Argument parsing, thread pool, text/JSON reporting, commands. |
| `gui/` | WinForms front end. Parses the CLI's JSON and shells out for actions; contains no detection logic. |

## Invariants

These are enforced by review, and breaking them is a bug:

1. **No detection logic outside `sources/` and `verdict/`.** The CLI prints, the
   cache stores, the driver (later) senses. None of them decide.
2. **Sources never decide a verdict.** They emit `Signal`s. Fusion owns the
   tier. This is what makes reclassification of third-party engines possible.
3. **No OS dependency in `engine/` or `verdict/`** beyond `std::filesystem`. It
   must build on Linux for CI and tests, even though the product is
   Windows-only.
4. **`Engine::analyze` is a pure function of a file path.** No globals, safe to
   call from many threads (the engine holds immutable databases; the ClamAV
   source opens one connection per file).
5. **A failing source never fails the file.** It becomes a warning; the other
   sources still run.
6. **Every rule produces a `Signal` with an id and a reason.** No anonymous
   booleans, no silent verdicts.

## Scan pipeline

```
enumerate -> [cache hit? reuse verdict]
          -> stream file through SHA-256
          -> read bounded prefix, parse PE
          -> run every source -> signals
          -> fuse (strongest signal wins; its category is kept)
          -> apply exclusions (unless malicious)
          -> cache write
          -> report
```

Hashing streams in 1 MiB chunks, so memory use is constant regardless of file
size. PE parsing reads at most 32 MiB (`EngineOptions::peReadLimit`); larger
files are analysed on their prefix, which is where headers, imports and section
tables live.

## Threading

A fixed pool of `std::thread` workers pulls indices from an atomic counter.
Results are written to a pre-sized vector, so there is no locking and output
order is deterministic. The cache is read concurrently (immutable during the
scan) and written single-threaded afterwards. The ClamAV source opens one socket
per file and closes it immediately, so no shared connection state exists across
workers.

## GUI boundary

`gui/` is deliberately dumb: it runs `feather.exe scan --json <temp>`, reads the
array, and calls `feather quarantine` for each checked row. There is no second
detection implementation to drift out of sync, and the GUI cannot invent a
verdict or remove anything the CLI would refuse.

## Future: where the driver fits

- **Minifilter** (`IRP_MJ_CREATE` pre-operation) asks the engine about a file
  before it is opened, with a small verdict cache in kernel memory and a
  user-mode service as the source of truth.
- **AMSI provider** gets script content before execution — highest
  value-per-line-of-code, and it needs no driver at all.
- **ETW-TI consumer** supplies behavioural telemetry (remote allocation, image
  loads, APC injection) that static analysis fundamentally cannot see.

All three are adapters over `feather_engine`. That is why the engine is
OS-independent now rather than after the fact.
