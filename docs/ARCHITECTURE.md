# Architecture

```
                 +-----------------------------+
                 |        feather_engine       |
                 |  portable C++20, no OS APIs |
                 |  hash / PE / IOC / verdict  |
                 +--------------+--------------+
                                |
        +-----------------------+------------------------+
        |                       |                        |
   +----v----+           +------v------+          +------v------+
   |   CLI   |           | AMSI provider|          |  minifilter |
   | scanner |           |  (planned)   |          |  (planned)  |
   | C++/std |           |   C++ / COM  |          |   C / WDK   |
   +---------+           +--------------+          +-------------+
```

## Modules

| Path | Responsibility |
|---|---|
| `engine/sha256.*` | Self-contained SHA-256. No OpenSSL/CNG, so the engine builds and tests anywhere. |
| `engine/pe.*` | Bounds-checked PE parser: sections, entropy, imports, exports, overlay, Authenticode presence. Never executes or maps anything. |
| `engine/ioc.*` | Hash-only known-bad database. |
| `engine/exclusions.*` | User tolerance list (hash or path glob). Cannot override `malicious`. |
| `engine/engine.*` | Rule evaluation, verdict aggregation, per-file analysis. |
| `cli/walk.*` | File enumeration. Does not follow directory symlinks. |
| `cli/cache.*` | `(path, size, mtime) -> (sha256, verdict)` cache. |
| `cli/main.cpp` | Argument parsing, thread pool, text/JSON reporting. |

## Invariants

These are enforced by review, and breaking them is a bug:

1. **No detection logic outside `engine/`.** The CLI prints, the cache stores,
   the driver (later) senses. None of them decide.
2. **No OS dependency in `engine/`.** It must build on Linux for CI and tests,
   even though the product is Windows-only.
3. **Engine API is a pure function of a file path.** `Engine::analyze` reads the
   file and returns a `Finding`. No globals, no mutable state, safe to call from
   many threads (the engine holds immutable databases).
4. **Every rule produces a `RuleHit` with an id and a reason.** No anonymous
   booleans, no silent verdicts.
5. **The driver never gets a bypass path.** If the engine cannot inspect
   something, it says so; it does not guess.

## Scan pipeline

```
enumerate -> [cache hit? reuse verdict]
          -> stream file through SHA-256
          -> read bounded prefix, parse PE
          -> evaluate rules -> severity
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
scan) and written single-threaded afterwards.

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
