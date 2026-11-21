# Quarantine

Quarantine exists because "scan" and "remove" must be separate verbs. A scanner
that deletes on its own is one bad signature away from deleting your work.

## What it guarantees

1. **Nothing is quarantined by a scan.** An on-demand scan has no path to
   quarantine. You run `feather quarantine` or press the button in the GUI. The
   separate real-time service may quarantine a detection before an executable
   open; it uses the same copy/verify/remove code and never wipes.
2. **Copy, verify, then remove.** The file is copied into the vault, the copy is
   re-hashed, and the original is removed only if the copy's SHA-256 matches the
   hash the scan recorded. A failed copy leaves the original untouched.
3. **Stored non-executable.** Objects are saved as `<sha256>.q`, not with their
   original extension, so a stray double-click does not run them.
4. **Reversible.** `feather restore <sha256>` puts the file back at its original
   path. It refuses if a file already exists there.
5. **Auditable.** Every action appends a line to `manifest.tsv` with the
   timestamp, hash, category, size and original path.

## Layout

```
%LOCALAPPDATA%\Feather\quarantine\
  manifest.tsv            timestamp \t sha256 \t category \t size \t path
  objects\
    <sha256>.q            the stored bytes, hash-named
```

The real-time service uses a system-wide root so detections are visible to the
GUI even though the service runs as SYSTEM:

```
%PROGRAMDATA%\Feather\quarantine\
  manifest.tsv
  objects\<sha256>.q
```

Override a root with `--quarantine-dir` (CLI) or `quarantine=` in
`%PROGRAMDATA%\Feather\realtime.conf` (service). The GUI lists both roots and
restores from either; each row remembers which root it came from.

## Commands

```powershell
# move a file into quarantine
feather quarantine .\setup.exe --category adware --reason "bundled offer"

# see what is in there
feather quarantine-list

# put it back
feather restore <sha256>
```

`--category` is free text on purpose: the CLI does not need the GUI's policy to
record *why* you removed something.

## The honest limitation

The vault is **not encrypted**. Anyone with write access to your profile can read
a quarantined file. That is a deliberate trade for this stage: encryption without
a key-management story is security theatre, and a botched key rotation destroys
the user's files. Treat quarantine as "out of the way and clearly marked", not as
a malware zoo.

It also does not defend against malware that is already running: a living process
can keep a handle on a file, and nothing here fights that. The copy will either
fail (original untouched) or succeed and the removal will fail (vaulted copy is
removed again), both reported as errors.

## Why not `MoveFile`?

Moving across volumes is a copy anyway, and a move that fails halfway is worse
than a copy that fails cleanly. The explicit copy/verify/remove sequence is
slower by a few milliseconds and much easier to reason about.
