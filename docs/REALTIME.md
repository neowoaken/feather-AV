# Real-time protection

Feather's on-access layer is two processes plus a shared protocol:

| Component | Role |
|---|---|
| `driver/featherflt/featherflt.c` | Minifilter. Intercepts `IRP_MJ_CREATE` for executable-looking files and asks for a verdict. Blocks on `BLOCK`/`QUARANTINE`. |
| `service/main.cpp` (`feathersvc.exe`) | SYSTEM service `FeatherRT`. Runs the same `Engine` as the CLI, quarantines detections, answers the filter. |
| `driver/featherflt/protocol.h` | Wire format shared by kernel and user mode. |

The detector is **ClamAV + local rules**: built-in heuristics, the SHA-256 IOC
list and an optional `clamd` at `127.0.0.1:3310`. ClamAV is a separate program
contacted with the documented `INSTREAM` protocol; `libclamav` is never linked,
so the repository remains MIT.

## What happens on an open

1. The filter sees an `IRP_MJ_CREATE` for one of the watched extensions
   (`.exe`, `.dll`, `.sys`, `.bat`, `.cmd`, `.ps1`, `.js`, `.vbs`, `.scr`, `.msi`,
   `.lnk`, ...). It skips its own service PID and remote filesystems.
2. It sends a `FEATHER_SCAN_REQUEST` (path, PID, desired access) to `FeatherRT`
   and waits up to 20 seconds.
3. The service skips trusted Feather processes, checks its verdict cache, then
   calls `Engine::analyze`.
4. `malicious` and `unwanted` deny the open. The service copies the file into
   `%PROGRAMDATA%\Feather\quarantine`, re-hashes the copy, and only then removes
   the original — before it replies. If quarantine fails, the open is still
   denied, and the failure is recorded.
5. The filter completes the create with `STATUS_ACCESS_DENIED`. `info` and
   `clean` opens proceed normally.

Nothing is wiped in real time. Permanent deletion is still only the explicit
GUI **Remove selected** action on a `malicious` finding or `feather wipe`.

## Setup

Everything below needs an elevated PowerShell.

```powershell
# 1. build the user-mode binaries
cmake -S . -B build
cmake --build build --config Release

# 2. build the driver (WDK 10.0.26100 + VS 2022 C++ tools)
powershell -ExecutionPolicy Bypass -File driver\build-driver.ps1

# 3. DISABLE SECURE BOOT IN UEFI, reboot into Windows

# 4. sign, install and start the filter + FeatherRT service
powershell -ExecutionPolicy Bypass -File driver\install-driver.ps1

# 5. optional: local ClamAV signatures and daemon
powershell -ExecutionPolicy Bypass -File tools\setup-clamav.ps1
```

The shipping installer already stages `feathersvc.exe` and starts `FeatherRT`;
the driver still needs step 4 because it is self-signed. With Secure Boot on,
test signing is rejected by firmware and the filter will not load. The install
script reports that instead of claiming success.

Verify:

```powershell
fltmc filters                       # featherflt, altitude 328770
Get-Service FeatherRT,featherflt,ClamAV
Get-Content "$env:PROGRAMDATA\Feather\realtime-status.json"
```

## Configuration

`FeatherRT` reads `%PROGRAMDATA%\Feather\realtime.conf`. Every key is optional;
absent keys use the defaults below.

```ini
# clamd endpoint, or "none" / "off" to disable ClamAV
clamd=127.0.0.1:3310

# absolute paths; defaults are rules/ioc.sample.txt next to the installed app
# and %LOCALAPPDATA%\Feather\allow.txt
ioc=C:\Program Files\Feather\rules\ioc.sample.txt
allow=C:\Users\me\AppData\Local\Feather\allow.txt

# where detected files go; must be writable by SYSTEM
quarantine=C:\ProgramData\Feather\quarantine

# quarantine "unwanted" as well as "malicious" (default: true)
quarantine_unwanted=true

# worker threads (1..16) and cache lifetime in seconds (60..86400)
threads=4
cache_ttl=600
```

Restart `FeatherRT` after editing the file. Exclusions (`allow.txt`) can lower
`unwanted` and below, but never suppress `malicious`.

## Status and events

The service publishes two files under `%PROGRAMDATA%\Feather`:

- `realtime-status.json` — service/filter connection, ClamAV state, active rule
  scope, counters (`scans`, `blocks`, `quarantines`, `failOpen`) and last action.
  Refreshed every 5 seconds.
- `realtime-events.jsonl` — one JSON object per checked open: timestamp, PID,
  path, action, verdict, severity, category, source, detail, SHA-256 and note.
  Rotated to `.1` after 2 MiB.

The Dashboard reads both and shows one of three states:

| State | Meaning |
|---|---|
| **Active** | `FeatherRT` is connected to the filter and ClamAV is reachable. |
| **Degraded** | Protection is connected but ClamAV is unreachable or some opens failed open. Local rules still apply. |
| **Inactive** | The service is not reporting, or the filter is not loaded. No on-access checking is happening. |

## Failure policy

Feather fails **open and loud**: if the port is missing, the service times out,
or a file cannot be read, the open proceeds and `failOpen` is incremented. The
dashboard shows the degraded state. This keeps the machine bootable and avoids
turning a scanner bug into a system-wide denial of service. It also means real
time is not a guarantee — see [LIMITATIONS.md](LIMITATIONS.md).

## Testing without the driver

`tests/realtime.ps1` feeds a synthetic filter request through the exact service
decision path (`feathersvc --probe`) and verifies allow, quarantine, manifest,
restore and byte identity:

```powershell
powershell -ExecutionPolicy Bypass -File tests\realtime.ps1
```
