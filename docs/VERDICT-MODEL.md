# Verdict model

The core design decision: a scanner should tell you **what it knows**, not what
it suspects, and it should not silently destroy data on suspicion.

## Tiers

```
malicious   evidence of badness          -> block / (future) quarantine
unwanted    capability worth a warning   -> user decides
info        structural oddity            -> display only
clean       nothing known                -> silence
```

A file's verdict is the **highest** severity among its rule hits. A file with no
hits is `clean`.

## Rule catalogue (v0.1)

| ID | Severity | Weight | Signal |
|---|---|---|---|
| `hash.known_bad` | malicious | 100 | SHA-256 present in the IOC database |
| `name.rtl_override` | malicious | 90 | U+202E right-to-left override in the filename (extension spoofing) |
| `name.double_extension` | unwanted | 30 | dangerous extension behind a bait extension, e.g. `invoice.pdf.exe` |
| `pe.injection_capable` | unwanted | 20 | imports that can write and execute code in another process |
| `pe.process_dump_capable` | unwanted | 15 | `MiniDumpWriteDump` (credential-dumping capability) |
| `pe.rwx_section` | unwanted | 15 | a section that is both writable and executable |
| `pe.high_entropy_exec` | info | 5 | high-entropy executable section (packed/compressed) |
| `pe.no_imports` | info | 4 | no import table |
| `pe.large_overlay` | info | 3 | large appended data after the last section |
| `pe.malformed` | info | 2 | starts with `MZ` but headers do not parse |

Weights are display/ordering metadata; the verdict is driven by severity, so a
single `info` hit can never promote a file to `unwanted`.

## Signals we refuse to use

These are the usual suspects in false positives on legitimate software. Each
one is excluded for a stated reason, and the reason is the point of the project.

| Signal | Why it is excluded |
|---|---|
| Packer / cryptor name | Cracked games are packed by definition. "Packed" describes distribution, not intent. |
| Unsigned binary | Most game fixes, indie tools and internal utilities are unsigned. Authenticode absence proves nothing. |
| Low prevalence | Indie and niche software is rare by nature. |
| Missing version info / odd resources | Cosmetic, trivially forged. |
| "HackTool", "PUA", "possibly unwanted" | This is the category the project explicitly declines to judge. |
| High entropy | Emitted as `info`; never escalates. |
| Company/product name mismatch | Common in repacked and localized software. |
| Filename suggests a game | Not evidence; also trivially spoofable in both directions. |

If a future contributor adds any of these as a hard verdict, the change is
wrong by design and should be rejected.

## Why capability signals are different

`pe.injection_capable` does not say "this file is malware". It says "this file
contains the code needed to inject into another process". A crack may genuinely
need that (overlay hooks, for example). So it warns at `unwanted` and lets the
user decide.

But a *stealer wearing a crack's clothes* has to do something a crack does not:
read browser credential stores, open LSASS, install persistence, talk to a C2.
Those are behavioural, and behaviour is where the real separation will happen
(see roadmap: ETW-TI). Static capability checks are a bridge, not the endpoint.

## Exclusions

`allow.sample.txt` can suppress `unwanted` and below, with a recorded reason
that is shown in the output.

It cannot suppress `malicious`. This is enforced in `Engine::analyze` by
checking `verdict != Severity::Malicious` before consulting exclusions. If a
"trusted game folder" could whitelist a known stealer, the tier model would be
worthless.

## Confidence and escalation

Current rule: severity is the maximum of hit severities. There is no scoring
threshold yet, because a numeric threshold invites tuning until false positives
disappear and detection goes with them.

When behavioural signals arrive, the model will need:

- correlation windows (injection *then* network, not injection alone)
- per-signal reliability weights instead of a flat maximum
- an explicit `confidence` field separate from `severity`

That is deliberate future work, not an oversight.
