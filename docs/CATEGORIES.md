# Categories

A tier answers **how sure** the scanner is. A category answers **what it thinks
it found**. You need both: `unwanted` alone does not tell you whether the file
is an adware bundle, a game fixer or a memory dumper, and those deserve different
answers.

Categories never raise or lower a tier. They are metadata attached to the
strongest signal, and they are what the GUI policy and your own reading use.

## The list

| Id | Label | Means | Typical sources | GUI default |
| --- | --- | --- | --- | --- |
| `malware` | Malware | a named family the source did not classify further | IOC, ClamAV fallback | auto-select |
| `trojan` | Trojan | named trojan family | ClamAV `*Trojan*` | auto-select |
| `ransomware` | Ransomware | named ransomware family | ClamAV `*Ransom*` | auto-select |
| `stealer` | Stealer | credential/info stealer family | ClamAV `*Stealer*` | auto-select |
| `spyware` | Spyware | surveillance/keylogger family | ClamAV `*Spyware*`, `*Keylog*` | auto-select |
| `miner` | Miner | coin miner family | ClamAV `*Miner*` | auto-select |
| `dropper` | Dropper | installer/loader for other malware | ClamAV `*Dropper*` | auto-select |
| `worm` | Worm | self-propagating family | ClamAV `*Worm*` | auto-select |
| `virus` | Virus | file infector family | ClamAV `*Virus*` | auto-select |
| `hacktool` | HackTool | game fixes, trainers, patchers, keygens, memory dumpers | ClamAV `*HackTool*`, `Tool.*`, rules `pe.process_dump_capable` | ask |
| `adware` | Adware | bundled offers, browser hijackers, "install this too" | ClamAV `*Adware*` | auto-select |
| `pua` | PUA | ClamAV's "potentially unwanted" bucket | ClamAV `PUA.*` | ask |
| `packer` | Packer | packed/compressed executable, no imports | rules `pe.high_entropy_exec`, `pe.no_imports` | ask |
| `injector` | Injector | imports capable of writing into another process | rules `pe.injection_capable` | ask |
| `suspicious` | Suspicious | structural oddity, heuristic match, double extension | rules `name.*`, `pe.rwx_section`, ClamAV `*Heur*` | ask |
| `test` | Test | anti-malware test files (EICAR) | ClamAV `*Eicar*` | ask |
| `unknown` | Unknown | a signal that did not declare a category | anything | ask |

"Auto-select" is only about the checkbox in the GUI. It never means delete.

## Where categories come from

### ClamAV signature names

| Signature contains | Verdict | Category |
| --- | --- | --- |
| `Eicar` | `malicious` | `test` |
| `HackTool`, `Tool.` / `.Tool.` | `unwanted` | `hacktool` |
| `Adware` | `unwanted` | `adware` |
| starts with `PUA.` | `unwanted` | `pua` |
| `Heur` | `unwanted` | `suspicious` |
| `Ransom` | `malicious` | `ransomware` |
| `Miner` | `malicious` | `miner` |
| `Stealer` | `malicious` | `stealer` |
| `Spyware`, `Keylog` | `malicious` | `spyware` |
| `Dropper` | `malicious` | `dropper` |
| `Inject` | `malicious` | `injector` |
| `Worm` | `malicious` | `worm` |
| `Virus` | `malicious` | `virus` |
| `Trojan` | `malicious` | `trojan` |
| anything else | `malicious` | `malware` |

### Built-in rules

| Rule id | Verdict | Category |
| --- | --- | --- |
| `hash.known_bad` | `malicious` | from the IOC entry |
| `name.rtl_override` | `malicious` | `suspicious` |
| `name.double_extension` | `unwanted` | `suspicious` |
| `pe.injection_capable` | `unwanted` | `injector` |
| `pe.process_dump_capable` | `unwanted` | `hacktool` |
| `pe.rwx_section` | `unwanted` | `suspicious` |
| `pe.malformed` | `info` | `suspicious` |
| `pe.high_entropy_exec` | `info` | `packer` |
| `pe.large_overlay` | `info` | `suspicious` |
| `pe.no_imports` | `info` | `packer` |

### IOC entries

An optional category word may follow the hash:

```
# sha256 <hash> [category] [label...]
sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f test eicar test file
sha256 0123... adware bundled with a media player
```

Without a word, the category is `malware`. Unknown words are treated as part of
the label, so a typo cannot silently downgrade anything.

## Policy file

The GUI stores per-category defaults in `%LOCALAPPDATA%\Feather\policy.json`:

```json
{
  "Adware": "Swipe",
  "HackTool": "Warn",
  "PUA": "Warn",
  "Trojan": "Swipe"
}
```

- `Swipe` — tick the checkbox on new results for this category.
- `Warn` — list it, leave it unchecked.

The file is advisory. A missing or malformed file falls back to the built-in
defaults; a policy can never make a scan act on its own.

## Two things categories do not do

1. **They do not change the tier.** An `unwanted` finding stays `unwanted`
   whether it is `hacktool` or `adware`. Only the facts decide the tier.
2. **They do not override malicious.** The allow list can suppress `unwanted`,
   `info` and `clean`; it cannot suppress `malicious`. That rule is enforced in
   `Engine::applyExclusions` and covered by a test.
