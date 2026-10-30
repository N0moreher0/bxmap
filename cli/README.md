# bxmap CLI

Command-line frontend for the `bxmap` memory-dump string extraction library.

## Install

```bash
cargo install bxmap-cli
# or
cargo binstall bxmap-cli
```

## Quick start

```bash
bxmap memory.dmp --auto-tune
bxmap memory.dmp --encoding ascii --format json -o strings.json
bxmap memory.dmp --entropy --format json -o triage.json
bxmap --help
```

## Useful flags

- `--encoding <all|ascii|utf16|utf32>` — restrict extracted strings by encoding.
- `--min-len <N>` — minimum string length.
- `--max-str-len <N>` — truncate very long strings in output.
- `--format <text|json|json-tree>` — output format.
- `--detect <list>` — IOC / credential triage.
- `--detect-format <flat|rich>` — `rich` keeps the original text and adds
  `rule`, `confidence`, `severity` and `context` to every finding.
- `--auto-tune` — choose a worker count for this machine.
- `--entropy` — report high-entropy regions.

For library usage see the crate README at <https://docs.rs/bxmap>.