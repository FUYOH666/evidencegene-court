# Dataset

## Demo case: DFIR Madness Case 001 — "The Stolen Szechuan Sauce"

- **Source:** <https://dfirmadness.com/the-stolen-szechuan-sauce/> (public training case)
- **Why this case:** it ships with a **published ground truth** walkthrough, so
  findings can be scored objectively for the accuracy report. It includes both
  a memory image and a disk image of the same Windows Server (DC01), which is
  exactly the multi-source correlation scenario the court is built for.
- **Author:** James Smith / DFIR Madness. Used here for research/education under
  the terms of the source site.

## Files used

| File | Evidence source id | Role in demo |
|------|--------------------|--------------|
| `citadeldc01.mem` (from `DC01-memory.zip`) | `memory:dc01` | Process list/scan, network, injection |
| `DC01 E01` (from `DC01-E01.zip`) | `disk:dc01` | Filesystem timeline for cross-source confirmation |
| `case001-pcap.zip` | `network:case001` | Context (optional) |

Evidence files are **not** committed to the repository (see `.gitignore`).
Fetch them with:

```bash
bash scripts/fetch_case001.sh DC01-memory.zip DC01-E01.zip case001-pcap.zip
```

## Integrity

Published MD5s (from the source site) are checked into chain-of-custody at the
start of every run via the `verify_image_integrity` tool, which records sha256
and md5 of each image as the first artifact. Example expected MD5s:

| File | MD5 |
|------|-----|
| `DC01-memory.zip` | `64A4E2CB47138084A5C2878066B2D7B1` |
| `DC01-E01.zip` | `E57FC636E833C5F1AB58DFACE873BBDE` |
| `case001-pcap.zip` | `422046B753CF8A4DF49D2C4CE892DB16` |

## Known ground truth (summary)

The documented incident involves external RDP/exploitation against an
internet-exposed Windows Server, credential access, and a persistence/C2
implant. Specific PIDs, IPs, and filenames are intentionally **not** restated
here so the agent's findings can be compared against the source walkthrough
without leakage into prompts. See the accuracy report for scored results.
