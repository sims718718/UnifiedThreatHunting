# Purple Operations

Synthetic purple teaming for the Unified Threat Hunting Framework. This folder supports the **Purple Operations (DPO)** hunt type: generate known attack telemetry across many sources, hunt it blind, and score the result against ground truth.

## Why it matters

A hunt that finds nothing only means something if you can show you would have seen the activity. Live validation (see the [Validation Hook](../references/validation_hook.md)) proves one technique on one sensor stack, but it is slow, needs approvals, and does not scale to a multi-stage intrusion that crosses web, endpoint, database, backup and network telemetry.

Synthetic telemetry from [EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) (Cisco Talos, MIT) fills that gap:

- **Scale.** One scenario produces consistent logs across ASA, eCAR, Sysmon, Windows Security, Zeek, web, syslog and more.
- **Ground truth.** Every run writes a `GROUND_TRUTH.md`, so you can score each step (Detected, Partial, Missed, Not observable by design) instead of guessing.
- **Repeatable.** Generation is deterministic with a seed, so a dataset becomes a regression test for hunts and detections.
- **Safe.** No production hosts, no approvals, no cleanup.
- **Finds pipeline problems.** Comparing logs to ground truth exposes parsing, timestamp and sensor-placement defects before they undermine a real hunt.

Synthetic results support, but do not replace, live validation. The guide explains where each fits.

## What is in this folder

| File | What it is |
|---|---|
| [Purple_Operations_with_EvidenceForge.md](Purple_Operations_with_EvidenceForge.md) | The guide: why, where it fits in the UTHF lifecycle, the nine-phase loop, scoring, defect triage, and a full walkthrough of the `calloway-php2shell` scenario |

**The generated dataset is not stored in this repo.** The EvidenceForge output for the walkthrough scenario (logs plus `GROUND_TRUTH.md`) is too large to commit. The guide quotes the relevant ground truth and hunt results directly, so it can be read without the data.

## Reproducing the dataset

EvidenceForge generation is deterministic, so the dataset can be rebuilt instead of downloaded:

1. Install [EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) (`git clone`, then `uv sync`).
2. Write or obtain the scenario YAML for `calloway-php2shell`. The attack steps, accounts and red herrings are described in section 7 of the guide.
3. Run `uv run eforge generate <scenario.yaml> -o <dir> --seed <N>` with the `splunk` target.
4. Record the EvidenceForge version and seed with the hunt record. The same inputs and seed give the same output.

Output from a rebuilt scenario may not match the walkthrough record for record if the tool version or scenario differs, so compare against the generated `GROUND_TRUTH.md`, not the guide's figures.

## Using the dataset

1. Keep `GROUND_TRUTH.md` sealed until your hunt is written up.
2. Load the logs into a dedicated Splunk index (the walkthrough uses `evidenceforge`) using the `splunk` output target.
3. Check timestamps first. In the walkthrough run, Splunk `_time` came from index time, not event time, so use the event's own `ts` or `timestamp_ms` until extraction is fixed.
4. Hunt blind, then score against ground truth with the scorecard in the guide.

## Notes

- The data is synthetic. Credentials, domains and IPs in it are generated. Keep it out of production indexes.
- The CVE identifiers in the scenario are scenario-defined, not real.
- GitHub rejects files over 100 MB, which is why the dataset is not committed here.

## Related

[Validation Hook](../references/validation_hook.md) · [Detection Handoff Spec](../references/detection_handoff_spec.md) · [Telemetry Gap Assessment](../references/telemetry_gap_assessment.md) · [DAIKI](../Data_Analysis/daiki.md)
