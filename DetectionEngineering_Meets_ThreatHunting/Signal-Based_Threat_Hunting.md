# Signal-Based Threat Hunting: Detection Analytics at Scale

A practical guide to building and operationalizing threat hunt detections using signal aggregation and anomaly analysis in Splunk.

---

## Table of Contents

1. [Introduction](#introduction)
2. [The Problem with Traditional Detections](#the-problem-with-traditional-detections)
3. [Detection Signals: A Different Approach](#detection-signals-a-different-approach)
4. [Architecture Overview](#architecture-overview)
5. [Building Detections](#building-detections)
6. [Lookup-Based Detections](#lookup-based-detections)
7. [The Analytics Dashboard](#the-analytics-dashboard)
8. [Testing and Validation](#testing-and-validation)
9. [References](#references)

---

## Introduction

Traditional Security Operations Centers (SOCs) operate in a reactive model: alerts fire, analysts triage, and incidents are investigated one at a time. This approach works for high-fidelity detections but fundamentally breaks down when dealing with the volume and ambiguity inherent in proactive threat hunting.

This guide presents an alternative methodology: instead of triaging individual alerts, we aggregate detection signals across hosts and users, then hunt for anomalies within that aggregated data. The goal is not to respond to every alert but to identify patterns, outliers, and stories that emerge when multiple lower-fidelity signals converge.

**Core Premise:** Hunts should be repeatable, not one-time events. By operationalizing hunt analytics as scheduled searches that feed a summary index, we create a persistent dataset for continuous analysis and visualization.

---

## The Problem with Traditional Detections

### Brittleness in Detection Engineering

Consider a simple detection for the offensive tool BloodHound:

```spl
index=windows source=security process_command_line="*bloodhound*"
```

This detection is **brittle** for several reasons:

1. **Single Source Dependency** — It only searches Windows Security logs. Evidence of BloodHound execution could appear in PowerShell Operational logs (EventCode 4104), Sysmon, or other telemetry sources.

2. **Trivial Evasion** — Threat actors routinely rename tools. The infamous example: early versions of Mimikatz were renamed to "mimidog" and bypassed most antivirus solutions at the time. A simple rename defeats string-matching detections entirely.

3. **Maintenance Overhead** — Building and maintaining hundreds of these brittle, tool-specific detections becomes operationally unsustainable.

### The False Positive Paradox

Many valuable threat hunting analytics are inherently "noisy." Take encoded PowerShell as an example:

- **The Signal:** Encoded PowerShell (`-EncodedCommand`, `-enc`) is a well-documented technique for obfuscating malicious commands (MITRE ATT&CK T1027).
- **The Reality:** In most enterprise environments, legitimate automation tools (Ansible, SCCM, custom scripts) use encoded PowerShell routinely.

The traditional approach forces a binary choice: either tune the detection into irrelevance or drown in false positives. Neither option is acceptable.

---

## Detection Signals: A Different Approach

### From Alerts to Signals

Instead of treating each detection as an alert requiring immediate response, treat it as a **signal** contributing to a larger analytical picture. This shift in mindset is fundamental.

**Key Insight:** Threat actor activity rarely occurs in isolation. Both the [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) and [MITRE ATT&CK](https://attack.mitre.org/) frameworks document this reality—adversaries execute multiple steps before achieving their objectives.

### Signal Stacking

Consider this sequence observed on a single host:

```
Anomalous Logon → Encoded PowerShell → net accounts execution
```

Individually:
- An anomalous logon might be a user on a new device
- Encoded PowerShell could be legitimate automation
- `net accounts` is a built-in Windows command

Together, these signals tell a different story. The **stacking** of detections across a host or user creates a composite view that reveals behavior obscured when examining events in isolation.

### Why Not Build Sequence-Based Analytics?

You could theoretically build a single detection that looks for this exact sequence:

```spl
| transaction host maxspan=1h
| search (anomalous_logon) AND (encoded_powershell) AND (net_accounts)
```

This approach has significant limitations:

1. **Combinatorial Explosion** — You would need to build analytics for every possible combination and ordering of attacker techniques.
2. **Temporal Assumptions** — What if PowerShell execution happened days after initial access? What if persistence was already established?
3. **Brittleness** — The moment an attacker deviates from your expected sequence, the detection fails.

By decoupling detections into individual signals and aggregating them in a summary index, we maintain flexibility while still surfacing the story.

---

## Architecture Overview

### Summary Index Pattern

The architecture centers on Splunk's summary indexing capability. From [Splunk Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesummaryindexing):

> Summary indexes enable you to efficiently search on large volumes of data. When you create a summary index you design a scheduled search that runs in the background, extracting a precise set of statistical information from a large and varied dataset.

**Workflow:**

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│  Hunt Analytics │ ───► │  Summary Index  │ ───► │    Dashboard    │
│  (Scheduled)    │      │   (summary_index)      │      │   (Analytics)   │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

1. **Hunt Analytics** — Scheduled searches (hourly, daily) that identify suspicious activity
2. **Summary Index** — Centralized storage for all detection signals
3. **Dashboard** — Visualization layer for anomaly identification

### Summary Index Specification

All detections output to a dedicated summary index:

```spl
index=<summary_index> source=th_detections
```

Every detection **must** terminate with the collect command:

```spl
| collect index=<summary_index> source=th_detections
```

### Required Field Schema

To enable consistent dashboard functionality, all detections must output these normalized fields:

| Field | Description | Example |
|-------|-------------|---------|
| `host` | The endpoint where activity occurred | `workstation01` |
| `first_time` / `last_time` | Temporal boundaries of the detection | Epoch timestamp |
| `technology` | The platform or log source | `windows`, `linux` |
| `keyword_detection` | Detection name or matched indicator | `AMSI Bypass Pattern` |

Additional fields provide enrichment but are not required for dashboard functionality:

| Field | Description |
|-------|-------------|
| `user` | Associated user account |
| `Tactics` | MITRE ATT&CK Tactics |
| `Technique` | MITRE ATT&CK Technique IDs |
| `category` | Detection category classification |
| `Process_Command_Line` | Full command line (Windows) |
| `Message` | PowerShell script block content |

---

## Building Detections

### Windows Detection Template

The following template provides a consistent baseline for Windows command-line detections:

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104 
    Message IN ("*[Ref].Assembly.GetType*","*SetValue($null,$true)*","*NonPublic,Static*")
| eval keyword_detection="AMSI Bypass Pattern Assembly GetType"
| eval technology="windows"
| eval metadata_tool_techniques="t1562.001"
| stats count 
    earliest(_time) as first_time 
    latest(_time) as last_time 
    values(user) as user 
    values(metadata_tool_tactics) as Tactics 
    values(Security_ID) as Security_ID 
    values(Account_Domain) as Account_Domain 
    values(EventCode) as EventCode 
    values(Creator_Process_Name) as Creator_Process_Name 
    values(New_Process_Name) as New_Process_Name 
    values(metadata_description) as Description 
    values(Process_Command_Line) as Process_Command_Line 
    values(tag) as tag 
    values(metadata_category) as category 
    values(metadata_tool_techniques) as Technique 
    values(Message) as Message 
    values(technology) as technology 
    by host keyword_detection 
| convert ctime(*time)
| collect index=summary_index source=th_detections
```

**Adapting the Template:**

1. Modify the base search to match your detection logic
2. Update `keyword_detection` to reflect the detection name
3. Map `metadata_tool_techniques` to the appropriate [MITRE ATT&CK Technique](https://attack.mitre.org/techniques/)
4. Keep the `stats`, `convert`, and `collect` pipeline intact

### Windows Non-CommandLine Example

For detections not based on command-line activity, maintain the required fields while adapting the output:

```spl
index=windows EventCode=4697 user!="*$" 
| eval keyword_detection="Service Creation"
| eval technology="windows"
| eval metadata_tool_techniques="t1543.003"
| stats earliest(_time) as first_time 
    latest(_time) as last_time 
    values(user) 
    values(Service_Account) 
    values(Account_Domain) 
    values(Logon_ID) 
    values(Service_File_Name) 
    values(Service_Type) 
    values(Service_Start_Type) 
    count 
    values(technology) as technology 
    by Service_Name user keyword_detection host
| convert ctime(*time)
| collect index=summary_index source=th_detections
```

The output structure differs, but the required fields (`host`, `first_time`, `last_time`, `technology`, `keyword_detection`) remain present.

### Linux Detection Template

Linux detections follow the same principle, adapted for auditd telemetry:

```spl
index=linux sourcetype=auditd type IN (EXECVE,TTY,USER_TTY) "grep" "password"
| eval keyword_detection="Credentials in Files"
| eval technology="linux"
| stats count 
    earliest(_time) as first_time 
    latest(_time) as last_time 
    values(cmdline) as audit_cmdline 
    values(COMMAND) as secure_cmdline 
    values(USER) as secure_user 
    values(PWD) as secure_pwd 
    values(_raw) as raw 
    values(technology) as technology 
    by host sourcetype keyword_detection
| convert ctime(*time)
| collect index=summary_index source=th_detections
```

Despite completely different field names and log structure, this detection populates the dashboard correctly because the normalized fields are present.

---

## Lookup-Based Detections

### Threat Hunting Keywords

For broad coverage of offensive tools and LOLBins, this implementation leverages lookup files derived from the [ThreatHunting-Keywords](https://github.com/mthcht/ThreatHunting-Keywords) project maintained by mthcht.

The original dataset is split into two categories:

| Lookup File | Description | Use Case |
|-------------|-------------|----------|
| `offensive_tool_keyword*.csv` | Default configurations and artifacts from red team tools | BloodHound, Mimikatz, Cobalt Strike, etc. |
| `greyware_tool_keyword*.csv` | LOLBins and dual-use utilities observed in attacks | certutil, bitsadmin, wmic abuse patterns |

### Lookup Definition Requirement

Due to the size of these files and wildcard matching requirements, Splunk lookup definitions must be configured. Direct `inputlookup` without a definition may fail to parse correctly.

```spl
| inputlookup ThKeywordsOffensive
| inputlookup ThKeywordsGrey
```

### Lookup-Based Detection Example

```spl
index=windows EventCode IN (4688,800,4103,4104) NOT user IN ("*$") 
| search NOT _raw IN ("*nessus*") 
| lookup ThKeywordsGrey keyword as _raw 
    OUTPUT keyword as keyword_detection 
           metadata_keyword_type 
           metadata_tool 
           metadata_description 
           metadata_tool_techniques 
           metadata_tool_tactics 
           metadata_malwares_name 
           metadata_groups_name 
           metadata_category 
           metadata_link 
           metadata_enable_endpoint_detection 
           metadata_enable_proxy_detection 
           metadata_comment 
| search metadata_description!="" AND metadata_enable_endpoint_detection=1 
| eval script_start=substr(Message,1,800) 
| search NOT keyword_detection IN (
    "*netstat -ano*"
) 
| eval technology="windows"
| stats count 
    earliest(_time) as first_time 
    latest(_time) as last_time 
    values(user) as user 
    values(metadata_tool_tactics) as Tactics 
    values(Security_ID) as Security_ID 
    values(Account_Domain) as Account_Domain 
    values(EventCode) as EventCode 
    values(Creator_Process_Name) as Creator_Process_Name 
    values(New_Process_Name) as New_Process_Name 
    values(metadata_description) as Description 
    values(Process_Command_Line) as Process_Command_Line 
    values(tag) as tag 
    values(metadata_category) as category 
    values(metadata_tool_techniques) as Technique 
    values(Message) as Message 
    values(technology) as technology 
    by host metadata_keyword_type keyword_detection 
| convert ctime(*time)
| collect index=summary_index source=th_detections
```

**Key Components:**

1. **Lookup Join** — The `lookup` command matches `_raw` (full log text) against the keyword field, outputting all associated metadata when a match is found.

2. **Filtering** — The `metadata_enable_endpoint_detection=1` filter ensures only endpoint-relevant detections fire. Environment-specific exclusions reduce noise from known-good activity.

3. **Normalization** — Despite the additional metadata fields, the output maintains the required schema for dashboard compatibility.

### Scheduled Alert Configuration

Four scheduled alerts provide coverage across platforms:

| Alert Name | Platform | Sources |
|------------|----------|---------|
| `THOffensiveKeywords - Process Command Line & PowerShell` | Windows | EventCodes 4688, 800, 4103, 4104 |
| `THGreyKeywords - Process Command Line & PowerShell` | Windows | EventCodes 4688, 800, 4103, 4104 |
| `ThKeywordsOffensiveKeywords-Linux Cmdline Alert` | Linux | linux_audit, auditd, linux_secure |
| `Linux Cmdline GreyKeywords_v2` | Linux | linux_audit, auditd, linux_secure |

All alerts run on an hourly schedule.

---

## The Analytics Dashboard

### Purpose

The dashboard serves as an analytical single pane of glass for aggregated detection signals. Rather than reviewing individual alerts, analysts identify anomalies by examining the distribution of detections across hosts, users, and time.
<img width="2476" height="1102" alt="image" src="https://github.com/user-attachments/assets/64667443-2f74-4c42-9c1c-821c96ac7c15" />
<img width="2488" height="432" alt="image" src="https://github.com/user-attachments/assets/3f7e32f2-6418-462f-bf04-07ddd239d2d8" />


### Time Range Configuration

**Important:** Set the dashboard time picker to **48 hours or longer**. Depending on your envinorment for hunt detections that run on 24-hour or longer schedules; shorter time ranges will miss these signals.

### Dashboard Components

#### Detection Timeline by Host

Visualizes detection volume over time, segmented by host. Anomalous spikes are immediately visible.

```spl
index=summary_index source=th_detections
| eval host=orig_host
| search $text$ 
| search technology=$technology$
| convert mktime(first_time)
| eval _time=first_time
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$"
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| timechart span=1h useother=False count by host
```

**Analysis Pattern:** Identify hosts with sudden increases in detection volume. A host that typically generates 2-3 signals suddenly producing 50+ warrants investigation.

#### Unique Detections by Host

Counts distinct detection types per host, surfacing endpoints exhibiting diverse suspicious behavior.

```spl
index=summary_index source=th_detections
| eval host=orig_host
| search $text$ 
| search technology=$technology$
| convert mktime(first_time)
| eval _time=first_time
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$"
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| stats values(_time) as time 
    values(keyword_detection) as detection 
    dc(keyword_detection) as distinct_detections 
    count 
    by host
| sort - distinct_detections
| convert ctime(time)
```

**Analysis Pattern:** Sort by `distinct_detections` descending. A host with 15+ unique detection types is exhibiting behavior consistent with active reconnaissance or attack progression.

#### Detections by Type

Shows which detections are firing most frequently and on how many distinct hosts.

```spl
index=summary_index source=th_detections
| convert mktime(first_time) 
| eval host=orig_host 
| search $text$ 
| search technology=$technology$
| eval _time=first_time 
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$" 
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| stats values(_time) as time
    values(host) as host
    dc(host) as distinct_host
    count as total_count 
    by keyword_detection 
| sort total_count
| convert ctime(time)
```

**Analysis Pattern:** Detections appearing on many hosts may indicate widespread activity (lateral movement, automated scanning). Detections isolated to few hosts with high counts may indicate targeted activity.

#### Detections by User

Aggregates signals by associated user account.

```spl
index=summary_index source=th_detections
| eval host=orig_host
| search $text$ 
| search technology=$technology$
| convert mktime(first_time)
| eval _time=first_time
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$"
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| stats values(_time) as time 
    values(keyword_detection) as detection 
    dc(keyword_detection) as distinct_detections 
    count 
    by user
| sort -distinct_detections
```

**Note:** User attribution varies by telemetry source. Windows EventCode 4688 with command-line logging provides reliable user context. Linux auditd may not consistently attribute command execution to specific users depending on configuration.

#### Category and Tactic Views

Additional panels provide MITRE ATT&CK alignment:

```spl
index=summary_index source=th_detections
| eval host=orig_host
| search $text$
| search technology=$technology$
| convert mktime(first_time)
| eval _time=first_time
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$"
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| stats count by category
```

### Filtering and Search

The dashboard supports multi-select filtering on:

- **Detections** — Isolate specific detection types
- **Hosts** — Focus on particular endpoints
- **Technology** — Filter by platform (Windows, Linux)

A free-text search field queries across all summary index fields:

```
host=*dc*              # Find Domain Controllers
cmd.exe OR powershell.exe   # Find command interpreter activity
```

**Note:** The search operates only on fields present in the summary index, not the original raw events.

### Raw Event Access

The final dashboard panel displays the underlying events for detailed analysis:

```spl
index=summary_index source=th_detections
| eval host=orig_host
| search $text$ 
| search technology=$technology$
| search EventCode=*4688*
| convert mktime(first_time)
| eval _time=first_time
| where _time >= relative_time(now(), "$global_time.earliest$") AND _time <= "$global_time.latest$"
| search keyword_detection IN ($multi_keywords|s$) 
| search host IN ($multi_host$)
| table host keyword_detection _time Message user Account_Domain Description EventCode Process_Command_Line Tactics Technique category count metadata_keyword_type
```

From here, analysts can pivot to the original index for full event context.

---

## Testing and Validation

### Verifying Detection Output

After creating or modifying a detection, validate that data populates the summary index:

```spl
index=summary_index source=th_detections keyword_detection="<your detection name>"
| table _time host keyword_detection technology
```

### Common Issues

| Symptom | Likely Cause | Resolution |
|---------|--------------|------------|
| Detection not appearing in dashboard | Missing required field | Verify `host`, `first_time`, `technology`, `keyword_detection` are present |
| Time filter not working | `_time` not set correctly | Ensure `convert mktime(first_time)` and `eval _time=first_time` are in the search |
| Lookup not matching | Lookup definition missing | Create lookup definition in Splunk to enable wildcard matching |
| High false positive rate | Insufficient exclusions | Add environment-specific exclusions to the `search NOT` clauses |

### Scheduled Search Considerations

- **Run Frequency:** Most detections run hourly. Adjust based on detection latency requirements and search cost.
- **Time Range:** Search over a window slightly larger than the run frequency to avoid gaps (e.g., `-70m` for hourly searches).
- **Resource Impact:** Summary indexing is significantly more efficient than running full searches repeatedly, but initial implementation may require capacity planning.

---

## References

### Frameworks and Methodologies

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Splunk Summary Indexing Documentation](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Usesummaryindexing)

### Detection Resources

- [ThreatHunting-Keywords by mthcht](https://github.com/mthcht/ThreatHunting-Keywords) — Source for offensive tool and greyware keyword lookups
- [LOLBAS Project](https://lolbas-project.github.io/) — Living Off The Land Binaries and Scripts
- [GTFOBins](https://gtfobins.github.io/) — Unix binaries for privilege escalation and persistence
