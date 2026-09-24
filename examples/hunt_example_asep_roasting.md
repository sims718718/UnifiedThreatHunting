# Worked Example: HUNT-042 — AS-REP Roasting

End-to-end walkthrough of the [Unified Threat Hunting Process](../README.md), from trigger to typed outcomes. Field names and tooling assume the Environment Profile below. Queries are written for Splunk with the Windows TA; adapt to your own dialect.

---

## Environment Profile (Step 0)

| Context | Value |
|---|---|
| SIEM | Splunk Enterprise Security |
| EDR | CrowdStrike Falcon |
| Environment | Hybrid — on-prem AD plus Entra ID |
| Vertical | Financial services |
| Retention | 90 days hot, 1 year cold |
| Maturity | Intermediate |
| Domain | Identity (on-prem AD) |

---

## Step 1 — Trigger

CISA advisory on a financially motivated actor abusing AS-REP Roasting against service accounts at peer institutions. Received via CTI feed. Relevance high — matching vertical and account architecture.

---

## Step 2 — Hypothesis (SMART)

> We hypothesize that an actor performing AS-REP Roasting (T1558.004) may be probing accounts with Kerberos pre-authentication disabled in our domain, evidenced by Event ID 4768 with pre-authentication type 0 originating from non-Domain Controller hosts in Splunk Windows Security logs, which we can validate by querying the last 30 days and cross-referencing the requesting host against our asset inventory within one sprint (10 business days).

**Rubric score** (see [hypothesis-rubric.md](../references/hypothesis-rubric.md)):

| Dimension | Score | Note |
|---|---|---|
| Specificity | 3 | Event ID and field-level condition stated |
| Testability | 3 | Query path defined; expected volume low |
| Falsifiability | 3 | Clean 30-day result meaningfully reduces risk |
| Relevance | 3 | Vertical-matched advisory, Tier 0/1 accounts |
| Pyramid level | 3 | TTP-level, not indicator-level |
| **Total** | **15** | **GO** |

**ABLE:** Actor — financially motivated eCrime group (per advisory) · Behavior — AS-REP request for pre-auth-disabled accounts · Location — on-prem domain controllers · Evidence — 4768 pre-auth type 0 from an unexpected client address.

---

## Step 3 — Initial Assessment

- **Internal:** pulled current list of accounts with `DONT_REQ_PREAUTH` set from AD; reviewed last AD audit for service account hygiene.
- **External:** MITRE ATT&CK T1558.004, the CISA advisory, and the relevant SigmaHQ AS-REP roasting rule as a logic reference.
- **SME:** Identity team confirmed three legacy service accounts intentionally have pre-auth disabled — documented as known-good exclusions.

---

## Step 4 — Feasibility

| Criterion | Status | Notes |
|---|---|---|
| Data Availability | ✅ GO | 4768 ingested from all DCs |
| Data Quality | ⚠️ CONDITIONAL | Pre-auth type parsed on 4 of 5 DCs; `DC05` sourcetype broken |
| Skillset | ✅ GO | SPL and AD experience on team |
| Timeline | ✅ GO | ~3 days |
| Tooling | ✅ GO | Splunk ES, AD inventory lookup |
| **Overall** | ⚠️ **CONDITIONAL** | Proceed with caveat; parallel ticket to fix parsing |

**Caveat carried into the report:** findings are bounded by device completeness of 4/5 domain controllers. A negative result does not establish absence of this activity on `DC05`.

---

## Step 5 — Scope and Objectives

- **In-scope:** all on-prem Windows Domain Controllers; all Tier 0 and Tier 1 service accounts
- **Time window:** last 30 days
- **Exclusions:** the three documented legacy accounts identified by the Identity team
- **Primary objective:** determine whether AS-REP Roasting activity has occurred
- **Secondary objective:** identify service accounts that should be remediated to require pre-authentication

---

# Step 6 — The Jira Plan

## Board configuration

| Field | Value |
|---|---|
| Project | `HUNT` |
| Issue types | Epic (hypothesis) · Story (test) · Task (outcome) |
| Components | `identity` · `on-prem-ad` · `splunk` |
| Labels | `t1558.004` `credential-access` `cti-driven` `conditional-feasibility` |
| Sprint | 2026.S18 |

**Workflow states** — map one-to-one to the process so board position answers "where is this hunt?":

```
Triage → Hypothesis → Feasibility → Ready for Hunt → Hunting
   → Analysis → Reporting → Done
                    ↘ Backlogged (NO-GO, with remediation ticket linked)
```

---

## Epic — `HUNT-042`

```markdown
Summary:     HUNT-042 AS-REP Roasting against pre-auth-disabled service accounts
Issue Type:  Epic
Status:      Reporting
Priority:    High
Owner:       Lead Threat Hunter
Sprint:      2026.S18        Estimate: 5 points        Hunt Type: TIO
```

### Environment Profile
Splunk ES · CrowdStrike Falcon · hybrid on-prem AD + Entra ID · financial services · 90d hot / 1y cold · identity domain.

### Hypothesis
> We hypothesize that an actor performing AS-REP Roasting (T1558.004) may be probing accounts with Kerberos pre-authentication disabled in our domain, evidenced by Event ID 4768 with pre-authentication type 0 originating from unexpected client addresses in Splunk Windows Security logs, which we can validate by querying the last 30 days and cross-referencing the requesting host against our asset inventory within one sprint (10 business days).

Rubric score: **15/15 — GO**. ABLE decomposition recorded above.

### Triggering Event
| Field | Value |
|---|---|
| Type | CTI |
| Source | CISA advisory (link) via internal CTI feed |
| Date received | 2026-04-14 |
| Relevance | Matching vertical, matching service-account architecture |
| Source confidence | High — government advisory, corroborated by two vendor reports |

### Feasibility Decision
**CONDITIONAL.** `DC05` sourcetype parsing broken — `Pre_Authentication_Type` not extracted. Proceeding with documented coverage caveat; remediation tracked at `HUNT-042-T2`.

Telemetry scoring (see [telemetry-gap-assessment.md](../references/telemetry-gap-assessment.md)):

| Data component | Visibility | Device completeness | Retention |
|---|---|---|---|
| Logon Session: Logon Session Creation (4768) | 4/5 | 80% (4 of 5 DCs) | 90d hot — covers 30d window ✅ |
| Active Directory: AD Object Access (`userAccountControl`) | 5/5 | 100% (daily inventory export) | Current state only |

### Scope
In-scope: all on-prem DCs; Tier 0 and Tier 1 service accounts. Window: 30 days. Exclusions: three documented legacy accounts (`svc-legacy-apppool`, `svc-oldscan`, `svc-fax01`) per Identity team.

### Objectives
1. **Primary** — determine whether AS-REP Roasting has occurred against in-scope accounts.
2. **Secondary** — identify accounts that should be remediated to require pre-auth regardless of hunt finding.
3. **Tertiary** — establish whether existing detection coverage would have caught this.

### ATT&CK Mapping
| ID | Technique | Tactic | Confidence |
|---|---|---|---|
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | Credential Access | High |
| T1078.002 | Valid Accounts: Domain Accounts | Persistence / Priv-Esc | Medium — follow-on if creds cracked |

### Data Sources Required
| Source | Fields | Location |
|---|---|---|
| `WinEventLog:Security` 4768 | `Account_Name`, `Client_Address`, `Pre_Authentication_Type`, `Ticket_Encryption_Type`, `Ticket_Options`, `ComputerName` | `index=wineventlog` |
| AD inventory export | `sAMAccountName`, `userAccountControl`, `pwdLastSet`, `servicePrincipalName`, `adminCount` | `| inputlookup ad_accounts.csv` |
| Asset inventory | `ip`, `hostname`, `owner`, `asset_class` | ES asset framework |

### Definition of Done (Epic)
- [ ] All Stories closed with documented findings
- [ ] Every finding triaged to benign or escalated
- [ ] Coverage caveat stated in the final report
- [ ] At least one typed outcome Task closed
- [ ] Follow-on hunt idea filed or explicitly declined

### Links
CISA advisory · MITRE T1558.004 · SigmaHQ AS-REP roasting rule · `IDM-3391` (Identity remediation) · `PLAT-8822` (DC05 sourcetype)

---

## Story — `HUNT-042-S1` · Baseline 4768 pre-auth-type-0 requests

```markdown
Parent: HUNT-042      Status: Done      Estimate: 2 points      Assignee: Hunter A
```

**Objective.** Establish every AS-REP request without pre-authentication in the last 30 days, and determine whether any originated from a client address that has no business making one.

**Observable behavior.** A roasting tool requests a TGT for an account with `DONT_REQ_PREAUTH` set. The DC returns an AS-REP containing material encrypted with the account's key — offline-crackable. The request is logged on the DC as 4768 with pre-auth type `0`. Tools such as Rubeus request RC4 (`0x17`) by default because it is the cheapest to crack, so encryption type is a strong secondary signal — but do not depend on it, since the type is attacker-selectable.

**Methodology.**
1. Pull 30 days of 4768 where pre-auth type is 0.
2. Normalize `Client_Address` (strip IPv6-mapped prefix) and exclude the documented known-good accounts.
3. Aggregate by client address: distinct accounts requested, encryption types, first/last seen.
4. Enrich against asset inventory; anything unresolved or outside the expected service-host set is a lead.
5. Triage leads against the account owner and the host's normal role.

**Detection logic.**

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768 earliest=-30d
| eval preauth = coalesce(Pre_Authentication_Type, PreAuthType)
| where preauth == "0"
| eval client_ip = replace(Client_Address, "^::ffff:", "")
| search NOT [ | inputlookup asrep_known_good.csv | fields Account_Name ]
| eval rc4 = if(Ticket_Encryption_Type == "0x17", 1, 0)
| stats count
        dc(Account_Name) as unique_accounts
        values(Account_Name) as accounts
        values(Ticket_Encryption_Type) as enc_types
        max(rc4) as rc4_requested
        min(_time) as first_seen
        max(_time) as last_seen
        by client_ip
| lookup asset_inventory ip as client_ip OUTPUT hostname, owner, asset_class
| eval first_seen = strftime(first_seen, "%F %T"),
       last_seen  = strftime(last_seen,  "%F %T"),
       window_min = round((last_seen - first_seen)/60, 1)
| sort - unique_accounts
```

> **Field-name caveat.** `Pre_Authentication_Type` is the Splunk_TA_windows extraction; raw XML uses `PreAuthType`. The `coalesce` handles both, which matters here because `DC05` is the host with the broken sourcetype.

**Data sources.**

| Source | Fields required | Location |
|---|---|---|
| `WinEventLog:Security` 4768 | `Account_Name`, `Client_Address`, `Pre_Authentication_Type`, `Ticket_Encryption_Type` | `index=wineventlog` |
| `asrep_known_good.csv` | `Account_Name` | Lookup (maintained by Identity) |
| `asset_inventory` | `ip`, `hostname`, `owner`, `asset_class` | ES asset framework |

**False positive risk — Medium.** Legitimate pre-auth-disabled accounts generate this event every time they authenticate. Volume is dominated by the three known-good accounts; the exclusion lookup is what makes the result readable. Misconfigured application servers and Linux/Kerberos clients with `DONT_REQ_PREAUTH` also appear.

**Expected outcomes.**
- *Malicious:* one client address requesting several distinct roastable accounts in a short window, RC4 requested, host not in the expected service-host set.
- *Benign:* only known-good accounts, each from its own stable, inventoried service host.

**Acceptance criteria.**
- [ ] Query executed across the full 30-day window on all reachable DCs
- [ ] Known-good exclusions applied and the lookup version recorded
- [ ] Every distinct `client_ip` resolved to an owner or escalated as unresolved
- [ ] `DC05` coverage gap noted in the Story result
- [ ] Findings and null results both documented — a clean result is a result

**Result.** 2,118 events, 3 distinct accounts — all three known-good, each from its own stable service host, no RC4 burst, no unresolved client addresses. Hypothesis **not supported** for the 4/5 DCs in coverage.

---

## Story — `HUNT-042-S2` · Cross-reference roastable accounts against current AD state

```markdown
Parent: HUNT-042      Status: Done      Estimate: 1 point      Assignee: Hunter B
```

**Objective.** Independent of whether roasting occurred, enumerate every account currently exposed to it and identify which should be remediated. S1 asks "did it happen"; S2 asks "could it, and how badly."

**Methodology.**
1. Pull current AD export, filter to accounts with `DONT_REQ_PREAUTH` in `userAccountControl`.
2. Flag privileged exposure: `adminCount=1`, membership in Tier 0/1 groups, presence of an SPN.
3. Assess crackability proxy: password age, and whether the account is a legacy service identity.
4. Diff against `asrep_known_good.csv` — anything present in AD but absent from the lookup is undocumented exposure.

**Detection logic.**

```spl
| inputlookup ad_accounts.csv
| where like(userAccountControl_flags, "%DONT_REQ_PREAUTH%")
| eval spn_present   = if(isnotnull(servicePrincipalName), "yes", "no"),
       privileged    = if(adminCount == 1, "yes", "no"),
       pwd_age_days  = round((now() - strptime(pwdLastSet, "%F %T")) / 86400, 0)
| eval risk = case(
      privileged == "yes",                       "critical",
      spn_present == "yes" AND pwd_age_days>365, "high",
      pwd_age_days > 365,                        "medium",
      true(),                                    "low")
| lookup asrep_known_good.csv Account_Name as sAMAccountName OUTPUT Account_Name as documented
| eval documented = if(isnull(documented), "UNDOCUMENTED", "documented")
| table sAMAccountName, privileged, spn_present, pwd_age_days, risk, documented, description
| sort - risk
```

**False positive risk — Low.** This is a configuration census, not behavioral detection. The judgment call is which exposures are accepted risk, and that belongs to the Identity team, not the hunter.

**Expected outcomes.**
- *Finding:* accounts with pre-auth disabled that are undocumented, privileged, or stale-password — each a Security Control Issue.
- *Clean:* the only exposed accounts are the three documented legacy identities.

**Acceptance criteria.**
- [ ] AD export is same-day
- [ ] Every exposed account classified and risk-rated
- [ ] Undocumented exposures handed to Identity with a named owner
- [ ] Known-good lookup updated if any exposure is formally accepted

**Result.** 5 accounts exposed — the 3 documented, plus `svc-reporting01` and `svc-etl-batch` (both undocumented, passwords older than 2 years, one with an SPN). Neither appeared in S1 traffic, meaning they were exposed but not yet targeted.

---

## Story — `HUNT-042-S3` · Validate detection coverage

```markdown
Parent: HUNT-042      Status: Done      Estimate: 2 points      Assignee: Hunter A + Red Team
```

**Objective.** Two clean Stories are only meaningful if the telemetry would have shown the activity. Prove it before closing the hunt — per the [validation hook](../references/validation-hook.md).

**Methodology.**
1. Coordinate the window with SOC leadership; record the approval reference.
2. Stand up a purpose-built lab account with `DONT_REQ_PREAUTH` set, on a designated test host.
3. Execute the Atomic Red Team atomic for T1558.004 (Rubeus `asreproast`) against that account only. *Confirm the current test index in the atomic-red-team repo before running — numbering changes.*
4. Re-run the S1 query blind over the test window.
5. Record telemetry generated, whether the query matched, and ingest lag. Tear down.

**Acceptance criteria.**
- [ ] Change approval recorded before execution
- [ ] Start/stop UTC, host, and account documented
- [ ] S1 query re-run without foreknowledge of exact timestamps
- [ ] Result recorded as Validated / False negative / Partial
- [ ] Lab account and artifacts removed, confirmed with host owner

**Result.** **Validated.** 4768 pre-auth-type-0 with RC4 generated on the target DC; S1 query matched within a 6-minute ingest lag. Two operational findings: the lab host did not appear in asset inventory (surfaced an inventory gap, filed as a new idea), and the same test against `DC05` produced *no parseable pre-auth field* — confirming the `HUNT-042-T2` gap empirically rather than by assumption.

---

## Tasks — outcomes

### `HUNT-042-T1` · Analytics/Detection
```markdown
Parent: HUNT-042-S1      Status: Done      Assignee: Detection Engineering
```
S1 logic promoted to a scheduled Splunk ES correlation search (`DET-118`), firing on a single client address requesting ≥3 distinct roastable accounts within 10 minutes, or any request from a client address absent from asset inventory. Handed off using the [Detection Handoff Spec](../references/detection-handoff-spec.md) with blind spots (RC4 not required for match; `DC05` excluded until parsing fixed), false positives (three known-good accounts, suppressed by lookup), robustness rationale, and the S3 validation evidence attached. Peer-reviewed, merged to the detection repo, 30-day review scheduled.

### `HUNT-042-T2` · Visibility Gap
```markdown
Parent: HUNT-042      Status: In Progress      Assignee: Platform Engineering (PLAT-8822)
```
`DC05` sourcetype misconfiguration prevents extraction of `Pre_Authentication_Type`, leaving 20% device-incomplete coverage for this technique. Empirically confirmed during S3 — the atomic executed against DC05 produced no parseable field. Blocks removal of the Epic's CONDITIONAL caveat and blocks full deployment of `DET-118`. Re-run S1 against DC05's 30-day window once fixed.

### `HUNT-042-T3` · Security Control Issue
```markdown
Parent: HUNT-042-S2      Status: Done      Assignee: Identity Team (IDM-3391)
```
`svc-reporting01` and `svc-etl-batch` have pre-authentication disabled with no documented justification and passwords older than two years. Recommended: re-enable pre-auth after application testing; rotate credentials; if either must stay exposed, add to `asrep_known_good.csv` with a named owner and a review date. Identity confirmed neither requires the setting — both remediated.

### `HUNT-042-T4` · Written Report
```markdown
Parent: HUNT-042      Status: Done      Assignee: Lead Threat Hunter
```
Final report attached to the Epic. Leads with the coverage caveat: *no evidence of AS-REP Roasting across 4 of 5 domain controllers over 30 days; DC05 not assessed pending PLAT-8822. Detection coverage validated by live execution. Two undocumented exposures identified and remediated.*

### `HUNT-042-T5` · New Hunt Idea
```markdown
Parent: HUNT-042-S2      Status: Backlog      Assignee: Unassigned
```
Kerberoasting (T1558.003) against the same service-account population — S2 already produced the SPN inventory, so the assessment work is half done. Rubric-score before scheduling.

### `HUNT-042-T6` · New Hunt Idea
```markdown
Parent: HUNT-042-S3      Status: Backlog      Assignee: Unassigned
```
Asset inventory completeness — the S3 lab host never appeared in inventory, meaning `DET-118`'s "unknown client address" condition may produce noise from legitimate uninventoried hosts. Worth an EDA hunt on inventory coverage before the 30-day detection review.

---

## Step 7 — Report & Iterate

**Metrics contributed** (see [maturity-and-metrics.md](../docs/maturity-and-metrics.md)):

| Metric | This hunt |
|---|---|
| Threats found that detection missed | 0 |
| Net-new detections shipped and validated | 1 (`DET-118`) |
| Visibility gaps raised / closed | 1 raised, 0 closed (in progress) |
| Security control issues remediated | 2 |
| Validated technique coverage | +1 (T1558.004, validated 2026-04-22) |
| Hunt→detection cycle time | 6 days |
| New hunt ideas generated | 2 |

---

## What this hunt demonstrates

- **A clean result is a result, but only with validation attached.** Without S3, "we found nothing" is indistinguishable from "we couldn't have seen it." S3 turned a null finding into a defensible coverage claim — and independently proved the DC05 gap.
- **CONDITIONAL is a real state, not a soft GO.** The caveat travels from the feasibility table into the Story result, the detection's blind spots, and the first line of the report.
- **The durable value wasn't the incident.** There wasn't one. It was a validated detection, a measured telemetry gap, and two remediated exposures that nobody had documented.
- **One hunt seeds the next.** T5 and T6 are the next Epics, and S2's output is already half their initial assessment.
