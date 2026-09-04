# Worked Example: HUNT-042 — AS-REP Roasting

End-to-end walkthrough of the [Unified Threat Hunting Process](../README.md), from trigger to typed outcomes. Field names and tooling assume the Environment Profile below.

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

**ABLE:** Actor — financially motivated eCrime group (per advisory) · Behavior — AS-REP request for pre-auth-disabled accounts · Location — on-prem domain controllers · Evidence — 4768 pre-auth type 0 from non-DC source.

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

## Step 6 — Jira Plan

**Epic `HUNT-042` — AS-REP Roasting Detection Hunt**
Links: CISA advisory, MITRE T1558.004, Sigma reference · Data sources: `wineventlog:security` (4768), AD inventory lookup · ATT&CK: T1558.004 (Credential Access)

**Story `HUNT-042-S1` — Baseline 4768 pre-auth-type-0 events**
Methodology: SPL over 30 days, group by `src_host` and `account_name`, exclude known-good list, rank by frequency.
- *Expected malicious:* requests from non-DC hosts targeting multiple roastable accounts
- *Expected benign:* only legacy known-good accounts, from expected service hosts

**Story `HUNT-042-S2` — Cross-reference roastable accounts against current AD state**
Methodology: compare findings against the current `DONT_REQ_PREAUTH` flag in AD; identify accounts needing remediation regardless of hunt outcome.

---

## Step 7 — Outcomes

| Task | Type | Result |
|---|---|---|
| `HUNT-042-T1` | Analytics/Detection | Validated query converted to a scheduled Splunk ES correlation rule — shipped via the [handoff spec](../references/detection-handoff-spec.md) after an Atomic Red Team validation confirmed it fires |
| `HUNT-042-T2` | Visibility Gap | `DC05` sourcetype parsing broken; ticket with platform team |
| `HUNT-042-T3` | Security Control Issue | Two service accounts with pre-auth disabled that should not have it; remediation handed to Identity |
| `HUNT-042-T4` | Written Report | Final report attached to the Epic, including the DC05 coverage caveat |
| `HUNT-042-T5` | New Hunt Idea | Kerberoasting (T1558.003) follow-up against the same service account population |

---

## What this hunt demonstrates

- A CONDITIONAL feasibility decision is a valid outcome, provided the caveat travels with the finding all the way into the report.
- The most durable results were not the incident (there wasn't one) — they were a shipped detection, a closed visibility gap, and a control issue that would have gone unnoticed.
- One hunt seeds the next. `T5` becomes the next Epic.

The same structure scales to larger campaigns by adding Stories under one Epic.