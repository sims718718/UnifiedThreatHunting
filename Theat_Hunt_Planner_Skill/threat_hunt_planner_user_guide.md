# 🎯 Threat Hunt Planner — User Guide

> **AI-powered threat hunt planning using the Unified Threat Hunting Process methodology.**  
> Generate structured, Jira-ready hunt plans from a CVE, CTI report, MITRE technique, or a rough idea — in minutes.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Triggering the Skill](#triggering-the-skill)
- [Quick Start](#quick-start)
- [The 6-Step Planning Process](#the-6-step-planning-process)
  - [Step 0 — Gather Environment Context](#step-0--gather-environment-context)
  - [Step 1 — Identify the Triggering Event](#step-1--identify-the-triggering-event)
  - [Step 2 — Develop a Hypothesis](#step-2--develop-a-hypothesis)
  - [Step 3 — Conduct an Initial Assessment](#step-3--conduct-an-initial-assessment)
  - [Step 4 — Perform a Feasibility Assessment](#step-4--perform-a-feasibility-assessment)
  - [Step 5 — Define Scope and Objectives](#step-5--define-scope-and-objectives)
  - [Step 6 — Formalize the Hunt Plan](#step-6--formalize-the-hunt-plan)
- [Express Mode — Rapid Hunt Skeleton](#express-mode--rapid-hunt-skeleton)
- [Hunt Types](#hunt-types)
- [Output Formats](#output-formats)
  - [Epic](#epic)
  - [Story](#story)
  - [Task](#task)
- [Outcome Categories](#outcome-categories)
- [Example Prompts](#example-prompts)
- [Tips and Best Practices](#tips-and-best-practices)
- [FAQ](#faq)

---

## Overview

The **Threat Hunt Planner** is a Claude skill that generates complete, structured threat hunt plans following the **Unified Threat Hunting Process** methodology. It is designed for threat hunters, detection engineers, and security operations teams who need to move quickly from a threat signal to an actionable, documented plan.

Key capabilities:

- Translates CTI reports, CISA advisories, MITRE ATT&CK techniques, CVEs, or red team findings into hunt plans
- Produces **SMART hypotheses** — Specific, Measurable, Achievable, Relevant, and Time-bound
- Outputs plans in **Jira-ready format** (Epics → Stories → Tasks)
- Generates **Sigma detection rules** from hunt findings
- Conducts **feasibility assessments** before committing the team
- Supports both full 6-step planning and rapid **Express Mode** for time-sensitive situations

---

## How It Works

The skill follows a structured, phased methodology:

```
Planning Phase         Pre-Execution Phase     Post-Execution Phase
──────────────         ───────────────────     ────────────────────
Steps 0–6              Data source exploration  Sigma rule generation
Hypothesis → Plan  →   Validate telemetry   →  Hunt outcome docs
Feasibility check      Confirm tool access     Jira task population
```

The planner will ask clarifying questions when context is missing, but it will **never block on perfect information**. If critical details are unavailable, it generates plans with clearly marked `[FILL IN: <detail>]` placeholders so your team can get started immediately.

---

## Triggering the Skill

The skill activates automatically when your message includes any of the following:

| Signal | Example |
|--------|---------|
| Threat hunt language | *"Build me a hunt plan for..."* |
| MITRE ATT&CK technique | *"I want to hunt for T1059.001"* |
| Threat actor or APT group | *"Fancy Bear / APT29 / Lazarus Group"* |
| CTI report or advisory | *"Here's a CISA advisory, turn it into a hunt"* |
| CVE in a detection context | *"CVE-2024-XXXX was just published, help me hunt for exploitation"* |
| Detection gap | *"We have no coverage for lateral movement via WMI"* |
| Purple team framing | *"We just finished a red team exercise, now let's hunt"* |
| Urgency signals | *"quick hunt plan," "hunt skeleton," "rough draft"* |

---

## Quick Start

The fastest way to get a hunt plan is to provide **what triggered the hunt** and **your SIEM platform**. Everything else can be filled in along the way.

**Minimum viable prompt:**

```
Build a hunt plan for [threat actor / technique / CVE / behavior].
We use [Splunk | Microsoft Sentinel | Elastic | Chronicle].
```

**Example:**

```
Build a hunt plan for detecting Kerberoasting activity.
We use Splunk with a 90-day retention window.
```

The planner will produce a complete Epic, at least one Story, and placeholder Tasks — along with MITRE ATT&CK mappings and example detection logic tailored to your SIEM.

---

## The 6-Step Planning Process

### Step 0 — Gather Environment Context

Before generating the plan, the planner captures your environment to ensure all queries, field names, and tool references are accurate — not generic.

| Context | Why It Matters |
|---------|----------------|
| **SIEM / Data Platform** | Splunk SPL vs. KQL vs. Elastic DSL vs. Chronicle affects every query |
| **EDR Platform** | CrowdStrike, SentinelOne, Defender for Endpoint — affects telemetry field names |
| **Environment Type** | On-premises, cloud-native (AWS/Azure/GCP), or hybrid |
| **Industry Vertical** | Tailors threat actor relevance (finance, healthcare, energy, etc.) |
| **Log Retention Window** | Determines which time windows are actually feasible |
| **Hunt Maturity Level** | First-time hunters get more scaffolding; experienced teams get a leaner skeleton |

> **Express path:** If you're in a hurry, just provide your **SIEM platform** and **environment type** — these are the minimum required for non-generic outputs.

---

### Step 1 — Identify the Triggering Event

Every hunt begins with a trigger. The planner will identify and document which type applies:

| Trigger Type | Description |
|--------------|-------------|
| **CTI** | Threat report, intelligence advisory, or intel feed |
| **Incomplete Use Cases** | Gaps in existing detection coverage |
| **Past Incidents** | Lessons learned from previous security events |
| **Red Team / Purple Team** | Offensive assessment results |
| **MITRE ATT&CK TTPs** | Specific techniques requiring validation |
| **Stakeholder Requirements** | Requests from leadership or business units |
| **Vulnerability Disclosure** | New CVEs affecting your environment |

The trigger source, date received, and organizational relevance are all documented at the top of the Epic.

---

### Step 2 — Develop a Hypothesis

The planner constructs a **SMART hypothesis** using this template:

```
We hypothesize that [THREAT ACTOR/TECHNIQUE/BEHAVIOR] may be present in our
environment, evidenced by [OBSERVABLE INDICATORS] in [DATA SOURCES], which
we can validate by [TEST METHODOLOGY] within [TIMEFRAME].
```

SMART criteria applied:

| Criterion | Requirement |
|-----------|-------------|
| **Specific** | Clear and unambiguous — no room for misinterpretation |
| **Measurable** | Quantifiable criteria to track progress |
| **Achievable** | Realistic given team capabilities and data access |
| **Relevant** | Aligned with organizational goals and risk priorities |
| **Time-bound** | Defined start/end dates — no open-ended hunts |

For complex hunts requiring **competing hypotheses**, the planner will generate multiple hypothesis branches and evaluate each.

---

### Step 3 — Conduct an Initial Assessment

The planner gathers supporting information from both internal and external sources before committing to a plan.

**Internal sources reviewed:**
- Previous hunt reports and lessons learned
- Network and application architecture (if provided)
- Internal threat intelligence
- Existing detection rules and coverage maps
- Asset inventory and crown jewels (if provided)

**External sources reviewed:**
- OSINT and vendor threat reports
- MITRE ATT&CK technique documentation
- Public Sigma rule repositories
- Threat actor profiles and campaign analysis

If specific systems or business units are involved, the planner will flag where **Subject Matter Expert (SME) engagement** is needed.

---

### Step 4 — Perform a Feasibility Assessment

Before generating the plan, the planner validates the hunt is actually executable.

**Five core questions:**

1. **Data Availability** — Do the required log sources exist and are they accessible?
2. **Data Quality** — Is telemetry complete, correctly parsed, and retained long enough?
3. **Team Skillset** — Does the team have the expertise the analysis requires?
4. **Timeline** — Can this be completed within the allocated sprint or time window?
5. **Tooling** — Are required tools (SIEM, EDR, notebooks) available?

**Decision outcomes:**

| Decision | Meaning |
|----------|---------|
| ✅ **GO** | All criteria met — proceed to planning |
| ❌ **NO-GO** | Critical blockers exist — backlog with a remediation plan |
| ⚠️ **CONDITIONAL** | Minor gaps — documented assumptions, proceed with caveats |

---

### Step 5 — Define Scope and Objectives

The planner locks down the boundaries and success criteria so the hunt stays focused.

**Scope definition covers:**
- Target environment segments (production, DMZ, cloud, endpoints)
- Time window for analysis (e.g., last 30 days, a specific incident window)
- In-scope systems and assets
- Explicit exclusions

**Objectives are split into:**
- **Primary** — What must be answered to validate or invalidate the hypothesis?
- **Secondary** — Additional findings that would add value
- **Metrics** — How success will be measured

---

### Step 6 — Formalize the Hunt Plan

The planner outputs a complete **Jira-ready plan** in a three-tier structure.

See the [Output Formats](#output-formats) section for full template details.

---

## Express Mode — Rapid Hunt Skeleton

When time doesn't allow the full 6-step process, **Express Mode** produces a condensed, actionable plan in a single pass.

**Trigger Express Mode with phrases like:**
- *"quick plan"*
- *"rough draft"*
- *"just give me a skeleton"*
- *"urgent — CVE just dropped"*

**What Express Mode produces:**
1. Trigger and hypothesis in 2–3 sentences
2. Top 2–3 required data sources
3. Key MITRE ATT&CK techniques under investigation
4. Rough effort estimate: **Low** (1–2 days) / **Medium** (3–5 days) / **High** (1–2 weeks)
5. A single condensed Epic with one placeholder Story

> ⚠️ **EXPRESS PLAN** — Full feasibility assessment and competing hypotheses analysis not completed. Upgrade to the full 6-step process before hunt execution.

Express Mode plans are explicitly labeled with this warning so your team knows what corners were cut.

---

## Hunt Types

Select the hunt type that matches your starting position in the **DAIKI chain** (Data → Information → Knowledge → Insight):

| Hunt Type | Abbreviation | Starting Point | Characteristics |
|-----------|-------------|----------------|-----------------|
| **Exploratory** | EDA | Raw data | Baselining, understanding data shape, no prior hypothesis |
| **Hypothesis-Based** | HBO | Situational awareness | Testing credible attack scenarios |
| **Threat-Informed** | TIO | Actionable CTI | Intelligence-driven, known actor/TTP focus |
| **Purple Operations** | DPO | Red team insight | Joint offensive/defensive validation |

Tell the planner which hunt type applies (or describe your starting point) and it will tailor the plan accordingly.

---

## Output Formats

All outputs follow the Jira **Epic → Story → Task** hierarchy.

### Epic

The Epic represents the overarching hunt hypothesis. One Epic per hunt.

```markdown
## Epic: [HUNT-XXX] [Descriptive Title]

### Hypothesis
[SMART hypothesis statement]

### Triggering Event
- Type: [CTI | Incident | Red Team | TTP Coverage | Stakeholder Request]
- Source: [Source name/reference]
- Date Received: [YYYY-MM-DD]
- Relevance: [Why this matters to the organization]

### Initial Research
[Summary of initial assessment findings, key references, prior art]

### Feasibility Assessment
- Data Availability: [GO/NO-GO with notes]
- Data Quality: [GO/NO-GO with notes]
- Skillset: [GO/NO-GO with notes]
- Timeline: [Estimated duration]
- Tooling: [Required tools]
- **Overall Decision**: [GO | NO-GO | CONDITIONAL]

### Scope
- Environment: [Target segments]
- Time Window: [Analysis period]
- In-Scope Assets: [List]
- Exclusions: [List]

### Objectives
1. [Primary objective]
2. [Secondary objective]

### MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic |
|--------------|----------------|--------|
| TXXXX.XXX    | Name           | Tactic |

### Data Sources Required
- [Log source 1]
- [Log source 2]

### References
- [Link/citation 1]
- [Link/citation 2]
```

---

### Story

Stories are discrete investigations under the Epic. Each Story tests a specific aspect of the hypothesis. Multiple Stories per Epic are common for complex hunts.

```markdown
## Story: [HUNT-XXX-S1] [Investigation Title]

### Parent Epic
[HUNT-XXX]

### Objective
[What this specific investigation aims to determine]

### Hypothesis Component
[Which part of the Epic hypothesis this tests]

### Methodology
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Data Sources
| Source | Fields Required | Location |
|--------|-----------------|----------|
| Source | field1, field2  | SIEM/EDR |

### Detection Logic
[Query pseudocode or Sigma rule]

### Expected Outcomes
- If malicious: [What evidence would confirm threat presence]
- If benign: [What evidence would invalidate the hypothesis]

### Acceptance Criteria
- [ ] Data sources validated
- [ ] Queries executed across full time window
- [ ] Findings documented
- [ ] False positives triaged
```

---

### Task

Tasks capture hunt outcomes. Placeholder Tasks are created during planning and populated after execution.

```markdown
## Task: [HUNT-XXX-T1] [Outcome Type]: [Brief Description]

### Parent Story
[HUNT-XXX-S1]

### Outcome Category
[New Hunt Idea | Analytics/Detection | Security Incident | Written Report | Visibility Gap | Security Control Issue]

### Description
[Details of the finding/outcome]

### Evidence
[Supporting data, screenshots, query results]

### Recommended Action
[Next steps based on this outcome]

### Assignee
[Team/individual responsible for action]
```

---

## Outcome Categories

Tasks are classified into six outcome categories from the **AIMOD2 framework**:

| Category | Description |
|----------|-------------|
| 🔍 **New Hunt Idea** | A future hypothesis surfaced during the hunt |
| 🛡️ **Analytics/Detection** | Rules, dashboards, or signatures created or improved |
| 🚨 **Security Incident** | Finding requiring escalation to Incident Response |
| 📄 **Written Report** | Final hunt documentation for leadership or records |
| 🕳️ **Visibility Gap** | Missing telemetry or log sources identified |
| 🔓 **Security Control Issue** | Gap or misconfiguration in defenses discovered |

---

## Example Prompts

Below are ready-to-use prompts that demonstrate the range of the skill.

**Hunt from a MITRE technique:**
```
Build a full hunt plan for T1078 — Valid Accounts.
We're a mid-size financial services company using Microsoft Sentinel
and Defender for Endpoint. Log retention is 180 days.
```

**Hunt from a CTI advisory:**
```
CISA just published an advisory on Volt Typhoon targeting critical infrastructure.
We're a utility company running Splunk on a hybrid environment.
Turn this into an actionable hunt plan.
```

**Hunt from a CVE:**
```
CVE-2024-XXXXX was just patched — it allows unauthenticated RCE on our VPN appliances.
We need to hunt for signs of exploitation before the patch was applied.
We use Elastic SIEM and CrowdStrike Falcon.
```

**Post-red-team hunt:**
```
Our red team successfully moved laterally using Pass-the-Hash last week.
Help us build a hunt to determine if a real attacker has done the same
over the last 6 months. We use Splunk.
```

**Express Mode:**
```
Quick hunt skeleton for credential dumping via LSASS — we're on Splunk.
Need something in the next 30 minutes.
```

**Coverage gap analysis:**
```
We have no detection coverage for living-off-the-land binaries (LOLBins).
Help us plan a hunt to identify suspicious use of certutil, mshta, and wmic
in our environment.
```

---

## Tips and Best Practices

**Provide your SIEM platform early.** This single piece of context has the largest impact on output quality. Query syntax, field names, and lookup examples all depend on it.

**Use placeholders, not perfection.** The planner will generate `[FILL IN: <detail>]` markers wherever information is missing. A plan with placeholders is always more useful than no plan — fill them in during your planning meeting.

**Let feasibility block bad hunts.** If the planner returns a NO-GO, take it seriously. Hunting against incomplete or missing telemetry wastes sprint capacity. Use the remediation recommendations to fix the gap first.

**Create Tasks before you hunt, not after.** Placeholder Tasks defined at planning time ensure outcomes get captured systematically. Don't wait until the hunt is over to think about what you might find.

**Iterate with follow-up prompts.** After the initial plan is generated, you can refine it:
- *"Add a second Story for lateral movement via RDP."*
- *"Convert the detection logic to KQL."*
- *"Make the hypothesis more specific to our cloud environment."*

**Scale to hunt maturity.** Tell the planner if your team is new to hunting — it will add more scaffolding, annotate methodology steps, and explain the reasoning behind each decision.

---

## FAQ

**Q: What if I don't know my MITRE ATT&CK technique IDs?**  
A: Describe the behavior in plain language (e.g., *"attackers dumping credentials from memory"*) and the planner will map it to the appropriate MITRE technique(s) for you.

**Q: Can I paste in a full CTI report or CISA advisory?**  
A: Yes. Paste the text (or a summary) directly into your prompt. The planner will extract the relevant TTPs, IOCs, and threat actor context and build the hunt plan from it.

**Q: Does the planner write actual SIEM queries?**  
A: It generates detection logic in pseudocode or Sigma format by default. If you specify your SIEM platform (Splunk SPL, KQL, Elastic DSL, etc.), it will produce platform-specific query examples.

**Q: Can I use this for purple team exercise planning?**  
A: Yes — use the **Purple Operations (DPO)** hunt type and provide your red team's findings. The planner will structure the defensive validation as a hunt plan with clear pass/fail criteria.

**Q: What if my environment is entirely cloud-based?**  
A: Specify your cloud provider (AWS, Azure, GCP) and the planner will tailor data source references, log types, and query examples to cloud-native telemetry (e.g., CloudTrail, Azure Activity Logs, GCP Audit Logs).

**Q: How do I handle a NO-GO feasibility decision?**  
A: The planner will document the specific blockers and suggest remediation steps (e.g., enabling a log source, onboarding data to the SIEM). Backlog the hunt and revisit once the gaps are addressed.

**Q: Can I request an Express plan and then upgrade to a full plan?**  
A: Yes. Start with Express Mode to get something actionable immediately, then follow up with *"Upgrade this to a full 6-step plan"* when time allows.

---

*Built on the Unified Threat Hunting Process methodology and the AIMOD2 outcome framework.*
