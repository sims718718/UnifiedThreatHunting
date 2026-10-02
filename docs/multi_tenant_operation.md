# Multi-Tenant Operation

**Fits at:** Step 0 (Environment Context) through Step 9 (Report & Iterate) — an optional operating mode for teams that hunt across more than one organization.
**Purpose:** Run the same Unified Threat Hunting Process across N tenants without leaking one tenant's data into another's artifacts, and without summing signals from different customers together. Single-org teams can ignore this page; nothing here changes the default process.

---

## 1. When this applies

Every artifact in this repo assumes **one organization** by default: one Environment Profile per Epic, one exclusion list, one detection repo, one summary index. That stays the default. Multi-tenant mode is additive and applies when one hunt team serves more than one environment.

| Model | Example | Data separation | Cross-tenant sharing |
|---|---|---|---|
| **A. MSSP / MDR** | One hunt team, N customers | Hard (contract, legal) | TTPs yes, raw evidence no |
| **B. Federated enterprise** | Holding with subsidiaries / BUs on separate SIEM/EDR tenants | Medium (policy) | Mostly yes |
| **C. Shared platform** | One Splunk/Sentinel hosting N tenants by index/workspace | Logical (RBAC) | Operator decides |

This page is written for **model A**, the strictest case. Section 4 notes where B and C can relax it.

---

## 2. Campaign and Instance

Multi-tenant mode introduces one concept: the **Hunt Campaign**, a tenant-agnostic hypothesis that is *instantiated* once per tenant.

```
Campaign HUNT-042 (hypothesis, ATT&CK, Sigma logic, required data components)
 ├─ Instance HUNT-042@tenant-a  (profile, feasibility, scope, exclusions, stories, outcomes)
 ├─ Instance HUNT-042@tenant-b  ...
 └─ Instance HUNT-042@tenant-c  NO-GO → Visibility Gap
```

| Stays at campaign level (shared) | Moves to instance level (per tenant) |
|---|---|
| Trigger, SMART hypothesis (tenant-neutral wording) | Environment Profile (Step 0) |
| ATT&CK mapping, required data components | Feasibility decision, telemetry scores |
| Canonical detection logic (Sigma) | Compiled query (index/table/field bindings) |
| Hunt type, methodology, stories as *templates* | Scope, time window (bounded by tenant retention) |
| Roll-up metrics, anonymized findings | Known-good exclusions, SMEs, owners |
| | All six outcome Tasks, the report, IR escalation path |

A single-org hunt is simply a campaign with one instance, so the existing Epic → Story → Task structure is unchanged.

### Jira mapping

| Concept | Jira | Key scheme |
|---|---|---|
| Campaign | Initiative, or a parent Epic in a shared `HUNT` project | `HUNT-042` |
| Instance | One Epic per tenant, with a required `Tenant` field | `HUNT-042-<TENANT>` |
| Stories / Tasks | Under the instance Epic, unchanged | `HUNT-042-<TENANT>-S1`, `-T1` |

Use an **issue security scheme** keyed on `Tenant` so analysts and customer viewers only see their own tenant. Where customers have Jira access (model A), the stronger alternative is one Jira project per tenant with the campaign in an internal project, linked by issue links; isolation improves, roll-ups get harder.

---

## 3. Tenant registry (Step 0)

In multi-tenant mode the Environment Profile moves out of the Epic and into a versioned registry, one directory per tenant:

```
tenants/
  _template/
    profile.yaml          # schema, copy per tenant
    exclusions/README.md  # per-tenant known-good lookups
  <tenant-id>/
    profile.yaml
    exclusions/<campaign>.csv
```

The instance Epic *references* the tenant (`tenant: <tenant-id>`) instead of embedding a profile. See [`tenants/_template/profile.yaml`](../tenants/_template/profile.yaml) for the schema.

### NOT AUTHORIZED

Multi-tenant mode adds a check **before** feasibility:

| Decision | Meaning |
|---|---|
| ⛔ **NOT AUTHORIZED** | No RoE / contract coverage for this tenant (`hunting_authorized: false`), or a planned action is outside `allowed_actions`. The instance stops here; feasibility is not assessed. |

If authorized, feasibility runs per tenant with the usual GO / NO-GO / CONDITIONAL outcomes ([Telemetry Gap Assessment §6](../references/telemetry_gap_assessment.md)).

### Queries: logic vs. bindings

**Rule: no tenant identifier inside shared query logic.** Bindings (index, table, workspace, field mappings) live only in the registry or a per-tenant pipeline. In recommended order:

1. **Sigma + pySigma per-tenant pipelines.** Sigma is the canonical form; each tenant gets a processing pipeline for index/table names and field mappings, e.g. `sigma convert -t splunk -p tenants/<id>/pipeline.yml rule.yml`.
2. **Splunk-native.** Per-tenant macros, or one shared index with an indexed `tenant` field plus role-based `srchIndexesAllowed`. Federated search where tenants run separate deployments (model B).
3. **Microsoft-native.** Sentinel via Azure Lighthouse with cross-workspace `workspace("…")` / `union` queries (check current per-query workspace limits); Defender XDR multi-tenant management for MDE advanced hunting.
4. **Chronicle / SecOps.** One instance per tenant, or one instance with namespaces / data RBAC scopes.

Known-good exclusions are tenant data too. Shared logic calls a lookup keyed on tenant (`| lookup th_exclusions tenant, account`) and never inlines names; see [`tenants/_template/exclusions/`](../tenants/_template/exclusions/README.md).

---

## 4. Constraints (model A)

| # | Constraint | What it means in practice |
|---|---|---|
| 1 | **Authorization first** | Hunting a tenant needs RoE or contract coverage, and so does each intrusive action (live response, memory capture, active validation). Enforced by NOT AUTHORIZED. |
| 2 | **Segregation** | Analyst RBAC per tenant in SIEM, EDR, Jira and notebooks. Per-tenant notebook kernels and credentials; no shared dataframes. |
| 3 | **Intel flow rules** | Abstracted TTPs and IOCs may flow across tenants under TLP. Raw evidence, identities and hostnames never do. |
| 4 | **Retention and residency** | Time window = `min(requested, tenant retention)`. Cross-region roll-ups respect `data_residency`. |
| 5 | **Reporting** | Customer-facing outputs never name or compare other tenants. |

For **model B**, constraints 3 and 5 are mostly internal policy. For **model C**, constraint 2 is the main control.

---

## 5. Cross-tenant signals

With N tenants you can run hunts no single organization can:

- **Cross-tenant rarity** — process, hash, domain or JA4 prevalence across the customer base ("seen at ≤ 2 of N tenants").
- **Campaign fan-out** — a TTP confirmed at one tenant opens a *new instance* of the campaign for every tenant with a matching vertical or stack. This adds a Trigger type: **Peer-tenant finding**.

**Guardrails**

- Aggregate only derived features (counts, hashes, TTPs), never raw events or identities.
- Only include tenants whose profile allows it (`sharing.allow_anonymized_rollup: true`).
- Keep the source tenant anonymous in the fan-out trigger.

---

## 6. Outcomes

| Outcome | Multi-tenant handling |
|---|---|
| Analytics/Detection | Shared detection repo (Sigma), then per-tenant deployment with tuning overlays and allowlists. 30-day review per tenant; a rule may be enabled for a subset of tenants. See [Detection Handoff Spec](../references/detection_handoff_spec.md). |
| Security Incident | Follow the tenant's `escalation` path from the registry. Check sibling exposure in other tenants (§5) without sharing evidence. |
| Visibility Gap / Control Issue | Per tenant. For MSSPs these are often contractual deliverables; track against SLA. |
| Written Report | Per-tenant report (no other tenant named or compared) plus an internal campaign roll-up. |
| New Hunt Idea | Campaign level by default. |

Validation ([Validation Hook](../references/validation_hook.md)) runs per tenant, only where RoE allows it.

---

## 7. Metrics roll-up

- HMM maturity is tracked **per tenant**, and program maturity separately.
- Outcome metrics per tenant, plus campaign roll-ups: % of tenants GO, detections deployed per tenant, mean time from peer-tenant finding to fan-out instance.
- Cross-tenant benchmarking is shown to a customer only as an anonymized percentile.

See [Maturity & Metrics §5](./maturity_metric.md).

---

## 8. Rollout

| Phase | Change | Breaking? |
|---|---|---|
| 1 | Adopt `tenants/` registry and this page; keep single-org Epics as-is | No |
| 2 | Re-run a past hunt as a campaign with 2–3 instances (GO / CONDITIONAL / NO-GO) to exercise the matrix | No |
| 3 | Per-tenant feasibility matrix, instance binding in the rubric, Campaign template in Jira | No |
| 4 | Port 2–3 queries to Sigma + per-tenant pipelines; add `tenant` at `collect` in Signal-Based searches | Per-deployment |
| 5 | Registry-aware Step 0 and campaign output in the threat-hunt-planner skill | No — falls back to single-org |

---

**References:** Unified Threat Hunting Process (README) · pySigma processing pipelines (https://github.com/SigmaHQ/pySigma) · Azure Lighthouse cross-tenant management (https://learn.microsoft.com/azure/lighthouse/) · Splunk federated search (https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutfederatedsearch) · Traffic Light Protocol (https://www.first.org/tlp/)