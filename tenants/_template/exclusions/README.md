# Per-Tenant Exclusions

**Fits at:** Step 3 (Initial Assessment, known-good behavior) and Step 5 (Scope, explicit exclusions) — multi-tenant mode only.
**Purpose:** Keep known-good lists as tenant data, outside shared query logic, so one tenant's account or host names never appear in another tenant's queries or reports.

---

## 1. Layout

One CSV per campaign, per tenant:

```
tenants/<tenant-id>/exclusions/<campaign>.csv
```

Example `tenants/example-tenant/exclusions/HUNT-042.csv`:

```csv
tenant,account,reason,owner,expires
example-tenant,svc-legacy01,Pre-auth disabled by design (legacy app),identity-team,2027-01-31
example-tenant,svc-legacy02,Pre-auth disabled by design (legacy app),identity-team,2027-01-31
```

Every row carries the `tenant` column, a reason, an owner, and an expiry. An exclusion without a reason or expiry is a permanent blind spot.

---

## 2. Using it in queries

Shared logic never inlines names. It joins on tenant and the excluded entity:

| Platform | Mechanism |
|---|---|
| Splunk | Lookup `th_exclusions` built from the CSVs; `\| lookup th_exclusions tenant, account OUTPUT reason \| where isnull(reason)` |
| Sentinel | Per-tenant watchlist `th_exclusions`; `_GetWatchlist('th_exclusions')` with an anti-join |
| Sigma | Keep the rule generic; apply exclusions in the per-tenant pipeline or as a post-filter |

---

## 3. Rules

- Exclusions are reviewed per tenant with that tenant's SMEs; never copy one tenant's list to another.
- Treat the files with the tenant's TLP (`sharing.tlp_default` in `profile.yaml`).
- Expired rows fail closed: the entity is hunted again until someone renews it with a reason.

---

**References:** [Multi-Tenant Operation](../../../docs/multi_tenant_operation.md) · Unified Threat Hunting Process, Initial Assessment (known-good behavior)