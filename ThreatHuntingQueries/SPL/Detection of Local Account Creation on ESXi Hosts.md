# 📄 Detection of Local Account Creation on ESXi Hosts

## 🔍 Analysis

This query detects **local account creation events** on **VMware ESXi hosts**, which are often logged with the event description `Account created`. Creating local accounts directly on ESXi hosts—outside of SSO or centralized identity providers—can be a sign of:

- **Adversary establishing persistence** post-exploitation
- **Insider threats or misconfigured automation**
- **Lateral movement or shadow IT operations**

The query extracts the account name from the message and surfaces important metadata for triage.

## 📚 Data Sources

- **Index:** `vmware-*`
- **Source:** `*` (all sources)
- **Event Description:** `vc_event_desc="Account created"`
- **Key Fields:**
  - `_time`
  - `host`
  - `vc_username` (initiator of the creation)
  - `account_created` (extracted from message)
  - `vc_event_type`
  - `vc_event_cat_0`
  - `message`

## 🧠 MITRE ATT&CK Mapping

- **T1136 – Create Account**
- **T1078 – Valid Accounts**
- **T1098 – Account Manipulation**
- **T1556 – Modify Authentication Process**

## 🧪 SPL Query

```spl
index="vmware-*" source="*" vc_event_desc="Account created"
| rex field=message "Account\s+(?<account_created>[^\s]+)\s+was created on host"
| table _time host vc_username account_created vc_event_desc vc_event_type vc_event_cat_0 message
