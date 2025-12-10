# 📄 Detection of Local SSO User Account Updates in vCenter

## 🔍 Analysis

This query detects **modification of local Single Sign-On (SSO) accounts** within vCenter systems, captured via `vc_event_desc="Principal Management event in SSO"` and `message="*Updating local*"`.

Account updates may include:
- Password changes
- Role or group modifications
- Privilege escalation or identity switching

Such activity may be indicative of:
- **Adversary privilege maintenance**
- **Internal misuse or rogue admin behavior**
- **Attempts to silently escalate or rotate credentials post-compromise**

## 📚 Data Sources

- **Index:** `vmware-*`
- **Event Description:** `Principal Management event in SSO`
- **Key Fields:**
  - `_time`
  - `host`
  - `vc_username` (who made the change)
  - `account_updated` (parsed from message)
  - `vc_event_type`
  - `vc_event_cat_0`
  - `message`

## 🧠 MITRE ATT&CK Mapping

- **T1098 – Account Manipulation**
- **T1078 – Valid Accounts**
- **T1003 – OS Credential Dumping** (if used for later access)
- **T1136 – Create Account** (as follow-up action)

## 🧪 SPL Query

```spl
index="vmware-*" vc_event_desc="Principal Management event in SSO" vc_username=* message="*Updating local*"
| rex field=message "Updating local person user\s+'(?<account_updated>[^']+)'"
| eval action="updated"
| table _time host vc_username vc_event_desc vc_event_type vc_event_cat_0 account_updated action message
