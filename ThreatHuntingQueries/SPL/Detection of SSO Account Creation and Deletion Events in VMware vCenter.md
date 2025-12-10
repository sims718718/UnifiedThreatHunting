# 📄 Detection of SSO Account Creation and Deletion Events in VMware vCenter

## 🔍 Analysis

This query detects **SSO principal management operations** in vCenter — specifically when accounts are **created or deleted** via the Single Sign-On (SSO) service. These actions may indicate:

- **Account creation for persistence**
- **Account deletion for anti-forensics**
- **Insider misuse or unauthorized privilege manipulation**
- **Lateral movement preparation or evasion**

This is commonly abused post-compromise by adversaries or rogue admins to:
- Establish long-term privileged access to vSphere
- Remove evidence of their activity or lock out defenders

The query inspects `vc_event_desc="Principal Management event in SSO"` and parses the message for both:
- `Creating local person user '<username>'`
- `Deleting principal '<username>'`

Then assigns a simplified `action` label and surfaces key metadata.

## 📚 Data Sources

- **Indexes:** `vmware-vclog`, `vmware-esxihost`
- **Event Description:** `Principal Management event in SSO`
- **Key Fields:**
  - `_time`
  - `host`
  - `vc_username`
  - `message`
  - `account_created` (parsed)
  - `account_deleted` (parsed)
  - `vc_event_type`
  - `vc_event_cat_0`

## 🧠 MITRE ATT&CK Mapping

- **T1136 – Create Account**
- **T1078 – Valid Accounts**
- **T1531 – Account Access Removal**
- **T1087 – Account Discovery**

## 🧪 SPL Query

```spl
index=vmware-vclog vc_event_desc="Principal Management event in SSO" vc_username=* (message="*Creating local*" OR message="*Deleting principal*")
| rex field=message "Deleting principal\s+'(?<account_deleted>[^']+)'"
| rex field=message "Creating local person user\s+'(?<account_created>[^']+)'"
| eval action=case(
    isnotnull(account_deleted), "deleted",
    isnotnull(account_created), "created",
    true(), "unknown"
)
| table _time host vc_username account_created account_deleted vc_event_desc vc_event_type vc_event_cat_0 action message
