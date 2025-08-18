# 📄 Detection of New User Logons in the Last 24 Hours

## 🔍 Analysis

This Splunk SPL query identifies **user accounts that have logged into systems for the first time in the past 24 hours**, using Windows Security Event ID `4624`. TO use effectively run this query over a longer period of time such as 30, 60, or 90 days to build a baseline of logons. The detection specifically focuses on logon types:

- **2 – Interactive (e.g., console logon)**
- **3 – Network (e.g., SMB or RDP without GUI)**
- **10 – RemoteInteractive (e.g., RDP with GUI)**

It excludes:
- Machine accounts (`*$`)
- System processes like `dwm*`, `umf*`
- Anonymous logons
- Events without a workstation name (Workstation_Name == "-")

This is useful for:
- Detecting new or unexpected user activity
- Identifying lateral movement using compromised credentials
- Building a baseline for normal user logons

## 📚 Data Sources

- **Index:** `windows`
- **Source:** `WinEventLog:Security`
- **EventCode:** `4624`
- **Key Fields:**
  - `_time`
  - `host`
  - `user`
  - `Workstation_Name`
  - `Logon_Type`

## 🧠 MITRE ATT&CK Mapping

- **T1078 – Valid Accounts**
- **T1021.001 – Remote Services: Remote Desktop Protocol**
- **T1036 – Masquerading (if usernames resemble expected accounts)**

## 🧪 SPL Query

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type IN (2,3,10)
| search NOT user IN ("*$", "*umf*", "*dwm*", "ANONYMOUS LOGON") Workstation_Name!="-"
| eval Logon_Type_Label=case(
    Logon_Type=2, "Interactive", 
    Logon_Type=3, "Network", 
    Logon_Type=10, "RemoteInteractive"
)
| stats earliest(_time) as firstSeenTime by host user Workstation_Name Logon_Type_Label
| eval currentTime = now()
| eval timeLimit = currentTime - 86400
| where firstSeenTime > timeLimit
| eval _time = firstSeenTime
