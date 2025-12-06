# 📄 Detection of New Local Admin Logons Outside Baseline

## 🔍 Analysis

This query identifies **local administrator accounts** that have logged onto **new devices** in the past 7 days, where those logons were **not observed in the historical baseline period**.

The query works by:
- Building a **baseline** of normal local admin logons by host and user
- Looking at **recent local admin logon events**
- Using a **leftanti join** to isolate activity **not seen before**
- Filtering out known service accounts and administrative prefixes

This hunt is especially useful for:
- Detecting lateral movement using valid local admin accounts
- Flagging credential abuse or local privilege escalation
- Identifying unmanaged or shadow IT devices used for privileged access

## 📚 Data Sources

- **Table:** `DeviceLogonEvents`
- **Key Fields:**
  - `Timestamp`
  - `AccountName`
  - `DeviceName`
  - `IsLocalAdmin`
  - `LogonType`
  - `Protocol`

## 🧠 MITRE ATT&CK Mapping

- **T1078 – Valid Accounts**
- **T1021 – Remote Services**

## 🧪 KQL Query

```kql
let BaselineLogons = DeviceLogonEvents
    | where Timestamp >= datetime(2025-05-01) and Timestamp < datetime(2025-07-01) //adjust timeframe for you baseline
    | where IsLocalAdmin == "1"
    | summarize BaselineHosts = make_set(DeviceName) by AccountName
    | mv-expand BaselineHosts
    | extend BaselineHosts = tostring(BaselineHosts)
    | project AccountName, BaselineHosts;

DeviceLogonEvents
| where Timestamp >= ago(7d)
| where IsLocalAdmin == "1"
| where LogonType in~ ("network", "interactive", "remoteinteractive")
| where AccountName !contains "adm" // Consider excluding certain account dpending on your use case. Such as if you want to idenify accounts that are not matching a naming convention
| join kind=leftanti BaselineLogons on AccountName, $left.DeviceName == $right.BaselineHosts
| project Timestamp, AccountName, DeviceName, Protocol, LogonType, IsLocalAdmin
| summarize 
    count(), 
    make_set(DeviceName), 
    make_set(Timestamp), 
    make_set(IsLocalAdmin), 
    make_set(LogonType), 
    make_set(Protocol) 
  by AccountName
| where count_ < 20
