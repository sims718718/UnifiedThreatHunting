# 📄 Suspicious Outbound HTTP Connections on Port 80 from Non-Browser Processes

## 🔍 Analysis

This query surfaces **outbound HTTP connections over port 80** from **non-browser processes** that successfully connected to **public IPs or URLs**. The logic:

- Excludes common and legitimate browsers (`chrome.exe`, `msedge.exe`, `explorer.exe`, etc.)
- Filters known benign domains (`*.office.com`, `windows.net`, `login.live.com`, etc.)
- Targets connections made by **less common or potentially malicious executables**
- Focuses on **low-prevalence** domains (i.e., seen from fewer than 10 hosts)

This is effective for identifying:
- Malware establishing command-and-control channels over HTTP
- Unapproved tools making outbound network connections
- Beaconing or data staging activity from compromised hosts

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `RemoteUrl`
  - `RemoteIP`
  - `RemoteIPType`
  - `RemotePort`
  - `InitiatingProcessFileName`
  - `InitiatingProcessParentFileName`
  - `DeviceName`
  - `Timestamp`

## 🧠 MITRE ATT&CK Mapping

- **T1071.001 – Application Layer Protocol: Web Protocols**
- **T1105 – Ingress Tool Transfer**
- **T1218 – Signed Binary Proxy Execution**

## 🧪 KQL Query

```kql
let ExclusionList = dynamic([
    "login.live.com"
    // Add more URLs to exclude as needed
]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemotePort == 80
| where InitiatingProcessFileName !in~ (
    "msedge.exe", "chrome.exe", "explorer.exe", 
    "ms-teams.exe", "Teams.exe", "inspect.exe", 
    "msedgewebview2.exe", "iexplore.exe"
)
| where not(RemoteUrl in (ExclusionList))
| where RemoteUrl !endswith "measure.office.com" 
      and RemoteUrl !endswith "windows.net" 
      and RemoteUrl !endswith "office.com"
| summarize 
    ConnectionCount = count(), 
    DistinctHostCount = dcount(DeviceName), 
    make_set(DeviceName), 
    make_set(RemoteIPType), 
    make_set(RemotePort), 
    make_set(InitiatingProcessParentFileName),
    make_set(InitiatingProcessFileName), 
    make_set(RemoteIP)  
  by RemoteUrl
| where DistinctHostCount < 10
| order by ConnectionCount asc
