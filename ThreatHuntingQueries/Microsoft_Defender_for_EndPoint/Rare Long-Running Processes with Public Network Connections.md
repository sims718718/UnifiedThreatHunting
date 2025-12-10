# 📄 Rare Long-Running Processes with Public Network Connections

## 🔍 Analysis

This analytic surfaces **long-running processes** (older than 10 days) that are still active and making **successful outbound connections to public IPs**. It filters for binaries that are:

- **Rarely observed internally** (≤ 5 unique devices)
- **Low global prevalence** (≤ 20 sightings across all tenants)
- **Contacting few unique external URLs** (≤ 2)

This detection is highly effective at identifying:
- **Stealthy malware** or **persistent C2 agents**
- Long-dwelling implants like **RATs**, **loaders**, or **proxyware**
- Abnormal processes that avoid lateral movement but remain active for extended periods

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Function:** `FileProfile()` (to enrich file signature and prevalence)
- **Key Fields:**
  - `Timestamp`
  - `InitiatingProcessCreationTime`
  - `RemoteIP`, `RemoteUrl`, `RemoteIPType`
  - `DeviceId`, `DeviceName`
  - `InitiatingProcessSHA256`, `InitiatingProcessCommandLine`

## 🧠 MITRE ATT&CK Mapping

- **T1027 – Obfuscated Files or Information**
- **T1105 – Ingress Tool Transfer**
- **T1071 – Application Layer Protocol**
- **T1053 – Scheduled Task / Job**
- **T1543 – Create or Modify System Process**

## 🧪 KQL Query

```kql
let Lookback = 30d;                 // Time window for analysis
let ProcessAge = 10d;               // Minimum age of the running process
let URLThreshold = 2;               // Max number of unique contacted URLs
let LocalPrevalenceThreshold = 5;   // Max number of unique internal sightings
let GlobalPrevalenceThreshold = 20; // Max number of global sightings

DeviceNetworkEvents
| where Timestamp > ago(Lookback)
    and isnotempty(InitiatingProcessSHA256)
    and RemoteIPType == "Public"
    and ActionType == "ConnectionSuccess"
    and InitiatingProcessCreationTime < Timestamp - ProcessAge
| summarize
    DeviceCount = dcount(DeviceId),
    DeviceNames = make_set(DeviceName, LocalPrevalenceThreshold),
    IPCount = dcount(RemoteIP),
    URLCount = dcountif(RemoteUrl, isnotempty(RemoteUrl)),
    arg_max(Timestamp, *) 
    by InitiatingProcessSHA256
| where URLCount <= URLThreshold and DeviceCount <= LocalPrevalenceThreshold
| as IntermediaryResult
| where assert(toscalar(IntermediaryResult | count) <= 1000, "Too many matches for FileProfile")
| invoke FileProfile("InitiatingProcessSHA256", 1000)
| where GlobalPrevalence <= GlobalPrevalenceThreshold
| project-reorder
    Timestamp,
    DeviceNames,
    GlobalPrevalence,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteUrl,
    SHA256,
    IPCount,
    URLCount
| order by GlobalPrevalence asc, URLCount asc, IPCount desc
