# 📄 Unsigned System Processes Connecting to Cloudflare

## 🔍 Analysis

This analytic identifies **unsigned processes running as `System`** that are initiating outbound connections to **Cloudflare IP ranges**. It leverages Microsoft Defender for Endpoint (MDE) telemetry to:

- Match system process connections against known Cloudflare IP subnets
- Filter out known signed binaries using certificate telemetry
- Highlight **low-prevalence, unsigned executables** communicating with public infrastructure

This detection is powerful for identifying:
- Malware or LOLBins abusing Cloudflare as a C2 proxy
- Backdoors or implants deployed under `System` privileges
- Suspicious binaries attempting to exfiltrate or beacon via CDN services

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Table:** `DeviceFileCertificateInfo`
- **Function:** `FileProfile()` (for prevalence and signature checks)
- **Custom Datatable:** Cloudflare IPv4 ranges

## 🧠 MITRE ATT&CK Mapping

- **T1218 – Signed Binary Proxy Execution** (if masquerading)
- **T1105 – Ingress Tool Transfer**
- **T1071.001 – Application Layer Protocol: Web Protocols**
- **T1036 – Masquerading**

## 🧪 KQL Query

```kql
let Lookback = 30d;
// Define Cloudflare IPs (see https://www.cloudflare.com/ips-v4/#)
let Cloudflare = datatable(Range: string)[
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
];

DeviceNetworkEvents
| where Timestamp > ago(Lookback) and InitiatingProcessAccountName =~ "System"
| evaluate ipv4_lookup(Cloudflare, RemoteIP, Range)
| summarize Count = count()
    by DeviceId, DeviceName, InitiatingProcessFolderPath,
       InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessSHA1
// Filter out signed binaries
| join kind=leftanti (
    DeviceFileCertificateInfo 
    | where Timestamp > ago(Lookback)
) on $left.InitiatingProcessSHA1 == $right.SHA1
| summarize 
    Devices = dcount(DeviceId),
    Count = sum(Count),
    InitiatingProcessFolderPath = make_list(InitiatingProcessFolderPath),
    DeviceName = make_list(DeviceName),
    InitiatingProcessFileName = make_list(InitiatingProcessFileName)
  by InitiatingProcessSHA256, InitiatingProcessSHA1
| as IntermediaryResult
| where assert(toscalar(IntermediaryResult | count) <= 1000, "Too many matches for FileProfile")
// Check for unsigned and globally rare binaries
| invoke FileProfile("InitiatingProcessSHA1", 1000)
| where SignatureState == "Unsigned" and GlobalPrevalence < 50000
| mv-expand DeviceName, InitiatingProcessFolderPath, InitiatingProcessFileName
| project-reorder DeviceName, InitiatingProcessFolderPath, SHA256, SHA1, Count
| order by Count desc
