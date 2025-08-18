# 📄 Suspicious `conhost.exe` Network Connections to Unusual Domains

## 🔍 Analysis

This query identifies instances where the Windows Console Host (`conhost.exe`) is initiating **outbound connections to public IPs or non-trusted domains**. While `conhost.exe` is typically a legitimate process, it has been abused by adversaries in:

- Living-off-the-land (LOTL) techniques
- Process hollowing or proxy execution
- C2 communication under the guise of a benign parent

By excluding trusted domains (like `microsoft.com`, `digicert.com`) and internal IPs, this query isolates unusual or suspicious external network connections.

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `Timestamp`
  - `InitiatingProcessFileName`
  - `RemoteIP`
  - `RemoteUrl`

## 🧠 MITRE ATT&CK Mapping

- **T1059.003 – Command and Scripting Interpreter: Windows Command Shell**
- **T1071 – Application Layer Protocol**
- **T1105 – Ingress Tool Transfer**
- **T1218 – Signed Binary Proxy Execution**

## 🧪 KQL Query

```kql
let ValidDomains = dynamic(['.microsoft.com', '.digicert.com']);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where InitiatingProcessFileName =~ "conhost.exe"
| where not(ipv4_is_private(RemoteIP) or RemoteIP == "127.0.0.1")
| where not(RemoteUrl has_any (ValidDomains))
