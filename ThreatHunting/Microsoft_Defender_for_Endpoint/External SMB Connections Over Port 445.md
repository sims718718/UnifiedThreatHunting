# 📄 External SMB Connections Over Port 445

## 🔍 Analysis

This KQL query identifies successful outbound connections to **public IP addresses** over **port 445 (SMB)**. SMB is a protocol typically used for file sharing within internal networks and should rarely be seen connecting externally. Outbound SMB traffic to public IPs could indicate:

- Misconfigured systems
- Lateral movement attempts beyond the internal network
- Potential worm activity or malware attempting to spread
- Data exfiltration channels over SMB

Any connection to port 445 over the public internet should be treated as highly suspicious and investigated further.

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `RemoteIPType`
  - `RemotePort`
  - `ActionType`
  - `DeviceName`
  - `RemoteIP`
  - `Timestamp`

## 🧠 MITRE ATT&CK Mapping

- **T1021.002 – Remote Services: SMB/Windows Admin Shares**
- **T1046 – Network Service Scanning**
- **T1071 – Application Layer Protocol**

## 🧪 KQL Query

```kql
DeviceNetworkEvents
| where RemoteIPType == "Public"
| where RemotePort == 445
| where ActionType == "ConnectionSuccess"
| project-reorder Timestamp, DeviceName, RemoteIP
