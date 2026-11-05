# 📄 Suspicious Registry Modifications with Embedded URLs (HKCU Scope)

## 🔍 Analysis

This hunt identifies **registry key or value modifications** under the **HKEY_CURRENT_USER** (HKCU) hive that contain **HTTP/HTTPS URLs** often a sign of:

- Malicious persistence mechanisms
- Rogue proxy configuration (e.g., setting a custom C2 proxy)
- User-specific malware implants or downloader configuration
- LOLBins or PowerShell scripts writing URLs to registry for later execution


This registry-based detection is valuable for catching **fileless malware**, **adversary persistence**, and **network evasion** techniques.

## 📚 Data Sources

- **Table:** `DeviceRegistryEvents`
- **Key Fields:**
  - `RegistryKey`
  - `RegistryValueName`
  - `RegistryValueData`
  - `InitiatingProcessFileName`
  - `InitiatingProcessCommandLine`
  - `InitiatingProcessAccountName`
  - `Timestamp`

## 🧠 MITRE ATT&CK Mapping

- **T1112 – Modify Registry**


## 🧪 KQL Query

```kql
DeviceRegistryEvents
| where Timestamp > ago(180d)
| where ActionType has_any ('RegistryValueSet','RegistryKeyCreated')
| where RegistryValueData has_any('http','https')  // Look for common protocols indicating web traffic
| where RegistryKey has "HKEY_CURRENT_USER"
// Optional exclusions: uncomment and replace the placeholder with a known-good
// value from your environment to reduce noise (e.g. an approved URL or value name).
// | where RegistryValueData !contains "<known-good value>"
// | where RegistryValueName !contains "<known-good value>"
| project 
    Timestamp, 
    DeviceName, 
    RegistryKey, 
    RegistryValueName, 
    RegistryValueData, 
    InitiatingProcessAccountName, 
    InitiatingProcessFileName, 
    InitiatingProcessCommandLine, 
    InitiatingProcessRemoteSessionDeviceName, 
    InitiatingProcessRemoteSessionIP, 
    InitiatingProcessParentFileName
