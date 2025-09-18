# 📄 Suspicious Registry Modifications with Embedded URLs (HKCU Scope)

## 🔍 Analysis

This hunt identifies **registry key or value modifications** under the **HKEY_CURRENT_USER** (HKCU) hive that contain **HTTP/HTTPS URLs**—often a sign of:

- Malicious persistence mechanisms
- Rogue proxy configuration (e.g., setting a custom C2 proxy)
- User-specific malware implants or downloader configuration
- LOLBins or PowerShell scripts writing URLs to registry for later execution

The detection excludes:
- Known safe `.gov` and `.sbu` domains
- Common benign keys like `application restart` and `ProxyServer`

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
| where RegistryValueData !contains ".gov" and RegistryValueData !contains ".sbu"
| where RegistryValueName !contains "application restart" and RegistryValueName != @"ProxyServer"
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
