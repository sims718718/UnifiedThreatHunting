# 📄 Low-Frequency External DNS Queries by TLD

## 🔍 Analysis

This query detects **low-volume outbound DNS queries** for specific query types (`A`, `TXT`, `AAAA`) and aggregates them by **Top-Level Domain (TLD)**. It is designed to help threat hunters identify:

- **Domain generation algorithm (DGA)** activity
- **Beaconing or staging** behavior via uncommon or obscure domains
- **Data exfiltration over DNS**, especially via `TXT` queries
- **Initial access or malware callouts** using newly registered or rarely seen domains

By focusing on low-frequency domains (less than 10 queries across the environment), this detection filters out noisy legitimate traffic and highlights outliers worth investigating.

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `ActionType`
  - `AdditionalFields.query`
  - `AdditionalFields.qtype_name`
  - `AdditionalFields.rcode_name`
  - `RemoteIPType`
  - `DeviceName`
  - `Timestamp`

## 🧠 MITRE ATT&CK Mapping

- **T1071.004 – Application Layer Protocol: DNS**
- **T1046 – Network Service Scanning**
- **T1008 – Fallback Channels**
- **T1568.002 – Dynamic Resolution: Domain Generation Algorithms**

## 🧪 KQL Query

```kql
DeviceNetworkEvents
| where ActionType == 'DnsConnectionInspected'
| extend json = todynamic(AdditionalFields)
| extend direction = tostring(json.direction), 
         query = tostring(json.query), 
         qtype = tostring(json.qtype_name), 
         rcode = tostring(json.rcode_name), 
         answers = tostring(json.answers)
| where direction == "Out" and qtype in~ ('A','TXT','AAAA')
| extend TLDArray = split(query,'.')
| extend TLD = strcat(".",TLDArray[array_length(TLDArray)-1])
| summarize count(), 
            dcount(DeviceName), 
            make_set(rcode), 
            make_set(qtype), 
            make_set(query) 
  by TLD
| where count_ < 10
