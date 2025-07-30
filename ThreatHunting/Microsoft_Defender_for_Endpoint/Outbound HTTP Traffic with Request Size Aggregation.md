
# 📄 Outbound HTTP Traffic with Request Size Aggregation

## 🔍 Analysis

This query analyzes **outbound HTTP connections** made by devices to **external (non-private) IP addresses**, focusing on:

- Extracting and grouping **user agent**, **host**, **remote IP**, and **request body length**
- Helping detect **abnormal data transfers**, beaconing activity, or custom HTTP C2 channels
- Identifying devices potentially involved in **data exfiltration** or suspicious communication patterns

By aggregating on `request_body_len` and `DeviceName`, this query enables stacking techniques to highlight outliers that may signal malicious use of HTTP POST methods.

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `ActionType`
  - `RemoteIP`
  - `AdditionalFields.request_body_len`
  - `AdditionalFields.user_agent`
  - `AdditionalFields.host`
  - `DeviceName`

## 🧠 MITRE ATT&CK Mapping

- **T1071.001 – Application Layer Protocol: Web Protocols**
- **T1041 – Exfiltration Over C2 Channel**
- **T1071 – Application Layer Protocol**
- **T1008 – Fallback Channels**

## 🧪 KQL Query

```kql
DeviceNetworkEvents
| where ActionType == 'HttpConnectionInspected'
| where not (ipv4_is_in_any_range(RemoteIP, "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))
| extend json = todynamic(AdditionalFields)
| extend direction = tostring(json.direction), 
         user_agent = tostring(json.user_agent), 
         req_len = tostring(json.request_body_len), 
         host = tostring(json.host)
| where direction == 'Out'
| summarize 
    count(), 
    make_list(host), 
    make_list(RemoteIP) 
    by req_len, DeviceName
