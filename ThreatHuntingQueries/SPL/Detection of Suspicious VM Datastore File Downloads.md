# 📄 Detection of Suspicious VM Datastore File Downloads

## 🔍 Analysis

This hunt identifies instances where virtual machines or their files are being **downloaded from VMware datastores**, which could signal malicious activity such as:

- Threat actors **exfiltrating sensitive VMs** (e.g., domain controllers, jump boxes)
- **Unauthorized access or internal misuse**
- Use of legitimate tools like vSphere or `ovftool` to export VMs to attacker-controlled systems

The query targets events labeled `DatastoreFileDownloadEvent`, sourced from either:
- **ESXi host logs** (`vmware-esxihost`)
- **vCenter logs** (`vmware-vclog`)

This detection should be paired with a **baseline of legitimate internal downloaders** (e.g., backup appliances, sysadmin jump hosts) to detect outliers and unauthorized access patterns.

## 📚 Data Sources

- **Indexes:** `vmware-esxihost`, `vmware-vclog`
- **Event Type:** `DatastoreFileDownloadEvent`
- **Key Fields:**
  - `_time`
  - `host`
  - `source`
  - `vc_event_desc`
  - `vc_event_type`
  - `vc_username`
  - `message`
  - `_raw`

## 🧠 MITRE ATT&CK Mapping

- **T1005 – Data from Local System**
- **T1039 – Data from Network Shared Drive**
- **T1048 – Exfiltration Over Alternative Protocol**
- **T1567 – Exfiltration Over Web Services**

## 🧪 SPL Query

```spl
(index="vmware-esxihost" OR index="vmware-vclog") DatastoreFileDownloadEvent
| table _time host source vc_event_desc vc_event_type vc_username message _raw
