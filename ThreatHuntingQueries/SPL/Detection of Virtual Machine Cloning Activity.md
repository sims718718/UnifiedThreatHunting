# 📄 Detection of Virtual Machine Cloning Activity

## 🔍 Analysis

This query detects **virtual machine cloning activity** captured in **vCenter** and **ESXi logs**, which may indicate:

- **Unauthorized data exfiltration** by exporting sensitive VMs
- **Lateral movement** via replica VMs
- **Persistence and evasion** using cloned environments
- **Snapshot abuse** for recon or rollback purposes

Cloning VMs can be part of advanced threat actor playbooks such as **UNC5221**, or internal misuse scenarios involving staging of sensitive workloads outside of official management channels.

This query searches for logs containing the term `cloned`, then surfaces contextual details such as:
- `vc_event_desc` (human-readable action)
- `vc_event_obj_name` (object or template used)
- `vc_vm_name` (resulting VM)
- `vc_username` (who performed the operation)

## 📚 Data Sources

- **Indexes:** `vmware-vclog`, `vmware-esxihost`
- **Keyword:** `cloned`
- **Key Fields:**
  - `_time`
  - `host`
  - `vc_event_desc`
  - `vc_event_type`
  - `vc_event_obj_name`
  - `vc_vm_name`
  - `vc_username`
  - `message`
  - `_raw`

## 🧠 MITRE ATT&CK Mapping

- **T1005 – Data from Local System**
- **T1070.004 – Indicator Removal on Host: File Deletion**
- **T1078 – Valid Accounts**
- **T1036 – Masquerading**

## 🧪 SPL Query

```spl
(index=vmware-vclog OR index=vmware-esxihost) TERM(cloned)
| table _time host vc_event_desc vc_event_type vc_event_obj_name vc_vm_name vc_username message _raw
