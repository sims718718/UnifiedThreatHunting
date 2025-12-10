# 📄 Detection of BRICKSTORM Proxying via Loopback in VMware vSphere Logs

## 🔍 Analysis

This analytic detects suspicious **loopback-to-loopback (`127.0.0.1 → 127.0.0.1`) proxy traffic** in VMware vSphere UI access logs (`ui-access`) which may be indicative of **BRICKSTORM malware** or similar activity by **UNC5221**.

**BRICKSTORM** is known to proxy traffic internally through ESXi hosts and vCenter loopback addresses to:
- Enumerate vCenter resources
- Maintain long-term persistence
- Obfuscate lateral movement and post-exploitation activity

The query filters out **expected system paths** such as:
- `/ds/vapi`
- `ui/resources/vsphere-ui-resource-bundle.zip`
- `/apigw/resourcebundle`

This highlights potentially **malicious internal API exploration**, often used for:
- Mapping datastores, users, VMs
- Lateral movement within vSphere infrastructure
- Persistence through appliance-level components

## 📚 Data Sources

- **Index:** `vmware-vclog`
- **Source:** `ui-access`
- **Key Fields:**
  - `_time`
  - `host`
  - `src_ip`
  - `message`

## 🧠 MITRE ATT&CK Mapping

- **T1071 – Application Layer Protocol**


## 🧪 SPL Query

```spl
index=vmware-vclog source="ui-access" "127.0.0.1 127.0.0.1"
NOT ("*/ds/vapi*" OR "*ui/resources/vsphere-ui-resource-bundle.zip*" OR "*/apigw/resourcebundle*")
| table _time host src_ip message
