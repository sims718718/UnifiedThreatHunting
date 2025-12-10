# 📄 Detection of Failed SSH Sessions on ESXi or vCenter (Last 24 Hours)

## 🔍 Analysis

This query identifies **failed SSH session attempts** against **ESXi hosts or vCenter appliances**, focusing on attempts that occurred in the **last 24 hours**. These are typically logged as `esx.audit.ssh.session.failed` events in VMware logs.

Use cases include detecting:
- **Brute force attempts** against management interfaces
- Credential stuffing or enumeration attempts
- Unauthorized access attempts on sensitive infrastructure

The query also extracts the attempted `username` and provides:
- Total number of failures (`totalCount`)
- Number of distinct hosts targeted
- Time range of attempts
- Source systems where the attempts were logged

## 📚 Data Sources

- **Indexes:** `vmware-vclog`, `vmware-esxihost`
- **Event Type:** `esx.audit.ssh.session.failed`
- **Key Fields:**
  - `_time`
  - `username` (extracted via `rex`)
  - `source`
  - `host`

## 🧠 MITRE ATT&CK Mapping

- **T1110.001 – Brute Force: Password Guessing**
- **T1110.003 – Brute Force: Password Spraying**
- **T1078 – Valid Accounts**
- **T1021.004 – Remote Services: SSH**

## 🧪 SPL Query

```spl
(index=vmware-vclog OR index=vmware-esxihost) "esx.audit.ssh.session.failed"
| rex field=_raw max_match=0 "(?:for\s+'(?<username>.+?)@[\d\.]+')"
| stats 
    earliest(_time) as firsttime, 
    latest(_time) as lasttime,  
    values(source), 
    dc(host) as distinct_host, 
    count as totalCount 
  by username 
| eval currenttime = now()
| eval timelimit = currenttime - 86400 
| where firsttime > timelimit 
| eval _time = firsttime 
| convert ctime(*time) ctime(timelimit)
