# Data Analysis for Threat Hunting: A Data Science Approach

> A comprehensive guide for blending data science methodologies with threat hunting operations

**Note** AI was used to clean up a pre-existing guide and assisst in building a non-internal product. Ideas are **original**.

---

## Table of Contents

1. [Introduction](#introduction)
2. [The PACE Framework](#the-pace-framework)
3. [Plan Phase](#plan-phase)
4. [Analyze Phase](#analyze-phase)
5. [Construct Phase](#construct-phase)
6. [Execute Phase](#execute-phase)
7. [AI/ML in Threat Hunting: Lessons Learned](#aiml-in-threat-hunting-lessons-learned)
8. [Key Takeaways](#key-takeaways)
9. [References](#references)

---

## Introduction

Threat hunting is fundamentally a subset of data science. Both disciplines begin with an underlying hypothesis or problem to solve, follow structured methodologies, and aim to derive actionable insights from complex datasets. This guide demonstrates how threat hunters can leverage data science principles to conduct thorough, hypothesis-driven investigations.

### Why Data Science Matters for Threat Hunting

Modern enterprise environments generate massive volumes of security telemetry. According to industry research, attackers often spend weeks moving laterally through networks before deploying their final payloadthe OldGremlin ransomware group, for example, has been observed spending an average of 49 days moving undetected within networks before launching attacks. Without a structured analytical approach, identifying these subtle indicators of compromise becomes nearly impossible.

The methodologies covered in this guide will help you:

- Formulate testable hypotheses based on threat intelligence
- Systematically explore and understand your data
- Build effective analytics and detections
- Communicate findings to stakeholders

### Target Audience

This guide is designed for:

- **Beginners**: Those new to threat hunting who want to understand the foundational methodology
- **Intermediate Analysts**: Security professionals looking to formalize their hunting processes
- **Advanced Practitioners**: Experienced hunters seeking to incorporate data science techniques

---

## The PACE Framework

This guide follows the **PACE** framework, adapted from data science practices:

| Phase | Data Science Focus | Threat Hunting Focus |
|-------|-------------------|---------------------|
| **P**lan | Formulate hypothesis, understand the problem | Define the threat scenario, identify data sources |
| **A**nalyze | Explore relationships between variables | Conduct EDA on security telemetry fields |
| **C**onstruct | Build predictive/analytic models | Create detection analytics and hunting queries |
| **E**xecute | Report findings and recommendations | Document results and propose security improvements |

This structured approach ensures consistency, repeatability, and the ability to improve your hunting program over time.

---

## Plan Phase

The planning phase establishes the foundation for your hunt. A well-defined hypothesis and thorough understanding of available data are critical to success.

### Formulating Your Hypothesis

A threat hunting hypothesis should be specific enough to be testable but broad enough to capture variations in attacker behavior. Consider this example:

> **Hypothesis**: Threat actors may use RDP (Remote Desktop Protocol) to conduct lateral movement within our environment.

Let's break down what this hypothesis tells us:

1. **RDP Focus**: We need datasets containing RDP connection information
2. **Lateral Movement**: We're looking for connections between internal hosts
3. **Threat Actor Behavior**: We can optionally leverage threat intelligence if targeting specific groups

### Understanding the Threat Landscape

Remote Desktop Protocol abuse is one of the most common lateral movement techniques observed in real-world attacks. According to MITRE ATT&CK (T1021.001), adversaries use valid accounts to log into computers using RDP, then perform actions as the logged-on user.

**Real-World Context**: Multiple ransomware families, including LockBit, Akira, and BianLian, heavily leverage RDP for lateral movement. The BianLian group specifically gains initial access through valid RDP credentials and uses open-source tools for discovery and credential harvesting. In the February 2024 BlackCat/ALPHV attack on Change Healthcare, attackers used stolen credentials to move laterally across the network before deploying ransomware, resulting in a reported $22 million ransom payment.

### Identifying Data Sources

For RDP lateral movement detection, MITRE ATT&CK identifies several relevant data sources:

- Windows Security Event Logs
- Network flow data (NetFlow, Zeek)
- Endpoint Detection and Response (EDR) telemetry
- Sysmon logs

For this guide, we'll focus on **Windows Security Event Logs**, specifically:

- **Event ID 4624**: Successful logon events
- **Logon Type 10**: Remote Interactive (RDP) connections

### Data Validation and Quality Assessment

Before diving into analysis, validate that your data is complete and properly formatted. This step is critical and often overlooked.

**Example Query - Assess Data Sources:**

```spl
index=windows 
| stats count by sourcetype source
```

**Why This Matters**: In real environments, you may discover data quality issues. For example, you might find the same log source being parsed with multiple sourcetypesone labeled `WinEventLog:Security` and another as `XmlWinEventLog:Security`. If you only searched one sourcetype, you could miss more than half of your data.

**Best Practice**: Always use the `source` field when it provides more consistent results than `sourcetype`.

**Refined Query Using Source:**

```spl
index=windows source="WinEventLog:Security" 
| stats count by source
```

### Understanding Event ID 4624

Windows Event ID 4624 is generated whenever a user successfully logs into a Windows system. It contains rich forensic data including:

- **Account Name**: The user account that logged in
- **Account Domain**: The domain the account belongs to
- **Logon Type**: How the authentication occurred (critical for RDP detection)
- **Source Network Address**: Where the login originated
- **Workstation Name**: The source system name
- **Authentication Package**: Kerberos, NTLM, etc.
- **Process Name**: The process that initiated the logon

**Windows Logon Types Reference:**

| Logon Type | Name | Description |
|------------|------|-------------|
| 2 | Interactive | Physical console login (keyboard/mouse) |
| 3 | Network | Access to shared resources over the network |
| 4 | Batch | Scheduled task execution |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network logon with cleartext credentials |
| 9 | NewCredentials | RunAs with /netonly |
| 10 | RemoteInteractive | **RDP/Terminal Services** |
| 11 | CachedInteractive | Cached credentials used |

**Key Insight**: Logon Type 10 (RemoteInteractive) is your primary filter for detecting RDP activity. This includes Remote Desktop connections, Remote Assistance, and Terminal Services sessions.

### Initial Data Exploration

With our hypothesis defined, let's explore the relevant dataset:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10
```

**Note**: Over a short time frame (e.g., 15 minutes), you may see very few results. Expand your search window to capture sufficient data for meaningful analysistypically at least 7 days for baseline establishment.

---

## Analyze Phase

The Analyze phase focuses on understanding relationships between variables (fields) in your data. This is where Exploratory Data Analysis (EDA) techniques from data science become invaluable.

### Key Questions for Analysis

As you explore the data, consider:

- What relationships exist between fields?
- What does the distribution of values look like?
- Are there any transformations needed (field extraction, coalescing, normalization)?
- What fields are most relevant to your hypothesis?

### Technique 1: Stacking by Source IP

Start by understanding where RDP connections originate:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| stats count by Source_Network_Address
```

**What to Look For:**

- **Internal IP Ranges**: Multiple internal subnets (e.g., 10.x.x.x, 192.168.x.x) may indicate different network segments or VLANs
- **External IPs**: Any external IP addresses should be investigated immediatelyRDP exposed to the internet is a critical security risk
- **Localhost/Loopback**: Source addresses like `127.0.0.1` or `::1` may indicate RDP tunneling, a technique used by attackers to hide their origin
- **VIP Addresses**: Virtual IP addresses for load balancers or jump servers may appear frequently

### Technique 2: Adding Context with Multi-Value Fields

Enrich your analysis by including destination hosts:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| stats values(host) count by Source_Network_Address
```

This reveals which systems each source IP is connecting to, helping identify patterns like:

- Single IPs connecting to many hosts (potential lateral movement)
- Expected patterns (VIPs routing to multiple backend servers)
- Anomalous connections to sensitive systems

### Technique 3: Pivot and Distinct Count Analysis

Flip the perspective to see which hosts are receiving the most unique connections:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| stats values(Source_Network_Address) as SourceIP 
        dc(Source_Network_Address) as distinctSource 
        count by host
| sort - distinctSource
```

**Interpretation Guide:**

- **High distinctSource values**: Expected for jump servers, bastion hosts, or terminal servers
- **Single source IPs to servers**: May indicate administrative access from a dedicated workstation
- **Repeated single IPs across servers**: Could be a jump server or potentially an attacker pivoting

### Technique 4: Adding User Context

Include user information to identify account usage patterns:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| stats values(Source_Network_Address) as SourceIP 
        dc(Source_Network_Address) as distinctSource 
        values(user) as user 
        count by host
| sort - distinctSource
```

**Key Observations:**

- **Admin account naming conventions**: Look for patterns like `*adm*`, `*admin*`, `svc_*`, etc.
- **Service accounts with RDP**: Service accounts shouldn't typically use interactive RDPflag these for investigation
- **Non-standard accounts**: Local accounts or accounts not following naming conventions may indicate compromise

### Technique 5: Temporal Analysis

Understanding when RDP activity occurs helps establish baselines and identify anomalies:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| timechart count by host
```

**Analysis Points:**

- **Business hours clustering**: Most legitimate RDP activity should occur during standard working hours
- **Weekend/after-hours activity**: May indicate maintenance windows, on-call personnel, or potentially malicious activity
- **Spike patterns**: Sudden increases in RDP activity warrant investigation
- **Jump server dominance**: Bastion hosts typically show the highest volume

Use `bin` or `span` to adjust granularity:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| timechart span=1h count by host
```

### Technique 6: Domain Analysis

Examine authentication domains to understand cross-domain activity:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| stats count by Account_Domain
```

**Look For:**

- Expected domains (primary AD domain, trusted domains)
- Local accounts (computer names as domains)
- Unknown or unexpected domains
- DMZ or isolated domain activity

---

## Construct Phase

The Construct phase is where you build analytics to validate your hypothesis. This involves creating detection queries, enriching data with context, and optionally applying machine learning techniques.

### Building Detection Analytics

Based on observations from the Analyze phase, we identified that administrative accounts use specific naming conventions. Let's build detections around this insight.

**Detection 1: Admin Account RDP Sessions**

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user="*adm*"
| stats values(Source_Network_Address) as SourceIP 
        dc(Source_Network_Address) as distinctSource 
        values(user) as user 
        count by host
| sort - distinctSource
```

While this confirms expected behavior, it establishes a baseline. The more interesting hunt is the inversefinding non-admin RDP sessions.

**Detection 2: Non-Admin RDP Sessions**

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 user!="*adm*"
| stats values(Source_Network_Address) as SourceIP 
        dc(Source_Network_Address) as distinctSource 
        values(user) as user 
        count by host
| sort - distinctSource
```

This significantly reduces the dataset and surfaces accounts that may warrant investigation.

**Detection 3: Filtering Known Good Accounts**

Refine further by excluding known legitimate patterns. Adapt the filter to your environment's naming conventions:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
    NOT user IN ("*adm*", "*admin*", "*svc_*", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| stats count 
        earliest(_time) as firsttime 
        latest(_time) as lasttime 
        values(Source_Network_Address) as SourceIP 
        values(user) as user 
        by host
| convert ctime(*time)
```

**What This Might Reveal:**

- Service accounts used in interactive RDP sessions (should never happen normally)
- Built-in accounts (Administrator, root) being used for RDP
- Local accounts on domain-joined systems
- Accounts not following naming conventions

**Example Finding**: In threat hunting exercises, this type of query has successfully identified red team activity where operators compromised service accounts and built-in root accounts to pivot throughout a domainactivity that would have gone unnoticed with standard monitoring.

### Enriching with Lookup Tables

Contextual enrichment dramatically improves detection accuracy. A lookup table of authorized jump servers enables you to identify unauthorized lateral movement paths.

**Example Lookup Table Structure (jumpservers.csv):**

| domain | hostname | ip | zone |
|--------|----------|-----|------|
| corp.local | JUMP01 | 10.1.1.50 | internal |
| corp.local | JUMP02 | 10.1.1.51 | internal |
| dmz.local | DMZJUMP01 | 172.16.1.50 | dmz |

**Query Using Lookup Enrichment:**

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| lookup jumpservers.csv hostname AS host OUTPUTNEW hostname AS lookup_hostname
| where isnull(lookup_hostname) 
| lookup jumpservers.csv ip AS Source_Network_Address OUTPUTNEW ip AS lookup_ip
| where isnull(lookup_ip)
| stats count 
        earliest(_time) as firsttime 
        latest(_time) as lasttime 
        values(Source_Network_Address) as SourceIP 
        values(Account_Domain) as domain 
        values(user) as user 
        by host
| convert ctime(*time)
```

**What This Query Does:**

1. Filters RDP logon events
2. Checks if the destination host is in the jump server list
3. Checks if the source IP is in the jump server list
4. Returns only connections where neither endpoint is an authorized jump server
5. These results represent potential unauthorized lateral movement

### High-Fidelity Detection Indicators

Based on industry research and real-world incidents, prioritize investigation of:

| Indicator | Risk Level | Rationale |
|-----------|------------|-----------|
| RDP from loopback (127.x.x.x, ::1) | **Critical** | Indicates RDP tunneling technique |
| Source IP outside organization's subnet | **High** | External RDP access or VPN anomaly |
| RDP to end-user workstations | **High** | Workstation-to-workstation RDP unusual |
| Account name ending with $ | **Medium-High** | Possible fake machine account |
| Service account with Logon Type 10 | **High** | Service accounts shouldn't RDP |
| RDP outside business hours | **Medium** | Anomalous timing |
| High-privilege account to many systems | **Medium** | Possible compromise or policy violation |

---

## Execute Phase

The Execute phase focuses on documenting findings, communicating results, and recommending improvements. This is where your analysis becomes actionable.

### Structuring Your Report

A threat hunting report should address:

1. **Executive Summary**: Brief overview of hypothesis, methods, and key findings
2. **Methodology**: Detailed description of data sources, queries, and analytical techniques
3. **Findings**: What was discovered, including both confirmed threats and notable observations
4. **Recommendations**: Actionable improvements to detection, prevention, or visibility
5. **Appendices**: Technical details, queries, and supporting evidence

### Key Questions to Answer

- What key insights emerged from your analytics?
- Were there any confirmed compromises or policy violations?
- What recommendations improve security posture?
- How could your analytics be improved or automated?
- What follow-up hunts does this analysis suggest?

### From Hunt to Detection

Successful hunting queries can be converted to automated detections:

**Criteria for Detection Candidates:**

- Low false positive rate after tuning
- Clear indicator of malicious or policy-violating behavior
- Can be enriched with context for analyst triage
- Maps to known attack techniques (MITRE ATT&CK)

**Example Alert Logic:**

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10 
| lookup jumpservers.csv hostname AS host OUTPUTNEW hostname AS is_jumpserver_dest
| lookup jumpservers.csv ip AS Source_Network_Address OUTPUTNEW ip AS is_jumpserver_src
| where isnull(is_jumpserver_dest) AND isnull(is_jumpserver_src)
| where NOT match(user, "(?i)(adm|admin|svc_)")
| stats count by host, user, Source_Network_Address
| where count > 0
```

**Alert Configuration Recommendations:**

- Run frequency: Every 15-30 minutes
- Alert threshold: Any match (count > 0)
- Enrichment: Include asset inventory, user context, historical baseline
- Routing: SOC triage queue with MITRE ATT&CK mapping (T1021.001)

---

## AI/ML in Threat Hunting: Lessons Learned

Machine learning can augment threat hunting, but it's not a silver bullet. This section shares practical lessons from applying ML to RDP lateral movement detection.

### Attempting Anomaly Detection

Using Splunk's Machine Learning Toolkit (MLTK), we can attempt statistical anomaly detection:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats values(_time) as Time 
        values(Source_Network_Address) as SourceIP 
        dc(Source_Network_Address) as distinctSource 
        values(user) as user 
        count by host
| eval isOutlier = if(probable_cause != "", "1", "0")
| anomalydetection Time host user distinctSource count action=annotate 
| table Time host user SourceIP distinctSource count probable_cause isOutlier
| sort 100000 probable_cause
```

**What Happened:**

The anomaly detection flagged the same patterns we already identified in manual analysisjump servers with the highest connection counts. While technically "outliers," these were expected behavior, not threats.

**Why This Occurred:**

1. **Categorical vs. Numerical Data**: ML algorithms struggle with categorical fields like usernames and IP addresses. What makes one IP more "suspicious" than another requires context computers don't inherently have.
2. **Lack of Labeled Data**: Without historical examples of known-bad activity, unsupervised anomaly detection tends to flag volume-based outliers rather than behavioral anomalies.
3. **Domain Context Missing**: The algorithm couldn't distinguish a jump server (expected high connections) from a compromised workstation (unexpected connections).

### Time-Series Forecasting Approach

An alternative approach uses time-series modeling to identify unusual patterns:

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10
| bucket span=1h _time
| stats count by _time 
| predict count as prediction algorithm=LLP future_timespan=150 holdback=0 
| where prediction!="" AND count!="" 
| eval residual = prediction - count
```

**Results:**

This approach can identify time periods with unusually high or low RDP activity. However, it loses context about which users and hosts are involvedcritical information for investigation.

**Split by Host:**

```spl
index=windows source="WinEventLog:Security" EventCode=4624 Logon_Type=10
| bucket span=1h _time
| stats count by _time host
| predict count as prediction algorithm=LLP future_timespan=150 holdback=0 
| where prediction!="" AND count!="" 
| eval residual = prediction - count
```

This provides per-host outliers but still lacks user context.

### Lessons Learned: When to Use ML

| Scenario | ML Effectiveness | Better Alternative |
|----------|------------------|-------------------|
| High-volume numerical data | ✅ Good |  |
| Categorical security fields | ❌ Poor | Domain-expert queries |
| Baseline deviation (time-based) | ✅ Good |  |
| Detecting known-bad patterns | ❌ Poor | Signature-based detection |
| User behavior anomalies | ⚠️ Moderate | Requires proper feature engineering |
| Network flow analysis | ✅ Good |  |

### Improving ML-Based Detection

To make machine learning more effective for this use case:

1. **Feature Engineering**: Convert categorical data to numerical features
   - Days since account creation
   - Number of historical RDP sessions for this user
   - Hour of day encoded cyclically
   - "New" vs. "established" connection pairs

2. **Labeled Training Data**: Collect examples of confirmed malicious RDP activity from:
   - Red team exercises
   - Historical incident investigations
   - Threat intelligence reports

3. **Hybrid Approaches**: Use ML to prioritize manual review
   - Score connections based on multiple risk factors
   - Surface highest-risk connections for analyst triage
   - Use ML for volume reduction, not replacement of analysis

4. **Entity-Based Baselines**: Build per-user or per-system behavioral profiles
   - Alert on first-time user→host connections
   - Detect new source IPs for privileged accounts
   - Identify after-hours activity for specific users

5. **Graph Analysis**: Model user-host relationships as a graph
   - Detect unusual connection paths
   - Identify accounts connecting to systems outside their normal scope
   - Visualize lateral movement chains

### The Reality of AI/ML in Threat Hunting

Machine learning works best when:

- You have large volumes of well-structured data
- Clear features distinguish normal from abnormal
- You can tolerate false positives during tuning
- Human analysts review and validate findings

Domain expertise and hypothesis-driven hunting remain essential. ML should augment, not replace, the human analyst.

---

## Key Takeaways

### For Beginners

1. **Start with a hypothesis**: Don't hunt randomly. Base your investigations on threat intelligence, MITRE ATT&CK, or environmental knowledge.

2. **Understand your data before querying**: Validate data sources, check for parsing issues, and understand field mappings.

3. **Use the PACE framework**: Plan → Analyze → Construct → Execute provides structure and repeatability.

4. **Learn to pivot**: Start broad, then narrow based on observations. Each finding should inform the next query.

5. **Document everything**: Your analysis process is as valuable as your findings for future hunts.

### For Intermediate Analysts

1. **Context is everything**: Enrich data with asset inventories, user information, and threat intelligence.

2. **Build lookup tables**: Jump servers, VIPs, admin accounts, and service accounts should be documented and queryable.

3. **Think like an attacker**: What would bypass your current detections? Hunt for those gaps.

4. **Convert successful hunts to detections**: Repeatable findings should become automated alerts.

5. **Measure your program**: Track hypotheses tested, findings discovered, and detections created.

### For Advanced Practitioners

1. **ML has its place, but know the limits**: Use machine learning for volume reduction and prioritization, not as a replacement for domain expertise.

2. **Feature engineering matters**: If using ML, invest in creating meaningful numerical features from security data.

3. **Graph analysis for lateral movement**: Model user→host relationships to detect unusual access patterns.

4. **Share and collaborate**: Contribute to community resources like MITRE ATT&CK, Sigma rules, and threat hunting playbooks.

5. **Continuous improvement**: Every hunt should improve your detection coverage, data quality, or analytical techniques.

---

## References

### MITRE ATT&CK

- [T1021.001 - Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)
- [TA0008 - Lateral Movement Tactic](https://attack.mitre.org/tactics/TA0008/)

### Microsoft Documentation

- [Event 4624 - Successful Logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)

### Threat Hunting Frameworks

- [PEAK Threat Hunting Framework (Splunk)](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
- [TaHiTI - Targeted Hunting integrating Threat Intelligence](https://www.betaalvereniging.nl/wp-content/uploads/DEF-TaHiTI-Threat-Hunting-Methodology.pdf)
- [Sqrrl Threat Hunting Reference Model](https://www.threathunting.net/files/framework-for-threat-hunting-whitepaper.pdf)

### Splunk Resources

- [Splunk Security Content - RDP Detection](https://research.splunk.com/endpoint/00ca7f9e-88ab-4841-a6c2-83979ab1ed29/)

---

## Contributing

This guide is designed to evolve with the threat landscape. Contributions are welcome:

- Submit issues for corrections or clarifications
- Propose new detection techniques via pull requests
- Share real-world hunting experiences (sanitized) to improve examples

---

## License

This work is provided for educational purposes. Adapt techniques to your specific environment and ensure compliance with your organization's policies.

---

*Last Updated: December 2024*
