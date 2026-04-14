# Security Baselining: A Threat Hunter's Perspective

What is normal? This is the grand question that many security operations professionals gravitate to when attempting to grasp a network. This concept of "normal" is engrained in training courses, books, articles and everything you can think of cyber security related. Knowing normal is the key to knowing the outliers…right? This comes to the simple or not so simple concept of a baseline. Give a security professional a baseline and they can spot bad easily supposedly. The problem is in the real world how many organizations have a baseline…like truly? Even if there is a baseline, is it maintained on a routine basis after tech creep, sprawl, new features, new tools, new and decommissioned systems, cloud integration, AI integration etc. the list can basically go on forever.

A good example of what could be used as a baseline is a golden image. A organization says we only use these images to provision systems. That means we have standard software and OS across the network. In a fairytale, possibly. What happens when users begin to need certain software? What happens when a key application breaks unless certain software or version of software is needed? What happens as system administrators develop a "fix" that needs to stay in place. A change management process and tracking/ticketing system should capture most of this, but this becomes unwieldy after organization gets bigger and years go by. It is difficult to have a true baseline of an ever-changing environments, and this is the underlying problem with baselining for threat hunting or security operations…there isn't one.



The picture above is what every seasoned responder has seen with their own eyes. Day one, the deployment team hands over a clean gold image and a CMDB entry that matches it. Day ninety, someone in finance "just needed" a PDF tool that wasn't in the standard catalog. Month six, a sysadmin disables a service to fix a ticket at 2am and it never gets re-enabled. Year two, half the fleet is talking to cloud APIs that didn't exist when the baseline was written, and the other half has an AI assistant extension nobody approved. The baseline on paper and the baseline in reality are two different documents, and only one of them is lying to you.

However, I do not get sad quite yet. Baselining does not necessarily need to be an artifact from the organization. We can instead use a tool such as a SIEM to help us baseline for ourselves. Threat Hunting is about finding the adversary within the network that have evaded the security stack. We can utilize the telemetry available to develop your own baseline and find the outliers yourself. Then investigate those outliers effetely until you are able to incorporate into a model. We allow the data to tell us something rather then relying on the organization to do it for us. While I would love a true software/hardware baseline, network baseline, etc. it is not that attainable. Now comes the question, how do we baseline with what we have?


The loop above is the whole game. You are not trying to write a document that describes the environment. You are trying to run a recurring query that describes it *for you*, right now, and then look at what falls off the edges. The rest of this post is five working examples of exactly that  three in SPL, two in KQL  each of them cheap to run, easy to tune, and honest about what it's doing.

---

## Use Case 1 - First-Time-Seen Tuple: User / Host Logons

The idea is brain-dead simple and that is why it works. Over some lookback window thirty days is a reasonable starting point record every distinct `(user, host)` pair that has successfully authenticated. Anything whose *first* appearance lands inside your detection window (the last day, the last hour, whatever you want to hunt on) is by definition new to the environment. You are not claiming it is malicious. You are claiming it is worth looking at.



This pattern catches lateral movement, stolen credentials being tested against new targets, service accounts suddenly logging into workstations, and the first hop of an insider poking around where they have no business being. It also generates noise for two weeks while you tune it. That is normal. Tune it anyway.

```spl
index=wineventlog sourcetype=WinEventLog:Security
    EventCode=4624
    LogonType IN (2, 3, 7, 10, 11)
    earliest=-30d@d latest=now
``` Drop fields early so the stats command has less to move around ```
| fields _time, user, Computer, src_ip, LogonType, Workstation_Name
``` Filter out the noise that will otherwise eat your results ```
| where NOT match(user, "(?i)^(ANONYMOUS LOGON|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-)")
    AND NOT match(user, "\$$")
``` Compute the first time each (user, host) tuple was seen across the full 30d window ```
| stats min(_time) AS first_seen,
        max(_time) AS last_seen,
        values(src_ip) AS src_ips,
        values(LogonType) AS logon_types,
        count AS total_logons
        BY user, Computer
``` Keep only tuples whose first appearance is inside the detection window ```
| where first_seen >= relative_time(now(), "-1d@d")
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

A few notes for the juniors reading this. `LogonType 2` is interactive, `3` is network, `10` is remote interactive (RDP), `7` is unlock, `11` is cached  those are the ones you usually care about. The regex at the top strips out machine accounts (`$` suffix) and the built-in junk that will otherwise dominate your output. We filter out those tuples *after* `stats` rather than before because we want `stats` to see the entire 30-day history and compute an accurate `min(_time)`. If you filter to the last day in the base search, you lose the baseline and every tuple looks new. That is the single most common mistake people make writing this pattern.

For environments with an accelerated `Authentication` data model, the `tstats` version will run roughly an order of magnitude faster:

```spl
| tstats min(_time) AS first_seen,
         max(_time) AS last_seen,
         values(Authentication.src) AS src_ips,
         count
         FROM datamodel=Authentication
         WHERE Authentication.action=success
               earliest=-30d@d latest=now
         BY Authentication.user, Authentication.dest
| rename Authentication.* AS *
| where first_seen >= relative_time(now(), "-1d@d")
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

---

## Use Case 2 - First-Time-Seen Tuple: Parent / Child Process

Same mental model, different telemetry. Instead of `(user, host)` the tuple is `(ParentImage, Image)`  what parent process spawned what child process. The value here is enormous and under-used. Most of what an adversary does on an endpoint eventually shows up as an unusual parent/child relationship: `winword.exe → powershell.exe`, `w3wp.exe → cmd.exe`, `services.exe → rundll32.exe` out of a non-standard path, `sqlservr.exe → whoami.exe`. None of these are novel tradecraft, but they are still novel *to your environment* the first time the attacker tries them.

```spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    EventCode=1
    earliest=-30d@d latest=now
``` Keep only what we need for the tuple and triage ```
| fields _time, host, user, ParentImage, Image, CommandLine, ParentCommandLine
``` Normalize to lowercase basename so C:\Windows\... and c:\windows\... collapse ```
| eval parent_basename = lower(replace(ParentImage, "^.*\\\\", ""))
| eval child_basename  = lower(replace(Image,       "^.*\\\\", ""))
| eval tuple = parent_basename . " -> " . child_basename
``` Compute first_seen across the full 30d baseline ```
| stats min(_time) AS first_seen,
        max(_time) AS last_seen,
        dc(host) AS host_count,
        values(host) AS hosts,
        values(user) AS users,
        values(CommandLine) AS cmdlines,
        count AS exec_count
        BY tuple
``` Only surface tuples new to the environment in the detection window ```
| where first_seen >= relative_time(now(), "-1d@d")
| convert ctime(first_seen) ctime(last_seen)
| sort 0 first_seen
```

The `dc(host)` field matters. A first-time-seen tuple that shows up on one host is interesting. A first-time-seen tuple that shows up on forty hosts in the same hour is either a legitimate new deployment you didn't know about, or something very bad moving fast. Sort on it both ways and you will find things.

One word of warning: tune on process *basename*, not full path, for the first pass. Full-path tuples are more precise but they will fire every time a binary moves location, every time a new version installs into a `Program Files\app\<semver>\` directory, every time someone runs a tool from their Downloads folder. Start loose, tighten later.

---

## Use Case 3 - Standard Deviation on Network Traffic

First-time-seen works for categorical things. For continuous things  bytes out, request counts, connection duration  you want a different tool. Standard deviation is the easiest one to reach for. For each host, compute the mean and standard deviation of its hourly egress over the last thirty days, then flag any hour where the host is more than three standard deviations above its own mean. You are not comparing hosts to each other. You are comparing each host to *itself*, which is the only fair comparison in a heterogeneous environment.

```spl
index=network sourcetype=pan:traffic action=allowed
    earliest=-30d@d latest=now
``` Reduce columns before any aggregation ```
| fields _time, src_ip, bytes_out
``` Bucket into hourly bins per host ```
| bin _time span=1h
| stats sum(bytes_out) AS hourly_bytes_out BY _time, src_ip
``` Build the per-host baseline in a single streaming pass ```
| eventstats avg(hourly_bytes_out) AS avg_bytes,
             stdev(hourly_bytes_out) AS stdev_bytes,
             count AS hours_observed
             BY src_ip
``` Require enough history to make the stdev meaningful ```
| where hours_observed >= 72 AND stdev_bytes > 0
``` Compute z-score for each hourly bucket against the host's own baseline ```
| eval zscore = round((hourly_bytes_out - avg_bytes) / stdev_bytes, 2)
``` Surface only recent, high-sigma events ```
| where zscore >= 3 AND _time >= relative_time(now(), "-1d@d")
| eval hourly_mb = round(hourly_bytes_out / 1024 / 1024, 2),
       avg_mb    = round(avg_bytes / 1024 / 1024, 2)
| table _time, src_ip, hourly_mb, avg_mb, zscore, hours_observed
| sort 0 - zscore
```

Three things to know about this query. First, `eventstats` is the right command here, not `stats`  `eventstats` keeps every event and decorates it with the aggregate, so you still have the raw hourly bucket to evaluate. Second, the `hours_observed >= 72` guard exists because a host with six hours of history will have a garbage standard deviation and will show up as a 40-sigma outlier on its seventh hour. Do not trust stdev without enough observations behind it. Third, z-score of 3 is a starting point, not a commandment. In a quiet network you will want to go higher. In a noisy one you will want to combine it with a floor like `AND hourly_bytes_out > 100000000` so you do not chase a workstation that normally sends nothing and briefly sent something.

This pattern finds the obvious stuff  exfil spikes, beacon bursts, a database suddenly dumping to an unfamiliar destination  and it finds it without you having to know in advance what "a lot of bytes" means for any particular host. The host tells you.

---

## Use Case 4 - File Prevalence Deviation with KQL (`FileProfile`)

Over on the Defender XDR side of the fence, Microsoft gives you something Splunk cannot give you out of the box; a global prevalence number for a file hash, computed across Microsoft's entire telemetry footprint. The `FileProfile()` function enriches a row with `GlobalPrevalence`, `GlobalFirstSeen`, and signer information, and it turns "is this binary weird" into a one-line question. A file with a global prevalence of 3 is not the same animal as a file with a global prevalence of 3 million, and you should not treat them the same.

```kql
// Low-prevalence executable content dropped in the last 24 hours
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileCreated"
| where FileName endswith ".exe"
     or FileName endswith ".dll"
     or FileName endswith ".ps1"
     or FileName endswith ".scr"
| where isnotempty(SHA256)
// Skip the usual managed-software drop paths to cut baseline noise
| where FolderPath !startswith @"C:\Windows\SoftwareDistribution"
    and FolderPath !startswith @"C:\ProgramData\Microsoft\Windows Defender"
    and FolderPath !startswith @"C:\Windows\WinSxS"
// Enrich each row with Microsoft's global telemetry view of the hash
| invoke FileProfile("SHA256", 1000)
// The interesting slice: rare or never-before-seen files
| where GlobalPrevalence < 100 or isempty(GlobalPrevalence)
| project Timestamp, DeviceName, InitiatingProcessFileName,
          FolderPath, FileName, SHA256,
          GlobalPrevalence, GlobalFirstSeen,
          Signer, IsCertificateValid
| sort by GlobalPrevalence asc nulls first, Timestamp desc
```

`FileProfile()` has a hard cap on how many rows it will enrich per query (the second argument, here set to 1000), so you need to pre-filter aggressively before you `invoke` it. The pattern above does that: restrict to file-create events, restrict to executable extensions, restrict to the last day, and strip out the three or four paths that account for most of the benign noise. What you get back is a short list of rare binaries that were written to disk in your environment in the last twenty-four hours, sorted by how rare they are globally. A binary with a prevalence of 1 and no signer is a very different conversation than a binary with a prevalence of 800,000 and a valid Microsoft signature, and now you can see both at once.

This is not a replacement for threat intel, and it is not a replacement for a detection rule. It is a hunting query. It gives you the short list; the analyst does the rest.

---

## Use Case 5  Network / Domain Deviation with KQL

Same pattern as the SPL first-time-seen tuple, translated to Defender's device network telemetry. Build a list of every external domain your devices have successfully connected to over the last thirty days, then look at the last day and show me everything that wasn't on yesterday's list.

```kql
let lookback  = 30d;
let detection = 1d;
// Historical set every RemoteUrl seen in the baseline window, but NOT in the detection window
let historic =
    DeviceNetworkEvents
    | where Timestamp between (ago(lookback) .. ago(detection))
    | where ActionType == "ConnectionSuccess"
    | where isnotempty(RemoteUrl)
    | distinct RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(detection)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl)
// Anti-join rows whose RemoteUrl is NOT in the historical set
| join kind=leftanti //historic on RemoteUrl
| summarize FirstSeen   = min(Timestamp),
            LastSeen    = max(Timestamp),
            DeviceCount = dcount(DeviceId),
            Devices     = make_set(DeviceName, 25),
            Processes   = make_set(InitiatingProcessFileName, 25),
            ConnCount   = count()
          by RemoteUrl, RemoteIP
| sort by DeviceCount desc, FirstSeen asc
```

A few details that matter. `leftanti` is the KQL way to say "rows on the left that have no match on the right" it is the efficient way to do a first-time-seen check in KQL and it is the pattern you should reach for instead of nested `in`/`!in` subqueries. `ConnectionSuccess` is important because `ConnectionAttempt` will light up with garbage (DNS probes, failed connections, noise from scanners). And sorting by `DeviceCount desc` first is deliberate: a brand-new domain that fifty devices contacted simultaneously is almost certainly either a new SaaS vendor rolling out, or a C2 rolling out. A brand-new domain that one device contacted once is far more likely to be a user clicking a link. Both are interesting, but they are not the same kind of interesting, and the sort order surfaces them differently.

You can extend this easily. Swap `RemoteUrl` for `RemoteIP` to find first-time-seen destinations at the IP level. Tuple it with `InitiatingProcessFileName` to find first-time-seen `(process, domain)` pairs, which is how you catch a legitimate browser suddenly calling a domain no browser on the network has ever called before. Tuple it with `DeviceName` to make it per-host. The shape of the query stays the same.

---

## Conclusion

So we come back to the grand question we started with. What is normal? And the honest answer the one nobody wants to put in the training course is that normal is not a document. Normal is not a spreadsheet the architecture team owned in 2019 and last opened in 2021. Normal is not a CMDB row. Normal is not a golden image. Normal is a moving target in a network that never stops changing, and the people telling you they have a maintained baseline are usually the same people who have not looked at it since the last audit.

If the organization cannot hand you a baseline, the telemetry can build you one an imperfect one, a noisy one, but an *honest* one, and an honest baseline beats a pristine fictional baseline every day of the week. That is what every query in this post is doing. First-time-seen tuples turn your SIEM into a rolling inventory of what is actually happening. Standard deviation turns your SIEM into a rolling model of what each host actually does. Global prevalence lets you borrow someone else's baseline when yours isn't big enough. None of these require a pristine environment. None of these require a change management program that actually works. They require telemetry, data, and the discipline to run the query on a schedule and *look at the results*.

The adversary is not going to wait for your baseline project to finish. They are in the network now, or they will be next week, and they are going to do something that has never happened in your environment before because almost everything is something that has never happened in your environment before, and that is exactly why it works. Your job as a hunter is to be the person who notices. Not to be the person who maintained the perfect document.

Let the data tell you. Then go look.
