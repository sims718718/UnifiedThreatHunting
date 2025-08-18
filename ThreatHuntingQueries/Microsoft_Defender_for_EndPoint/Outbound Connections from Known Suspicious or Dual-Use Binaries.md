# 📄 Outbound Connections from Known Suspicious or Dual-Use Binaries

## 🔍 Analysis

This query surfaces **successful outbound connections** made by a large list of **living-off-the-land binaries (LOLBINs)**, dual-use tools, and potentially abused legitimate executables and DLLs. It is designed to detect:

- Beaconing or command-and-control (C2) activity using trusted system processes
- Malicious tooling using rarely monitored binaries to bypass detection
- Suspicious use of administrative or scripting tools for network access

By excluding private IP ranges and known-good domains, this query helps reduce false positives and prioritize high-fidelity leads.

## 📚 Data Sources

- **Table:** `DeviceNetworkEvents`
- **Key Fields:**
  - `Timestamp`
  - `InitiatingProcessFileName`
  - `RemoteIP`
  - `RemoteUrl`
  - `RemoteIPType`
  - `RemotePort`
  - `InitiatingProcessParentFileName`
  - `InitiatingProcessCommandLine`
  - `DeviceName`

## 🧠 MITRE ATT&CK Mapping

- **T1105 – Ingress Tool Transfer**
- **T1218 – Signed Binary Proxy Execution**
- **T1071 – Application Layer Protocol**
- **T1568.002 – Dynamic Resolution**

## 🧪 KQL Query

```kql
// Define Exclusion list of URLs  
let ExclusionList = dynamic([
    "login.live.com"
    // Add more URLs to exclude as needed
]);

// Define the list of potentially suspicious executables
let SuspiciousExecutables = dynamic([
    "AppInstaller.exe", "cmd.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", 
    "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", 
    "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", 
    "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", 
    "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", 
    "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", 
    "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", 
    "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", 
    "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", 
    "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", 
    "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", 
    "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", 
    "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", 
    "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", 
    "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", 
    "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", 
    "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", 
    "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", 
    "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", 
    "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", 
    "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", 
    "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", 
    "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", 
    "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", 
    "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", 
    "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", 
    "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", 
    "DefaultPack.EXE", "Devinit.exe"
]);

// Main query
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (SuspiciousExecutables)
| where ActionType == 'ConnectionSuccess' 
| where RemoteIPType != "Private"
| where not(RemoteUrl in (ExclusionList)) 
| where RemoteUrl !endswith "measure.office.com" 
      and RemoteUrl !endswith "windows.net" 
      and RemoteUrl !endswith "office.com" 
      and RemoteUrl !endswith "msn.com" 
      and RemoteUrl !endswith "microsoft.com"
| summarize 
    ConnectionCount = count(), 
    DistinctHostCount = dcount(DeviceName), 
    make_set(DeviceName), 
    make_set(RemoteIPType), 
    make_set(RemotePort), 
    make_set(InitiatingProcessParentFileName),
    make_set(InitiatingProcessFileName), 
    make_set(RemoteIP), 
    make_set(InitiatingProcessCommandLine) 
  by RemoteUrl
| order by ConnectionCount asc
