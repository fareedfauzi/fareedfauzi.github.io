---
layout: article
title: "Cheatsheet: Windows Forensics Analysis"
date: 2023-12-22
tags:
- DFIR
---

During a Windows Forensics engagement, I occasionally find myself forgetting essential tasks or unintentionally skipping analyzing importants artifacts. Therefore, this checklist (along with cheatsheet) could help myself (or readers) and ensure that I adhere to a systematic workflow when conducting Windows Forensics.

# Typical Forensic investigation flow
![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/fd7dcfc9-f006-4343-895d-ad8d272382ab)

If you ask me the details on the acquisition and analysis part, here it is:
1. Evidence acquisition ⇛ Disk, memory
2. Live response, scanner and live forensics ⇛ Autoruns, process hacker, THOR or Loki, Inquisitor
3. Memory forensics ⇛ MemProcFS, volatility
4. Disk Image mounting ⇛ Mounting and Triage important artifact
5. Persistence analysis ⇛ Autoruns location, registry, WMI, Scheduled Tasks
6. Malware analysis ⇛ Static and Dynamic analysis
7. Checking system information ⇛ Registry
8. Root cause analysis ⇛ Logs, web, malware, file folder activity, exploit, email, executed file
9. Lateral movement investigation ⇛ event log, executed file, registry, file system
10. Timeline analysis ⇛ MFT, Logfile, UsnJ parsing
11. File access artifacts ⇛ File sharing, MountPoints, USB
12. Recovering deleted data ⇛ Recyclebin, MFT, VSS, File carving, Keyword search (Autopsy)
13. Malware reverse engineering
14. Writing report

# Tools
## Acquire artifact's Tools

| Tools | Description |
| --- | --- |
| FTK Imager | Disk Imaging |
| Magnet RAM Capturer | Generate memory dump |
| KAPE | Triage only selected important artifacts instead of the whole disk image |
| Inquisitor / FastIR | Live analysis triage |
| Mandiant Redline | Collect live and file's data and produce analysis |
| External Hard disk | To store the artifact acquisition |
| Velociraptor's agent and server | Remote forensics framework |
| EDD | Check disk encryption |

## Forensic analysis tools

| Tools | Description |
| --- | --- |
| Arsenal Image Mounter | Mounting image |
| Autopsy / FTK Imager | Disk forensics |
| KAPE | Triage artifact and parse artifact |
| Eric Zimmerman tools | Artifact parser and viewer |
| Regripper | Registry parser |
| Volatility Workbench / MemProcFS / MemProcFS-Analyzer | Memory analysis tools |
| Event log explorer | Event log viewer |
| Reg_hunter | Hunt for malicious registry in live forensics |
| Other open/close source tools | - |

## OS / Linux Distros
1. Windows
2. SIFT Linux
3. Tsurugi Linux
4. REMnux

# Acquire artifacts
1. Check disk encryption using EDD
2. Perform disk imaging using FTK Imager
3. Perform memory dump activity using Magnet RAM Capturer for example.
4. Save all files in the external harddisk
5. Optional:
    - Perform live analysis collection scanner such as Inquisitor
    - Scan the compromised using scanner such as THOR
    - Perform Registry scanner such as RegHunter
    - Perform memory scanner such as hollows_hunter or moneta
    - Perform persistent scanner such as PersistenceSniper or Trawler

# KAPE cheatsheet
Basic command
```
# Target
.\kape.exe --tsource [DRIVE LETTER] --tdest [DESTINATION INCLUDE FOLDER NAME] --module [MODULE NAME] --gui
# Module
.\kape.exe --msource [DRIVE LETTER] --mdest [DESTINATION INCLUDE FOLDER NAME] --module [MODULE NAME] --gui
```

## Target
### KAPE target extraction
```
.\kape.exe --tsource E: --tdest D:\KAPE_cases\ --target KapeTriage,MessagingClients,RemoteAdmin,ServerTriage,WebBrowsers,WebServers,WSL,MemoryFiles --gui
```

## Module: Live Response

### Memory dump
```
.\kape.exe --msource C:\ --mdest D:\KAPE_cases\%m --module MagnetForensics_RAMCapture --gui
```

### Live response command and scanner
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\%m --module PowerShell_Get-InjectedThread,PowerShell_Get-NetworkConnection,PowerShell_Netscan,PowerShell_Signed,SIDR_WindowsIndexSearchParser,WIFIPassView,MagnetForensics_EDD,Nirsoft_BluetoothView,Nirsoft_LastActivityView,Nirsoft_OpenedFilesView,NirSoft_USBDeview,NirSoft_VideoCacheView,NirSoft_WebBrowserPassView,Nirsoft_WhatInStartup,Nirsoft_WifiHistoryView,Nirsoft_WirelessKeyView,SysInternals_Autoruns,SysInternals_Handle,SysInternals_PsFile,SysInternals_PsInfo,SysInternals_PsList,SysInternals_PsLoggedOn,SysInternals_PsService,SysInternals_PsTree,SysInternals_Tcpvcon,Powrshell_LiveResponse_SystemInfo,PowerShell_Arp_Cache_Extraction,PowerShell_Bitlocker_Key_Extraction,PowerShell_Bitlocker_Status,PowerShell_Defender_Exclusions,PowerShell_DLL_List,PowerShell_Dns_Cache,PowerShell_Local_Group_List,PowerShell_LocalAdmin,PowerShell_NamedPipes,PowerShell_NetUserAdministrators,PowerShell_Network_Configuration,PowerShell_Network_Connections_Status,PowerShell_Network_Share,PowerShell_Process_Cmdline,PowerShell_ProcessList_CimInstance,PowerShell_ProcessList_WMI,PowerShell_Services_List,PowerShell_SMBMapping,PowerShell_SMBOpenFile,PowerShell_SMBSession,PowerShell_Startup_Commands,PowerShell_User_List,PowerShell_WMIRepositoryAuditing,Windows_ARPCache,Windows_DNSCache,Windows_GpResult,Windows_IPConfig,Windows_MsInfo,Windows_nbtstat_NetBIOSCache,Windows_nbtstat_NetBIOSSessions,Windows_Net_Accounts,Windows_Net_File,Windows_Net_LocalGroup,Windows_Net_Session,Windows_Net_Share,Windows_Net_Start,Windows_Net_Use,Windows_Net_User,Windows_netsh_portproxy,Windows_NetStat,Windows_qwinsta_RDPSessions,Windows_RoutingTable,Windows_schtasks,Windows_SystemInfo,Reghunter,hasherezade_HollowsHunter --gui

.\kape.exe --msource E:\ --mdest D:\KAPE_cases\%m --module Thor-Lite_Upgrade,Thor-Lite_Scan --gui

.\kape.exe --msource E:\ --mdest D:\KAPE_cases\%m --module Loki_LiveResponse --gui

.\kape.exe --msource E:\ --mdest D:\KAPE_cases\%m --module hasherezade_HollowsHunter --gui

.\kape.exe --msource E:\ --mdest D:\KAPE_cases\%m --module MagnetForensics_RAMCapture --gui
```

## Module: Parsing and scanning

### All in one artifact parsing 
Warning: Super slow!
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module Loki_Scan,DensityScout,BackstageParser,BitsParser,CCMRUAFinder_RecentlyUsedApps,Chainsaw,DeepblueCLI,DHParser,EvtxHussar,hasherezade_HollowsHunter,INDXRipper,LevelDBDumper,OneDriveExplorer,PowerShell_Get-ChainsawSigmaRules,TeamsParser,ThumbCacheViewer,WMI-Parser,Zircolite_Scan,Zircolite_Update,LogParser_ApacheAccessLogs,LogParser_DetailedNetworkShareAccess,LogParser_LogonLogoffEvents,LogParser_RDPUsageEvents,LogParser_SMBServerAnonymousLogons,Nirsoft_AlternateStreamView,NirSoft_BrowsingHistoryView,NirSoft_FullEventLogView_AllEventLogs,NirSoft_FullEventLogView_Application,NirSoft_FullEventLogView_PowerShell-Operational,NirSoft_FullEventLogView_PrintService-Operational,NirSoft_FullEventLogView_ScheduledTasks,NirSoft_FullEventLogView_Security,NirSoft_FullEventLogView_System,NirSoft_TurnedOnTimesView,NirSoft_WebBrowserDownloads,Nirsoft_WinLogonView,SysInternals_SigCheck,TZWorks_CAFAE_Registry_System,Events-Ripper,Hayabusa,LogParser,MFTECmd,NTFSLogTracker,RECmd_AllBatchFiles,Reghunter,RegRipper,AmcacheParser,AppCompatCacheParser,EvtxECmd,EvtxECmd_RDP,iisGeoLocate,JLECmd,LECmd,PECmd,RBCmd,RecentFileCacheParser,SBECmd,SQLECmd,SQLECmd_Hunt,SrumECmd,SumECmd,WxTCmd,Sync_EvtxECmd,Sync_KAPE,Sync_RECmd,Sync_SQLECmd,Windows_ManageBDE_BitLockerKeys,Windows_ManageBDE_BitLockerStatus --gui
```

### Event log / log scanning and parsing 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module !!ToolSync,PowerShell_Get-ChainsawSigmaRule,Chainsaw,DeepblueCLI,EvtxHussar,Zircolite_Update,Zircolite_Scan,Events-Ripper,hayabusa_EventStatistics,hayabusa_OfflineEventLogs,hayabusa_OfflineLogonSummary,hayabusa_UpdateRules,EvtxECmd,EvtxECmd_RDP,LogParser,iisGeoLocate
```

### Program Execution 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module CCMRUAFinder_RecentlyUsedApps,AmcacheParser,AppCompatCacheParser,PECmd,RecentFileCacheParser --gui
```

### File folder activity 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module BackstageParser,OneDriveExplorer,ThumbCacheViewer,JLECmd,LECmd,RBCmd,SBECmd,WxTCmd --gui
```

### NTFS and FileSystem parsing 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module !!ToolSync,INDXRipper,MFTECmd,NTFSLogTracker,RegRipper,RECmd_AllBatchFiles --gui
```

### System activity 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module SRUMDump,WMI-Parser,RECmd_AllBatchFiles,SrumECmd,SumECmd --gui
```

### Mounted image scanner 
```
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module Loki_Scan --gui
.\kape.exe --msource E:\ --mdest D:\KAPE_cases\ --module DensityScout --gui
```

# Analysis Findings
First, create a spreadsheet that will be the main documentation of your findings especially for Timeline. Include few relavant aspects in the spreadsheet such as:
1. Artifact type
2. Findings
3. Location of artifact
4. Created
5. Accessed
6. Modified
7. Notes / Payload

## Live Forensics
1. Check all the results of the script collection (Inquisitor / Kansa / FastIR)

## Memory analysis
1. Tool used: Volatility, MemProcFS, MemProcFS-Analyzer
2. Check network connection (netstat, netscan)
3. Check process list (pslist, pstree, psscan, cmdline)
4. Check injected process, dll injection (malfind, dlllist)
5. Dump malicious process (dumpfiles --pid PID)
6. Volatilit3 command: `python3 vol.py -f <memdump> <plugin name>`
7. MemProcFS command: `memprocfs.exe -device D:\mem.raw -forensic 1`
8. MemProcFS-Analyzer: `.\MemProcFS-Analyzer.ps1`

## Disk analysis
### Mount image
1. Perform KAPE execution on the mounted drive using "KAPE triage" module to extract important artifacts.
2. Run malware scanner on the mounted drive (Loki scanner, THOR scanner, AV scanner, Densityscout)
3. Perform data recovery on the mounted drive using Photorec
4. Check any shadow copy, view it in Shadow Explorer

### Autopsy
1. Attach disk in Autopsy
2. Run ingest module "Recent activity" and "Keyword search"
3. Check Data artifacts in Autopsy, record all interesting findings
4. Check file and folder (Access time, and created time)
5. View Timeline Analysis in Autopsy
6. Search any interesting keywords

## Windows event logs analysis
1. Located at `C:\Windows\System32\winevt\Logs`
2. Perform event log scanner
3. Manually view in Event Log Explorer

### Interesting log sources

| Log sources | Context |
| --- | --- |
| Security.evtx | Security-related events |
| System.evtx | Tracks system component events |
| Application.evtx | Logs application-specific events |
| Microsoft-Windows-Sysmon/Operational.evtx | Enhanced process, network, and file monitoring |
| Microsoft-Windows-PowerShell/4Operational.evtx | Records PowerShell activity |
| Microsoft-Windows-Windows Defender/Operational.evtx | Logs Windows Defender events |
| Microsoft-Windows-WMI-Activity/4Operational.evtx | Logs WMI events  |
| Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx | Logs RDP session events |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational.evtx | Logs RDP session events |
| Microsoft-Windows-TaskScheduler/Operational.evtx | Logs Task Scheduler events |
| Microsoft-Windows-DNS-Server%4Operational.evtx | Active Directory Server Logs |
| Directory Service.evtx | Active Directory Server Logs |
| File Replication Service.evtx | Active Directory Server Logs |
| %SystemDrive%\inetpub\logs\LogFiles | IIS log |
| %SystemRoot%\System32\LogFiles\HTTPERR | IIS log  |
| %ProgramFiles%\Microsoft\Exchange Server\V15\Logging | Exchange log |
| Panther*.log | Windows setup details |
| RPC Client Access*.log | Exchange Server, if applicable |
| Third party antivirus log | AV logs |

### Event log scanner

| Tools | Commands |
| --- | --- |
| Hayabusa | `hayabusa.exe update-rules` and `hayabusa.exe csv-timeline -d ..\Logs -p verbose -o results.csv` |
| DeepBlueCLI | `.\DeepBlue.ps1 -log security` |
| Chainsaw | `chainsaw.exe hunt evtx_logs/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results` |
| Zircolite | `zircolite_win10.exe --evtx ../Logs` |
| APT-Hunter | `APT-Hunter.exe -p ..\Logs -o Foldername -allreport` |
| EVTXHussar | `EvtxHussar.exe C:\evtx_compromised_machine -o C:\evtxhussar_results` |
| Rhaegal | `rhaegal.exe -lp ..\Logs -rp rules -n 100 -o output.csv` |
    

### Important Security Event IDs

| IDs | Event log | Context |
| --- | --- | --- |
| 4624 | Security | Successful Login |
| 4625 | Security | Failed Login |
| 4634/4647 | Security| User Initiated Logoff/An Account was Logged Off |
| 4648 | Security | A Logon was Attempted Using Explicit Credentials |
| 4662 | Security | An Operation was Performed on an Object |
| 4663 | Security | An Attempt was Made to Access an Object |
| 4672 | Security | Special Logon |
| 4688 | Security | Process Creation |
| 4689 | Security | Process Termination |
| 4697 | Security | Service Installed |
| 4698/4702/4700 | Security | Scheduled Task Created or Updated |
| 4699 | Security | Scheduled Task Deleted |
| 4701 | Security | Scheduled Task Enabled |
| 4702 | Security | Service Removed |
| 4720 | Security | A User Account was Created |
| 4722 | Security | A User Account was Enabled |
| 4723 | Security | An Attempt was Made to Change an Account's Password |
| 4724 | Security | An Attempt was Made to Reset an Account's Password |
| 4725 | Security | A User Account was Disabled |
| 4726 | Security | A User Account was Deleted |
| 4728 | Security | A Member was Added to a Security-Enabled Global Group |
| 4729 | Security | A Member was Removed from a Security-Enabled Global Group |
| 4732 | Security | A Security-Enabled Local Group was Created |
| 4733 | Security | A Security-Enabled Local Group was Changed |
| 4734 | Security | A Security-Enabled Local Group was Deleted |
| 4741 | Security | A Computer Account was Created |
| 4742 | Security | A Computer Account was Changed |
| 4768 | Security (DC) | Kerberos TGT request |
| 4769 | Security (DC) | Kerberos Service Ticket request |
| 4771 | Security  | Locked Out Account |
| 4776 | Security  | NTLM authentication |
| 4778 | Security | Session Reconnected |
| 4779 | Security | Session Disconnected by User |
| 4794 | Security | An Attempt was Made to Set the Directory Services Restore Mode Administrator Password |
| 5136 | Security | Directory Service Changes |
| 5140 | Security | A Network Share Object was Accessed |
| 5141 | Security | A Directory Service Object was Deleted |
| 5145 | Security | Network Share Object was Checked |
| 5376 | Security | Credential Manager Credentials Submitted |
| 5377 | Security | Credential Manager Credentials Auto-Logon |
| 1102 | Security | Event Log Cleared |
| 1100 | Security | Event Log Service Shutdown |

### Logon type corresponding to Succesfull (4624) or Failed logins (4625)

| Logon Type | Explanation |
|---|---|
| 2 | Logon via console |
| 3 | Network Logon. A user or computer logged on to this computer from the network |
| 4 | Batch Logon (Task scheduler and AT) |
| 5 | Windows Service logon  |
| 7 | Credentials used to unlock screen  |
| 8 | Network logon sending credentials (cleartext)    |
| 9 | Different credentials used than logon user |
| 10 | Remote Interactive logon (RDP)  |
| 11 | Cached credentials used to logon |
| 12 | Cached remote interactive (RDP) |
| 13 | Cached Unlock (Similar to logon type 7)  |

### Other's log important Event IDs

| IDs | Event log | Context |
| --- | --- | --- |
| 7045 | System | Service installed |
| 7034 | System | The service terminated unexpectedly |
| 7035 | System | Service Control Manager |
| 7036 | System | Service State Change |
| 7040 | System | Service was changed from disabled to auto start.  |
| 7001 | System | Service Start Failed |
| 1001 | System | BSOD |
| 6005 | System | Start-up time of the machine	|
| 6006 | System | Shutdown time of the machine |
| 104 | System | Log cleared |
| 59 | MicrosoftWindows Bits Client/operational | Bits Jobs |
| 2004 | Microsoft-Windows-Windows Firewall with Advanced Security | Rule has been added to the Window Firewall exception list |
| 2006 | Microsoft-Windows-Windows Firewall with Advanced Security | Deleted firewall rule |
| 1116  | Microsoft Windows Windows Defender/Operational | Defender Antivirus has detected malware |
| 1117 | Microsoft Windows Windows Defender/Operational | Action taken |
| 1006 | Microsoft Windows Windows Defender/Operational | Scan result |
| 4103 | Microsoft Windows PowerShell/Operational | Module logging |
| 4104 | Microsoft Windows PowerShell/Operational | Script Block Logging |
| 4105 | Microsoft Windows PowerShell/Operational | Transcription Logging |
| 4688 | Microsoft Windows PowerShell/Operational | Process Creation (including PowerShell processes) |
| 400 | Windows PowerShell | Start of a PowerShell activity, whether local or remote.  |
| 403 | Windows PowerShell | Completion of a PowerShell activity |
| 800 | Windows PowerShell | Pipeline execution |
| 1000 | Application | Application Error/crash |
| 1001 | Application | Application Error reporting |
| 1002 | Application | Application Hang |
| 1024 | Application | Software Installation |
| 1040 | Application | User Initiated Software Installation |
| 1033 | Application | Software installed |
| 1034 | Application | Windows Installer removed the product |
| 11707 | Application | Installation operation completed successfully |
| 11708 | Application | Installation failed |
| 11724 | Application | Installation completed successfully |
| 1 | Microsoft-Windows-Sysmon/Operational | Process Creation |
| 2 | Microsoft-Windows-Sysmon/Operational | A process changed a file creation time |
| 3 | Microsoft-Windows-Sysmon/Operational | Network connection detected |
| 6 | Microsoft-Windows-Sysmon/Operational | Driver Loaded |
| 7 | Microsoft-Windows-Sysmon/Operational | Image Loaded |
| 8 | Microsoft-Windows-Sysmon/Operational | CreateRemoteThread |
| 10 | Microsoft-Windows-Sysmon/Operational | ProcessAccess |
| 11 | Microsoft-Windows-Sysmon/Operational | FileCreate |
| 12 | Microsoft-Windows-Sysmon/Operational | RegistryEvent (Object create and delete) |
| 1149 | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP User authentication succeeded |
| 21 | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session logon succeeded |
| 24 | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session has been disconnected  |
| 25 | Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational | RDP Session reconnection succeeded |
| 131 | RDPCoreTS | RDP connection is first established |
| 106 | Task Scheduler | New scheduled task is created |
| 140 | Task Scheduler | New scheduled task is created |
| 141 | Task Scheduler | User deleted Task Scheduler task |
| 200 | Task Scheduler | Task executed |
| 201 | Task Scheduler | Task scheduler successfully completed the task |
| 5857 | WMI-Activity Operational | WMI activity is detected  |
| 5858 | WMI-Activity Operational | WMI error |
| 5859 | WMI-Activity Operational | Subscription-based activity |
| 5860 | WMI-Activity Operational | Detailed subscription-based activity |
| 5861 | WMI-Activity Operational | Permanent subscription activity |

Event ID KB: https://system32.eventsentry.com/ and https://www.myeventlog.com/search/browse

## Triage artifacts parsing and analysis

### File Records

MFT Attributes:
1. $STANDARD_INFORMATION ($SI)
2. $FILE_NAME ($FN)
3. $DATA
4. $EA (Extended Attributes)

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| MFT | `C:\` | `MFTECmd.exe -f "C:\Temp\SomeMFT" --csv "c:\temp\out" --csvf MyOutputFile.csv`|
| UsnJrnl | `C:\$Extend` | `MFTECmd.exe -f "C:\Temp\SomeJ" --csv "c:\temp\out" --csvf MyOutputFile.csv`|

Other useful tools:
1. analyzeMFT.py: Parse $MFT files and summarize those information
2. MFTRCRD: MFT record decoder for online filesystem
3. Mft2Csv: Parse $MFT files and raw disk images. It can extract resident files from $MFT.
4. Fte: Parse MFT and INDX
5. MFTCarver: Can recover old MFT entries that are not listed in current MFT
6. Bulk Extractor: Contains scanner plug-ins for records of $MFT, $LogFile, $UsnJrnl:$J, $INDEX_ALLOCATION, and utmp structure.
7. NTFS Log Tracker: Parses $Logfile and $UsnJrnl:$J
8. USN Analytics: Parse records of $UsnJrnl that were extracted by BE
9. Indx2Csv: Parse for INDX
10. INDXParse: Parses a single $I30
11. IndxCarver: Can recover old INDX records to get information about deleted files and folders

Follow Windows Time Rules below:

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/70270442-6316-420a-b183-971624a141f9)
Credit: SANS Windows Forensic Analysis Poster (digital-forensics.sans.org)

### System and user Information (via Registry)

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Operating System Version | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | Registry Explorer |
| System Boot & Autostart Programs | Run registries | Registry Explorer |
| Computer Name | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | Registry Explorer |
| System Last Shutdown Time | `SYSTEM\CurrentControlSet\Control\Windows` | Registry Explorer |
| Cloud Account Details | `SAM\Domains\Account\Users\<RID>\InternetUserName` | Registry Explorer |
| User Accounts | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` | Registry Explorer |
| Last Login and Password Change | `SAM\Domains\Account\Users` | Registry Explorer |

### Application Execution

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Shimcache | `SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache` | RegRipper |
| Amcache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Registry Explorer |
| UserAssist | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` | Registry Explorer |
| Win10 Timeline | `C:\%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\L.Administrator\ActivitiesCache.db` | `WxTCmd.exe -f "ActivitiesCache.db" --csv D:\Hands-On` |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | srum-dump |
| BAM / DAM | `SYSTEM\ControlSet001\Services\bam\State\UserSettings\` | Registry Explorer |
| Prefetch, MFT, USNJ | `C:\Windows\prefetch` | `PECmd.exe -d D:\Windows\Prefetch, MFT, USNJ--csv "D:\Hands-On" --csvf prefetch.csv` or WinPrefetch, MFT, USNJ |
| Task Bar Feature Usage | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` | Registry Explorer |
| Jumplist | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` | Jumplist Explorer |
| Last Visited MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | RegRipper |
| CapabilityAccessManager | `NTUSER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` | Registry Explorer |
| Commands Executed in the Run Dialog | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Registry Explorer |
| Services | `System\CurrentControlSet\Services` | Registry Explorer |

### File and Folder Opening

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Shellbag | `NTUSER.dat\Software\Microsoft\Windows\Shell\Bags` | Shellbags Explorer |
| Open/Save MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU` | Registry Explorer |
| Shortcut (LNK) Files | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows|Office\Recent\` | Autopsy |
| Jumplist | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations` | Jumplist Explorer |
| Recent Files | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Registry Explorer |
| Office Recent Files | `NTUSER.DAT\Software\Microsoft\Office\<Version>\<AppName>` | Registry Explorer |
| Office Trust Records | `NTUSER\Software\Microsoft\Offi ce\<Version>\<AppName>\Security\Trusted Documents\TrustRecords` | Registry Explorer |
| MS Word Reading Locations | `NTUSER\Software\Microsoft\Offi ce\<Version>\Word\Reading Locations` | Registry Explorer |
| Office OAlerts | OAlerts.evtx | Event log explorer |
| Last Visited MRU | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Registry Explorer |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat` | Text Editor |


### Deleted Items and File Existence

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Recycle Bin | `C:\$Recycle.Bin` | Recbin |
| Thumbcache | `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` | Thumbcache Viewer |
| User Typed Paths | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Registry Explorer |
| Search – WordWheelQuery | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` | Registry Explorer |
| Internet Explorer file:/// | `%USERPROFILE%\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat` | Text Editor |
| Windows Search Database | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb` | LostPassword's Search Index Examiner |


### Browser activity

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Browser activity | `C:\Users\%user%\AppData\Local\\Roaming\BrowserName` | DBBrowser | 

### Network Usage

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Network History | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Network*` | Registry Explorer |
| Timezone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Registry Explorer |
| WLAN Event Log | `Microsoft-Windows-WLAN-AutoConfig Operational.evtx` | Event log viewer |
| Network Interfaces | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | Registry Explorer |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | srum-dump |

### USB Usage

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| USB Device Identification | `SYSTEM\CurrentControlSet\Enum\*` | Registry Explorer |
| Drive Letter and Volume Name | `SOFTWARE\Microsoft\Windows Portable Devices\Devices` and `SYSTEM\MountedDevices` | Registry Explorer |
| User Information | `SYSTEM\MountedDevices` and `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Registry Explorer |
| Connection Timestamps | `SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_&Prod_\USBSerial` | Registry Explorer |
| Volume Serial Number (VSN) | `SOFTWARE\Microsoft\WindowsNT\CurrentVersion\EMDMgmt` | Registry Explorer |
| Shortcut (LNK) Files | `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\\Office\Recent\` | Autopsy |
| Event Logs | `System.evtx` | Event log viewer |


### AntiVirus logs

| Filesystem | Location |
| --- | --- |
| Avast | `C:\ProgramData\Avast Software\` |
| AVG | `C:\ProgramData\AVG\Antivirus\` |
| Avira | `C:\ProgramData\Avira\Antivirus\LOGFILES\` | 
| Bitdefender | `C:\Program Files*\Bitdefender*\` | 
| ESET | `C:\ProgramData\ESET\ESET NOD32 Antivirus\Logs\` | 
| F-Secure | `C:\ProgramData\F-Secure\Log\` or `C:\Users\%user%\AppData\Local\F-Secure\Log\`   | 
| McAfee |`C:\ProgramData\McAfee\*`  | 
| Sophos | `C:\ProgramData\Sophos\Sophos *\Logs\` | 
| Trend Micro | `C:\ProgramData\Trend Micro\` or `C:\Program Files*\Trend Micro\` |
| Symantec | `C:\ProgramData\Symantec\` or `C:\Users\%user%\AppData\Local\Symantec\` |
| WinDefender | `C:\ProgramData\Microsoft\Windows Defender\*` or `C:\ProgramData\Microsoft\Microsoft AntiMalware\Support\` or MpCmdRun.log |

Another good reference: https://ruler-project.github.io/ruler-project/RULER/av/

## Other Artifacts

| Filesystem | Location | Tools or Commands |
| --- | --- | --- |
| Task Scheduler | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` or `\Windows\Tasks` or `Windows\System32\Tasks` | Registry Explorer |
| Startup folder | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` | Autopsy |
| Startup folder user | `C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` | Autopsy |
| Shadow copy | - | Shadow Explorer |
| hiberfil.sys | `C:\` | Hibernation Recon |
| pagefile.sys | `C:\` | strings |
| Unalloc file | - | Autopsy |
| Anydesk | `C:\Users\%user%\AppData\Roaming\AnyDesk\*` or `C:\ProgramData\AnyDesk\*` | Autopsy |
| WMI persistence | `C:\WINDOWS\system32\wbem\Repository\OBJECTS.DATA` | WMI_Forensics |
| WMI persistence | `C:\WINDOWS\system32\wbem\Repository\FS\OBJECTS.DATA` | WMI_Forensics |
| RDP Cache | `C:\%USERPROFILE%\AppData/Local/Microsoft/Terminal Server Client/Cache` | BMC-Tools |

## Other
- Command to parse all registry in a folder using Regripper
```
cd folder_containing_all_registries
for /r %i in (*) do (C:\RegRipper3.0\rip.exe -r %i -a > %i.txt)
```
- USB usage also can be investigate using "USB Detective Community Edition"
- Nirsoft software might have a good tool for viewing your artifacts
- Reghunter command on the live system: `reg_hunter --all -z --outfile reg_hunter_result.txt`

# Lateral Movement Detection and Investigation
Detail information refer: https://jpcertcc.github.io/ToolAnalysisResultSheet/#

Typically lateral movement will involve with (depend on the attacker TTP):
1. Credential harvesting
2. File sharing
3. Remote login
4. AD enumeration
5. Remote execution
6. Pass-the-hash/ticket
7. Privilege Escalation
8. Golden/Silver Ticket
9. User creation
10. Deleting evidence

Below list shows the sum up of the information in the above reference but focusing only on standard setting and configuration of Windows.

## 1. Credential harvesting
- Analysts can rely on the Prefetch, MFT, USNJartifact for standard settings on the host computer.
- Various password dump tools that utilize PowerShell can be found in:
    - `Microsoft-Windows-PowerShell/Operational`
    - `C:\Users\[User Name]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

## 2. File sharing
### Windows Admin share (net use)
Commonly for transfering their tools and malware. Or can be abuse for exfiltrate data.

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| SMBClient-Security | 31001 | Source |
| Security | 4624, 4672, 4776, 4768, 4769, 5140, 5145 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\net.EXE-RANDOM.pf` and `C:\Windows\Prefetch\net1.EXE-RANDOM.pf`| Source |
| Jumplist | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` | Source |
| USNJ or MFT | Created file | Source |

| Registry | Findings | Computer |
| --- | --- | --- |
| User Profile (NTUSER.DAT) | `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Source |
| USRCLASS.dat | Shellbags (Remote folders accessed) | Source |
| Shimcache (SYSTEM) | `net.exe` and `net1.exe` | Source |
| BAM/DAM (SYSTEM) | Last time executed `net.exe` and `net1.exe` | Source |
| Amcache.hve | First Execution time of `net.exe` and `net1.exe` | Source |

## 3. Remote login
Attacker might utilizes the remote login feature such as RDP, VNC, external software or SSH to login remotely

### RDP

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| RDPClient Operational | 1024, 1025, 1026, 1102 | Source |
| Security |  4624 (logon type 10 or 12), 4778, 4779 | Destination |
| RDPCoreTS Operational | 131, 98, 99 | Destination |
| RemoteConnection Manager Operational | 1149 | Destination |
| RemoteConnection Manager Admin | 1158 | Destination |
| LocalSession Manager Operational | 21, 23, 24, 25, 41 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\MSTSC.EXE-RANDOM.pf` | Source |
| Jumplist | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` (MSTSC-APPID-automaticDestinations-ms) | Source |
| Bitmap Cache | `C:\Users\USERNAME\AppData\Local\Microsoft\Terminal Server Client\Cache\*` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\rdpclip.exe-RANDOM.pf` and `C:\Windows\Prefetch\tstheme.exe-RANDOM.pf` | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| User Profile (NTUSER.DAT) | `NTUSER\SOFTWARE\Microsoft\Terminal Server Client\Servers` | Source |
| Shimcache (SYSTEM) | `mstsc.exe` | Source |
| BAM/DAM (SYSTEM) | Last Execution time of `mstsc.exe` | Source |
| Amcache.hve | First Execution time of `mstsc.exe` | Source |
| UserAssist (NTUSER.dat) | Last Execution time and Numbers of Times of `mstsc.exe` | Source |
| RecentApps (NTUSER.DAT) | Last Execution time and Numbers of Times of `mstsc.exe` | Source |
| ShimCache (SYSTEM) | `rdpclip.exe` and `tstheme.exe` | Destination |
| AmCache.hve | `rdpclip.exe` and `tstheme.exe` | Destination |

### Remote tools software
- Check for any installation, files of remote tools or services
- List of remote administaration tool can be refer here: https://ruler-project.github.io/ruler-project/RULER/remote/ and https://docs.google.com/spreadsheets/d/1G_pJ1H2yJeoLUnki6kibujUJ9445M_2hRTEm3kUCf0M
- Identify the software installed and running processes. Oftenly it has agent running.
- Investigate the logs.

### SSH

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4624,4625,4688, 5154 | Destination |
| System | 10016 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[SSH executable].exe-RANDOM.pf` | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| User Profile (NTUSER.DAT) | `Software\SimonTatham\PuTTY\SshHostKeys` | Destination |

## Remote Execution

### Pass-The-Hash-Ticket (WCE)

| Event Log | Event ID | Computer |
|---|---|---|
| System | 7045, 7036 (WCESERVICE) | Source |
| Security | 4624, 4634 | Destination |
| Security | 4776, 4771, 5156 | DC |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Tool name].exe-RANDOM.pf` | Source |
| USNJ | 	wceaux.dll` | Source |

### Pass-The-Hash-Ticket (Mimikatz)

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4624, 4672, 4634 | Destination |
| Security | 4776, 4771, 5156, 4769 | DC |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Tool name].exe-RANDOM.pf` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\WMIC.EXE-[RANDOM].pf` | Source |

### PsExec

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| Security | 4624 (Logon type 3 or 2), 4672, 5140 | Destination |
| System | 7045, 7036 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\[Executable File Name of Tool]-[RANDOM].pf` | Source |
| MFT, USNJ | psexec.exe executable | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\PSEXESVC.EXE-RANDOM.pf` | Destination |
| C:\Windows | `psexesvc.exe` or renamed executable | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| User Profile (NTUSER.DAT) | `NTUSER\SOFTWARE\Sysinternals\PsExec\EulaAccepted` | Source |
| Shimcache (SYSTEM) | `psexec.exe` | Source |
| BAM/DAM (SYSTEM) | Last execution time of`psexec.exe` | Source |
| Amcache.hve | First Execution time of `psexec.exe` | Source |
| SYSTEM | `SYSTEM\CurrentControlSet\Services\PSEXESVC` | Destination |
| Shimcache (SYSTEM) | `psexecsvc.exe` | Destination |
| Amcache.hve | First Execution time of `psexecsvc.exe` | Destination |

Memory analysis, find this pipe in the processes:
```
\\X.X.X.X\pipe\PSEXESVC-<sourcehostname>-<PID>-stdin
\\X.X.X.X\pipe\PSEXESVC-<sourcehostname>-<PID>-stdout
\\X.X.X.X\pipe\PSEXESVC-<sourcehostname>-<PID>-stderr
```

### Remote Services

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4624 (Logon type 3), 4697 | Destination |
| System | 7034, 7035, 7036, 7040, 7045 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\sc.exe-RANDOM.pf` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-RANDOM.pf` | Destination |
| File disk | Creation of evil.exe or dll | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| BAM/DAM (SYSTEM) | `sc.exe` | Source |
| Shimcache (SYSTEM) | `sc.exe` | Source |
| Amcache.hve | First Execution time of `sc.exe` | Source |
| SYSTEM | `\CurrentControlSet\Services\` | Destination |
| Shimcache (SYSTEM) | `evil.exe` | Destination |
| Amcache.hve | First Execution time of `evil.exe` | Destination |

### Scheduled Task

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| Security | 4672, 4624, 4698, 4702, 4699, 4700, 4701 | Destination |
| Task scheduler Operational | 106, 140, 141, 200, 201 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\SCHTASKS.EXE-[RANDOM].pf` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\at.EXE-[RANDOM].pf` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\TASKENG.EXE-[RANDOM].pf` | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.EXE-[RANDOM].pf` | Destination |
| Job files | `C:\Windows\Tasks` | Destination |
| Task files | `C:\Wmdows\System32\Tasks` | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| BAM/DAM (SYSTEM) | `at.exe` and `schtasks.exe` | Source |
| Shimcache (SYSTEM) | `at.exe` and `schtasks.exe`  | Source |
| Amcache.hve | `at.exe` and `schtasks.exe`  | Source |
| Shimcache (SYSTEM) | `evil.exe` | Destination |
| Amcache.hve | First Execution time of `evil.exe` | Destination |
| SYSTEM | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\*` | Destination |

### WMIC

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| Security | 4624, 4672 | Destination |
| WMI Activity Operational | 5857,5860,5861 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\WMIC.EXE-[RANDOM].pf` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-[RANDOM].pf` | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\scrcons.exe-[RANDOM].pf` | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\mofcomp.exe-[RANDOM].pf` | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\wmiprvse.exe-[RANDOM].pf` | Destination |
| WMI repository | `C:\Windows\System32\wbem\Repository` | Destination |
| File creation | `evil.exe` or `evil.mof` | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| Shimcache (SYSTEM) | `Wmic.exe` | Source |
| BAM/DAM (SYSTEM) | `Wmic.exe` | Source |
| Amcache.hve | First Execution time of `Wmic.exe` | Source |
| ShimCache (SYSTEM) | `scrcons.exe`, `mofcomp.exe`, `wmiprvse.exe`, `evil.exe` | Destination |
| AmCache.hve | `scrcons.exe`, `mofcomp.exe`, `wmiprvse.exe`, `evil.exe` | Destination |

### WinRM and Powershell

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4648 | Source |
| WinRM Operational | 6,8,15,16,33 | Source |
| Powershell Operational | 40691, 40692, 8193, 8194, 8197 | Source |
| Security | 4624, 4672 | Destination |
| Powershell Operational | 4103, 4104, 53504 | Destination |
| Powershell | 400, 403, 800 | Destination |
| WinRM | 91, 168 | Destination |

| Filesystem | Location | Computer |
| --- | --- |--- |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\powershell.exe-RANDOM.pf` | Source |
| Conmand history | `C:\Users\USERNAME\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` | Source |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\evil.exe-RANDOM.pf` | Destination |
| Prefetch, MFT, USNJ | `C:\Windows\Prefetch\wsmprovhost.exe-RANDOM.pf` | Destination |

| Registry | Findings | Computer |
| --- | --- | --- |
| Shimcache (SYSTEM) | `Powershell.exe` | Source |
| BAM/DAM (SYSTEM) | `Powershell.exe` | Source |
| Amcache.hve | First Execution time of `Powershell.exe` | Source |
| ShimCache (SYSTEM) | `wsmprovhost.exe` and `evil.exe` | Destination |
| SOFTWARE | `Microsoft\PowerShell\1\ShellIds\Microsoft.Powershell\ExecutionPolicy` | Destination |
| AmCache.hve | `wsmprovhost.exe` and `evil.exe` | Destination |

### SMB

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4688,4624,4656,5140,5142,5143,5144,5145 | Source |
| SMB Server Operational | 4100,4103,4104,800,4104,40961,40962 | Source |

### DCOM

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4624,4662, 4688, 4697, 4698, 4702 | Destination |

### File Transfer

| Event Log | Event ID | Computer |
|---|---|---|
| Security | 4688 | Destination |
| Microsoft-Windows-PowerShell/ Operational | 4103, 4104 | Destination |

### Impacket
