# Threat Hunt Report: Helpdesk Deception
**Participant:** Joarder Rashid  
**Date:** November 2025

---

## Platforms and Languages Leveraged
- Log Analytics Workspaces (Microsoft Azure)  
- Kusto Query Language (KQL)

---

## Scenario
In early October 2025, several **intern and employee machines** in the Helpdesk department began showing suspicious behavior. Multiple systems executed programs directly from their **Downloads** directories — an abnormal pattern for enterprise devices. These executables shared similar names such as *desk*, *help*, *support*, and *tool*, indicating a deceptive “Helpdesk Utility” lure designed to trick users into running malicious files.

The investigation aimed to **identify the initial point of compromise**, **analyze attacker behavior across stages**, and **eradicate persistence mechanisms** used to maintain access within the environment.

---

## High-Level IoC Discovery Plan
- Check **DeviceProcessEvents** to identify the suspicious machine, execution chain, and reconnaissance activity.  
- Check **DeviceFileEvents** to locate tampering, artifact creation, and planted narrative files.  
- Check **DeviceNetworkEvents** to track outbound communication and exfiltration attempts.

---

## Starting Point
The issue began in the first half of October. Using DeviceProcessEvents, we searched for any executables launched from the Downloads folder that contained helpdesk-related keywords.  
This helped pinpoint the most suspicious endpoint for deeper investigation.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where ProcessCommandLine contains "Download"
| where ProcessCommandLine matches regex @"(?i)(desk|help|support|tool).*\.exe"
Question: Identify the most suspicious machine based on the given conditions.
Answer: gab-intern-vm

🚩 1. Initial Execution Detection
Once the suspicious host was identified, we searched for the first instance of PowerShell execution to determine when malicious code first ran.

kql
Copy code
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-16))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "powershell"
| project TimeGenerated, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
Question: What was the first CLI parameter name used during execution?
Answer: -ExecutionPolicy

🚩 2. Defense Disabling
We then checked if any tampering attempts occurred on the compromised host by searching for files referencing tamper.

kql
Copy code
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName matches regex @"(?i)(tamper)"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath
| order by TimeGenerated asc
Question: What was the name of the file related to this exploit?
Answer: DefenderTamperArtifact.lnk

🚩 3. Quick Data Probe
Next, we looked for commands that accessed clipboard data — a common quick-data theft tactic.

kql
Copy code
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "powershell"
| where ProcessCommandLine contains "clip"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
Question: Provide the command value tied to this exploit.
Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

🚩 4. Host Context Recon
We searched for reconnaissance commands used to enumerate user sessions.

kql
Copy code
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
Question: Point out when the last recon attempt occurred.
Answer: 2025-10-09T12:51:44.3425653Z

🚩 5. Storage Surface Mapping
After session recon, the attacker enumerated available drives and shares.

kql
Copy code
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where tolower(ProcessCommandLine) has_any ("net share", "net view", "dir /s", "Get-Volume", "Get-SmbShare", "wmic", "fsutil fsinfo drives", "Get-CimInstance -ClassName Win32_LogicalDisk")
| project TimeGenerated, DeviceName, AccountName, FolderPath, ProcessCommandLine
| order by TimeGenerated asc
Question: Provide the 2nd command tied to this activity.
Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size

🚩 6. Connectivity & Name Resolution Check
We verified whether the attacker tested external connectivity using common diagnostic commands.

kql
Copy code
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("ping", "nslookup", "tracert")
| where FileName contains "cmd" or FileName contains "powershell"
| where IsProcessRemoteSession == "true"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
Question: Provide the File Name of the initiating parent process.
Answer: RuntimeBroker.exe

🚩 7. Interactive Session Discovery
We inspected any attempts to query active user sessions.

kql
Copy code
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessUniqueId
Question: What is the unique ID of the initiating process?
Answer: 2533274790397065

🚩 8. Runtime Application Inventory
Question: Provide the file name of the process that best demonstrates a runtime process enumeration event.
Answer: tasklist.exe

🚩 9. Privilege Surface Check
We searched for privilege enumeration attempts using whoami.

kql
Copy code
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "whoami"
| order by TimeGenerated asc
| take 1
Question: Identify the timestamp of the first attempt.
Answer: 2025-10-09T12:52:14.3135459Z

🚩 10. Proof-of-Access & Egress Validation
We checked for outbound connections made by the malicious process to confirm network reachability.

kql
Copy code
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteUrl
| order by TimeGenerated asc
Question: Which outbound destination was contacted first?
Answer: www.msftconnecttest.com

🚩 11. Bundling / Staging Artifacts
We analyzed file operations for evidence of data staging or compression.

kql
Copy code
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName has_any ("zip")
| order by TimeGenerated asc
Question: Provide the full folder path where the artifact was first dropped.
Answer: C:\Users\Public\ReconArtifacts.zip

🚩 12. Outbound Transfer Attempt (Simulated)
We identified simulated outbound data transfer attempts following artifact creation.

kql
Copy code
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl
| order by TimeGenerated desc
Question: Provide the IP of the last unusual outbound connection.
Answer: 100.29.147.161

🚩 13. Scheduled Re-Execution Persistence
We looked for creation of persistence mechanisms through scheduled tasks.

kql
Copy code
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessParentFileName contains "runtimebroker.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc
Question: Provide the value of the task name.
Answer: SupportToolUpdater

🚩 14. Autorun Fallback Persistence
Question: What was the name of the registry value associated with autorun persistence?
Answer: RemoteAssistUpdater

🚩 15. Planted Narrative / Cover Artifact
The attacker left behind a fake helpdesk log file to disguise their actions as legitimate support work.

kql
Copy code
DeviceFileEvents
| where TimeGenerated > (todatetime('2025-10-09T13:01:29.7815532Z'))
| where DeviceName == "gab-intern-vm"
| order by TimeGenerated asc
Question: Identify the file name of the artifact left behind.
Answer: SupportChat_log.lnk

Summary Table
Flag	Description	Value
Start	Suspicious Machine	gab-intern-vm
1	1st CLI parameter used in execution	-ExecutionPolicy
2	File related to exploit	DefenderTamperArtifact.lnk
3	Exploit command value	"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard
4	Last recon attempt	2025-10-09T12:51:44.3425653Z
5	2nd command tied to mapping	"cmd.exe" /c wmic logicaldisk get name,freespace,size
6	Initiating parent process	RuntimeBroker.exe
7	Process unique ID	2533274790397065
8	Process inventory	tasklist.exe
9	Privilege-check timestamp	2025-10-09T12:52:14.3135459Z
10	1st outbound destination	www.msftconnecttest.com
11	Artifact path	C:\Users\Public\ReconArtifacts.zip
12	Unusual outbound IP	100.29.147.161
13	Scheduled task name	SupportToolUpdater
14	Registry value name	RemoteAssistUpdater
15	Artifact left behind	SupportChat_log.lnk

Report Completed By: Joarder Rashid
Status: ✅ All 15 flags investigated and confirmed
