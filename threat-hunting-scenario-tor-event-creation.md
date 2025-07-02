# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - Current Dread Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion```
   - Dark Markets Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumyeudtha62s4oaowwm7ifmnunz3khs4sllhvinphfm4nirfcqd.onion```
6. Create a folder on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
Appendix: KQL Queries


Appendix A: Initial Discovery Query for a Target Host


let target_device = "z-travelagent";
let target_terms = dynamic(["tor", "firefox"]);
DeviceFileEvents
| where TimeGenerated between (datetime(2025-06-24T20:01:23.612868Z) .. datetime(2025-06-24T20:30:03.9246195Z)) //2025-06-24 3:01:23 PM CDT and 2025-06-24 3:30:03 PM CDT
| where DeviceName == target_device
| where InitiatingProcessCommandLine has_any (target_terms) or FileName has_any (target_terms)
| project TimeGenerated, DeviceName, AdditionalFields, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256
| sort by TimeGenerated asc

Appendix B: Process Analysis Query (Confirming Manual Launch on Host)

let target_device = "z-travelagent";
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-06-24T20:03:20.0014546Z) // 2025-06-24 3:03:20 PM CDT
| where DeviceName == target_device
| where FileName has "tor-browser-windows"
| where InitiatingProcessFileName =~ "cmd.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName

Appendix C: Network Reconstruction Query (Single Host)

let target_device = "z-travelagent";
let target_terms = dynamic(["tor", "firefox"]);
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2025-06-24T20:03:54.6867011Z') .. todatetime('2025-06-24T20:31:07.7209084Z'))
| where DeviceName == target_device
| where InitiatingProcessCommandLine has_any (target_terms)
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl,LocalPort ,RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc

Appendix D: Content Analysis Query (Tor Shopping List File)

let target_device = "z-travelagent";
let target_files = dynamic(["tor-shopping-list.txt", "tor-shopping-list.lnk"]);
DeviceFileEvents
| where TimeGenerated between (datetime(2025-06-24T20:28:46.000Z) .. datetime(2025-06-24T20:28:47.000Z)) // Central Time: 2025-06-24 3:28:46 PM CDT
| where DeviceName == target_device
| where FileName has_any (target_files)
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName,AdditionalFields, SHA256
| sort by TimeGenerated asc


```

---

## Created By:
- **Author Name**: Jorge Juarez
- **Author Contact**: https://www.linkedin.com/in/jorgejuarez1/
- **Date**: July 1, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `July 1, 2025`  | `Jorge Juarez`   
