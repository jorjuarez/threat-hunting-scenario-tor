<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jorjuarez/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

**Initial Discovery -** An investigation was initiated to address concerns about unauthorized TOR usage. Used the following KQL query to hunt for file events related to "tor" or "firefox," which led to the initial discovery on z-travelagent  (see Appendix A).

**Query used to locate events - Appendix A:**

```kql
let target_device = "z-travelagent";
let target_terms = dynamic(["tor", "firefox"]);
DeviceFileEvents
| where TimeGenerated between (datetime(2025-06-24T20:01:23.612868Z) .. datetime(2025-06-24T20:30:03.9246195Z)) //2025-06-24 3:01:23 PM CDT and 2025-06-24 3:30:03 PM CDT
| where DeviceName == target_device
| where InitiatingProcessCommandLine has_any (target_terms) or FileName has_any (target_terms)
| project TimeGenerated, DeviceName, AdditionalFields, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256
| sort by TimeGenerated asc
```
![image](https://github.com/user-attachments/assets/76a5fe0e-18bb-48c6-94cf-2df83798fb03)

---

### 2. Searched the `DeviceProcessEvents` Table

**Process Tree Analysis -** The process execution history on z-travelagent was analyzed to determine the origin of the TOR installation. This confirmed the installer was launched by the Command Prompt (cmd.exe), which was manually launched by the user (see Appendix B).

**Query used to locate event - Appendix B**

```kql

let target_device = "z-travelagent";
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-06-24T20:03:20.0014546Z) // 2025-06-24 3:03:20 PM CDT
| where DeviceName == target_device
| where FileName has "tor-browser-windows"
| where InitiatingProcessFileName =~ "cmd.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName

```
![image](https://github.com/user-attachments/assets/c7e2b5d0-6974-4aee-a880-d5a21ca73393)

---

### 3. Searched the `DeviceNetworkEvents` Table

**Network Event Reconstruction -** A focused query was used to reconstruct the timeline of all network activity from the TOR Browser on z-travelagent , verifying successful connections to the C2-like domains (see Appendix C).

**Query used to locate events - Appendix C**

```kql
let target_device = "z-travelagent";
let target_terms = dynamic(["tor", "firefox"]);
DeviceNetworkEvents
| where TimeGenerated between (todatetime('2025-06-24T20:03:54.6867011Z') .. todatetime('2025-06-24T20:31:07.7209084Z'))
| where DeviceName == target_device
| where InitiatingProcessCommandLine has_any (target_terms)
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteUrl,LocalPort ,RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```
![image](https://github.com/user-attachments/assets/16b111cb-f03e-45d4-90ce-e7455f517557)


---

### 4. Searched the `DeviceFileEvents` Table 

**Content Analysis -** Further investigation revealed the creation of a suspicious text file named "tor-shopping-list.txt" and its associated shortcut (.lnk) file on the user's desktop, indicating the user's intent or activities while using the unauthorized software (see Appendix D)

**Query used to locate events - Appendix D**

```kql
let target_device = "z-travelagent";
let target_files = dynamic(["tor-shopping-list.txt", "tor-shopping-list.lnk"]);
DeviceFileEvents
| where TimeGenerated between (datetime(2025-06-24T20:28:46.000Z) .. datetime(2025-06-24T20:28:47.000Z)) // Central Time: 2025-06-24 3:28:46 PM CDT
| where DeviceName == target_device
| where FileName has_any (target_files)
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName,AdditionalFields, SHA256
| sort by TimeGenerated asc
```
![image](https://github.com/user-attachments/assets/7f19a399-3909-42f7-b879-3f50eea0bdc8)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **June 24, 2025**, 3:01:23 PM CST (UTC: 20:01:23.612868Z): The TOR browser installer (**tor-browser-windows-x86_64-portable-14.5.4.exe**) was downloaded via Microsoft Edge to **C:\Users\Analyst1\Downloads\.**

### 2. TOR Installer Execution

- **June 24, 2025**, 3:03:20 PM CST (UTC: 20:03:20.0014546Z): The downloaded installer was executed silently via Command Prompt **(cmd.exe)** with the command **tor-browser-windows-x86_64-portable-14.5.4.exe /S**, resulting in the installation of Tor Browser files on the user's Desktop.

### 3. TOR Browser First Launch

- **June 24, 2025**, 3:03:54 PM CST (UTC: 20:03:54.6867011Z): The TOR Browser application **(firefox.exe)** was launched for the first time.

### 4. TOR Browser Suspicious Network Connections

- **June 24, 2025**, 3:04:13 PM CST (onward) (UTC: from 20:04:13.000Z): The TOR Browser initiated connections to suspicious, DGA-like domains, specifically **www[.]77yi3yrudvnyxnxc42fdsnm[.]com** and **www[.]sucamq2[.]com**.

### 5. Suspicious File Creation - **'tor-shopping-list.txt'**

- **June 24, 2025**, 3:28:46 PM CST (UTC: 20:28:46.5955992Z): A Notepad file named **tor-shopping-list.txt** was manually created and saved to **C:\Users\Analyst1\Desktop\.**

---

## Summary

The investigation confirmed unauthorized TOR Browser installation and use by "Analyst1" on workstation "z-travelagent". Evidence indicates deliberate, manual installation via the command line and subsequent use for connections to suspicious, C2-like domains. This constituted a high-priority security incident, which led to the immediate isolation of "z-travelagent" from the network.

---

## Response Taken

Confirmed TOR usage on endpoint z-travelagent. The device was immediately isolated via Microsoft Defender for Endpoint (MDE), and the investigation's findings were communicated to the user's direct manager.

---
