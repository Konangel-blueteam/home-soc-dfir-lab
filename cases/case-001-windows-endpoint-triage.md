# Case 001: Windows Endpoint Security Log Triage

**Case ID:** CASE-001  
**Investigation Type:** Endpoint log review and file verification  
**Status:** Preliminary analysis completed; documentation in progress  
**Environment:** Windows 11  
**Tools:** Windows Event Viewer, PowerShell

## 1. Objective

Review selected Windows Security events, examine process-creation information, and verify the digital signature and SHA-256 hash of a Windows system executable.

The objective is to practice a structured SOC/DFIR investigation workflow, not to presume that an incident has occurred.

## 2. Scope

The investigation covered:

- Successful logon events (Event ID 4624)
- Failed logon events (Event ID 4625)
- Process-creation events (Event ID 4688)
- Authenticode signature verification
- SHA-256 file hashing
- Preliminary event-timeline documentation

## 3. Methodology

1. Opened Windows Event Viewer and reviewed the Security log.
2. Filtered for Event ID 4624 and examined the available logon details.
3. Filtered for Event ID 4625 and checked whether matching events were present in the reviewed records.
4. Examined Event ID 4688 and recorded available process-creation details.
5. Used PowerShell `Get-AuthenticodeSignature` to check the signature status of `C:\Windows\System32\lsass.exe`.
6. Used PowerShell `Get-FileHash` with the SHA-256 algorithm to calculate the file hash.
7. Began documenting observations in a case timeline.

## 4. Observations

### 4.1 Successful logon — Event ID 4624

A reviewed event showed **Logon Type 5**, which corresponds to a service logon. The event details subsequently reviewed identified the target account as `SYSTEM`.

A service logon is not, by itself, evidence of suspicious activity. The event should be interpreted in its system and service context.

### 4.2 Failed logon — Event ID 4625

No matching events were returned by the filter during the reviewed check.

This does not establish that failed logons never occurred. The result is limited to the records available and the filtering performed.

### 4.3 Process creation — Event ID 4688

A reviewed event contained the following process details in the General view:

- **New process:** `C:\Windows\System32\lsass.exe`
- **Creator process:** `C:\Windows\System32\wininit.exe`
- **New process ID:** `0x518`
- **Creator process ID:** `0x470`

These details are consistent with a process relationship that can occur during normal Windows startup. However, the event alone is insufficient to establish that the activity was malicious or to prove the full context of the process.

### 4.4 File signature verification

PowerShell `Get-AuthenticodeSignature` returned **Status: Valid** for `C:\Windows\System32\lsass.exe`.

A valid signature supports the authenticity of the signed file under the applicable signature-verification checks. It does not, by itself, prove that the system is free from compromise.

### 4.5 SHA-256 hashing

PowerShell `Get-FileHash` was used to calculate the SHA-256 hash of the executable.

The hash value is retained in the local working notes and is not reproduced in this public case summary. A hash can support file identification and integrity comparisons, but a hash value alone does not determine whether a file is malicious.

## 5. Preliminary Assessment

The reviewed records and checks did not, on their own, establish a confirmed security incident.

The service logon, process relationship, and valid signature require contextual interpretation rather than automatic classification as malicious. The absence of matching 4625 events in the reviewed filter is a limited observation, not proof that no failed logons occurred.

## 6. Limitations

- The review covered selected events rather than a complete forensic acquisition.
- The absence of 4625 matches is limited to the available records and selected filter.
- The complete event XML and surrounding event sequence have not been documented in this public summary.
- The time zone and precise timestamp interpretation have not yet been independently confirmed.
- The signature and hash checks do not independently establish whether the endpoint is compromised.
- No Wazuh SIEM deployment or detection validation is claimed in this case.

## 7. Next Steps

- Complete the local event timeline with exact timestamps and relevant event fields.
- Preserve the relevant event records and hash output in the private working directory.
- Review surrounding events and verify the process details against additional context.
- Document the lab architecture and plan the next stage of SIEM telemetry collection.
- Add sanitized screenshots after reviewing them for usernames, machine identifiers, paths, and other private details.

## 8. Conclusion

This exercise provided practical experience reviewing Windows Security events, interpreting logon and process-creation details, checking an executable's Authenticode signature, and calculating a SHA-256 hash.

The available observations do not justify declaring a confirmed incident. Further contextual review would be required before making stronger conclusions.

---

**Disclaimer:** This case study is for educational and defensive cybersecurity training. It summarizes selected local lab observations and does not claim to represent a complete forensic investigation.

### Controlled Process-Lineage Validation

**Objective:** Validate process relationships using Windows Security Event ID 4688.

**Methodology:**
- Generated a controlled PowerShell-to-Notepad process-launch scenario.
- Examined process-creation events in the Windows Security log.
- Correlated `NewProcessId`, creator `ProcessId`, executable paths, and UTC timestamps.

**Key observations:**
- The PowerShell event recorded PID `0x6db0`.
- A subsequent Notepad process candidate recorded PID `0x44b8`, with creator PID `0x6db0`.
- A further Notepad process recorded PID `0x507c`, with creator PID `0x44b8`.
- The timestamps were chronologically consistent with the observed process relationships.

**Assessment:** The available Event ID 4688 records support the PowerShell-to-Notepad process lineage observed during the controlled test. The Explorer-to-PowerShell relationship was not independently verified.

**Limitations:** Process-creation telemetry establishes recorded process relationships, not malicious intent. PID reuse and incomplete event coverage must be considered during investigation.

**Outcome:** Controlled process-lineage validation completed with a documented limitation. No malicious activity was established by these events alone.


## Windows Service Configuration and Executable Verification

### Objective

Inspect selected Windows services to understand their configuration, execution context, and executable authenticity indicators.

### 1. Windows Update Service — `wuauserv`

**Observed configuration:**
- Service name: `wuauserv`
- Status: Stopped
- Startup type: Manual
- Executable configuration: `svchost.exe -k netsvcs -p`

**Forensic interpretation:**

The service was stopped and configured for Manual startup at the time of inspection. This configuration alone does not indicate malicious activity.

### 2. Microsoft Defender Antivirus Service — `WinDefend`

**Observed configuration:**
- Service name: `WinDefend`
- Status: Running
- Startup mode: Automatic
- Service account: LocalSystem
- Executable: `MsMpEng.exe`

**Executable path:**

```text
C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe
```

**Forensic interpretation:**

The service was running under the highly privileged LocalSystem account. This is consistent with the requirements of a Windows security service. However, privileged execution alone does not establish whether a service is legitimate or malicious.

### 3. Digital Signature Verification

The executable's Properties window was inspected through the Digital Signatures tab.

**Observed results:**
- Signer: Microsoft Windows Publisher
- Signature verification: This digital signature is OK

**Forensic interpretation:**

Windows reported the digital signature as valid. This supports the authenticity of the signed executable but does not independently establish that the process or the host system is free from compromise.

### 4. SHA-256 Hash Calculation

The executable's SHA-256 hash was calculated using PowerShell.

**Command:**

```powershell
Get-FileHash "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe" -Algorithm SHA256
```

**Observed SHA-256:**

```text
0365D64D786E4C8EBB34C0F6FB017441B0A34C866D9E6E5673D00C5BFED56AFB
```

The hash provides a reproducible cryptographic fingerprint of the inspected file at the time of examination. It has not been independently compared against a trusted reference database.

### 5. Forensic Assessment

The observed service configuration, executable location, and successful digital signature verification are consistent with a legitimate Microsoft Defender installation.

However, executable authenticity and runtime behaviour are separate investigative dimensions.

A valid digital signature does not guarantee that a process is behaving benignly. Further investigation may be required if unusual process activity, unexpected network connections, or suspicious service configurations are identified.

### 6. Investigation Limitations

- The SHA-256 hash was calculated but not independently reputation-checked.
- No network traffic analysis was performed as part of this exercise.
- No conclusion regarding the overall security state of the host was established.
- Findings represent observations from the inspected system at the time of examination.

**Outcome:** Completed a practical examination of Windows service configuration, execution context, executable location, digital signature verification, and cryptographic hash calculation.


## Windows Service-to-Process Correlation

### Objective

Correlate a Windows service with its associated runtime process and examine whether historical process creation records are available for verification.

### Observations

**Windows Update (`wuauserv`)**
- Service state: Stopped
- Process ID: 0
- Configured executable: `C:\WINDOWS\system32\svchost.exe -k netsvcs -p`

A Process ID of 0 was returned because the service was stopped during inspection. Its configured executable path does not establish that the process was running.

**Microsoft Defender Antivirus (`WinDefend`)**
- Service state: Running
- Process ID: 5644
- Runtime process: `MsMpEng.exe`
- Parent Process ID reported by Windows: 1276
- Parent process currently associated with PID 1276: `services.exe`
- Process creation timestamp: 19 November 2026, 23:43:37

The service PID and runtime process PID matched, supporting the correlation between `WinDefend` and `MsMpEng.exe`.

The process executable path and `Get-Process` start time were not returned by the respective queries. However, CIM returned the process creation timestamp and parent PID.

### Historical Event Correlation

An attempt was made to locate Event ID 4688 for PID `0x160C` (decimal 5644) around the reported process creation time.

No matching events were returned for the period 19 November 2026, 23:40–23:47.

The oldest retained Event ID 4688 record identified during inspection was dated 24 November 2026, 19:29:23.

### Security Log Configuration

The Security log configuration was inspected using `wevtutil gl Security`.

- Maximum log size: 20 MiB
- Retention: Disabled (`false`)
- Automatic backup: Disabled (`false`)
- Logging: Enabled

With retention disabled, older events may be overwritten when the configured log reaches capacity. This configuration is consistent with the absence of older records, but does not independently establish why the 19 November event is unavailable.

### Forensic Assessment

The investigation established a current service-to-process correlation for Microsoft Defender Antivirus.

The reported parent PID is consistent with `services.exe` at the time of inspection, but the historical parent-child relationship has not been independently corroborated using a retained Event ID 4688 record.

The missing historical event limits retrospective process-lineage verification. The available evidence does not establish malicious activity.

### Limitations

- Current PID associations do not independently prove historical process relationships.
- Process IDs may be reused.
- The process executable path was not returned by the process queries.
- Historical Event ID 4688 coverage for 19 November could not be established.
- The Security log's retention configuration may contribute to missing historical records, but the precise cause remains unverified.


## Windows Service Registry and DLL Verification

### Objective

Examine Windows service registry configurations and verify the configured service DLL associated with the Windows Update service.

### 1. Registry Configuration Analysis

The following Windows service registry keys were examined:

- `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`
- `HKLM\SYSTEM\CurrentControlSet\Services\wuauserv`

**Microsoft Defender Antivirus (WinDefend)**

- Startup configuration: Automatic (`2`)
- Service type: Own Process (`16` / `0x10`)
- Service account: LocalSystem
- Configured executable: `MsMpEng.exe`

**Windows Update (wuauserv)**

- Startup configuration: Manual (`3`)
- Service type: Share Process (`32` / `0x20`)
- Service account: LocalSystem
- Configured executable: `svchost.exe -k netsvcs -p`

The registry values were consistent with the service properties previously collected through Windows CIM queries.

### 2. Windows Update Service DLL Identification

The following registry subkey was inspected:

`HKLM\SYSTEM\CurrentControlSet\Services\wuauserv\Parameters`

The configured `ServiceDll` was:

`C:\Windows\System32\wuaueng.dll`

This DLL is associated with the Windows Update service.

### 3. Digital Signature Verification

The DLL was examined using PowerShell Authenticode signature verification.

- Signature status: Valid
- Signer: Microsoft Windows
- Publisher: Microsoft Corporation
- Verification result: Signature verified

The result supports the authenticity of the signed file. However, a valid signature alone does not establish that the host system is uncompromised or that the service is behaving benignly.

### 4. SHA-256 Hash Calculation

A SHA-256 hash was calculated to establish a file identification value.

**File:** `wuaueng.dll`

**Algorithm:** SHA-256

**SHA-256:**
```text
68EB32EADA15FCC24FA9D06AD856DD40FC99D00FB1F2C2635D443F1EA885BE5E
```

The hash was recorded for identification and potential future comparison. It was not independently compared against a trusted reference.

### 5. Forensic Assessment

The inspected registry configuration matched the previously collected CIM service configuration.

The Windows Update service was configured to use `wuaueng.dll`, and the DLL returned a valid Microsoft Windows digital signature.

No suspicious configuration discrepancy was identified within the examined properties.

### 6. Investigation Limitations

- Registry configuration does not independently establish runtime behaviour.
- A valid digital signature does not guarantee that a system is free from compromise.
- The SHA-256 hash was calculated but not independently reputation-checked.
- The investigation covered selected service properties and one configured service DLL; it does not represent a complete Windows persistence assessment.


## Service Control Manager Event Analysis (Event ID 7040)

### Objective

To examine Windows Service Control Manager (SCM) events for service startup configuration changes and assess whether the observed activity requires further investigation.

### 1. Event Collection

Queried the Windows System event log for the following event IDs:

- **7036:** Service entered a running or stopped state.
- **7040:** Service startup type was changed.
- **7045:** A new service was installed.

The query returned multiple Event ID 7040 records involving:

- Background Intelligent Transfer Service (BITS)
- Windows Modules Installer (TrustedInstaller)
- IsolationSession

Repeated startup-type changes were observed across the collected records.

### 2. Event 7040 Analysis

A representative Event ID 7040 record was examined in XML format.

**Observed event details:**

- Provider: Service Control Manager
- Event ID: 7040
- Event level: Information
- Service: IsolationSession
- Previous startup type: Automatic
- New startup type: Demand Start
- Timestamp: 24 November 2026, 19:03:28 IST
- Event record ID: 140679
- Security context: LocalSystem (S-1-5-18)

The event confirms that the startup configuration of the identified service changed from Automatic to Demand Start.

### 3. Current Service Configuration Verification

The current service configuration was collected using the Windows CIM interface.

**Observed configuration:**

- **BITS**
  - State: Running
  - Startup mode: Automatic
  - Service account: LocalSystem

- **IsolationSession**
  - State: Stopped
  - Startup mode: Manual
  - Service account: LocalSystem

- **TrustedInstaller**
  - State: Stopped
  - Startup mode: Manual
  - Service account: LocalSystem

These values represent the configuration at the time of collection. They do not independently establish the service's historical state.

### 4. Execution Process Correlation

The Event 7040 XML contained an execution Process ID of 1276.

A current process lookup identified PID 1276 as:

- Process name: `services.exe`

However, the process start-time field was unavailable during verification.

Therefore, the current process lookup cannot conclusively establish the historical identity of PID 1276 at the time the event was generated.

The event's LocalSystem security context also does not identify the specific application, component, or human responsible for initiating the configuration change.

### 5. Forensic Assessment

The collected records establish that multiple Windows services experienced startup-type changes during the examined period.

Repeated service configuration changes can warrant investigation because service configuration is relevant to persistence and system administration. However, legitimate Windows servicing, updates, maintenance operations, and security software may also modify service startup settings.

No malicious activity can be concluded from Event ID 7040 alone.

The observed activity should therefore be treated as an investigative lead rather than a confirmed security incident.

### 6. Investigation Limitations

- The available event records do not independently identify the initiating application or human operator.
- The current process lookup does not conclusively establish historical PID ownership.
- Current service configurations may differ from their historical configurations.
- The examined event records do not establish malicious intent.
- Additional corroborating evidence would be required before attributing the changes to suspicious activity.

### 7. Conclusion

Windows Service Control Manager events were examined to identify and interpret service startup configuration changes.

Event ID 7040 provided evidence of an IsolationSession startup-type modification from Automatic to Demand Start. Current service configuration and process information were also examined to add context.

The investigation demonstrates how Windows System logs, CIM-based service inspection, and process correlation can be combined during endpoint forensic triage while maintaining appropriate evidentiary limitations.


