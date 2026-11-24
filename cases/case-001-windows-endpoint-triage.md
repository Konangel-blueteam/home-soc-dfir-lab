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



