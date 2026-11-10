
# XII. Review Questions and Analysis

## 1a. Identify and explain the purpose and availability of the Microsoft Sentinel, Log Analytics Workspace, Azure Monitor Agent (AMA), Data Collection Rule, and KQL tools used in the SOC attack simulation. Explain how each tool supports security monitoring and ethical security investigation. (CO1)

**Answer:**

The following tools work together to collect, analyze, and investigate security events in a SOC environment.

- **Microsoft Sentinel:** A cloud-based SIEM solution that detects threats, generates alerts, investigates incidents, and supports security response.
- **Log Analytics Workspace:** Stores collected security logs and allows analysts to search and investigate events.
- **Azure Monitor Agent (AMA):** Collects security events from the Windows virtual machine and sends them to the Log Analytics Workspace.
- **Data Collection Rule (DCR):** Specifies which events should be collected and where the collected data should be sent.
- **Kusto Query Language (KQL):** Queries and analyzes security logs to identify suspicious activities, such as failed logins and unauthorized account changes.

**How they support security monitoring:**

AMA collects events according to the DCR, and the events are stored in the Log Analytics Workspace. Analysts use KQL to investigate the data, while Microsoft Sentinel uses detection rules to generate alerts.

**Ethical investigation:**

These tools help students simulate attacks in an authorized, isolated lab, examine the resulting events, and understand how security incidents are detected without affecting real users or systems.

## 1b. From the simulated authentication failures, password-spray activity, account creation, and privilege modification events, discuss the business and security implications of these activities and explain how Microsoft Sentinel can support security policies for protecting organizational accounts and resources. (CO2)

**Answer:**

The simulated activities can indicate attempts to gain unauthorized access or misuse system privileges.

- **Authentication failures:** Repeated failed logins may indicate password guessing or brute-force attempts.
- **Password spraying:** An attacker tries common passwords against multiple accounts to avoid triggering account-specific lockout thresholds.
- **Account creation:** Unauthorized accounts may allow attackers to maintain access to a system.
- **Privilege modification:** Adding an unauthorized user to an administrator group may give them access to sensitive data and system settings.

**Business and security implications:**

These activities can cause data theft, financial loss, service disruption, privacy violations, and reputational damage. Unauthorized administrator access can also allow attackers to change security settings or create additional accounts.

**Role of Microsoft Sentinel:**

- Detects repeated failed logins and suspicious account activity.
- Generates alerts for account creation and privilege changes.
- Helps analysts investigate related events and identify possible attacks.
- Supports security policies such as strong passwords, multi-factor authentication (MFA), least privilege, and regular account monitoring.

Thus, Microsoft Sentinel helps organizations identify potential threats and respond before further damage occurs.

## 1c. Develop suitable detection logic and investigation metrics in Microsoft Sentinel for the simulated security activities. Explain how the selected policies, thresholds, and correlation rules help distinguish normal activity from potentially malicious behavior. (CO3)

**Answer:**

Microsoft Sentinel uses KQL detection queries to identify suspicious activities in collected Windows security logs.

**1. Multiple failed logins — Event ID 4625**

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

This query detects five or more failed login attempts for the same account and IP address within a five-minute interval.

**2. New account creation — Event ID 4720**

```kql
SecurityEvent
| where EventID == 4720
```

This identifies events associated with new user account creation.

**3. User added to Administrators — Event ID 4732**

```kql
SecurityEvent
| where EventID == 4732
| where TargetUserName =~ "Administrators"
```

This identifies additions to the local Administrators group when the recorded group name matches.

**4. Security log cleared — Event ID 1102**

```kql
SecurityEvent
| where EventID == 1102
```

This detects events indicating that the Windows Security audit log was cleared.

**Investigation metrics:**

- Number and frequency of failed logins.
- Source IP address and targeted account.
- Time of account creation.
- Users added to administrator groups.
- Time at which the Security log was cleared.

**Role of thresholds and correlation:**

A threshold of five failed logins within five minutes helps identify unusual authentication activity. Correlating events using timestamps, account names, host names, and source IP addresses helps analysts identify related activities.

These rules must be adjusted to the organization's normal activity. Legitimate users may also generate failed logins, and legitimate administrators may create accounts. Therefore, alerts require investigation before being classified as malicious.

## 1d. Analyze the security risks and potential dangers associated with conducting controlled penetration-testing activities such as password spraying, account creation, privilege modification, process execution, and network/DNS activity, and explain the precautions required to perform them safely in an isolated environment. (CO4)

**Answer:**

Controlled penetration testing helps identify security weaknesses, but improper testing can affect system availability, confidentiality, and integrity.

**Security risks:**

1. **Password spraying:** May cause account lockouts or unauthorized access if a password is guessed correctly.
2. **Account creation:** Unauthorized accounts may provide attackers with continued access.
3. **Privilege modification:** Excessive privileges may expose sensitive information or allow unwanted system changes.
4. **Process execution:** Unknown or malicious programs may damage files, alter configurations, or compromise the VM.
5. **Network and DNS activity:** Excessive traffic or incorrect configurations may disrupt connectivity or affect systems outside the lab.

**Precautions for safe testing:**

- Obtain authorization before performing tests.
- Use isolated virtual machines and a dedicated lab network.
- Use test accounts and non-sensitive data.
- Take VM snapshots before testing so the system can be restored.
- Limit authentication attempts and network traffic.
- Monitor security logs during the exercises.
- Avoid targeting public systems or devices outside the authorized environment.
- Restore the lab to a clean state after testing.

These precautions reduce the risk of data loss, service disruption, and unauthorized access while ensuring that testing remains safe and ethical.

## 1e. Interpret the security telemetry generated during the simulation using KQL. Correlate the events to construct an incident timeline, identify the affected host and account, determine the likely attack sequence, and recommend an appropriate response action based on the investigation findings. (CO5)

**Answer:**

Security telemetry from the Windows VM can be investigated using KQL in the Log Analytics Workspace.

**1. Query security events**

```kql
SecurityEvent
| where EventID in (4624, 4625, 4720, 4732, 1102)
| project TimeGenerated, EventID, Computer, Account, SubjectUserName, TargetUserName, Activity
| order by TimeGenerated asc
```

This query retrieves selected login, account creation, administrator group modification, and Security log-clearing events in chronological order.

**2. Construct an incident timeline**

The analyst examines event timestamps to understand the sequence of activities. For example:

- Repeated failed logins may indicate password guessing.
- A successful login shortly afterward may require investigation.
- A new account or administrator group modification may indicate an attempt to establish access or increase privileges.
- A cleared Security log may indicate an attempt to remove evidence.

This is a possible attack sequence, not proof that the events are connected.

**3. Identify the affected host and account**

The `Computer` field identifies the host that recorded the event. Fields such as `Account`, `SubjectUserName`, and `TargetUserName` help identify the initiating user and the account affected. The available fields vary by event type.

**4. Correlate the events**

Compare timestamps, host names, account names, and source IP addresses where available. Check whether multiple suspicious events involve the same host or account. This helps determine whether the events may be part of a single incident.

**5. Recommend response actions**

- Investigate suspicious login attempts and source IP addresses.
- Reset compromised credentials and revoke active sessions when necessary.
- Disable unauthorized accounts.
- Remove unauthorized administrator privileges.
- Preserve relevant logs and investigate suspicious processes.
- Document findings and improve detection rules.

**Conclusion:**

KQL-based investigation helps analysts build an incident timeline, identify affected systems and accounts, assess possible attack activity, and recommend suitable response actions.

