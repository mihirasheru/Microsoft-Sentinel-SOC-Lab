
# Microsoft Sentinel SOC Lab

A beginner-friendly Security Operations Center (SOC) lab built using **Microsoft Sentinel, Azure, and a Windows Virtual Machine**.

This project demonstrates how security events are collected, monitored, detected, and investigated in a real-world SOC workflow. It includes controlled attack simulations, KQL-based investigations, and custom analytics rules.

---

## 1. What is Microsoft Sentinel?

**Microsoft Sentinel** is a cloud-based Security Information and Event Management (SIEM) platform provided by Microsoft Azure.

In simple terms, Sentinel helps security teams monitor systems, identify suspicious activities, and investigate potential cyberattacks.

Imagine an organization with hundreds of computers. Each computer generates logs whenever someone logs in, creates an account, runs a program, or makes a system change.

Manually checking all these logs would be difficult.

Microsoft Sentinel helps by:

- Collecting and analyzing security data.
- Identifying suspicious activities.
- Generating alerts when predefined conditions are met.
- Helping analysts investigate security incidents.
- Supporting faster security response.

It acts as a centralized monitoring platform for security teams.

## 2. What Are We Building?

In this project, we build a small SOC environment using Microsoft Azure.

We create a Windows Virtual Machine, connect it to Microsoft Sentinel, generate security events through controlled attack simulations, and investigate those events using KQL.

We also create custom detection rules to identify suspicious activities automatically.

**The main objective is to understand how a SOC analyst detects and investigates suspicious activities using security logs.**

### Project Workflow

The complete workflow looks like this:

![Microsoft Sentinel SOC Lab Architecture](./screenshots/sentinel-soc-lab-architecture.png)

In simple terms:

1. A Windows VM generates security events.
2. Azure Monitor Agent collects the events.
3. A Data Collection Rule determines which events are collected.
4. The collected logs are stored in a Log Analytics Workspace.
5. Microsoft Sentinel uses this data for security monitoring.
6. KQL queries help investigate suspicious activities.
7. Analytics rules detect predefined suspicious patterns and generate alerts.
8. A SOC analyst reviews the evidence and determines whether the activity is suspicious.

## 3. Why Are We Building This?

Understanding cybersecurity concepts is important, but a SOC analyst must also know how to work with actual security logs.

This lab provides practical experience with the following activities:

- Setting up a cloud-based SOC environment.
- Collecting Windows security events.
- Understanding Windows Event IDs.
- Simulating common attack techniques in a controlled environment.
- Investigating security events using KQL.
- Creating detection rules in Microsoft Sentinel.
- Correlating multiple events to understand a possible attack sequence.
- Understanding how security analysts identify and investigate suspicious activity.

The project focuses on the basic workflow followed by a Tier 1 SOC analyst:

**Monitor → Detect → Investigate → Analyze → Respond**

## 4. Components Used in This Project

The following components work together to make the SOC lab function.

### 4.1 Microsoft Azure

**Microsoft Azure** is Microsoft's cloud computing platform.

It provides the infrastructure and services required to build this lab.

In this project, Azure is used to create and manage:

- Resource Group
- Log Analytics Workspace
- Windows Virtual Machine
- Microsoft Sentinel

### 4.2 Resource Group

A **Resource Group** is a container used to organize related Azure resources.

Instead of managing each resource separately, we keep the resources required for this lab under one Resource Group.

Resource Group used:

`rg-soc-lab`

### 4.3 Windows Virtual Machine (VM)

A **Virtual Machine** is a computer that runs inside another physical computer or a cloud environment.

For this project, we create a Windows VM in Azure.

It acts as the system being monitored during the SOC exercises.

We use it to:

- Generate Windows security events.
- Create and manage test user accounts.
- Simulate suspicious login attempts.
- Perform controlled account and privilege modifications.
- Generate process, file, DNS, and network activity.

VM name:

`MyWindowsVM`

### 4.4 Log Analytics Workspace

A **Log Analytics Workspace** is a centralized location where collected logs are stored.

Think of it as a storage and analysis area for security logs.

In this project:

- Windows security events are sent to the workspace.
- Logs are stored in tables such as `SecurityEvent`.
- Analysts can use KQL to search and investigate the collected data.

Workspace name:

`law-soc-lab`

### 4.5 Azure Monitor Agent (AMA)

**Azure Monitor Agent (AMA)** is an agent installed on a monitored machine to collect logs and send them to Azure.

In this project:

- AMA collects Windows security events from the VM.
- It sends the collected events to the Log Analytics Workspace.
- This allows Microsoft Sentinel to use the collected data for monitoring and investigation.

Without log collection, Sentinel would not have the required event data to investigate.

### 4.6 Data Collection Rule (DCR)

A **Data Collection Rule (DCR)** defines what data should be collected, from which machines, and where that data should be sent.

Think of it as an instruction sheet for the Azure Monitor Agent.

In this project, the DCR:

- Selects the Windows VM as the data source.
- Specifies the Windows Security Events collection option.
- Sends the collected events to the Log Analytics Workspace.

DCR name:

`MySecEvtRule1`

### 4.7 Microsoft Sentinel

Microsoft Sentinel is the central security monitoring platform in this project.

It uses the logs stored in the Log Analytics Workspace to help analysts:

- Search security events.
- Identify suspicious activities.
- Create analytics rules.
- Generate security alerts.
- Investigate potential incidents.

### 4.8 Kusto Query Language (KQL)

**Kusto Query Language (KQL)** is used to search, filter, and analyze data stored in Log Analytics.

SOC analysts use KQL to investigate security events and identify suspicious patterns.

For example, the following query identifies failed login attempts:

```kql
SecurityEvent
| where EventID == 4625
```

This query searches the `SecurityEvent` table for events with Event ID `4625`, which represents a failed logon.

KQL is used throughout this project for event investigation and detection.

### 4.9 Windows Security Events

Windows generates security events whenever certain activities occur on a system.

Each event has an Event ID that helps identify the activity.

Some important Event IDs used in this project:

| Event ID | Activity |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4672 | Special privileges assigned to a logon |
| 4720 | User account created |
| 4732 | Member added to a security-enabled local group |
| 4740 | User account locked out |
| 4698 | Scheduled task created |
| 1102 | Security audit log cleared |

These events provide evidence that helps analysts understand what happened on a system.

### 4.10 Sysmon

**System Monitor (Sysmon)** is a Windows system service that records detailed information about system activity.

It provides additional telemetry that can help analysts investigate:

- Process creation.
- Network connections.
- File creation.
- DNS queries.
- Registry modifications.

Some Sysmon Event IDs used in this project:

| Sysmon Event ID | Activity |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 11 | File creation |
| 22 | DNS query |
| 12–14 | Registry events |

Sysmon events provide additional evidence for investigations. Their availability in Sentinel depends on configuring the appropriate log collection.

---

## 5. Attack Simulations Performed

After setting up the environment and verifying log collection, we perform controlled security activity simulations on the Windows VM.

The purpose is to generate events and understand how these activities appear in security logs.

The following scenarios are covered:

| No. | Simulation | What We Investigate |
|---|---|---|
| 1 | Failed Login / Brute-Force Simulation | Repeated failed authentication attempts |
| 2 | Failed Login → Successful Login | Failed attempts followed by a successful login |
| 3 | Password Spray Simulation | Attempts across multiple user accounts |
| 4 | Unauthorized Account Creation | Creation of a new local user |
| 5 | Privilege Escalation | Addition of a user to the Administrators group |
| 6 | Privileged Logon | Logons involving special privileges |
| 7 | Process Creation | Processes executed on the Windows VM |
| 8 | PowerShell Investigation | Running processes and services |
| 9 | File Creation | Creation of a test file |
| 10 | DNS Investigation | DNS queries made by the system |
| 11 | Network Connection | Outbound network connections |
| 12 | Registry Modification | Changes made to the Windows Registry |
| 13 | Account Lockout | Account lockout after repeated incorrect passwords |
| 14 | Scheduled Task Creation | Creation of a scheduled task |
| 15 | Security Log Clearing | Clearing of the Windows Security audit log |

All simulations are performed in the authorized lab environment using test accounts and controlled activities.

## 6. KQL-Based SOC Investigations

Once security events are generated, we use KQL to investigate them.

KQL helps us filter large amounts of log data and focus on relevant events.

The investigations include:

- Identifying failed and successful logins.
- Checking account creation activities.
- Investigating administrator group modifications.
- Examining privileged logons.
- Reviewing process and system activity.
- Identifying suspicious DNS and network activity.
- Constructing an incident timeline.

### Master SOC Investigation

A master investigation query is used to retrieve important events involving the lab accounts.

```kql
SecurityEvent
| where Account has "soc_"
| where EventID in (4624, 4625, 4648, 4672, 4688, 4697, 4720, 4728, 4732, 4740, 1102)
| project TimeGenerated, EventID, Computer, Account, SubjectUserName, TargetUserName, Activity
| order by TimeGenerated asc
```

This query:

- Filters events involving accounts containing `soc_`.
- Selects important security Event IDs.
- Displays relevant event details.
- Sorts events by time, from oldest to newest.

This helps an analyst construct a timeline and understand the sequence of activities.

## 7. Attack → Evidence → Detection

A SOC analyst does not identify an attack based on one event alone.

The analyst examines the available evidence and correlates related events to determine whether the activity is suspicious.

For example:

| Activity | Evidence | Investigation |
|---|---|---|
| Failed login | Event ID 4625 | Check account, source IP, and frequency |
| Successful login | Event ID 4624 | Check user, source, and logon type |
| Password spray | Event ID 4625 | Check the number of targeted accounts |
| Account creation | Event ID 4720 | Identify who created the account |
| Privilege modification | Event ID 4732 | Identify who added whom to the group |
| Process execution | Event ID 4688 / Sysmon 1 | Examine process and parent process |
| Network activity | Sysmon 3 | Check destination and process |
| File creation | Sysmon 11 | Examine the file and creating process |
| DNS activity | Sysmon 22 | Check the domain and process |
| Registry modification | Sysmon 12–14 | Examine the registry key and value |
| Account lockout | Event ID 4740 | Identify the affected account |
| Scheduled task | Event ID 4698 | Identify the task and creator |
| Log clearing | Event ID 1102 | Identify who cleared the log |

**Important:** Events provide evidence, not automatic proof of an attack. Analysts must consider context, correlate related activities, and investigate before deciding whether an event is malicious.

## 8. Creating Analytics Rules in Microsoft Sentinel

Apart from manually investigating events, SOC analysts can create rules to detect suspicious activities automatically.

An **Analytics Rule** is a detection rule that runs a query against collected log data and generates an alert when its configured conditions are met.

In this project, we create four scheduled query rules:

| Rule | Detection |
|---|---|
| SOC Lab - Multiple Failed Logins | Detects five or more failed login attempts for the same account and IP address within five minutes |
| SOC Lab - New Local Account Created | Detects new local user account creation |
| SOC Lab - Local Administrator Group Modification | Detects additions to the local Administrators group |
| SOC Lab - Security Log Cleared | Detects when the Windows Security log is cleared |

These rules help identify important security activities without requiring an analyst to manually search for every event.

The generated alerts still need to be reviewed and investigated by a SOC analyst.

## 9. What Does This Project Demonstrate?

By completing this lab, we understand how the different components of a SOC environment work together.

The project demonstrates practical knowledge of:

- Microsoft Azure resource management.
- Microsoft Sentinel setup and configuration.
- Log Analytics Workspace creation.
- Azure Monitor Agent and Data Collection Rules.
- Windows Security Event monitoring.
- Controlled attack simulations.
- Windows Event ID analysis.
- Sysmon telemetry.
- KQL-based investigations.
- Scheduled analytics rule creation.
- Incident timeline construction.
- Basic SOC detection and investigation workflows.

## 10. Repository Structure

The repository is organized into separate sections so that beginners can follow the project step by step.

```text
Microsoft-Sentinel-SOC-Lab/
│
├── README.md
│
├── 01-Azure-Environment-Setup/
│   ├── 01-Create-Resource-Group/
│   ├── 02-Log-Analytics-Workspace/
│   ├── 03-Microsoft-Sentinel/
│   └── 04-Create-Windows-VM/
│
├── 02-Log-Collection/
│   ├── 01-Sentinel-Data-Connector/
│   ├── 02-Generate-Windows-Security-Events/
│   └── 03-Verify-Log-Collection/
│
├── 03-Attack-Simulations/
│   ├── 01-Prerequisites/
│   └── 02-Attack-Scenarios/
│
├── 04-KQL-Investigations/
│   ├── 01-Master-SOC-Investigation/
│   └── 02-Attack-Evidence-Detection/
│
├── 05-Analytics-Rules/
│   └── 01-Sentinel-Analytics-Rules/
│
├── 06-Incident-Investigation/
│   └── 01-Review-Questions-and-Analysis/
│
└── screenshots/
```

Each section contains its own `notes.md` file with step-by-step instructions, commands, KQL queries, and relevant screenshots.

## 11. Getting Started

If you are new to Microsoft Sentinel, follow the repository in this order:

1. **Azure Environment Setup** – Create the Azure resources required for the lab.
2. **Log Collection** – Connect the Windows VM to Microsoft Sentinel and verify that logs are being received.
3. **Attack Simulations** – Generate controlled security events on the Windows VM.
4. **KQL Investigations** – Search and investigate the generated events.
5. **Analytics Rules** – Create rules to detect selected suspicious activities.
6. **Incident Investigation** – Correlate events, construct timelines, and recommend response actions.

You do not need prior experience with Microsoft Sentinel to follow the documentation. Basic familiarity with Windows, networking, and Azure concepts will be helpful.

## 12. Safety and Ethical Considerations

This project is intended for educational purposes and authorized security testing.

- Perform simulations only on systems you own or have permission to test.
- Use an isolated lab environment and dedicated test accounts.
- Do not use real user credentials or sensitive information.
- Avoid targeting public systems or networks.
- Take VM snapshots before performing potentially disruptive activities.
- Restore the lab environment after testing.

All activities should remain within the authorized lab environment.

---

## Final Note

This project demonstrates the basic workflow of a SOC environment using Microsoft Sentinel.

Starting with a Windows VM, we collect security logs, generate controlled security events, investigate them using KQL, and create analytics rules to detect suspicious activities.

**The goal is not just to generate security events, but to understand what happened, identify the evidence, and determine how a SOC analyst would investigate it.**
