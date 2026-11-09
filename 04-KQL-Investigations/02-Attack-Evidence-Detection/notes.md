# X. Attack → Evidence → Detection

The following table can be used as a lab worksheet to understand what evidence to investigate for each attack simulation.

| Simulation | Primary Event | What Students Investigate |
|---|---|---|
| Failed login | 4625 | Account, source IP, frequency |
| Successful login | 4624 | User, source, logon type |
| Password spray | 4625 | Number of targeted accounts |
| Account creation | 4720 | Creator and new account |
| Admin-group modification | 4732 | Who added whom |
| Privileged logon | 4672 | Privileges and account |
| Process execution | 4688 / Sysmon 1 | Process, parent process, and command line |
| Network activity | Sysmon 3 | Destination and process |
| File creation | Sysmon 11 | File and creating process |
| DNS | Sysmon 22 | Domain and process |
| Registry change | Sysmon 12–14 | Key, value, and process |
| Account lockout | 4740 | Account and source |
| Scheduled task | 4698 | Task and creator |
| Log clearing | 1102 | Who cleared the log |

## Important SOC Principle

Sysmon's event model is designed to provide detailed behavioral telemetry. However, Sysmon events are evidence rather than automatic alerts.

SOC analysts must use context and correlation to determine whether activity is suspicious.
