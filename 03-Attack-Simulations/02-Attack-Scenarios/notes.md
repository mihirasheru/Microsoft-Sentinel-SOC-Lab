# VIII. Attack Simulations

### 1. Failed Login / Brute-Force Simulation

- Open Remote Desktop / Windows App and connect to MyWindowsVM.
- At the Windows login screen, select Use another account.
- Enter:
  - Username: `soc_user01`
- Enter an intentionally incorrect password:
  - WrongPassword@123
- Click Sign in.
- Repeat the failed login approximately 5 times.
- The expected event is **4625 — An account failed to log on.**

**MS Sentinel**

- Open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID == 4625
  | where Account has "soc_"
  | project TimeGenerated, Computer, Account, IpAddress, LogonType, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 35](../../screenshots/35.png)

- To detect 5 or more failed attempts within 5 minutes, run:

  ```kql
  SecurityEvent
  | where EventID == 4625
  | summarize FailedAttempts=count() by Account, IpAddress, bin(TimeGenerated, 5m)
  | where FailedAttempts >= 5
  | order by TimeGenerated desc
  ```

  ![Screenshot 36](../../screenshots/36.png)

This identifies a potential brute-force activity when the same account has 5 or more failures within a 5-minute window. This is a detection hypothesis requiring investigation. It’s not an attack.

### 2. Failed Login → Successful Login

- After generating the failed login attempts, connect to MyWindowsVM again.
- Log in using:
  - Username: `soc_user01`
  - Enter the correct password for soc_user01.
- Open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID in (4624, 4625)
  | where Account has "soc_"
  | project TimeGenerated, EventID, Computer, Account, IpAddress, LogonType, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 37](../../screenshots/37.png)

- Check the timeline of events. You see a sequence similar to:

  | Event ID | Status |
  |---|---|
  | 4625 | Failed |
  | 4625 | Failed |
  | 4625 | Failed |
  | 4625 | Failed |
  | 4624 | Successful |

- This lets you investigate a failed-login sequence followed by a successful login.

### 3. Password Spray Simulation

- Open the Windows login interface.
- Attempt to log in using:
  - `soc_user01`
  - `soc_user02`
  - `soc_user03`
  - `soc_user04`
- Use the same deliberately incorrect password for each account as WrongPassword@123.

- The concept being demonstrated is:
  - Brute Force: One account → Many passwords
  - Password Spray: One password → Many accounts

  ![Screenshot 38](../../screenshots/38.png)

   (do the same with other users too)

- Then open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ![Screenshot 39](../../screenshots/39.png) 

- Check the TargetAccounts value.
- dcount(Account) counts the number of distinct accounts targeted.

### 4. Unauthorized Account Creation

- Open Command Prompt as Administrator.
- Create a temporary test account:

  ```cmd
  net user soc_test01 "LabTest@123" /add
  ```
 ![Screenshot 40](../../screenshots/40.png) 

- This should generate **Event ID 4720 — User account created.**
- Open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID == 4720
  | project TimeGenerated, Computer, SubjectUserName, TargetUserName, Account, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 41](../../screenshots/41.png)

- Then SOC Investigates: Who created soc_test01?

### 5. Privilege Escalation

- Open Command Prompt as Administrator.
- Add the standard user soc_user01 to the local Administrators group:

  ```cmd
  net localgroup Administrators soc_user01 /add
  ```

  ![Screenshot 42](../../screenshots/42.png)

- This should generate **Event ID 4732 — Member added to a security-enabled local group.**

**MS Sentinel**

- Open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID == 4732
  | project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 43](../../screenshots/43.png)

- Investigate: Why was a standard account added to the local Administrators group?

### 6. Privileged Logon

- Log out of the Windows VM.
- Log in using:
  - Username: `soc_user01`
- Since soc_user01 was added to the Administrators group in the previous attack, this is now a privileged account.
- Open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID == 4672
  | where Account has "soc_"
  | project TimeGenerated, Computer, Account, SubjectUserName, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 44](../../screenshots/44.png)

Event 4672 indicates that special privileges were assigned to a new logon.

### 7. Process Creation

- Download Sysmon, extract it into C:\ folder.
- Open PowerShell as Administrator.
- Type the command:
  - `cd C:/`
  - `.\Sysmon64.exe -i`
  - Click Agree

 ![Screenshot 45](../../screenshots/45.png)
    
- Check whether Sysmon is running:

  ```powershell
  Get-Service Sysmon64
  ```

  ![Screenshot 46](../../screenshots/46.png)

- Check recent Sysmon events:

  ```powershell
  Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
  ```

  ![Screenshot 47](../../screenshots/47.png)

- Generate harmless process activity:
  - `notepad.exe`
  - `whoami`
  - `ipconfig`

  ![Screenshot 48](../../screenshots/48.png)

- Then:

  ```powershell
  Get-Process
  ```

![Screenshot 49](../../screenshots/49.png)

- Search specifically for Sysmon Process Creation events:

  ```powershell
  Get-WinEvent -FilterHashtable @{
      LogName='Microsoft-Windows-Sysmon/Operational'
      Id=1
  } -MaxEvents 20
  ```
  ![Screenshot 50](../../screenshots/50.png)

- Sysmon Event ID 1 records process creation.

### 8. PowerShell Investigation

- Open PowerShell.
- Run:
  - `Get-Process`

  ![Screenshot 51](../../screenshots/51.png)
 
  - `Get-Service`
 
  ![Screenshot 52](../../screenshots/52.png)
    
- Investigate the corresponding process telemetry in Sysmon/Sentinel.

### 9. File Creation

- Open PowerShell.
- Create a temporary directory:
  - `New-Item C:\Temp -ItemType Directory -Force`

    ![Screenshot 53](../../screenshots/53.png)
  
- Create a test file:
  - `"Sentinel SOC Lab Test" | Out-File C:\Temp\soc-test.txt`
 
  ![Screenshot 54](../../screenshots/54.png)

- This generates file-creation activity. Sysmon Event ID 11 records file creation/overwrite activity.

**MS Sentinel**

- Verify locally using:

  ```powershell
  Get-WinEvent -FilterHashtable @{
      LogName='Microsoft-Windows-Sysmon/Operational'
      Id=11
  } -MaxEvents 20
  ```
  ![Screenshot 55](../../screenshots/55.png)

- Investigate: Which process created the file, under which account, and where?

### 10. DNS Investigation

- Open PowerShell.
- Run:
  - `nslookup example.com`

    ![Screenshot 56](../../screenshots/56.png)
  
- This generates DNS query activity.
- Sysmon Event ID 22 records DNS query activity.

**MS Sentinel**

- Then look for the DNS event:

  ```powershell
  Get-WinEvent -FilterHashtable @{
      LogName='Microsoft-Windows-Sysmon/Operational'
      Id=22
  } -MaxEvents 20
  ```

  ![Screenshot 57](../../screenshots/57.png)

- Result: nslookup successfully resolved example.com, and Sysmon Event ID 22 confirmed that the DNS query was recorded. This demonstrates basic DNS monitoring and investigation using Sysmon.

### 11. Network Connection

- Open PowerShell.
- Run the following benign connection test:
  - `Test-NetConnection example.com -Port 443`
 
  ![Screenshot 58](../../screenshots/58.png)

- This tests connectivity to example.com on TCP port 443.
- Verify if the network activity was recorded:

  ```powershell
  Get-WinEvent -FilterHashtable @{
      LogName='Microsoft-Windows-Sysmon/Operational'
      Id=3
  } -MaxEvents 10
  ```

  ![Screenshot 59](../../screenshots/59.png)

- Sysmon Event ID 3 can record network connections when it is enabled in the Sysmon configuration.

### 12. Registry Modification

- Open Command Prompt.
- Create a dedicated test registry key:
  - `reg add HKCU\Software\SOC-Lab /v TestValue /t REG_SZ /d "SentinelDemo" /f`

    ![Screenshot 60](../../screenshots/60.png)

- Meaning of the above command:

  ![Screenshot 61](../../screenshots/61.png)
  
- This creates/modifies a registry value under the current user's registry hive.
- Sysmon Event IDs 12–14 cover registry activity.
- Verify:

  ![Screenshot 62](../../screenshots/62.png)

### 13. Account Lockout

- Use a lab account only.

  Username: `soc_test01`

  Password: enter wrong password

- Generate enough incorrect authentication attempts to trigger the configured Windows account-lockout policy. (10-11 wrong password attempts)

![Screenshot 63](../../screenshots/63.png)

![Screenshot 64](../../screenshots/64.png)
  
- After the account is locked, open Microsoft Sentinel → law-soc-lab → Logs.
- Run:

  ```kql
  SecurityEvent
  | where EventID == 4740
  | where Account has "soc_"
  | project TimeGenerated, Computer, Account, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 65](../../screenshots/65.png)

- Event 4740 represents an account lockout.

### 14. Scheduled Task

- Open Poweshell as Administrator.
- Create a harmless scheduled task:
  - `schtasks /create /sc once /tn "SOC-Lab-Test" /tr "notepad.exe" /st 23:59`

  ![Screenshot 66](../../screenshots/66.png)

- This creates a scheduled task named SOC-Lab-Test that is configured to run notepad.exe.
- Open Microsoft Sentinel → law-soc-lab → Logs.
- Search for:

  ```kql
  SecurityEvent
  | where EventID == 4698
  | project TimeGenerated, Computer, SubjectUserName, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 67](../../screenshots/67.png)

- Event 4698 represents scheduled-task creation.

**MS Sentinel**

- After the demonstration, delete the test task:
  - `schtasks /delete /tn "SOC-Lab-Test" /f`

  ![Screenshot 68](../../screenshots/68.png)

### 15. Security Log Clearing

- Perform this only on your isolated lab VM.
- The objective is to demonstrate that an attempt to clear the Windows Security log can itself generate a security event.
- Open PowerShell as Administrator.
- Run:
  - `wevtutil cl Security`

  ![Screenshot 69](../../screenshots/69.png)

- Check locally for Event 1102, using the command:

  ```powershell
  Get-WinEvent -FilterHashtable @{
      LogName='Security'
      Id=1102
  } -MaxEvents 5 | Format-List TimeCreated, Id, Message
  ```
  ![Screenshot 70](../../screenshots/70.png)

- After performing the lab demonstration, open Microsoft Sentinel → law-soc-lab → Logs.
- Search for:

  ```kql
  SecurityEvent
  | where EventID == 1102
  | project TimeGenerated, Computer, SubjectUserName, Activity
  | order by TimeGenerated desc
  ```

  ![Screenshot 71](../../screenshots/71.png)

- Event 1102 indicates that the Security audit log was cleared.

