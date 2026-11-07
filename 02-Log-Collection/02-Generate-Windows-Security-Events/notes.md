# VI. Generate Windows Security Events and Verify That Sentinel Is Receiving Them

1. Go to **Virtual Machines**.

2. Open `MyWindowsVM` → **Connect** → **RDP** → **Download RDP file**.

3. Open the downloaded `.rdp` file on your PC and connect using the username and password created for the VM.

4. You should now be connected to the VM as `azureuser`.

   ![Screenshot 13](../../screenshots/13.png)

5. Open **Command Prompt as Administrator**. Create four SOC users and one SOC admin user using:

   ```cmd
   net user <username> "<password>" /add
   ```

6. Verify that the users were created:

   ```cmd
   net user
   ```

   To check an individual user:

   ```cmd
   net user soc_user01
   ```

7. View the available local groups:

   ```cmd
   net localgroup
   ```

8. Add `soc_admin01` to the Administrators group:

   ```cmd
   net localgroup Administrators soc_admin01 /add
   ```

9. Verify that `soc_admin01` was added successfully:

   ```cmd
   net localgroup Administrators
   ```

   ![Screenshot 14](../../screenshots/14.png)

10. Open **Event Viewer** from the Windows search bar.

11. Go to **Windows Logs → Security**.

12. Look for **Event ID 4732**. This event is generated when a member is added to a security-enabled local group.

13. Right-click the event and select **Event Properties** to view its details.

    ![Screenshot 15](../../screenshots/15.png)

14. Open Command Prompt as Administrator. Add the SOC users to the Remote Desktop Users group:

    ```cmd
    net localgroup "Remote Desktop Users" soc_user01 /add
    ```

    Repeat this for all users, including `soc_admin01`.

15. Verify that the users were added successfully:

    ```cmd
    net localgroup "Remote Desktop Users"
    ```

    This allows the accounts to connect to the Windows VM through Remote Desktop.

    ![Screenshot 16](../../screenshots/16.png)

16. Close the current Remote Desktop session.

17. Open Remote Desktop / Windows App again.

18. Select **Use another account** and enter:

    - **Username:** `soc_user01`
    - **Password:** The password created for `soc_user01`

    ![Screenshot 17](../../screenshots/17.png)

19. After connecting, open **Microsoft Sentinel → law-soc-lab → Logs**.

20. Switch from **Simple Mode** to **KQL Mode**.

21. Run the following query to verify that Windows Security events are being received:

    ```kql
    SecurityEvent
    | take 10
    ```

    This displays 10 Windows Security events collected from the VM.

    ![Screenshot 18](../../screenshots/18.png)

22. To verify the Event ID 4732 generated earlier, run:

    ```kql
    SecurityEvent
    | where EventID == 4732
    | order by TimeGenerated desc
    ```

    This displays recent events where a user was added to a local security-enabled group.

    ![Screenshot 19](../../screenshots/19.png)

23. To verify the successful login made using `soc_user01`, run:

    ```kql
    SecurityEvent
    | where EventID == 4624
    | order by TimeGenerated desc
    ```

    Event ID 4624 represents a successful logon.

    ![Screenshot 20](../../screenshots/20.png)

**Next screenshot:** `21.png`.
