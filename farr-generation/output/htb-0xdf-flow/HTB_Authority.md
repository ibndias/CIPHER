* Findings: The target IP is 10.10.11.222, Action: Running nmap with the command `nmap -p- --min-rate 10000 10.10.11.222`, Reasoning: To discover all open ports on the target, Result: Found multiple open TCP ports including 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 8443, 9389, and several RPC ports.

* Findings: The open ports include HTTP (80) and HTTPS (8443), Action: Running a service version scan with `nmap -p 53,80,88,135,139,389,445,595,636,3268,3269,5985,8443,9389,47001,49664-49667,49673,49688,49689,49691,49692,49700,49706,49710,49730 -sCV 10.10.11.222`, Reasoning: To gather more detailed information about the services running on the open ports, Result: Identified services such as Microsoft IIS 10.0 on port 80 and various Microsoft services on other ports.

* Findings: The SMB service is running on TCP 445, Action: Using `netexec` to enumerate SMB shares with the command `netexec smb 10.10.11.222`, Reasoning: To check for accessible shares and gather information about the SMB service, Result: Found the domain name `authority.htb` and hostname `authority`, but encountered errors when trying to list shares without credentials.

* Findings: The command `netexec smb 10.10.11.222 -u oxdf -p '' --shares` was executed, Action: Attempting to list SMB shares using junk credentials, Reasoning: To see if any shares could be accessed with invalid credentials, Result: Successfully enumerated shares including `ADMIN$`, `C$`, `Department Shares`, `Development`, `IPC$`, `NETLOGON`, and `SYSVOL`.

* Findings: The `Development` share was accessible, Action: Listing the contents of the `Development` share with `smbclient -N //10.10.11.222/Development`, Reasoning: To explore the contents of the accessible share for potential sensitive information, Result: Found a directory structure under `Automation\Ansible` with subdirectories for `ADCS`, `LDAP`, `PWM`, and `SHARE`.

* Findings: The `ADCS` directory contains various files related to Ansible, Action: Listing the contents of `Automation\Ansible\ADCS`, Reasoning: To identify any potentially useful files or configurations that could aid in further exploitation, Result: Discovered files such as `README.md`, `LICENSE`, and `requirements.yml`, indicating a setup for Active Directory Certificate Services.

* Findings: The DNS service is running on TCP/UDP 53, Action: Attempting a zone transfer with `dig axfr authority.htb @10.10.11.222`, Reasoning: To gather DNS records for the domain, Result: The zone transfer failed, indicating that it is not allowed.

* Findings: The HTTP service on port 80 serves the default IIS page, Action: Accessing the site via a web browser and checking the HTTP response headers, Reasoning: To understand the web server's configuration and any potential vulnerabilities, Result: Confirmed the server is running Microsoft IIS 10.0 with no additional information provided in the headers.

* Findings: The default IIS page returned a 404 for various guessed paths, Action: Running `feroxbuster` against the site, Reasoning: To discover hidden directories or files that may not be linked from the main page, Result: The scan is initiated to identify any accessible endpoints that could be exploited.
* Findings: Active Directory Certificate Services (ADCS) is a target of interest, Action: noted as a hint for future reference, Reasoning: credentials are needed to exploit ADCS, Result: no immediate action taken.
* Findings: TCP 53 is open on the target, Action: attempted a zone transfer using `dig axfr authority.htb @10.10.11.222`, Reasoning: to gather DNS information about the domain, Result: zone transfer failed.
* Findings: Reverse lookup on the target IP did not yield useful information, Action: executed `dig -x 10.10.11.222 @10.10.11.222`, Reasoning: to gather more information about the target, Result: received a SERVFAIL status.
* Findings: Added `authority.htb` to `/etc/hosts`, Action: edited `/etc/hosts` file, Reasoning: to resolve the domain name to the target IP, Result: successful resolution of the domain.
* Findings: The website loads the default IIS page, Action: accessed the site via IP and domain name, Reasoning: to identify the web application running, Result: confirmed it is an IIS server.
* Findings: HTTP response headers indicate the server is Microsoft-IIS/10.0, Action: checked HTTP response headers, Reasoning: to gather information about the web server, Result: confirmed server type.
* Findings: Default 404 page is displayed for non-existent paths, Action: attempted to access various paths, Reasoning: to discover any hidden directories or files, Result: all attempts returned 404.
* Findings: Ran `feroxbuster` against the site, Action: executed directory brute-forcing, Reasoning: to find accessible directories or files, Result: found no additional directories.
* Findings: TCP 8443 is open, Action: accessed the PWM application, Reasoning: to explore the web application for vulnerabilities, Result: identified PWM as a password self-service application.
* Findings: PWM requires a password to access configuration options, Action: attempted to access configuration mode, Reasoning: to explore potential misconfigurations, Result: prompted for a password.
* Findings: Downloaded Ansible files from SMB share, Action: accessed the `PWM` directory via SMB, Reasoning: to gather configuration files that may contain credentials, Result: successfully downloaded several files.
* Findings: `ansible_inventory` file contains WinRM credentials, Action: examined the `ansible_inventory` file, Reasoning: to find valid credentials for accessing the target, Result: found `administrator` and `Welcome1`.
* Findings: Attempted to use the found credentials with `netexec`, Action: executed `netexec winrm authority.htb -u administrator -p 'Welcome1'`, Reasoning: to gain access to the target via WinRM, Result: authentication failed.
* Findings: `defaults/main.yml` contains encrypted passwords, Action: reviewed the file for sensitive information, Reasoning: to identify any usable credentials, Result: found encrypted values.
* Findings: Used `ansible2john.py` to format encrypted values, Action: executed the script on the vault files, Reasoning: to create hashes for cracking, Result: generated hashes for the encrypted passwords.
* Findings: Cracked the hashes using `hashcat`, Action: ran `hashcat` against the generated hashes with `rockyou.txt`, Reasoning: to recover the plaintext passwords, Result: all passwords were found to be `!@#$%^&*`.
* Findings: Decrypted the vault values using `ansible-vault`, Action: used the recovered password to decrypt the values, Reasoning: to retrieve the actual credentials, Result: obtained `DevT3st@123`, `svc_pwm`, and `pWm_@dm!N_!23`.
* Findings: Attempted to access SMB with `svc_pwm` credentials, Action: executed `netexec smb authority.htb -u svc_pwm -p 'pWm_@dm!N_!23'`, Reasoning: to check if the credentials work for SMB access, Result: authenticated but could not access shares.
* Findings: Attempted to access WinRM with `svc_pwm` credentials, Action: executed `netexec winrm authority.htb -u svc_pwm -p 'pWm_@dm!N_!23'`, Reasoning: to check if the credentials work for WinRM access, Result: authentication failed.
* Findings: Attempted to access LDAP with `svc_pwm` credentials, Action: executed `netexec ldap 10.10.11.222 -u svc_pwm -p 'pWm_@dm!N_!23'`, Reasoning: to check if the credentials work for LDAP access, Result: connection error.
* Findings: Accessed PWM configuration manager with `pWm_@dm!N_!23`, Action: logged into the PWM configuration manager, Reasoning: to explore configuration options, Result: successful login.
* Findings: Captured LDAP credentials by modifying the LDAP URL, Action: listened on port 389 and tested the LDAP profile, Reasoning: to capture cleartext credentials, Result: obtained `lDaP_1n_th3_cle4r!`.
* Findings: Used captured LDAP credentials to access SMB and WinRM, Action: executed `netexec smb authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'` and `netexec winrm authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'`, Reasoning: to gain access to the target using valid credentials, Result: successfully authenticated and gained access.
* Findings: Cached credentials are stored but not retrievable through the web GUI, Action: Edit the URL to point at the author’s machine using cleartext LDAP on port 389, Reasoning: To capture the LDAP credentials being sent in cleartext, Result: Successfully captured the credentials `CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htblDaP_1n_th3_cle4r!` with password `lDaP_1n_th3_cle4r!`.

* Findings: The captured credentials work for SMB and WinRM, Action: Use the credentials to authenticate via SMB and WinRM, Reasoning: To gain access to the target machine, Result: Successfully authenticated and gained access to the target machine `AUTHORITY` as `svc_ldap`.

* Findings: The filesystem on the target is sparse with only a few user directories, Action: Enumerate the filesystem to identify user directories, Reasoning: To locate potential targets for privilege escalation, Result: Found directories for `Administrator`, `Public`, and `svc_ldap`.

* Findings: The target has Active Directory Certificate Services (ADCS) configured, Action: Use `certipy` to find vulnerable certificate templates, Reasoning: To identify potential paths for privilege escalation through certificate abuse, Result: Found a vulnerable certificate template named `CorpVPN`.

* Findings: The `CorpVPN` template allows `Domain Computers` to enroll, Action: Create a fake computer account using `addcomputer.py`, Reasoning: To exploit the ESC1 vulnerability by enrolling a certificate as a computer account, Result: Successfully added the computer account `0xdf$`.

* Findings: The CA name is `AUTHORITY-CA`, Action: Request a certificate using the newly created computer account, Reasoning: To obtain a certificate that can be used for authentication, Result: Successfully requested a certificate and saved it as `administrator_authority.pfx`.

* Findings: The certificate cannot be used for Kerberos authentication due to KDC configuration, Action: Use `PassTheCert` to perform an LDAP shell attack, Reasoning: To gain administrative access without relying on Kerberos, Result: Connected to the LDAP shell with limited command capabilities.

* Findings: The LDAP shell allows adding users to groups, Action: Add `svc_ldap` to the `Administrators` group, Reasoning: To escalate privileges to administrative level, Result: Successfully added `svc_ldap` to the `Administrators` group.

* Findings: The `svc_ldap` account now has administrative privileges, Action: Reconnect to the target using Evil-WinRM as `svc_ldap`, Reasoning: To verify the privilege escalation and access administrative resources, Result: Gained access to the `Administrator` desktop.

* Findings: The `Administrator` desktop contains the `root.txt` flag, Action: Read the contents of `root.txt`, Reasoning: To complete the objective of the penetration test, Result: Successfully retrieved the contents of `root.txt`. 

* Findings: The fake computer account `0xdf$` has delegation rights, Action: Use `getST.py` to obtain a Silver Ticket for the `Administrator`, Reasoning: To impersonate the `Administrator` and gain further access, Result: Successfully obtained a Silver Ticket saved in `Administrator.ccache`.

* Findings: The Silver Ticket allows dumping NTLM hashes, Action: Use `secretsdump.py` with the Silver Ticket, Reasoning: To extract credentials from the domain controller, Result: Successfully dumped NTLM hashes for `Administrator`, `Guest`, `krbtgt`, `svc_ldap`, and `0xdf$`. 

* Findings: The NTLM hash for `Administrator` is available, Action: Use the hash to authenticate via Evil-WinRM, Reasoning: To gain full control over the target system, Result: Successfully authenticated as `Administrator` and gained full access to the system.
* Findings: The author has a fake computer account `0xdf$` and wants to give it delegation rights over the Domain Controller (DC), Action: running the command `python PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from '0xdf$' -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222`, Reasoning: to exploit the delegation rights and allow `0xdf$` to impersonate users on `AUTHORITY$`, Result: successfully modified delegation rights, allowing `0xdf$` to impersonate users on `AUTHORITY$` via S4U2Proxy.

* Findings: The author needs to synchronize their clock with the Domain Controller to avoid Kerberos ticket issues, Action: running `sudo ntpdate 10.10.11.222`, Reasoning: to ensure that the time is in sync with the DC for Kerberos authentication, Result: time successfully synchronized with the DC.

* Findings: The author wants to obtain a Silver Ticket for the Administrator account, Action: executing `getST.py -spn 'cifs/AUTHORITY.AUTHORITY.HTB' -impersonate Administrator 'authority.htb/0xdf$:0xdf0xdf0xdf'`, Reasoning: to impersonate the Administrator account and gain access to resources, Result: successfully obtained a Silver Ticket saved in `Administrator.ccache`.

* Findings: The author has the Silver Ticket and wants to dump NTLM hashes from the DC, Action: running `KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass authority.htb/administrator@authority.authority.htb -just-dc-ntlm`, Reasoning: to extract NTLM hashes for further exploitation, Result: successfully dumped NTLM hashes for several accounts including Administrator and `0xdf$`.

* Findings: The author has the NTLM hash for the Administrator account, Action: using Evil-WinRM to connect with the command `evil-winrm -i authority.htb -u administrator -H 6961f422924da90a6928197429eea4ed`, Reasoning: to gain remote access to the Administrator account on the target machine, Result: successfully established a remote shell as Administrator.
