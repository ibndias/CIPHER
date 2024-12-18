* Findings: The target IP is 10.10.11.236, Action: running nmap with command `nmap -p- --min-rate 10000 10.10.11.236`, Reasoning: to discover open ports on the target, Result: found multiple open ports including 53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 5985, and 9389.

* Findings: The target is a Windows host, Action: running nmap with command `nmap -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389 -sCV 10.10.11.236`, Reasoning: to gather service version information on the open ports, Result: identified services such as Microsoft IIS 10.0 on port 80 and Microsoft SQL Server on port 1433.

* Findings: The hostname is dc01 in the domain manager.htb, Action: analyzing nmap output, Reasoning: to understand the network structure and identify the role of the host, Result: concluded that the host is likely a Windows domain controller.

* Findings: MSSQL database server is exposed on port 1433, Action: noting the presence of the database, Reasoning: to explore potential access points for further exploitation, Result: identified that credentials would be needed to connect.

* Findings: WinRM is open on port 5985, Action: recognizing the potential for remote command execution, Reasoning: if valid credentials are found, it could provide a shell, Result: noted this as a potential attack vector.

* Findings: The web server on port 80 is a static site for a content writing service, Action: accessing the site and analyzing its content, Reasoning: to identify any vulnerabilities or points of interest, Result: found a contact form that does not submit data correctly.

* Findings: The web server is running IIS, Action: checking HTTP response headers, Reasoning: to gather more information about the server configuration, Result: confirmed it is a static site with standard IIS headers.

* Findings: No interesting directories were found during directory brute forcing, Action: running `feroxbuster` against the site, Reasoning: to discover hidden files or directories, Result: found no additional useful endpoints.

* Findings: SMB service is running on port 445, Action: using `netexec` to check SMB details, Reasoning: to gather information about the SMB configuration and shares, Result: confirmed the host is a Windows 10/Server 2019 machine.

* Findings: Attempted to enumerate SMB shares without credentials, Action: running `netexec smb 10.10.11.236 --shares`, Reasoning: to see if any shares are accessible, Result: received an error indicating no shares could be listed.

* Findings: Null authentication is allowed on SMB, Action: trying a RID cycling attack using `lookupsid.py`, Reasoning: to enumerate users by brute-forcing SIDs, Result: successfully retrieved a list of users including administrator and other accounts.

* Findings: A list of users was generated from the RID cycling, Action: processing the output to create a clean list of usernames, Reasoning: to prepare for potential credential guessing or further enumeration, Result: compiled a list of usernames including administrator, guest, and several others.
* Findings: The target domain is manager.htb, Action: Brute forcing Windows user security identifiers (SIDs) using `lookupsid.py`, Reasoning: To enumerate users in the domain without needing a password, Result: Retrieved a list of users including Administrator, Guest, and several others.

* Findings: The output from `lookupsid.py` includes user SIDs and types, Action: Extracting usernames from the output using Bash commands, Reasoning: To create a clean list of usernames for further enumeration, Result: Generated a list of usernames: administrator, guest, krbtgt, dc01$, zhong, cheng, ryan, raven, jinwoo, chinhae, operator.

* Findings: The guest account is available, Action: Using `netexec` with the guest account to perform RID cycling, Reasoning: To enumerate users without needing a password, Result: Successfully enumerated users and groups similar to the previous step.

* Findings: The LDAP service is running on TCP 389, Action: Using `ldapsearch` to confirm the base domain name, Reasoning: To verify the LDAP structure and domain context, Result: Confirmed the naming contexts for the domain.

* Findings: LDAP queries require authentication, Action: Attempting to query LDAP without credentials, Reasoning: To check for access permissions, Result: Received an error indicating a successful bind is required.

* Findings: Kerberos is available on TCP 88, Action: Using `kerbrute` to brute force usernames, Reasoning: To find valid usernames for authentication, Result: Found valid usernames: administrator, guest, and operator.

* Findings: The operator account is valid, Action: Checking if any usernames use their username as their password with `netexec`, Reasoning: To quickly identify weak passwords, Result: Discovered that the operator account uses the password 'operator'.

* Findings: The operator account credentials are valid for SMB, Action: Attempting to connect to the target using the operator credentials, Reasoning: To gain access to shares and further enumerate the system, Result: Successfully connected to SMB shares.

* Findings: The shares on the target are standard DC shares, Action: Enumerating SMB shares with `netexec`, Reasoning: To identify accessible shares and their permissions, Result: Listed shares including ADMIN$, C$, IPC$, NETLOGON, and SYSVOL.

* Findings: The operator account has LDAP access, Action: Connecting to LDAP with operator credentials, Reasoning: To gather more information about the domain, Result: Successfully connected to LDAP.

* Findings: Using `ldapdomaindump` to gather domain information, Action: Dumping LDAP data to a more viewable format, Reasoning: To analyze user and group information easily, Result: Generated multiple HTML and JSON files containing domain data.

* Findings: The `domain_users_by_group.html` file provides an overview of users, Action: Reviewing the file for potential targets, Reasoning: To identify users with higher privileges or interesting roles, Result: Identified Raven as a target for further exploitation.

* Findings: The operator credentials work for MSSQL, Action: Connecting to the MSSQL database using `mssqlclient.py`, Reasoning: To explore the database for potential vulnerabilities or sensitive information, Result: Successfully connected to the MSSQL server.

* Findings: The MSSQL server has four default databases, Action: Querying the databases using `select name from master..sysdatabases`, Reasoning: To identify the databases available for enumeration, Result: Listed the default databases: master, tempdb, model, msdb.

* Findings: The operator account lacks permissions for `xp_cmdshell`, Action: Attempting to execute `xp_cmdshell` commands, Reasoning: To check for command execution capabilities, Result: Received permission denied errors.

* Findings: The `xp_dirtree` command is available, Action: Using `xp_dirtree` to list files on the filesystem, Reasoning: To gather information about the file structure on the server, Result: Successfully executed the command and retrieved directory listings.
* Findings: The `enum_db` command shows the databases and their trustworthiness status, Action: queried `enum_db`, Reasoning: to check the trustworthiness of the databases, Result: `msdb` is trustworthy while others are not.

* Findings: The `xp_cmdshell` feature is disabled for the operator user, Action: attempted to run `xp_cmdshell whoami`, Reasoning: to check if the command shell is accessible, Result: received an error indicating permission denial.

* Findings: The `xp_dirtree` command is accessible and can list directories, Action: executed `xp_dirtree C:\`, Reasoning: to explore the filesystem for interesting directories, Result: listed several directories including `C:\Users`.

* Findings: The `C:\Users` directory contains a user named `Raven`, Action: executed `xp_dirtree C:\inetpub\wwwroot`, Reasoning: to check the web root for interesting files, Result: found a backup zip file named `website-backup-27-07-23-old.zip`.

* Findings: The backup zip file is accessible, Action: downloaded the backup zip file using `wget`, Reasoning: to analyze the contents for sensitive information, Result: successfully downloaded the zip file.

* Findings: The backup zip file contains an XML configuration file with LDAP credentials, Action: extracted the zip file, Reasoning: to inspect its contents for sensitive data, Result: found LDAP configuration with the username `raven@manager.htb` and password `R4v3nBe5tD3veloP3r!123`.

* Findings: The user `raven` is part of the Remote Management Users group, Action: used `netexec` to check WinRM access, Reasoning: to see if `raven` can connect via WinRM, Result: confirmed that `raven` can connect to WinRM.

* Findings: Successfully connected to WinRM as `raven`, Action: used `evil-winrm` to establish a shell, Reasoning: to gain command line access to the target system, Result: obtained a shell as `raven`.

* Findings: The `user.txt` file is present on `raven`'s desktop, Action: executed `type user.txt`, Reasoning: to retrieve the user flag, Result: successfully retrieved the user flag.

* Findings: `raven` has Manage CA permissions, Action: used `certipy` to find vulnerable certificate templates, Reasoning: to check for potential privilege escalation paths, Result: identified that `raven` has dangerous permissions (ESC7).

* Findings: `raven` can add themselves as a Manage Certificates officer, Action: executed `certipy ca -add-officer raven`, Reasoning: to escalate privileges by gaining Manage Certificates access, Result: successfully added `raven` as an officer.

* Findings: `raven` now has Manage Certificates permissions, Action: requested a certificate using the SubCA template, Reasoning: to obtain a certificate for the administrator account, Result: received an error indicating template denial.

* Findings: The request for a certificate failed but saved the private key, Action: used `certipy ca -issue-request` to issue the request, Reasoning: to bypass the template denial using Manage CA permissions, Result: successfully issued the certificate.

* Findings: The issued certificate can be retrieved, Action: executed `certipy req -retrieve`, Reasoning: to obtain the issued certificate for the administrator, Result: successfully retrieved the certificate and saved it.

* Findings: The certificate can be used to retrieve the NTLM hash for the administrator, Action: executed `certipy auth -pfx administrator.pfx`, Reasoning: to obtain the administrator's NTLM hash, Result: successfully retrieved the NTLM hash.

* Findings: The NTLM hash for the administrator is available, Action: used `evil-winrm` to connect as administrator using the hash, Reasoning: to gain elevated privileges on the system, Result: obtained a shell as administrator.

* Findings: The `root.txt` file is present on the administrator's desktop, Action: executed `type root.txt`, Reasoning: to retrieve the root flag, Result: successfully retrieved the root flag.
