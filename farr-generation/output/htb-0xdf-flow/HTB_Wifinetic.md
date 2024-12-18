* Findings: The target IP is 10.10.11.247, Action: running nmap with command `nmap -p- --min-rate 10000 10.10.11.247`, Reasoning: to discover open ports on the target, Result: found FTP (21), SSH (22), and DNS (53) open.

* Findings: FTP service is running vsftpd 3.0.3, Action: running nmap with command `nmap -p 21,22,53 -sCV 10.10.11.247`, Reasoning: to gather more detailed information about the services running on the open ports, Result: confirmed anonymous FTP login is allowed.

* Findings: Anonymous FTP login is allowed, Action: connecting to the FTP server using `ftp 10.10.11.247` with username "anonymous", Reasoning: to explore the files available on the FTP server, Result: successfully logged in.

* Findings: Five files are present on the FTP server, Action: listing files using `ls`, Reasoning: to see what files are available for download, Result: files `MigrateOpenWrt.txt`, `ProjectGreatMigration.pdf`, `ProjectOpenWRT.pdf`, `backup-OpenWrt-2023-07-26.tar`, and `employees_wellness.pdf` are listed.

* Findings: The files contain potentially useful information, Action: downloading all files using `mget *`, Reasoning: to analyze the contents of the files for sensitive information, Result: all files downloaded successfully.

* Findings: The file `employees_wellness.pdf` contains HR contact information, Action: reading the file, Reasoning: to gather information about employees, Result: found email `samantha.wood93@wifinetic.htb`.

* Findings: The file `ProjectGreatMigration.pdf` contains more contact information, Action: reading the file, Reasoning: to gather more employee details, Result: found email `management@wifinetic.htb`.

* Findings: The file `ProjectOpenWRT.pdf` contains a proposal with useful enumeration details, Action: reading the file, Reasoning: to understand the network infrastructure, Result: identified the use of OpenWRT.

* Findings: The file `backup-OpenWrt-2023-07-26.tar` contains configuration files, Action: extracting the contents of the tar file, Reasoning: to analyze the configuration for sensitive information, Result: found an `etc` directory with configuration files.

* Findings: The `passwd` file in the backup contains usernames, Action: reading the `passwd` file, Reasoning: to enumerate user accounts on the system, Result: identified users including `netadmin`.

* Findings: The `config` directory contains network configuration files, Action: listing files in `etc/config/`, Reasoning: to find relevant configuration details, Result: found files like `wireless` which contains WiFi credentials.

* Findings: The `wireless` configuration file contains a WiFi pre-shared key, Action: reading the `wireless` file, Reasoning: to obtain the WiFi password for potential access, Result: found the key `VeRyUniUqWiFIPasswrd1!`.

* Findings: The domain `wifinetic.htb` is referenced in the documents, Action: adding `10.10.11.247 wifinetic.htb` to `/etc/hosts`, Reasoning: to resolve the domain to the target IP for further enumeration, Result: able to resolve the domain.

* Findings: DNS service is running on the target, Action: attempting a zone transfer with `dig asxf @10.10.11.247 wifinetic.htb`, Reasoning: to discover any subdomains, Result: only the main domain is found with no additional subdomains.

* Findings: The WiFi password is known, Action: using `crackmapexec` to brute force SSH with the password against known usernames, Reasoning: to gain access to the system, Result: successfully authenticated as `netadmin`.

* Findings: Logged in as `netadmin`, Action: reading the user flag with `cat user.txt`, Reasoning: to capture the user flag for the challenge, Result: retrieved the user flag.

* Findings: The home directory of `netadmin` is mostly empty, Action: listing files in the home directory, Reasoning: to check for any sensitive files, Result: confirmed minimal files present.

* Findings: Other user home directories exist, Action: listing `/home` directory, Reasoning: to enumerate other users, Result: found multiple user directories.

* Findings: The `/opt/share` directory contains files similar to the FTP server, Action: listing files in `/opt/share`, Reasoning: to check for any additional files, Result: confirmed presence of previously downloaded files.

* Findings: The `vsftpd.conf` file indicates the FTP configuration, Action: reading the `vsftpd.conf` file, Reasoning: to understand the FTP server settings, Result: confirmed anonymous access and file storage location.

* Findings: Searching for SetUID and SetGID binaries, Action: running `find / -perm -4000 -or -perm -2000`, Reasoning: to identify any binaries that could be exploited, Result: found standard binaries with no immediate vulnerabilities.

* Findings: Checking for capabilities on binaries, Action: running `getcap -r /`, Reasoning: to find binaries with elevated capabilities, Result: found `reaver` with capabilities that could be exploited.

* Findings: Multiple network interfaces are present, Action: running `ifconfig`, Reasoning: to check network configurations, Result: identified `eth0`, `lo`, `mon0`, `wlan0`, and `wlan1`.

* Findings: The `wpa_supplicant.conf` file is present but not readable, Action: attempting to read the file, Reasoning: to find additional WiFi credentials, Result: permission denied.
* Findings: The target AP is `wlan0` with MAC `02:00:00:00:00:00`, Action: Run `reaver -i mon0 -b 02:00:00:00:00:00 -vv`, Reasoning: To brute force the WPS PIN and retrieve the WPA PSK, Result: Successfully cracked the WPS PIN as '12345670' and retrieved the WPA PSK 'WhatIsRealAnDWhAtIsNot51121!'.

* Findings: The password for the root account is the same as the WPA PSK, Action: Use `su -` to switch to the root user, Reasoning: To gain root access to the system, Result: Successfully switched to root user.

* Findings: The root password works for SSH, Action: Execute `sshpass -p 'WhatIsRealAnDWhAtIsNot51121!' ssh root@10.10.11.247`, Reasoning: To access the system remotely as root, Result: Successfully logged into the system as root.

* Findings: The `wpa_supplicant.conf` file exists but is not readable by `netadmin`, Action: Attempt to read the file with `cat wpa_supplicant.conf`, Reasoning: To check the wireless settings, Result: Received a "Permission denied" error.

* Findings: The `iw dev` command provides details about wireless interfaces, Action: Run `iw dev`, Reasoning: To gather information about the wireless interfaces and their configurations, Result: Obtained details about `mon0`, `wlan0`, `wlan1`, and `wlan2`.

* Findings: `wash` hangs when run as `netadmin`, Action: Execute `wash -i mon0`, Reasoning: To enumerate networks and check WPS status, Result: The command hangs without output.

* Findings: Running `wash` as root also hangs, Action: Execute `wash -i mon0` as root, Reasoning: To see if root privileges change the behavior, Result: The command still hangs without output.

* Findings: `wash` works on `wlan2`, Action: Execute `wash -i wlan2`, Reasoning: To check if it can enumerate networks on a different interface, Result: Successfully enumerated the network with BSSID `02:00:00:00:00:00`.

* Findings: Running `wash -i wlan2` while `wash -i mon0` is running shows simultaneous output, Action: Execute `wash -i mon0` while `wash -i wlan2` is running, Reasoning: To test if both commands can run concurrently, Result: Both commands output the same network information.

* Findings: `mon0` is in monitor mode and cannot send packets, Action: Analyze the behavior of `wash` in relation to monitor mode, Reasoning: To understand why `wash` hangs when using `mon0`, Result: Concluded that `wash` fails to send probes in monitor mode, causing it to hang.

* Findings: `wlan2` and `mon0` are the same physical device, Action: Analyze the relationship between `wlan2` and `mon0`, Reasoning: To understand the interface behavior and capabilities, Result: Confirmed that `wlan2` can send packets while `mon0` cannot.
