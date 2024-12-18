* Findings: The target IP is 10.10.11.213, Action: running nmap with command `nmap -p- --min-rate 10000 10.10.11.213`, Reasoning: to discover open ports on the target, Result: found ports 22 (SSH), 80 (HTTP), and 3000 (HTTP) open.

* Findings: The open ports include SSH (22) and HTTP (80 and 3000), Action: running nmap with command `nmap -p 22,80,3000 -sCV 10.10.11.213`, Reasoning: to gather more detailed information about the services running on the open ports, Result: identified OpenSSH 8.4p1 on port 22 and nginx 1.18.0 on ports 80 and 3000.

* Findings: The HTTP service on port 3000 redirects to `microblog.htb`, Action: performing subdomain brute force using `ffuf`, Reasoning: to discover any additional subdomains that might be hosted on the target, Result: found two subdomains: `app.microblog.htb` and `sunny.microblog.htb`.

* Findings: The main page at `app.microblog.htb` allows user registration and login, Action: registering a new user on the site, Reasoning: to gain access to the dashboard and explore the functionality of the microblog service, Result: successfully registered and redirected to the dashboard.

* Findings: The dashboard allows creating subdomains, Action: creating a subdomain `oxdf.microblog.htb`, Reasoning: to test the functionality of the microblog service and see how it handles user-generated content, Result: the subdomain was created and appeared in the dashboard.

* Findings: The site has an editor for creating blog posts, Action: examining the editor functionality, Reasoning: to understand how content is stored and managed, Result: identified that the editor allows arbitrary file names for blog content.

* Findings: The `id` parameter in the POST request to create/edit blog content is not sanitized, Action: attempting to write to `/etc/passwd` using the `id` parameter, Reasoning: to test for arbitrary file write vulnerabilities, Result: the attempt to write failed, but the traversal payload was added to `order.txt`.

* Findings: The `fetchPage` function reads files listed in `order.txt`, Action: reading the contents of `/etc/passwd` by manipulating the `id` parameter, Reasoning: to confirm the ability to read arbitrary files, Result: the contents of `/etc/passwd` were displayed on the microblog page.

* Findings: The ability to read files is confirmed, Action: scripting the file read process to automate the exploitation, Reasoning: to streamline the process of reading files without manual intervention, Result: created a Python script that registers a new user and reads specified files.

* Findings: The script successfully registers a user and reads files, Action: executing the script with the target file as an argument, Reasoning: to verify the functionality of the script and retrieve sensitive information, Result: successfully retrieved the contents of `/etc/passwd` or other specified files.
* Findings: The user controls the `id` parameter in a PHP script, Action: Analyzing the PHP code for vulnerabilities, Reasoning: To identify potential security issues related to file handling, Result: Discovered that the `id` parameter is not sanitized, allowing for arbitrary file read/write.

* Findings: Attempting to read `/etc/passwd` using the `id` parameter, Action: Sending a request with `id=../../../../../../etc/passwd`, Reasoning: To check if the application allows reading sensitive files, Result: Failed to write to `/etc/passwd`, but the traversal payload was written to `order.txt`.

* Findings: The contents of `order.txt` are displayed on the microblog page, Action: Extracting data from `order.txt`, Reasoning: To see if the traversal payload can be exploited to read sensitive information, Result: Successfully displayed the contents of `order.txt` on the site.

* Findings: The application allows creating a new account, Action: Writing a Python script to automate account registration and file reading, Reasoning: To streamline the process of reading files from the server, Result: Successfully read `/etc/passwd` and other files.

* Findings: The `/content` directory is writable but does not allow PHP execution, Action: Attempting to write a `.php` file to `/uploads`, Reasoning: To see if I can execute PHP code by uploading a file, Result: The file is downloaded instead of executed.

* Findings: The nginx configuration restricts PHP execution in certain directories, Action: Analyzing the nginx config for potential misconfigurations, Reasoning: To find a way to execute PHP files, Result: Confirmed that `/uploads` allows PHP execution when accessed directly.

* Findings: The application allows uploading images, Action: Uploading a `.php` file disguised as an image, Reasoning: To exploit the upload functionality for remote code execution, Result: Successfully executed PHP code by accessing the uploaded file.

* Findings: The application uses Redis for user management, Action: Accessing Redis to enumerate users and their data, Reasoning: To find credentials or sensitive information, Result: Retrieved the password for the `cooper` user.

* Findings: The `cooper` user can run a specific command as root, Action: Using `sudo` to run the `license` command, Reasoning: To check if it can be exploited for privilege escalation, Result: Discovered that the command generates a license key based on user data.

* Findings: The `license` command uses a secret stored in `/root/license/secret`, Action: Crafting a Redis entry to extract the secret, Reasoning: To gain access to root privileges, Result: Successfully retrieved the secret.

* Findings: The secret allows `su` to root, Action: Using the secret to switch to the root user, Reasoning: To gain full control of the system, Result: Successfully logged in as root and retrieved `root.txt`.

* Findings: The box was patched shortly after the initial release, Action: Reviewing the patch notes for vulnerabilities, Reasoning: To understand what security measures were implemented, Result: Identified that the patch addressed the arbitrary file write vulnerability.
* Findings: The secret is stored in a Redis database and can be accessed through a format string injection, Action: Created a new user in Redis with a last name that includes an injection payload `{license.__init__.__globals__[secret]}`, Reasoning: To exploit the format string vulnerability and retrieve the hidden secret, Result: Successfully retrieved the secret `unCR4ckaBL3Pa$$w0rd` when the format string was processed.

* Findings: The secret works as the password for root access, Action: Used the retrieved secret to execute `su -` and SSH into the root account, Reasoning: To gain elevated privileges on the system, Result: Successfully logged in as root.

* Findings: The system has a race condition vulnerability in the `addSite` function, Action: Identified the writable state of the `microblog` directory during site creation, Reasoning: To exploit the race condition and write a PHP webshell to the server, Result: Successfully uploaded a webshell to the server.

* Findings: The nginx configuration allows for PHP execution in certain directories, Action: Crafted a URL with two `.php` extensions to bypass the Content-Disposition header, Reasoning: To execute the uploaded webshell instead of downloading it, Result: Successfully executed the webshell.

* Findings: The original race condition vulnerability was patched, Action: Analyzed the new implementation of the `addSite` function, Reasoning: To understand how the patch mitigated the race condition, Result: Confirmed that the new implementation creates a temporary directory in `/tmp`, making it difficult to exploit.

* Findings: The nginx configuration was also patched but incompletely, Action: Reviewed the updated nginx configuration for handling requests to the `/content` directory, Reasoning: To identify any remaining vulnerabilities that could be exploited, Result: Discovered that variations of the original exploit still work, allowing for potential execution of PHP files.
