---
title: resource
published: 2024-08-06
description: ''
image: ''
tags: []
category: ''
draft: true
---

# resource

___
_Diffeculty: MEDUIM_</br>
TL.DR:

___


### solution:

1- start with nmap we discover 3 open ports
```
22 ssh
80 http
2222 ssh
```
+ i fall for a trap because of the inconsistency of scanning i initially saw only 22 and 2222 and went the rabbit hole of regreSSHion CVE which is a race condition vuln and super hard to win may take more than a week if you're lucky.

+ redid scan an port 80 popped up now let the fun begin.
+ visiting http://10.10.11.27 yield a redirect to http://itrc.ssg.htb/
+ we add itrc.ssg.htb to out `/etc/hosts`

2- invesitgating the website :

+ from wappalizer the website use (bootstrap , ngnix, php) as mean tech .

+ it's always good to let fuzzing run in the background while doing your manual research 

```shell
╭─kali at kali in ~/CTF/HTB/season6/resource
╰─○ gobuster dir -u http://itrc.ssg.htb/ -w $wordlists/raft-large-words-lowercase.txt -t 60 --no-error   
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.htm                 (Status: 403) [Size: 277]
/uploads              (Status: 301) [Size: 314] [--> http://itrc.ssg.htb/uploads/]
/api                  (Status: 301) [Size: 310] [--> http://itrc.ssg.htb/api/]
/assets               (Status: 301) [Size: 313] [--> http://itrc.ssg.htb/assets/]
/.                    (Status: 200) [Size: 3120]
/.htaccess            (Status: 403) [Size: 277]

```

+ we can already see /upload and  /api are interesting.
+ start burp and navigate to different dir around the site, this will construct a map in your target tab under burp to help you better inderstand how the site is structured.

+ after tweaking a bit we find that :
    - there's /api/login /api/register pages
    - no simple generic sql injetion 
    - no costum headers send X-XXX with requests.
    - tried to register with admin user and it says it already exist.
    - created a new user :   `user=ali&pass=ali&pass2=ali`
    - after login we get redirected to : `http://itrc.ssg.htb/index.php?page=dashboard`
    - was tweaking around and just tried http://itrc.ssg.htb/?page=admin and got to admin page , i was like huuh sorry what bro??
    - looks like we got a auser called zzinter


#### references:

+ https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability
