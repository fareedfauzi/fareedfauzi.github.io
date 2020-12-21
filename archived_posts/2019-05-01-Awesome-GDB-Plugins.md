---
title: "Awesome GDB plug-ins!"
date: "2019-05-01"
layout: single
tags:
- RE
categories:
- Blog-post
---

Hey folks. Good morning!

Today, I wanna share about GDB plug-ins which are *gdb-peda*, *pwndbg* and *gef*. And also a something cool for me called **GDB-Switcher**. 

![enter image description here](https://camo.githubusercontent.com/d9ae44364fa82f4d54d97a33504e96d3b2fcae6e/687474703a2f2f692e696d6775722e636f6d2f3733726d6d36712e706e67){: .align-center}

Generally when I'm playing CTF, there are two category of challenges that I'll be using GDB. One is pwn challenge and the other one is reversing challenge. In my case, I usually use GDB-Peda as my extension for reversing challenge and Pwndbg for pwn challenge.

**Why not use the normal GDB?**  

Vanilla GDB is terrible to use for reverse engineering and exploit development. Typing `x/g30x $esp` is not fun, and does not confer much information. GDB's syntax is arcane and difficult to approach.

---

**My friend, Peda**

Peda was with me for almost 1 year in this CTF field. For those who don't know what Peda is, Peda is like a extension or add-on for GDB debugger that help in doing many process easily, it also adds color and more good looking command line based interface features that makes GDB more user friendly. It also adds, custom command and functionality and much more. Peda is written in python.

![gdb](https://camo.githubusercontent.com/15284c1b718e51626fdb73aef6107ce0288b433a/687474703a2f2f692e696d6775722e636f6d2f6d5132303851642e706e67){: .align-center}

From above picture, we can see Peda adds color and more good looking command line based interface features that makes GDB more user friendly than normal GDB. Below is the Vanilla GDB. Seems it's quite boring to look at it's interface.

![enter image description here](https://i.ytimg.com/vi/wIuZajISL-E/maxresdefault.jpg){: .align-center}

For those who want to try Peda, you guys can install this extension by run these command.

    git clone https://github.com/longld/peda.git ~/peda
    echo "source ~/peda/peda.py" >> ~/.gdbinit

Just try it!

---
**Pwndbg**

How about Pwndbg? Pwndbg are tend to focus on pwning binaries with its various and nice capabilities.

`pwndbg` (/poʊndbæg/) is a GDB plug-in that makes debugging with GDB terrible less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers.

You can check its awesome feature at their github [here](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md).


![enter image description here](https://cdn-images-1.medium.com/max/1600/1*7RQgTX78ZI0tq6IVQZdnrg.png){: .align-center}

With pwndbg, you are able custom your own theme typing command `theme`.

![enter image description here](https://raw.githubusercontent.com/pwndbg/pwndbg/dev/caps/theme.png){: .align-center}

The installation is pretty straightforward too.

    git clone https://github.com/pwndbg/pwndbg
    cd pwndbg
    ./setup.sh

If you use any other Linux distribution, we recommend using the latest available GDB built from source. Be sure to pass  `--with-python=/path/to/python`  to  `configure`.

---
**GDB Enhanced Features (a.k.a. GEF)**

gef is one of the popular extension for the reverser.

`GEF` (pronounced ʤɛf - "Jeff") is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. It provides additional features to GDB using the Python API to assist during the process of dynamic analysis and exploit development. Application developers will also benefit from it, as GEF lifts a great part of regular GDB obscurity, avoiding repeating traditional commands, or bringing out the relevant information from the debugging runtime. - hugsy

![enter image description here](https://camo.githubusercontent.com/d5b1d89b53fdf2f34222dca2c7446a6f6182df86/68747470733a2f2f692e696d6775722e636f6d2f453345755150732e706e67){: .align-center}

A few of  `GEF`  features include:

-   **One**  single GDB script.
-   Entirely  **OS Agnostic**,  **NO**  dependencies:  `GEF`  is battery-included and is installable in 2 seconds (unlike  [PwnDBG](https://github.com/pwndbg/pwndbg)).
-   **Fast**  limiting the number of dependencies and optimizing code to make the commands as fast as possible (unlike  _PwnDBG_).
-   Provides a great variety of commands to drastically change your experience in GDB.
-   **Easily**  extendable to create other commands by providing more comprehensible layout to GDB Python API.
-   Works consistently on both Python2 and Python3.
-   Built around an architecture abstraction layer, so all commands work in any GDB-supported architecture such as x86-32/64, ARMv5/6/7, AARCH64, SPARC, MIPS, PowerPC, etc. (unlike  [PEDA](https://github.com/longld/peda))
-   Suited for real-life apps debugging, exploit development, just as much as CTF (unlike  _PEDA_  or  _PwnDBG_)

There are two ways to install this tool. Choose one.

    # 1. via the install script
    $ wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
    
    # 2. manually
    $ wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py
    $ echo source ~/.gdbinit-gef.py >> ~/.gdbinit

You can refer their documentation [here](https://gef.readthedocs.io/en/master/).

And here's why use GEF over PEDA? 

[PEDA](https://github.com/longld/peda)  is a fantastic tool that provides similar commands to make the exploitation development process smoother.

However, PEDA suffers from a major drawbacks, which the code is too fundamentally linked to Intel architectures (x86-32 and x86-64). On the other hand, GEF not only supports all the architecture supported by GDB (currently x86, ARM, AARCH64, MIPS, PowerPC, SPARC) but is designed to integrate new architectures very easily as well!

Also, PEDA development has been quite idle for a few years now, and many new interesting features a debugger can provide simply do not exist.

---
**GDB-Switcher**

There is a situation where you want to use both of peda and pwndbg or gef.

I'm comfortable with Peda when I'm doing reversing, but the Peda itself doesn't have capabilities like Pwndbg to do pwning. So, I need to change to Pwndbg to do pwn challenges. It will be hard for us to always change the `.gdbinit` when we want to switch between of them.

Here I found something cool called **gdbs: GDB-Switcher**.

![enter image description here](https://lh3.googleusercontent.com/kCnNdyyru0ieLPFFcsQGvNhItbschBtAeb8WIgjut_YAcmo9k_JzWl0cs5DS_zJoOSKk--JM2ZxM){: .align-center}

*gdbs* is just simple gdb switcher between peda, gef, pwndbg and radare2. It provide menu to you, to choose between those debuggers, just by typing `gdbs` and the number selection.

You can install it by clone `gdb-switcher` repo first.

   ` $ git clone https://github.com/2O2L2H/gdb-switcher.git`

Then, change directory to `gdb-switcher` and execute command


    $ ./install.sh
    $ ./setup.sh

After that, the installer will add these line in your `.bashrc` (cat command it) and it will look like this. 

![enter image description here](https://lh3.googleusercontent.com/6mQgVJzVuXs0EYCnaE5cCYagZ-JVAPuDFg1ENaB3jrRm09Kt-pKku-uvs62LQmI11JKG-vdkDGsS){: .align-center}

 If you use zsh shell, then you must add these lines in your `.zshrc` file.
 

    # gdbs : gdb-switcher
    function gdbs() {
      echo -e "\n[*] Which debugger ?"
      echo -e "\n1 : Legacy GDB"
      echo "2 : peda"
      echo "3 : gef"
      echo "4 : pwndbg"
      echo "5 : radare2"

      radare="no"

      read choice
      case $choice in
          1) echo "[+] gdb-switch => gdb"
             cp ~/.gdbinit-gdb ~/.gdbinit
             ;;
          2) echo "[+] gdb-switch => peda"
                 cp ~/.gdbinit-peda ~/.gdbinit
             ;;
          3) echo "[+] gdb-switch => gef"
                 cp ~/.gdbinit-gef ~/.gdbinit
             ;;
          4) echo "[+] gdb-switch => pwndbg"
                 cp ~/.gdbinit-pwndbg ~/.gdbinit
             ;;
          5) echo "[+] gdb-switch => radare2"
                  radare="run"
             ;;
      esac

      if [ "$#" -eq 1 ]; then
         if [ "$radare" = "run" ]; then
            echo "[+] debugger execution : radare2"
            r2 $1
         else
            echo "[+] debugger execution"
            gdb -q $1
         fi
      fi
     }

After installation, don't forget to restart your terminal first before using gdbs. 


Usage will something like this.

    $ gdbs
    
    [*] Which debugger ?
    
    1 : Legacy GDB
    2 : peda
    3 : gef
    4 : pwndbg
    5 : radare2
    2
    [+] gdb-switch => peda


After you execute "`gdb`" command, it will automatically load the extension you use.

     $ ❯ gdb ./executable
        Reading symbols from ./executable...(no debugging symbols found)...done.
        gdb-peda$


Easy right?

I hope this posts will give you some ideas to choose between those GDB plug-ins and make us easier when switching between the debuggers.

So, that's all from me. Happy reversing and pwning!
