---
title: " Note: Nmap probing services"
date: "2020-02-14"
layout: single
tags:
- Boot2root
- Nmap
categories:
- Notes
---

This note tend to compile all nmap useful command line that will be useful for HTB, VulnHub, PWK labs and OSCP exam.

## Scan for alive hosts

First of all, we need to know what boxes exist on the network.

So, we need to run a ping command to all subnet of the network.
```
$ nmap -sn [target ip network] > ip-range.txt
or
$ nmap -vvv -sn [target ip network]

Example: 
$ nmap -sn 10.0.0.0/24
```
Command above will test connection to all machines (```10.0.0.0 - 10.0.0.255```) in the network 10.0.0.0/24 subnet that are alive.

If you want a little faster, this command doesnt scan for hostnames, where `-n` option disable DNS lookups.
```
$ nmap -sn -n 10.0.0.0/24
```

## Scan specific IP range
Scanning for specific IP range
```
$ nmap -sP 10.0.0.0-100
```
## Sort out the machines that are up
So let's say you find that 40 machine exists in that range. We can use grep to output those IPs.

First let's find the IPs that were online. Ip-range is the output from previous command. You can of course combine them all.

```
$ cat ip-range.txt | grep -B 1 "Host is up"
```

and now filter all the IPs and create a file.
```
grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' ip-range.txt > only-ip.txt
```
## Scan a host
```
nmap www.testhostname.com
```

## Scan specific machine

Once you have chosen a host (target), the first thing is always to do is:
### Scan common port
```
$ nmap -A -oA [filename] [target ip]

Example:
$ nmap -A -oA host1 10.0.1.0/24
```
The command:
* Scan 1024 most common ports
* Run OS detection
* Run default nmap scripts
* Save the result into `.nmap`, `.gnmap` and `.xml`
* Faster

### Fast scanning

Scan 100 most common ports
```
nmap -F [target ip]
```


### Scan deeply
Scanning more deeply:
```
$ nmap -v -p- -sT [target ip]

Example:
$ nmap -v -p- -sT 10.0.1.0/24
```
This command:
* Scan all 65535 ports with full connect scan
* Take very long time
* Print out straigt away instead of having to wait until end of the scan

Tips:

Scanning this takes a long time, suggest to leave the scan running overnight, when you're sleep or move on to different box in the meantime.

### Scan for specific port
You might want to limit a scan to check whether specific ports are open. 

```
$ nmap -p T:80,443,8080 192.168.1.0/24
```
Use `-T`: specifies TCP ports. Use `-U`: for UDP ports.

## Scan for unused IP addresses and store in text file
```
$ nmap -v -sn [network ip address] | grep down | awk '{print $5}' > [filename]

Example:
$ nmap -v -sn 192.168.1.0/24 | grep down | awk '{print $5}' > filename.txt
```
## Other option
```
nmap -sV -sC -v -oA output [targetip]
```

## UDP scan
Scanning this might slow and unreliadble
```
$ nmap [target ip] -sU

Example:
$ nmap 10.11.1.X -sU
```

### Scan targets from a text file
Create a text file contains of our targets machine (like in method Scan for unused IP addresses and store in text file):
```
192.168.1.144
192.168.1.179
192.168.1.182
```

Run this nmap command with `-iL`
```
nmap -iL list-of-ips.txt
```

## Onetwopunch.sh

Grab the latest bash script
```
git clone https://github.com/superkojiman/onetwopunch.git
cd onetwopunch
```
Create a text file contains of our targets machine (like in method Scan for unused IP addresses and store in text file):
```
192.168.1.144
192.168.1.179
192.168.1.182
```
Then, run the script and tell it to read our txt file and perform TCP scan against each target.
```
./onetwopunch.sh ip-range.txt tcp
```

So, the idea behind the script to generate a scan of 65,535 ports on the targets. The script use unicornscan to scan all ports, and make a list of those ports that are open. The script then take the open ports and pass them to nmap for service detection. 

## Last but not least
Cheatsheet:
* [https://highon.coffee/blog/nmap-cheat-sheet/](https://highon.coffee/blog/nmap-cheat-sheet/)

Credit:
* superkojiman
* hakluke
* sushant747
* hackettarget.com
