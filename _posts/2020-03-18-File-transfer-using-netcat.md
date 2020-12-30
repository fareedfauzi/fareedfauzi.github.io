---
title: "File transfers using Netcat"
date: "2020-03-18"
layout: single
tags:
- OS
categories:
- Blog-post
---
Netcat is a featured networking utility which reads and writes data across network connections, using the TCP/IP protocol.

Netcat works across all platforms (Windows,Mac OS X, Linux). One of the feature is transfering file to another host. To transfer file using this tool, make sure sender and receiver has connection. You can check the connection by pinging to each other.

### Receiver / Destination
On receiver machine, issue this command to listen for the connection that sender will send after this:
```
nc -l -p 1234 > yourfilename
```
The filename could be anything. 
This command will start listening ``-l`` on port ``-p`` 1234.

### Sender / Source
After that, in the sender machine:
```
cd directoryOfTheFile
nc -w 3 192.168.0.x 1234 < filename.txt
```
Replace ``192.168.0.x`` with the receiver/destination IP.

The filename should be the file you want to send. Example here we will send ``filename.txt``.

Now, the file should be transfered successfully.
