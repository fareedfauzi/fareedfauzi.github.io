---
layout: article
title: "Cheatsheet: Threat Attribution in Threat Intelligence"
date: 2025-08-16
tags:
- Threat-Intelligence
---

Hey yow. What's up? It's been a year since I wrote anything in my blog. I came up with this idea for a blog topic when my ex-junior asked me, "_Yed, how can we attribute a malware to a threat actor?_" Then I remembered the first time I had to do it and asked the same question to myself at my current job.

Today, malware reversing and threat intelligence becane my day-to-day tasks. When I first joined my current employer, I was a pure malware analyst with basically zero knowledge of TI. But still, I had to do threat attribution whenever I worked on malware or threat research.

As a first-timer in this whole threat intelligence scene, I honestly found attribution really tough. It felt overwhelming at the start. But after a year, reading a bunch of books, and constantly asking my senior teammates for guidance, I’ve managed to put together a few points on how we can attribute a piece of malware or a campaign to certain threat groups.

That said, I’m still a noob even today. So this guide isn’t 100% correct. It’s just based on what I’ve read, what I’ve seen at work, and what I’ve learned from others. So, let’s go through a few aspects that can be used for threat attribution in threat intelligence. But, before that, let's talk about several importants code of conducts in threat attribution.

# Code of conducts
1. **Stick to evidence, not guesses**. Assumptions can guide your analysis, but they should never be the foundation of your attribution.
2. **Attribution takes time**. It’s rarely quick, sometimes it takes years of tracking and connecting the dots.
3. **One clue isn’t enough**. An IP, a string, or a single sample won’t cut it. Always cross-check with multiple data points using your internal data or maybe ask other researchers.
4. Track the **bigger picture**. Document attack timelines, overlaps between campaigns, and differences in malware versions.
5. **Actors change**. Groups evolve their tools and sometimes shift their targeting, so keep an eye on how they grow over time.
6. **Expect deception**. Advanced actors may deliberately leave behind false trails to mislead investigators.
7. Attribution to a specific actor = hard.
8. Attribution to a government/nation = way harder. Why?
    - Use front companies, proxies, or criminal affiliates
    - Naming a country can trigger diplomatic, legal, or military consequences.
    - Public reports are often toned down. That’s why you’ll often see phrasing like “likely linked to Chinese state interests” instead of direct blame.
9. **Know when to stop**. Usually, attribution ends at the actor-level (e.g., APT29), and you should always state your confidence level.
    - Use confidence ratings clearly:
      - Low = weak evidence, too many gaps.
      - Moderate = some solid evidence with supporting context.
      - High = strong, consistent, and well-corroborated evidence.
10. **Be transparent**. Always explain what’s based on evidence, what’s assumption, and how you reached your conclusion.
11. **Don’t overstate**. Use careful wording like “likely,” “possibly,” or “with moderate confidence” instead of making it sound absolute.

# What usually you need to conduct threat attribution?

1. A LOT of telemetry and dataset. Attribution isn’t possible without a big pool of telemetry and evidence.
    - Endpoint
    - Network
    - Logs
    - Samples
2. A collection of previous samples and campaign data helps you spot code overlaps and recurring TTPs.
3. Knowledge and experience about the samples, group, campaign. The more you’ve worked with certain malware families, groups, or campaigns, the easier it is to recognize patterns and connect dots. Yeah, it's a long term game my friend.
4. Threat intelligence feeds and reports
    - Threat intel reports (public and private)
    - Free/Commercial feeds
    - Sharing groups and communities
    - Blog-posts

# Threat Attribution Checklist

Below is a checklist you can use as a reference for threat attribution. For each item, you’ll need to decide whether it supports attribution with weak, moderate, or high confidence depending on the quality and amount of evidence you have.

![](https://github.com/user-attachments/assets/67a76258-f63d-4ce5-bf3b-2b2901054542)

## [1] Malware, Toolset, and Code Analysis

### Sample Similarities
- VirusTotal (VT) hunting and lookup: Use VT to check relations, comments, and prior submissions. This often reveals reuse across campaigns.
- Build or use Machine Learning algorithm to find sample similarities.

For example, using lookup or YARA hunting in VT can helps you find more samples.

![](https://github.com/user-attachments/assets/4c840c56-dc15-46e0-9085-3f0bfde7bc3a)

### Code Features & Style
- Binary diffing (Diaphora): Compare samples to see code overlaps or reused functions.  
- Function naming: Custom names or weird naming conventions may persist across builds.  
- Function structure & logic reuse: Attackers often recycle code logic, even across different malware families.  
- Compilation timestamps: Look for consistent build times (e.g., always compiled during certain working hours).  
- Internal versioning/build clues: Strings like `ver 1.0.3` or compiler artifacts may tie samples together.  
- Project structure remnants: Artifacts from IDEs (e.g., Visual Studio paths).  
- Code paths & import tables: Repeated API usage or unusual imports can suggest the same developer.

With Diaphora, you can compare code to identify updates, spot similar variants, or even attribute samples to specific threat actors.

![](https://github.com/user-attachments/assets/8e1b5f8a-408f-4d2c-a2b4-59441e551f61)

For example, early WannaCry (February 2017) shares nearly identical code with Lazarus malware from 2015, known as Contopee.

![](https://github.com/user-attachments/assets/e1a29248-c22f-4f22-bf50-c68316829beb)

### Detection Names
- Threat Intelligence Platforms: Check how the sample has been labeled across platforms.   
- VirusTotal relations & behavior: Explore relation graphs, lookup results, and sandbox behavior.

Detection names in VirusTotal (VT) can provide useful context about the malware you are analyzing.

![](https://github.com/user-attachments/assets/e03e4f6a-6ebd-4f1c-8791-e2de47610a7b)

Additionally, the VT Community can also help in identifying the specific variant of a sample.

![](https://github.com/user-attachments/assets/41a49e08-a26e-485f-bedc-90ab4efca0f5)

### PDB Paths
- Leaked developer usernames or paths: PDB files sometimes reveal usernames, directories, or internal project names.  

### Build Artifacts
- Builder leaks: If a malware builder leaks, compare generated samples.  
- Stager styles: Early-stage loaders (stagers) often have unique patterns.  
- Custom or reused packers: Threat groups sometimes rely on their own packers.  
- Section naming patterns: Strange or repeated section names (`.abcd`, `.xyz`) can link samples.  
- Overlay data: Additional data stored after the PE file can be unique to a group.  

### String & Resource Analysis
- FLOSS: Use FLOSS to extract hidden/obfuscated strings.  
- Embedded configuration: Config files (JSON, XML, encrypted blobs) may reveal hardcoded C2s or campaign IDs.  
- Hardcoded C2s, usernames, commands: Reuse of infrastructure or operator nicknames.  
- Resource metadata & entropy: Check icons, images, or version info fields.  
- Interesting strings: Custom error messages, debug logs, or memes.  
- Unusual resources: Embedded DLLs, HTML files, or executables with unique traits.

Examples of similar strings can be found in many variants of the Talos Trojan, also known as QReverse.

![](https://github.com/user-attachments/assets/425b3207-0564-4a47-90b7-ee0c5a18ae04)

### Anti-analysis Techniques
- Obfuscation/packing: Consistent use of certain obfuscators across campaigns.  
- Anti-debug/anti-VM/AV evasion: Shared evasion tricks (like checking for VM).  

### Cryptographic Artifacts
- Hardcoded keys: Keys or salts reused across samples can be a strong link.  
- Encryption scheme similarities: Custom crypto routines are often reused by the same developers.  

### API and Syscall Usage
- WinAPI usage patterns: Consistent ways of calling APIs (custom API hashing algo).  
- Custom syscall wrappers: Actors sometimes write their own wrappers to bypass EDR hooks.  

### Synchronization Primitives
- Mutex/event names: Malware often creates mutexes to avoid multiple infections. Reused names can tie campaigns together.  

### Code Comments & Developer Signatures
- Easter eggs, humor, ASCII art: Developers sometimes leave personal touches in code.  
- Political messages or slogans: Some groups embed ideological statements.  
- Comments in a specific language: Language choice in code comments can hint at the origin (e.g., Chinese, Russian).  

## [2] Infrastructure and Network Indicators

The list below can serve as a guideline for hunting or attributing malware and campaigns based on C2 infrastructure.

![](https://github.com/user-attachments/assets/4bd3c9f3-316b-4aef-903c-c3669a87809f)

### IP/Domain Reuse
- Look up IP addresses associated with the activity at the time of the incident.  
- Common elements to track:  
  - IP/Domain used for C2 servers  
  - Malware hosting infrastructure  
  - Spear-phishing originating IPs  
- Types of servers:  
  - Compromised servers  
  - VPS/Cloud providers  
  - Standard web hosting  
  - Legitimate services abused (e.g., Telegram, Google Drive)  

### Tools and Platforms
- VirusTotal, APTDB, and other intel platforms for infrastructure lookups.  
- Passive DNS: historical DNS data to see domain-to-IP resolutions over time.  
- WHOIS data:  
  - [SecurityTrails](https://securitytrails.com/)  
  - [ViewDNS](https://viewdns.info/)  
- Reverse WHOIS:  
  - [Whoisology](https://whoisology.com/)  

Use VT for deeper intelligence insights:

![](https://github.com/user-attachments/assets/ffe0484e-7846-4193-915e-9e15300510be)

Not to mention the comment section! (Credit to Rectifyq).

![](https://github.com/user-attachments/assets/086e29a9-9168-4161-a13f-b7a9078a2258)

In another case, you can perform IOC hunting across platforms such as Google, security reports, TIPs, GitHub, X, AlienVault, and others.

![](https://github.com/user-attachments/assets/350c5fc2-d42c-4341-bb36-bfc232836af3)

Example of Alienvault use-case:

![](https://github.com/user-attachments/assets/802d1510-499d-45cf-825a-a32c60d695fc)

### Certificate Reuse or Similarities
- TLS/SSL certificate reuse across multiple campaigns.  
- Shared domain registrants or hosting companies.  
- Similar server configurations across different operations.  
- Reused IP addresses or overlapping hosting providers.  

Be careful: DNS is **dynamic** (records may change frequently, resold infrastructure is common). Some domains may also be sinkholed by researchers.  

### Infrastructure Analysis & Hunting
- Use tools like **Censys, Shodan, FOFA, Validin** to identify live infrastructure.  
- Look for recurring traits:  
  - Services or banners  
  - Open ports across DGA-resolved IPs  
- Pivot on unique artifacts:  
  - TLS certificate hashes  
  - Favicon hashes  
  - Server configurations  
- Combine these with passive DNS and reverse WHOIS for stronger links.  
- Check if infrastructure shows preferences for certain **regions, hosting providers, or ASNs**.  

### Hosting Patterns
- Frequent use of the same hosting/VPS providers.  
- Common ASNs, IP blocks, or registrars reused across campaigns.  
- SSL certificate details (especially if self-signed).  
- Passive DNS correlation for overlapping domains.  

### C2 Using DGA (Domain Generation Algorithms)
- Tools/resources:  
  - [DGArchive](https://dgarchive.caad.fkie.fraunhofer.de/)  
  - VirusTotal  
  - Shodan  
  - SecurityTrails  
  - DNSDB  
- Techniques:  
  - Lookup passive DNS for DGA-generated domains.  
  - Compare DGA patterns to known malware families.  
  - Analyze resolved IPs and their hosting providers.  
  - Identify overlaps in C2 infrastructure.  
  - Look at registrant or hosting provider reuse.  
  - Watch for domain grammar/linguistic traits or specific naming patterns.
 
## [3] Tactics and Techniques

TTPs often overlap across different actors. Many groups use the same techniques (e.g., Cobalt Strike, Mimikatz, RDP for lateral movement), so they may only be **weak indicators** on their own. However, if you find a **very unique or unusual TTP** (for example, a custom POST request style during C2 connection), it can serve as a **much stronger attribution clue**.

### Behavioral Observables
- Filesystem: Dropped files, unusual directories, file timestamp tampering.  
- Registry: Persistence keys, autoruns, registry modifications tied to malware.  
- Process: Suspicious child processes, process injection, LOLBins usage.  
- Network artifacts: Unusual ports, beaconing intervals, traffic patterns.

### Command Usage
- Batch, PowerShell, or bash syntax preferences can indicate actor habits. 

### Naming Conventions
- Filenames: Reused names in many aspects such malware filename, dropped files, registry, created files.  
- Domains: Look for specific naming themes or patterns.  
- Lure themes: Common phishing themes (e.g., diplomatic cables, COVID-19 updates).  
- File content: Decoy documents often reflect regional or thematic targeting.  

### Exploitation Techniques
- CVE usage: Preference for zero-days (0day) vs. publicly available exploits (N-day).  
- Exploit builder fingerprints: Some actors reuse exploit kits or custom builders that leave unique traces.  

### Operational Style
- Lateral movement: RDP, SMB, PsExec, WMI, or custom tools.  
- Initial access: Phishing, supply-chain compromise, watering holes, credential stuffing.  
- Exfiltration methods: Direct C2 uploads, cloud storage (Dropbox, Google Drive), or staging servers.  

### Tooling & Tradecraft
- C2 frameworks: Cobalt Strike, Sliver, Empire, Metasploit.  
- Custom RATs: Bespoke malware developed by the threat group.  
- RMM tools: Abuse of legitimate remote management software (AnyDesk, TeamViewer).  
- Exfiltration tooling: RClone, WinSCP, curl, custom scripts.  

## [4] Campaign Context and Targeting

### Victimology
- Sectors: Industries or verticals consistently targeted (e.g., government, defense, telecom, NGOs).  
- Regions: Geographic focus of attacks (e.g., Southeast Asia, Eastern Europe).  
- Languages: Language used in lures, decoys, or malware builds can hint at intended targets.  
- Geographies: Broader targeting patterns (regional alliances, neighboring states, cross-border conflicts).  

### Motivation
- Espionage: Stealing sensitive data, government secrets, intellectual property.  
- Political: Targeting dissidents, activists, elections, or international relations.  
- Financial: Direct theft, ransomware, or fraud operations.  
- Disruptive: Sabotage, destructive malware, or operations designed to cause instability.  

### Historical Targeting Patterns
- Known victims: If the same sector, region, or organizations are repeatedly hit, it suggests actor persistence.  
- Vertical alignment: Consistency in targeting specific industries over time.  

### Theme Overlaps
- Phishing theme and decoy reuse: Same lure types reused across campaigns (e.g., fake diplomatic invites, COVID-19 alerts).  
- Regional or topical lures: Documents or emails crafted around issues tied to specific countries, organizations, or events.

## [5] Operational Security Mistakes
OpSec mistakes are some of the strongest indicators for attribution, but they are rare. When they do occur, they can reveal personal habits, working hours, or even identities of operators.

### Bad OpSec Indicators
- Real names or usernames in debug paths: Developers accidentally compile with personal directory structures (e.g., `C:\Users\Ivan\Projects\malware\`).  
- Hardcoded credentials or passwords: Embedded in malware, configs, or scripts. Example, FTP server credential embedded in command or script. 
- Password reuse: Same credentials showing up across multiple campaigns or services.  
- Created usernames or naming patterns: Operator accounts created with consistent styles.  
- Leaked builder artifacts or staging files: Unintentionally left behind in samples or servers.  
- Logs left on C2 servers: Debug logs, web logs, or admin notes exposing activity.  

### Timestamp and Time-Zone Correlation
- Malware compile times: Can point to developer time zones or work hours.  
- Time zone of activities: C2 or log files revealing consistent time zones.  
- Work-hour alignment: Activities clustering around 9–5 schedules in specific regions.  
- Timestamp correlation: Malware execution, C2 registration, mail send times, and IP resolutions may align with operator routines.  

### Language Artifacts
- Embedded strings, resources, or code comments: May contain hints of native language (e.g., Cyrillic, Chinese).  
- Language settings: Office lure documents or malware compiled with specific locale/language IDs.

## [6] Passwords, Notes, and Human Elements
Human elements like passwords, ransom notes, and wording styles can be very telling. They are often reused across operations, intentionally or by mistake, and can strongly support attribution when combined with other evidence.

### Passwords
- Reused passwords: Operators sometimes recycle the same credentials across campaigns.  
- Found in compressed samples: Password-protected ZIPs or RARs often contain reused keys.  
- Embedded in RAT configs: Hardcoded passwords for C2 or operator authentication.  

### Ransomware-Specific Features
- Note formatting: Consistent layout, tone, or instructions in ransom notes.  
- Ransom email addresses: Reuse of contact emails across campaigns.  
- Wallet reuse: Same Bitcoin, Monero, or cryptocurrency wallets tied to multiple attacks.  
- Onion hosting reuse: Darknet (.onion) portals showing continuity across operations.  
- Payment site templates/URLs: Same structure or cloned portal designs reused by the same group.  

### Textual Similarity
- Ransom notes or README files: Comparing text across different campaigns can reveal overlaps.  
- Similar wording, grammar, and tone: Language quirks, grammar mistakes, or even cultural references can link operations back to the same authors.

For example, Hermes, Ryuk, GoGalocker, and MegaCortex ransomware share notable similarities in their ransom note readme files. Credit goes to the Art of Cyber Warfare book for this insight!

![](https://github.com/user-attachments/assets/27de5cc0-2370-4a79-8722-90bd81d02287)

## [7] Open Source and External Clues

### Public Threat Reports
- CTI blogs, vendor writeups, and APT reports often contain IOCs, TTPs, and attribution assessments.  
- Useful for cross-referencing but be mindful of bias or different threat actor naming schemes.

For example, you can read Securelist, Trend Micro blogs, or the Check Point Research blog for references and to keep your knowledge up to date on current threats.

![](https://github.com/user-attachments/assets/4e7ebbfe-d3cb-41f9-9684-361120b93a6f)

![](https://github.com/user-attachments/assets/bf724c0d-767f-4827-834a-fe71bdd9b525)

Not to mention, website like Feedly will make you stay up to date!

![](https://github.com/user-attachments/assets/77872ecf-225a-4cc4-96e7-d9177e709b98)

And this [one](https://www.hendryadrian.com/threat-research/) too!

![](https://github.com/user-attachments/assets/8d763c1d-46d5-4e8d-98a7-dbc9eb1b2474)

Or maybe you want to find a specific keyword in other public TI reports. You can use [this](https://mthcht.github.io/ThreatIntel-Reports/).

<img width="1278" height="678" alt="image" src="https://github.com/user-attachments/assets/82f3acc2-eb19-4fa5-a65b-0a96863561f8" />


### Forum and Underground Activity
- Language and behavior in underground markets can hint at operator origin.  
- Alias reuse across forums or consistent forum signatures may connect activity.  
- Monitoring forums and dark web spaces may reveal early tool sales, exploit leaks, or recruitment posts.  

### Search Techniques
- Googling file hashes, C2 domains/IPs, or unique strings can uncover prior research or mentions.  
- Platforms to check:  
  - GitHub (open repositories containing code, configs, or tooling)  
  - Pastebin (leaked configs, credentials, or scripts)  
  - Forums and Telegram channels (shared malware, infrastructure, chatter)  
  - Google Transparency Reports and Safe Browsing for malicious sites

## [8] Offensive intelligence Against Threat Actors

Hacking back into an adversary’s servers is almost always illegal for private researchers, and tbh, I don’t recommend doing it. I’ve seen cases where researchers around the world have shared a post on X or in blogs hinted about how they get the intel by gaining access to attacker infrastructure.

When these techniques are used, it can provide valuable insights such as verifying internal tools used by the threat actor, identifying victims, exposing malware builders, and mapping out campaigns and many more loot and juicy stuff. So, yeah.

### Infrastructure Takeovers
- Sometimes law enforcement or CERTs seize attacker C2 servers. This lets them map infections, collect victim data, and in some cases even push kill-switches to disable malware.

### Exploiting Attacker Infrastructure
- Panel takeovers: Many crimeware groups rely on web-based C2 panels. Weak authentication, SQL injection, or outdated software sometimes allow defenders to hijack these panels, exposing operator accounts, activity logs, and victim data.
- Attacker storage servers and FTP sites can also leak useful data. I’ve seen cases where malware samples contained hardcoded FTP credentials, researchers used them to access staging servers and pull down exfiltrated files.

### Monitoring Legitimate Services Used as C2
- Some operators abuse services like Telegram for C2 communication. Monitoring malicious Telegram channels can reveal how victims interact with attacker infrastructure, and in some cases, uncover new C2 addresses or payloads.

### Canary Tokens
- Another trick is planting bait files with a canary token inside. If attackers steal and open the file, it will reveals their IP. If the operators aren’t careful like they forget to hide behind a VPN you can sometimes trace it back to their real location.

# Attribution Mistakes Tips
Attribution is tricky. Threat actors share tools, infrastructure, and even techniques, which makes things messy. The points below are reminders of what *not* to do whic can help you avoid rushing into conclusions when investigating a campaign. Always stack multiple evidence types (infrastructure, TTPs, victimology, OpSec mistakes, etc.) before making an attribution call. 

## General Rules
- Never assume when attributing activity. It’s better to leave something unattributed than to make a wrong call.  

## Infrastructure
- Be cautious with shared servers and domains. Multiple groups can use the same infrastructure.  
- Don’t assume that domains hosted on the same IP all belong to the same actor.  
  - IPs can be reassigned, spoofed, or routed through VPNs.  
- Domains bought through brokers aren’t reliable for attribution.  
  - Brokers register domains on behalf of others, so you need to dig into the actual registrant.  

## Malware & Tools
- Don’t attribute just because you see a certain malware family or tool.  
  - Many groups share the same malware, especially commodity tools.  
- Public, open-soruce or leaked tools don’t prove actor origin. Anyone can use them.  
- Code similarity isn’t always meaningful.  
  - Malware often reuses open-source code or shared libraries.  
  - Just because two samples look alike doesn’t mean they come from the same developer.  

## TTPs
- Don’t assume two groups are the same just because they use similar techniques.  
  - Common methods (like phishing, PowerShell, RDP) are used by many actors.  
- What matters is how TTPs are sequenced and implemented, that’s where unique fingerprints sometimes show up.  

## Victimology
- Targeting the same sector doesn’t mean the same actor is behind it.  
  - Multiple groups may attack the same organizations or industries.  
- Consider contractors or third-party operators.  
  - Some threat groups outsource work, so tools don’t always match the sponsor.  

## False Flags & Deception
- Watch out for false flags. Actors sometimes plant fake clues (like language artifacts) to throw investigators off.  
- Language strings and metadata can be faked, so don’t rely on them alone.  
- Differentiate between real actor activity and mimicry.  
  - Techniques and lures can be copied by others.  
  - Look for consistency across infrastructure and TTPs before making a call.  

## OSINT
- Open-source intel (OSINT) is helpful, but it’s not enough on its own.  
  - Always back it up with technical evidence from your own data.  
- Public claims can be misleading or incomplete. Double-check everything.  

## Actor Profiles & Evolution
- Keep profiles of threat groups up to date.  
  - Groups evolve, rebrand, or get renamed by vendors.  
- Expect changes. Teams may split, merge, or shift focus. Attribution has to stay flexible.  

## Tool Reuse & Access
- Malware and tools get sold, leaked, or stolen. Don’t assume the original developer is behind every use.  
- Long-term access doesn’t always mean the same actor is still inside a network.  
  - Another group could take over an old foothold.  
  - Validate behavior over time, not just the presence of a tool.  

## Motivation
- Be careful when judging intent. 
- Looking at intent can help narrow down attribution, but it’s rarely a silver bullet.

# Shared tools, malware, open-source & frameworks amongst threat actor

Shared tools are very common. You’ll often see multiple attackers using the same commercial, leaked, or open-source tools. This makes attribution harder. Just because you see one of these tools in use doesn’t mean it belongs to a specific group. Always combine tool usage with other evidence (infrastructure, TTPs, targeting, etc.) before making conclusions.

## Popular Amongst APTs
- Cobalt Strike  
- Mimikatz  
- PlugX  
- ShadowPad  
- Metasploit / Meterpreter  
- China Chopper  
- Empire  
- QuasarRAT  
- NjRAT  

## Command and Control (C2) Frameworks
- Cobalt Strike  
- Covenant  
- Empire (PowerShell Empire)  
- Metasploit  
- Merlin  
- Mythic  
- Pupy  
- SilentTrinity  
- Sliver  

## Post-Exploitation / Credential Tools
- AdFind  
- BloodHound (SharpHound)  
- Evil-WinRM  
- Koadic  
- LaZagne  
- Mimikatz  
- Nishang  
- PowerSploit  
- PowerView  
- Rubeus  
- Seatbelt  
- SharpChrome  

## Remote Access Trojans (RATs)
- Adwind RAT (aka JRAT)  
- AsyncRAT  
- Bifrost  
- BitRAT  
- CyberGate RAT  
- DarkComet  
- Firebird RAT  
- Gh0st RAT  
- Hworm (aka Houdini RAT)  
- Imminent Monitor (IM-RAT)  
- LuminosityLink  
- NanoCore  
- NetWire  
- NjRAT  
- Orcus RAT  
- PlugX  
- PlugX2 (variant)  
- Poison Ivy  
- QuasarRAT  
- RevengeRAT  
- Remcos  
- Sakula RAT  
- ShadowPad  
- Sliver RAT  
- Tofsee  
- Warzone RAT  
- XtremeRAT  
- XXMM RAT  
- ZeroAccess  

## Infostealers / Keyloggers
- Agent Tesla  
- Amadey  
- Arkei  
- Azorult  
- FormBook  
- GrandSteal  
- KeyBase  
- LokiBot  
- Nanocore Stealer variant  
- Predator the Thief  
- Pony  
- Raccoon Stealer  
- RedLine Stealer  
- Vidar  
- XWorm  

## Backdoors / Loaders
- CactusTorch (DLL side-loader)  
- ChChes  
- Derusbi  
- Htran  
- Icefog  
- JSocket  
- Meterpreter payloads (via Metasploit)  
- Rekoobe  
- Sakula RAT  
- ShadowPad  
- Zegost  

## Web Shells
- B374K Web Shell  
- Behinder Webshell  
- China Chopper  
- Godzilla Web Shell  
- RevCode Web Shell  
- WSO Web Shell  

## Commercial / Leaked Tools 
- EternalBlue (NSA leak)  
- FinFisher (FinSpy)  
- FuzzBunch  
- Hacking Team RCS  
- Pegasus (NSO Group)  
- RCSAndroid  
- RemoteUtilities  
- SMBTouch

# Must read/watch list
Here I’ve listed some books, articles, and videos that can help you learn more about threat attribution in threat intelligence.

## Books
- [Art of cyberwarfare](https://nostarch.com/art-cyberwarfare)
- [Attribution of Advanced Persistent Threats](https://link.springer.com/book/10.1007/978-3-662-61313-9)

## Articles
- [A Comprehensive Survey of Advanced Persistent Threat Attribution](https://arxiv.org/html/2409.11415v3)
- [Kaspersky's The power of threat attribution](https://content.kaspersky-labs.com/se/media/en/business-security/enterprise/threat-attribution-engine-whitepaper.pdf)

## Videos
- [Attribution and Bias: My terrible mistakes in threat intelligence attribution](https://www.youtube.com/watch?v=rjA0Vf75cYk)
- [What is the role of technical attribution?](https://www.youtube.com/watch?v=hUvV1S9xHyg)
- [A Brief History of Attribution Mistakes - SANS CTI Summit 2019](https://www.youtube.com/watch?v=Y3EPkDUoGyc)
- [24 Techniques to Gather Threat Intel and Track Actor](https://www.youtube.com/watch?v=beh5VUKc2EU)
- [Unveiling shadows: key tactics for tracking cyber threat actors, attribution, and infrastructure](https://www.youtube.com/watch?v=bXDMsWZOeWY)


# Wrap-up
I can say that threat attribution is hard, and it always requires experienced and expert people to do it. Many aspects can be considered for attribution, but as long as you have enough evidence to support it, then you're good to go. Remember, do not attribute if you are not confident or if you do not have any proof for your attribution. It is always better to stay cautious than to make a wrong call.  

Always express attribution with confidence levels:  
- Low: weak evidence, not enough to stand on its own.  
- Medium: some supporting evidence, but still gaps.  
- High: strong, consistent, and well-corroborated across multiple sources.

And goooddd luckk on your threat intel journey!

Anyway, if this content has any wrong information, please let me know. My DM at X (@frdfzi) are always open. See ya!
