# SOC Level 1

This is *actually* fun! :)
## Cyber Defence Frameworks
### Junior Security Analyst Intro (1/29/2025)
#### Open-Source Databases 
- For IP Reputation and Location Checks:
	- AbuseIPDB, Cisco Talos Intelligence
### Pyramid of Pain (1/29/2025-2/2/2025)
#### Hashes
- MD5-Not secured
- SHA-1-susceptibel to brute-force attacks susceptible 
- SHA-2-Designed by NIST and NSA.  Many variants.  Most common SHA-256.  Returns hash value of 256-bits as a 64 digit hexadecimal number.
- Not cryptographically secured if two files have the same hash value or digest.
- Examples of hashes related to mal files at the end of reports: The DFIR Report and FireEye Threat Research Blogs.
- Hash lookup tools: VirusTotal and Metadefender Cloud - OPSWAT.
- Hashes can get changed very easily, with any change in the file.  Threat hunting can become difficult.
#### IP Address (Easy)
- A common defense tactic is to block, drop, or deny inbound requests from IP addresses on your parameter or external firewall.
- **Fast Flux** is a DNS technique used by botnets to hide phishing, web proxying, malware delivery, and malware communication activities behind compromised hosts acting as proxies. The purpose of using the Fast Flux network is to make the communication between malware and its command and control server (C&C) challenging to be discovered by security professionals.
- https://unit42.paloaltonetworks.com/fast-flux-101/ 
- Report from any.run.  That was pretty insightful!  It's a sandboxing service.  
#### Domain Names (Simple)
- Domain Names can be a little more of a pain for the attacker to change as they would most likely need to purchase the domain, register it and modify DNS records. Unfortunately for defenders, many DNS providers have loose standards and provide APIs to make it even easier for the attacker to change the domain.
- Punycode attack: A way of converting words that cannot be written in ASCII, into a unicode ASCII encoding
- To detect malicious domains, proxy logs or web server logs can be used.
- A URL Shortener is a tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL Shortener link.
	- bit.ly, goo.gl, ow.ly, s.id, smarturl.it, tiny.pl, tinyurl.com, x.co
- You can see the actual website the shortened link is redirecting you to by appending "+" to it Example: `http://tinyurl.com/cn6xznu+`  If you type it directly into the address box, you'll just go to a page that tells you what the link is to. (It's safe.)
- Any.run is a sandboxing service that executes the sample, we can review any connections such as HTTP requests, DNS requests or processes communicating with an IP address.
	- HTTP Requests: shows the recorded HTTP requests since the detonation of the sample. This can be useful to see what resources are being retrieved from a webserver, such as a dropper or a callback.
	- Connections: shows any communications made since the detonation of the sample. This can be useful to see if a process communicates with another host. For example, this could be C2 traffic, uploading/downloading files over FTP, etc.
	- DNS Requests: the DNS requests made since the detonation of the sample. Malware often makes DNS requests to check for internet connectivity (I.e. if It can't reach the internet/call home, then it's probably being sandboxed or is useless).
- What term refers to an address used to access websites?  Domain Name.
#### Host Artifacts (Annoying)
- Host artifacts are the traces or observables that attackers leave on the system, such as registry values, suspicious process execution, attack patterns or IOCs (Indicators of Compromise), files dropped by malicious applications, or anything exclusive to the current threat.
- With these questions, pay attention to detail, and be OK with asking Copilot...I DON'T KNOW EVERYTHING!!  lol
#### Network Artifacts (Annoying)
- Remember me not knowing everything?  There was a question, and I had to copy/paste the string to have it translate what I was looking for...
	- It was MSIE 7.0.  MSIE: Microsoft Internet Explorer 7.0.
#### Tools (Challenging)
- MalwareBazaar, Malshare resource for malware samples and malicious feeds and YARA results
- SOC Prime Threat Detection Marketplace - get some detection rules latest CVEs that are being exploited in the wild.
- Fuzzy hashing - helps perform similarity analysis.  See SSDeep.  AKA context triggered piecewise hashes.
#### TTPs (Tough)
This is the apex of the Pyramid of Pain.  Tactics, Techniques & Procedures.  See MITRE ATT&CK Matrix.
Steps often are: phishing attempts to persistence and data exfiltration.

If you could detect a [Pass-the-Hash](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack) attack using Windows Event Log Monitoring and remediate it, you would be able to find the compromised host very quickly and stop the lateral movement inside your network.

Remember, attackers are people too...if you defeat their TTPs they're often left with two options:
1. Go back, do more R&D, training, reconfig their custom tools and try again. OR
2. Give up and find another target.
To answer the question, I ended using Copilot.  I was close in researching on MITRE, and getting to the specific tool...with Copilot, it offered that different groups are also on MITRE ATT&CK!
It's under CTI > Groups.  
#### CTF Pyramid of Pain
From Top to Bottom!
TTP: The attacker's plans and objectives.
Tools: The attacker has utilized these to accomplish their objective.
Network: These artifacts can present themselves as C2 traffic for example.
Domain Names: An attacker has purchased this and used it in a typo-squatting campaign.
IP Addresses: These addresses can be used to identify the infrastructure an attacker is using for their campaign.
Hashes: These signatures can be used to attribute payloads and artifacts to an actor.
(I WIN!)
### Cyber Kill Chain - Done (2/2/2025)
### Unified Kill Chain - Done (2/3/2025)
- It also recommends:
	- Principle of Security
	- Pentesting Fundamentals
	- Cyber Kill Chain
### Diamond Model - Done (2/3/2025)
- Adversary
- Victim
- Capability
- Infrastructure
- Event Meta Features
- Social-Political Component
- Technology Component
### MITRE
- TTP
	- Tactic: adversary's goal or objective
	- Technique: how they achieve the goal or objective
	- Procedure: how the technique is executed.
### CAR
[MITRE Cyber Analytics Repository]([Welcome to the Cyber Analytics Repository | MITRE Cyber Analytics Repository](https://car.mitre.org/)).  
The **MITRE Cyber Analytics Repository (CAR)** is a knowledge base developed by MITRE based on the MITRE ATT&CK adversary model. It provides a set of ==validated analytics== designed to detect adversary behaviors in cybersecurity. CAR includes implementations for specific tools like Splunk and EQL, and it offers detailed information on each analytic, such as hypotheses, data models, and pseudocode descriptions.

This looks like a great resource!
### MITRE Engage
[MITRE Engage™ | An Adversary Engagement Framework from MITRE](https://engage.mitre.org/)
Per the website, "_MITRE Engage is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals._"
MITRE Engage is considered an Adversary Engagement Approach. This is accomplished by the implementation of Cyber Denial and Cyber Deception. 
With Cyber Denial we prevent the adversary's ability to conduct their operations and with Cyber Deception we intentionally plant artifacts to mislead the adversary. 
The Engage website provides a [starter kit](https://engage.mitre.org/starter-kit/) to get you 'started' with the Adversary Engagement Approach. The starter kit is a collection of whitepapers and PDFs explaining various checklists, methodologies, and processes to get you started. 
As with MITRE ATT&CK, Engage has its own matrix.

### MITRE D3FEND
[D3FEND Matrix | MITRE D3FEND™](https://d3fend.mitre.org/)
_A knowledge graph of cybersecurity countermeasures._
D3FEND stands for Detection, Denial, and Disruption Framework Empowering Network Defense.
### ATT&CK Emulation Plans

### Summit
1. Sandbox the malware and review the report.
2. Mitigate:
	- Block Hashes with Manage Hashes
	- Block IPs with Firewall Manager
	- Block domain with DNS Filter
	- Create a Sigma Rule for registry keys
		- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
		- DisableRealtimeMonitoring
		- 1
	- Create a Sigma Rule for Network Connections (info from victim's logs)
		- Remote IP: ~~51.102.10.19~~ Actually...it's "Any"
		- Remote Port: ~~443~~ Actually...it's Any
		- Size: 97
		- Frequency (seconds): 1800
		- ATT&CK ID: TA0011
		- The size and frequency are what we're blocking...since IPs and Ports can just be re-done willy nilly.
	- Create a Sigma Rule for commands.log
		- %temp%\exfiltr8.log is from the Log itself
		- Sigma Rule
			- Sysmon Event Logs
			- File Create and Modification
			- File Path: %temp%
			- File Name: exfiltr8.log
			  ATT&CK ID: TA0010
- I had to get some help with the Sigma Rules from [TryHackMe Room — Summit | Haircutfish](https://haircutfish.com/posts/Summit-room/)
### Eviction
Cruising around MITRE!
