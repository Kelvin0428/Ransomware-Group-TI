# Ransomware TTP

This is a comprehensive analysis of ransomware trends and activities over the past five years, focusing on the evolution, impact, and mitigation of such threats. The methodology adopted for gathering this intel is detailed below, offering insights into the categorization and evaluation of various ransomware families.

## Table of Contents
- [Introduction](#Methodology)
- [Initial Access (TA0001)](Initial-Access-(TA0001))
- [Execution (TA0002)](#Execution-(TA0002))
- [Persistence (TA0003)](#Persistence-(TA0003))
- [Privilege escalation (TA0004)](#Privilege-escalation-(TA0004))
- [Defense evasion (TA0005)](#Defense-evasion-(TA0005))
- [Credential access (TA0006)](#Credential-access-(TA0006))
- [Discovery (TA0007)](#Discovery-(TA0007))
- [Lateral Movement (TA0008)](#Lateral-Movement-(TA0008))
- [Collection (TA0009)](#Collection-(TA0009))
- [Exfiltration (TA0010)](#Exfiltration-(TA0010))
- [Command and Control (TA0011)](#Command-and-Control-(TA0011))
- [Impact (TA0040)](#Impact-(TA0040))
- [References](#References)

  
## Methodology

### Data Collection and Identification

- Data are systematically gathered from multiple sources including:
  - **MITRE databases**: leveraging its extensive database for identification of relevant malwares as well as their TTPs recorded in the Mitre’s database. Since the TTPs present in Mitre’s database are often compiled through other sources, the information gathered through this source served as a foundation to my analysis and identification of the TTPs commonly utilised in the past 5 years of our threat landscape.
  - **Cybersecurity firms**: such as Palo Alto, Unit42, Kaspersky, Group-IB, etc.
  - **Government agencies**: Reports and bulletins from governmental cybersecurity agencies (e.g., CISA in the United States) offer authoritative information on ransomware incidents, national-level threat assessments, and recommended defence strategies.
  - **Incident Reports**: by observing various organisations provide real-world case studies of ransomware attacks, offering practical insights into the impact and response mechanisms.
  - A total of 29 ransomware variants were identified during my research, each analysed for its unique characteristics and behaviours.

### Categorization Criteria

To ease my analysis and to provide a more comprehensive overview of Ransomware TTPs over the last 5 years, I categorised these differing ransomwares into three types based on their activity status and impact on the industries. This categorization helps in understanding the evolving nature of ransomware threats and their potential future trajectories.

#### Types of Ransomware:

- **Type 1 - Currently Very Active Ransomware**: This category includes ransomware families that are actively engaging in attacks and have shown significant activity in the recent past. These are the most immediate threats, often employing sophisticated techniques and continuously evolving to bypass security measures. This type of ransomware will be the primary focus of discussion when presenting the TTPs in this report.
- **Type 2 - Currently Somewhat Active Ransomware**: These are ransomware variants that were active in the past couple of years but have shown a decline in activity recently, surpassed by type 1 ransomware variant. While not currently as prominent as a threat compared to type 1, they hold the potential to be reactivated or used as a basis for developing new threats.
- **Type 3 - Inactive or Discontinued Ransomware**: This category consists of ransomware that seems to have ceased operation or has been neutralised within the last 5 years or so. Although these ransomwares are currently non-operational, their techniques, tactics, and procedures (TTPs) are still pertinent to this analysis. This consideration stems from historical patterns where dormant ransomware has reemerged under new names. As such, these entities continue to pose potential security threats despite their apparent inactivity.

To determine which ransomware variant to be categorized into Type 1 for my TTP analysis, I utilized a dataset from RansomWatch, which monitored leaksites from 2020 to 2023. This extensive dataset enabled us to identify the top 10 ransomwares based on their prevalence and activity on these leaksites. These top 10 ransomwares form the core of my analysis providing a focused and comprehensive understanding of their TTPs.
##
![Analysis](/Img/Picture2.png)
| Type 1 - Currently Very Active Ransomware | Type 2 - Previously Active Ransomware | Type 3 - Inactive or Discontinued Ransomware |
|-------------------------------------------|---------------------------------------|----------------------------------------------|
| Lockbit 3.0                               | Grief                                 | DoppelPaymer                                |
| AlphV/BlackcatClop                        | TFlower                               | Conti                                       |
| Royal                                     | Wannacry                              | Erebus                                      |
| BlackBasta                                | Jcry                                  | Hermes                                      |
| Clop                                      | Pay2Key                               | REvil                                       |
| 3AM                                       | Ekans                                 | Ragnar                                      |
| AvosLocker                                | Deathransom                           |                                              |
| Diavol                                    | FiveHands                             |                                              |
| Cuba                                      | Sombrat                               |                                              |
| Ryuk                                      | ProLock                               |                                              |
| Akira                                     | Lockergoga                            |                                              |
| Maze                                      | Bitpaymer                             |                                              |
|                                           | WastedLocker                          |                                              |

##
![Recent Ransomware TTPs](/Img/Picture1.png)

# Initial Access (TA0001)
![Alt text for the image](/Img/Picture3.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Blackcat           | Emotet, Phishing, Purchasing Accounts          |
| Royal              | Nircmd                                         |
| BlackBasta         | Emotet, Spear Phishing                         |
| Clop               | Phishing                                       |
| AvosLocker         | ServiceDeskPlus         |
| Cuba               | Proxy shell, Hancitor                               |
| Ryuk               | Spear phishing   |
| Akira              | Spear phishing, Bruteforce, Cisco VPN compromised accounts |
| Play               | ProxyNotShell, OWASSRF, MS Exchange Server Remote Code Execution               |
| Bianlian           | RDP, Valid Accounts, Phishing                                                  |


## Phishing (T1566)

my research indicates a significant shift in cyber-attack methodologies, with phishing, particularly spear phishing (T1566.001), emerging as a prominent technique for initial access. This trend aligns with the current "big game hunting" model adopted by many cybercriminals. 

In this approach, attackers invest more time in preparation and reconnaissance, crafting spear phishing campaigns. This targeted strategy allows them to effectively penetrate defenses and infiltrate high-value targets. This evolution in tactics underscores the need for heightened vigilance and tailored defense mechanisms against these more personalized.

The chart positioned on top presents a visual comparison of the TTPs between Type 1 and Types 2, 3 ransomware. In this graph, the red markers highlight specific techniques predominantly employed by Type 1 ransomware, distinguishing them from those used by Types 2 and 3, which are marked in black. Illustrating the evolutionary paths and operational differences between these ransomware types. By conducting analysis on these charts, I hope to offer deeper insights into the evolving landscape of ransomware, contributing to a better understanding of their unique characteristics and strategies. 


> **Example**: BlackCat, a Ransomware-as-a-Service (RaaS) group, uses the Emotet botnet as their initial entry point. After gaining foothold, the botnet installs a Cobalt Strike beacon, acting as a secondary payload, which allows BlackCat to execute lateral movements within the compromised systems. Similarly, in the case of Black Basta, the goal of using Emotet is specifically to drop Qakbot. The link shown in the below figure drops a .Ink file that is disguised as a document, which deploys Qakbot onto the system. Black Basta was observed to utilise Qakbot, Mimikatz, Rclone, SDBOT as potential payloads through this technique.

![Ref. https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis](/Img/Picture4.png "Optional title")

### Mitigation Strategies

- Internal training to raise phishing awareness
- Use of detection technology to block malicious/suspicious attachments and links
- Whitelisting of websites

## Valid Accounts (T1078)

my research indicates a rising trend in ransomware attacks using valid accounts alongside with the rise of phishing techniques, which is a shift from traditional non-RaaS ransomware TTPs. This increase is likely due to the growing role of Initial Access Brokers (IABs), who sell compromised accounts, streamlining initial access for attackers. While purchasing from IABs is prevalent, attackers also can achieve this technique by directly compromising accounts, often exploiting vulnerabilities or using Remote Desktop Protocol (RDP) for initial infiltration. 

> **Example**: The differing procedure is highlighted between affiliates within the BlackCat, Akira, and Bianlian ransomware actors. Where BlackCat affiliates are known to buy access to victim networks via underground forums, whilst groups like Akira ransomware actors are known to target compromised VPN credentials to gain initial access. Bianlian leverages compromised RDP credentials likely acquired from initial access brokers. A notable example is their recent targeting of Cisco VPN credentials, exploiting CVE-2023-20269, a zero-day vulnerability impacting Cisco ASA and FTD devices.

## Mitigation Strategies

- Track user accounts for any irregular activities, like odd login locations or numerous unsuccessful login attempts
- Frequent prompts for password changes
- Periodic review and deactivation of outdated accounts

# Execution (TA0002)
![Alt text for the image](/Img/Picture5.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Lockbit 3.0          | Chocolatey, Powershell Toolkit       |
| BlackCat            | Cobalt Strike,    Beacon                                     |
| Royal        | Powershell Toolkit                       |
| BlackBasta              | Powershell Toolkit,   Command Shell,   WMI                                |
| Clop	         | Get2 Loader         |
| Avoslocker               |	Powershell Toolkit,  Command Shell  , PsExec and Nltest                         |
| Cuba             | 	Power shell Toolkit, PsExec  |
| Ryuk            | 	Powershell Toolkit, Command Shell,Buer Loader,WMI,Cobalt Strike Beacon |
| Play          |	Cobeacon,   SystemBC          |

## Command and Scripting interpreter (T1059)


According to my research, the Command and Scripting Interpreter technique is widely employed in ransomware attacks, with two predominant sub-techniques: Command Shell (T1059.003) and PowerShell (T1059.001). These tools are versatile, commonly used for system discovery, reconnaissance, credential hunting, privilege escalation, and maintaining persistence. 


> **Example**: Clop ransomware serves as a notable example of the strategic use of Command Shell in cyber-attacks. Specifically, Clop utilizes Command Shell to execute commands that disable Windows Defender and other anti-ransomware defenses. This tactic effectively weakens the security posture of the target system, making it more susceptible to further attack steps.

> Command Shell is also often used to delete shadow copies, a technique aimed to hinder the recovery process of the defenders. 
![Alt text for the image](/Img/Picture6.png "Optional title")

> In a similar vein, Black Basta ransomware showcases the versatile use of PowerShell. This ransomware has been observed leveraging PowerShell for network scanning, file encryption, and the disabling of anti-ransomware tools. The use of PowerShell in these instances underlines its capability to perform more complex and targeted operations within a network, aligning with the sophisticated requirements of modern ransomware attacks. Together, these examples illustrate the diverse yet complementary roles of Command Shell and PowerShell in the landscape of ransomware strategies.
![Alt text for the image](/Img/Picture7.png "Optional title")

### Mitigation Strategies

- Enforce signature checks with PowerShell scripts. 
-	Remove PowerShell from unnecessary endpoints.
-	Whitelist known scripts.
-	Monitor your network for anomalous activities.
> **Note**:  Compared to previous ransomwares, an increase in usage of windows command shell and a decrease in visual basic script (T1059.005) was noticed

## Native API (T1106)

Native APIs used by adversaries have seen an upsurge, paralleling technique T1059. Native APIs provide access to low-level OS services within the kernel, and open attack vectors that manipulate hardware/devices, memory, and processes. 

> **Example**: Ryuk ransomware uses a combination of Native APIs to inject itself into remote processes.
> - VirtualAlloc
> - WriteProcessMemory
> - CreateRemoteThread
> Black Basta ransomware showcases the versatility of Native APIs in executing its attack. It employs SystemParametersInfoW() to change victims’ desktop wallpapers, uses GetSystemMetrics() for assessing boot options and modifying the registry, ShellExecuteA() to reboot systems, and FindFirstFileW() and FindNextFileW() to locate and encrypt files.  

## Mitigation Strategies

- Activate ASR rules to restrict Office VBA macros.
- Implement application control tools, such as Windows Defender Application Control, AppLocker, or Software Restriction Policies.

# Persistence (TA0003)
![Alt text for the image](/Img/Picture8.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
|Black Cat          | Cobalt Strike     |
|Ryuk           | Bazaar                                  |

## Valid accounts (T1078)


The exploitation of valid accounts in the initial access phase of cyber-attacks often serves a dual purpose, extending into a persistence technique as well. Attackers may use these credentials, which may be acquired either during the initial breach or created by the attackers themselves, to secure multiple access points within the compromised infrastructure. This approach ensures continued network access, even if some entry points are discovered and removed.

> **Example**:An illustrative case is LockBit 3.0, where its affiliates have frequently been noted for using compromised user accounts to sustain their presence on the target network. 

### Mitigation Strategies

-	Track user accounts for any irregular activities, like odd login locations or numerous unsuccessful login attempts 
-	Frequently prompt users to change their passwords. 
-	Periodically review user accounts to spot and deactivate any that are outdated.

## Boot or logon Auto start Execution (T1549)

The Registry Run Keys/Startup Folder (T1547.001) has been a common technique used by adversaries for persistence for the past few years, involving the incorporation of programs or scripts to specific registry keys or startup folders that are executed upon system boot or user logon. This method ensures that malicious software is automatically launched without user intervention, maintaining the adversary's presence on the system. 

> **Example**: An example of this technique is seen in the Bazaar backdoor's operation that is implemented by many ransomwares, including conti and Ryuk. During the operation, the backdoor copies itself to the %APPDATA%\Microsoft folder, adds this file path to the registry 'Run' key under the value 'BackUp Mgr', and executes from the copied location. Alternatively, if access to %APPDATA% is restricted or if the backdoor is already running from this location, it adds the current file path to the 'Run' key and re-executes, ensuring persistence even in challenging environments.

## Mitigation Strategies

-	Create a whitelist of allowed auto start processes.
-	Implement monitoring feature towards where process is created during the auto start process, check the auto started process against the whitelist created.

# Privilege escalation (TA0004)
![Alt text for the image](/Img/Picture9.png "Optional title")


## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Royal         | NSudo      |
| Ryuk            | Cobalt Strike                                |
| BlackCat      | Cobalt Strike                      |


## Access token manipulation (T1134)

By altering access tokens in Windows systems, adversaries can assume different user or system security contexts and bypass access controls. This manipulation often involves the Windows API functions, AdjustTokenPrivileges(), which is capable of enabling or disabling particular privileges in the specified access token. However to use this command, the adversary must possess TOKEN_ADJUST_PRIVILEGES access first.

> **Example**:This technique enables processes to mimic ownership by another user, allowing escalation from administrator to SYSTEM level privileges. BlackCat and Conti actors were both observed using access token manipulation for privilege escalation, often leveraging AdjustTokenPrivileges().
> Furthermore, tools like Cobalt Strike offer features for SYSTEM token impersonation (T1134.003) via named pipes (using the “getsystem” command). Within Cobalt Strike, the steal_token command allows impersonation of a token from an existing process, while make_token can generate a token with specific credentials. This flexibility in token manipulation is a significant asset in the arsenal of cyber attackers, enabling them to effectively navigate and control compromised systems.

### Mitigation Strategies

-	Limit permissions so that local system users cannot generate tokens.
-	As mentioned, in order to carry this technique, especially using AdjustTokenPrivileges(), attacker must have administrator level access on the local system first, therefore the system should employ principle of least privilege.

# Defense evasion (TA0005)
![Alt text for the image](/Img/Picture10.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
|Royal        | AV Tamper,  PCHunter,  Process Hacker     |
| AvosLocker            | BAT file,      Avast Anti-Rootkit Scanner,       PowerShell Rootkit                      |
| Cuba        |BurntCigar,  KillAV                   |
|Ryuk              | Systembc   , GMER                         |
|Akira	         | PowerTool,KillAV          |
| Black Basta              |	CommandShell                        |
| 	Black Cat            | 	Command Shell|
| LockBit 3.0           | 	KillAv, PC Hunter, Process Hacker|
| Play          |	GMER,  IOBit, Process Hacker,  Power Tool    |
| Bianlian         |	Powershell,   Command shell        |

## Impair Defenses (T1562)   


Impairing defenses is a tactic frequently employed by Type 1 ransomware, where attackers, upon infiltrating a network, weakens the target's security measures. This often involves uninstalling or disabling antivirus applications. There are various tools capable of executing this technique,


> **Example**:
> -	Black Cat and Black Basta ransomware are known to exploit command line vulnerabilities to weaken system defenses.
> -	Royal ransomware, following the installation of remote software, uses tools like PCHunter or Process Hacker to manually remove antivirus products.
> -	Avoslocker adopts a unique tactic, leveraging the Avast Anti-Rootkit Driver coupled with a PowerShell script to specifically target and disable antivirus processes. Additionally, it employs a BAT script to obstruct antivirus services when the system is in Windows Safe Mode.
> - Cuba ransomware follows a similar strategy, using the KillAV tool to halt AV-related processes and exploiting a vulnerability in an Avast driver ("C:\windows\temp\aswArPot.sys") to terminate services.
> - Lockbit ransomware, leveraging previously obtained access tokens, is capable of deactivating Windows Defender. 

![Alt text for the image](/Img/Picture11.png "Optional title")


### Mitigation Strategies

-	Implement authentication for disabling AV or other anti-ransomware tools.
-	Implement authentication for disabling AV or other anti-ransomware tools.


## Indicator removal (T1070)
Attackers are increasingly aware of evading detection, and one of the common strategies employed is the removal of indicators to erase evidence of their presence and disrupt defenses.  Artefacts like log files, user action records, and downloaded file strings are often removed. The lack of indicators would significantly impede the process of event collection and reporting, thus weakening the effectiveness of security solutions and complicating forensic analysis.


> **Example**: For instance, Lockbit 3.0 ransomware affiliates actively eliminates its own traces. They achieve this by clearing Windows Event Logs and halting corresponding services through the use of cleareventlogw(). This approach ensures that the evidence left behind by the ransomware’s operations are not easily traceable, which poses significant challenges to intrusion detection and subsequent investigative efforts.
![Alt text for the image](/Img/Picture12.png "Optional title")

## Mitigation Strategies
- Actively monitor the system’s event logs.


# Credential access (TA0006)
![Alt text for the image](/Img/Picture13.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Lockbit 3.0          | Impacket, ProcDump, Mimikatz    |
| BlackCat            | 	Cobalt Strike, Mimikatz, Nirsoft                                    |
| BlackBasta           | 	Mimikatz	                      |
|  AvosLocker          | Mimikatz, XenArmor Password Recovery Tool Pro                              |
| Cuba 	         |	Mimikatz      |
| Ryuk               |		Cobalt Strike                       |
| Play             | 	Mimikatz  |
| Bianlian       | 		Valid accounts, Command Shell, RDP recognizer, Impacket |

## Credential dumping (T1003)


Numerous Type 1 ransomwares are observed using the Credential Dumping: LSASS Memory (T1003.001) sub technique. Due to the amount of cached data LSAAS stores and caches for credential management purposes, Kerberos tickets, reversibly encrypted plaintext, and NT/LM hashes, it is an attractive  target for adversaries to gather credential material in order to execute the next step for lateral movement.


> **Example**: Mimikatz stands out as a widely used tool for LSASS credential dumping, capable of retrieving various credential materials and facilitating pass-the-hash attacks. However, its requirement for local administrator rights and Debug privileges makes it susceptible to antivirus detection.
> To bypass this, ransomwares like LockBit 3.0 employ Procdump, a component of the Windows Sysinternals suite. As a legitimate tool, Procdump avoids immediate AV detection, making it an effective method for dumping the LSASS process. The dumped data is then processed by Mimikatz for credential extraction
![Alt text for the image](/Img/Picture14.png "Optional title")
> ![Alt text for the image](/Img/Picture15.png "Optional title")

### Mitigation Strategies

-	In Windows 10, activate ASR (Attack Surface Reduction) rules to protect LSASS. 
-	Use Credential Guard to protect LSA secrets from credential dumping techniques. 
-	Educate users to not reuse passwords.
-	Users should have strong passwords.

# Discovery (TA0007)
![Alt text for the image](/Img/Picture16.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Lockbit 3.0          | SoftPerfect Network Scanner   |
| BlackCat            | 	ADRecon, Nirsoft, Bloodhound, Softperfect Network Scanner               |
| BlackBasta           | Netcat                     |
|  AvosLocker          |Netscan,Nmap                            |
| Clop         |	FlawedAmmyy,SDBOT RAT      |
|Cuba|		Wedgecut                     |
|Ryuk        | Cobalt Strike,Bloodhound,Command Shell |
| Akira       | 	AdFind,PCHunter,Advanced IP Scanner,SharpHound,MASSCAN|
| Royal       | 	NetScan,AdFind|
| Play       | 	Adfind,Bloodhound,Grixba,Netscan,NITest|
|Bianlian     | 	Netscan,Advanced Port Scanner,Sharpshare,Ping castle|

## File and directory discovery (T1083)


This technique involves adversaries seeking specific files and directories that are crucial for their attack objectives. This discovery process is integral to identifying valuable data for encryption or exfiltration.

> **Example**:
> - Royal: Attackers also use tools like NetScan and AdFind along with windows net.exe and nltest.exe to gain information of the victims Active Directory and connected remote systems.
> - Avoslocker: Also uses Nmap, NetScan, and native Windows commands (such as ipconfig, nslookup, and others) to perform discovery on the target network.


## System information discovery (T1082)
Attackers gather detailed system information to tailor their attacks more effectively. 
> **Example**:
> - Lockbit 3.0: Enumerate system information to include hostname, host configuration, domain information, local drive configuration, remote shares, and mounted external storage devices

## Network Share discovery (T1135))
Lockbit and Avoslocker use tools to enumerate network shares for their network-based encryption. Cuba ransomware targets files on connected and shared networks, and with the component Wedgecut, it verifies the online status of hosts or IPs using ICMP packets. This method of discovery is crucial for identifying and exploiting network resources and shared data.

# Lateral Movement (TA0008)
![Alt text for the image](/Img/Picture17.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
|Lockbit 3.0        |PsExec,Splashtop    |
| Black Cat           | PsExec,CrackMapExec                |
| Royal      |PsExec                |
|Black Basta          |BITSAdmin,Coroxy,PsExec                       |
|Clop         |Cobalt Strike          |
|AvosLocker             |	PDQ Deploy                     |
| 	Cuba         | 	Cobeacon,Termite,PsExec|
| Ryuk        | 	Cobalt Strike|
| Play          |	Cobeacon,PsExec,PowerShell Empire,RDP  |
| Bianlian         |	PsExec,RDP,Valid account    |

## Remote Services (T1021)

Utilizing Remote services for lateral movement, an adversary may use valid credentials to log into a system using Telnet, SSH, RDP, or VNC and then execute commands or scripts on that system to gather information, install malware, or perform other malicious actions. 

> **Example**:PsExec is a versatile tool in the Microsoft Sysinternals suite, enabling execution of processes on remote systems. PsExec facilitates lateral movement by allowing attackers to execute commands or launch shells on remote systems.  Modern ransomwares such as Lockbit3.0, Black Cat, Royal, Black Basta, Cuba have all seen actors utilize PsExec for lateral movement and remote execution.

![Alt text for the image](/Img/Picture23.png "Optional title")

> While powerful, PsExec’s visibility has led some antivirus solutions to flag it as potentially malicious.

### Mitigation Strategies

-	Monitor infrastructure for suspicious PsExec events.


# Collection (TA0009)
![Alt text for the image](/Img/Picture18.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
|Ryuk     |Sharphound  |
|Black Basta           | Qakbot            |
|Clop   |SDBbot            |
|Black Cat         |ExMatter                      |

My research into the collection techniques of Type 1 ransomware yielded limited findings. 

However, some instances of collection techniques were noted through reading incidence response and ransomware analysis reports.

## Data from local system

Black Cat and Clop were observed to have an approach towards exploiting local file systems. For example, Black Cat ransomware employs ExMatter function that actively searches in local file systems for files to exfiltrate that matches its requirements.
![Alt text for the image](/Img/Picture19.png "Optional title")

Overall, the lack of widespread identifiable collection techniques in Type 1 ransomwares underscores an area needed for deeper research.


# Exfiltration (TA0010)
![Alt text for the image](/Img/Picture20.png "Optional title")

## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Lockbit 3.0          | MEGA Ltd MegaSync,Rclone,WinSCP   |
| BlackCat            | 	ExMatte                                  |
| Royal| 	Ursnif/GoziExfil                      |
|  Black Basta      |Cobeacon,Rclone                             |
| Clop        |DEWMODE     |
| Cuba            |		Cobeacon                     |
| Ryuk           | 	Cobalt strike,System BC |
| Akira     | 		WinSCP,Rclone,FileZilla|
|Play    | 	WinRAR,WinSCP|
|Bianlian    | 	Powershell|

## Exfiltration Over C2 channel (T1041)

Data exfiltration over Command and Control (C2) channels is a critical technique in cyber-attacks, where adversaries transfer stolen data from a compromised system to a control server. 

> **Example**: For instance, Clop ransomware, known for its double extortion approach, has shifted focus more on data exfiltration over encryption since 2021. It employs a specialised web shell, "DEWMODE", to systematically extract and transmit information from victims. This shell can retrieve and download file listings and their metadata from a database. Cuba ransomware and Black Basta also exemplifies this technique, using its Cobeacon network to send back stolen information. Like Clop, Cuba employs double extortion, demanding ransom for decryption and threatening public release of the stolen data if demands are not met.

## Exfiltration over web services (T1567)
Contrary to the previous technique, this method capitalizes on the pre-existing network communication with these services, which often goes unnoticed due to its perceived legitimacy. Additionally, many of these web services use SSL/TLS encryption, providing an extra layer of security for the data being exfiltrated.

> **Example**: LockBit 3.0 affiliates utilize Steal_bit, a custom tool previously seen with LockBit 2.0, along with rclone, an open-source cloud storage manager, and public file-sharing services like MEGA for exfiltrating sensitive data before encryption. These tools, typically used for legitimate purposes, offer a cover for their malicious activities, including system compromise and data exfiltration. Blackbasta ransomware employs rclone for data exfiltration into their cloud server. This strategy serves as an alternative to transfer data, especially in scenarios where traditional C2 channels are disrupted or blocked. Similarly, operators of Akira ransomware also utilises RClone to exfiltrate stolen data. They also use tools like FileZilla or WinSCP for transferring information via FTP.

### Mitigation Strategies

-	Deploy network intrusion detection and prevention system.
-	Block network connections to cloud storage providers that are not within the organization.
-	Whitelist known FTP servers.


# Command and Control  (TA0011)
![Alt text for the image](/Img/Picture21.png "Optional title")
## Tools and Ransomware

| Ransomwares        | Tool/Method                                    |
|--------------------|------------------------------------------------|
| Lockbit 3.0          | FileZilla,Ngrok,PuTTY Link (Plink)  |
| Royal| 	TCP/UDP Tunnel over HTTP (Chisel),Remote Access (AnyDesk)                     |
|  Black Basta      |Cobeacon,Qakbot                          |
| Clop        |SDBbot   |
| AvosLocker           |AnyDesk,Ligolo,chisel                  |
| Cuba          | 	Cobeacon |
| Ryuk    | 		Cobalt strike,systemBC|
|Akira  | AnyDesk, Radmin,Cloudflare Tunnel,MobaXterm,RustDesk,ngrok|

##Application layer protocol (T1071)


In Command and Control (C2) operations, modern threat actors frequently utilize application layer protocols. These protocols, which include web protocols like HTTP and HTTPS (T1071.001), are extremely common due to their ubiquity and the widespread use of commodity malware and post-exploitation frameworks. Additionally, file transfer protocols such as FTP and FTPS are also common due to their efficiency in setting up servers for data exfiltration.

> **Example**: For instance, the Clop ransomware employs web protocols (HTTP/S) for communicating with its C&C servers, leveraging the widespread availability and standard nature of these protocols. Similarly, LockBit 3.0 has been observed using FileZilla, a file transfer protocol tool, for its C2 communications.

## Encrypted Channel (T1573)
Royal operators have been noted for their use of Chisel, a tunnelling tool that operates over HTTP and is secured with SSH, creating an encrypted channel for C2 communications. This approach ensures secure and concealed communications between the malware and its control servers.

Likewise, AvosLocker affiliates are known to use open-source networking tunnelling tools like Ligolo and Chisel, emphasizing the trend toward encrypted channels for secure C2 operations. The use of such tools indicates a sophisticated approach to maintaining secure and undetected control over compromised systems.
### Mitigation Strategies
-	Deploy network intrusion detection and prevention systems, use network signatures to detect traffic from adversary malware, mitigate the c2 traffic.



# Impact (TA0040)
![Alt text for the image](/Img/Picture22.png "Optional title")
## Data encrypted for impact (T1486)
For ransomware attacks, the objective is commonly to encrypt the victim's data, crippling their system’s availability. This encryption serves as a tool for leveraging financial gain, personal vendettas, or political motives. 

## Inhibit System Recovery (T1490)
An integral part of many ransomware strategies involves hindering system recovery efforts. Attackers deliberately target and disable backup and recovery systems to prevent victims from restoring their data without paying the ransom. This often includes deleting shadow copies, disabling Windows restore points, or attacking network-based backup systems. By cutting off these avenues of recovery, attackers increase the likelihood of their demands being met, as the victims are left with few, if any, alternatives for restoring their data. This technique further amplifies the impact of the attack, extending the duration of system downtime and increasing potential losses.

## Service Stop (T1489)
Many ransomware variants forcibly terminate specific services on the victim's system. This is typically aimed at stopping security software, backup processes, and other services. The stopping of services exacerbates the system's downtime, further deepening the crisis for the affected party and amplifying the pressure to meet the attacker's demands.

# References
1.	https://www.cybereason.com/blog/a-brief-history-of-ransomware-evolution
2.	2023 Unit 42 Ransomware and Extortion Report - Palo Alto Networks
3.	Evolution of Ransomware: So Far and Hereafter - SOCRadar
4.	https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis 
5.	https://www.group-ib.com/blog/blackcat/ 
6.	https://blogs.cisco.com/security/akira-ransomware-targeting-vpns-without-multi-factor-authentication 
7.	https://www.trendmicro.com/vinfo/sg/security/news/ransomware-spotlight/ransomware-spotlight-clop 
8.	https://www.kroll.com/en/insights/publications/cyber/black-basta-technical-analysis 
9.	https://www.trendmicro.com/vinfo/hk-en/security/news/ransomware-spotlight/ransomware-spotlight-blackbasta 
10.	https://fourcore.io/blogs/ryuk-ransomware-simulation-mitre-ttp 
11.	https://securityscorecard.com/research/a-deep-dive-into-black-basta-ransomware/
12.	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a  
13.	https://blog.fox-it.com/2020/06/02/in-depth-analysis-of-the-new-team9-malware-family/ 
14.	https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges 
15.	https://book.hacktricks.xyz/c2/cobalt-strike 
16.	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-284a 
17.	https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-cuba 
18.	https://blogs.vmware.com/security/2022/10/lockbit-3-0-also-known-as-lockbit-black.html 
19.	https://redcanary.com/threat-detection-report/techniques/lsass-memory/ 
20.	https://www.onlinehashcrack.com/how-to-procdump-mimikatz-credentials.php 
21.	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-284a 
22.	https://learn.microsoft.com/en-us/sysinternals/downloads/psexec 
23.	https://www.netskope.com/blog/blackcat-ransomware-tactics-and-techniques-from-a-targeted-attack 
24.	https://www.trendmicro.com/vinfo/sg/security/news/ransomware-spotlight/ransomware-spotlight-clop 
25.	https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-lockbit 
26.	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-284a 
27.	https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/ransomware-double-extortion-and-beyond-revil-clop-and-conti 
28.	https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a 
29.	https://socradar.io/dark-web-profile-lockbit-3-0-ransomware/
---

*For more detailed insights and examples, refer to the specific sections within the document.*



