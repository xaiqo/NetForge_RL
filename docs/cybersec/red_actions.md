# Red Team Action Catalogue

Complete reference for all 17 Red Team actions. Each action documents its real-world origin, preconditions, success mechanics, SIEM footprint, and reward impact.

---

## Reconnaissance Phase

### `NetworkScan`
**MITRE**: T1046 — Network Service Discovery  
**Real tool**: nmap, masscan  
**Agent**: `red_commander`  
**Cost**: 5 energy | **Duration**: 3 ticks

Maps active IP addresses across a target subnet. This is the mandatory first action in any kill chain — without it, the Red agent cannot discover which hosts to exploit.

| Property | Value |
|----------|-------|
| Precondition | None — always valid |
| Effect | Updates `agent_knowledge` with discovered host IPs |
| SIEM footprint | Sysmon Event ID 3 (network connection bursts) |
| Blocks | Blue `ConfigureACL` on port 80/443/22 can slow subsequent probing |

---

### `DiscoverRemoteSystems`
**MITRE**: T1018 — Remote System Discovery  
**Real tool**: net view, BloodHound, ICMP ping sweep  
**Agent**: `red_commander`  
**Cost**: 3 energy | **Duration**: 2 ticks

Executes a ping sweep to enumerate live hosts. Interacts with Blue's deception layer — if a subnet contains active decoy nodes (`DecoyApache`, `DecoySSHD`, `DecoyTomcat`), the returned host list is poisoned with fake IPs.

| Property | Value |
|----------|-------|
| Precondition | None |
| Effect on Honeypot | Returns fake IP list `['10.x.x.99', '10.x.x.100']` |
| SIEM footprint | Sysmon Event ID 3 (ICMP / ARP bursts), Event ID 4625 (failed auth probes) |

---

### `DiscoverNetworkServices`
**MITRE**: T1046 — Network Service Scanning  
**Real tool**: nmap -sS -sV, Nessus  
**Agent**: `red_commander`  
**Cost**: 2 energy | **Duration**: 3 ticks

Port scan against a specific host to enumerate running services, OS banner, and known vulnerabilities. This is the key intelligence-gathering step before choosing which exploit to use.

| Property | Value |
|----------|-------|
| Precondition | Host in `agent_knowledge` |
| Output | `host.services`, `host.os`, `host.vulnerabilities` |
| Decoy interaction | Returns fake service banners if host has active decoy |
| SIEM footprint | Sysmon Event ID 3 (port scan burst), Event ID 4625 |

---

## Initial Access Phase

### `ExploitEternalBlue`
**MITRE**: T1210 — Exploitation of Remote Services  
**CVE**: MS17-010 (EternalBlue)  
**Real tool**: Metasploit `exploit/windows/smb/ms17_010_eternalblue`  
**Agent**: `red_operator`  
**Cost**: 10 energy | **Duration**: 5 ticks

Exploits the MS17-010 SMB vulnerability present in unpatched Windows 7 / Server 2008 systems. One of the most historically significant exploits ever deployed — used by WannaCry, NotPetya, and the NSA's Shadow Brokers toolkit.

| Property | Value |
|----------|-------|
| Precondition | `can_route_to(target_ip)`, port 445 reachable |
| Target OS | `Windows_7`, `Windows_Server_2008` (penalty on Linux) |
| Base success rate | 72% (OS-matched) |
| Sim2Real | Dispatches to `Sim2RealBridge` → real Docker exec of echo-payload |
| SIEM footprint | Sysmon 3 (dst_port=445), Event ID 4624 (NTLM logon) |
| On success | Sets `host.privilege = 'Root'`, `compromised_by = agent_id` |
| Reward delta | +5.0 (success), -10.0 to -25.0 (failure tiers) |

??? example "Authentic Metasploit STDOUT (from `payload_library.json`)"
    ```
    [*] Started reverse TCP handler on 10.0.0.1:4444
    [*] 10.0.1.3:445 - Sending all but last fragment of exploit packet
    [+] 10.0.1.3:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
    [*] Sending stage (200262 bytes) to 10.0.1.3
    [*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.1.3:1042)
    meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM
    ```

---

### `ExploitBlueKeep`
**MITRE**: T1210 — Exploitation of Remote Services  
**CVE**: CVE-2019-0708 (BlueKeep)  
**Real tool**: Metasploit `exploit/windows/rdp/cve_2019_0708_bluekeep_rce`  
**Agent**: `red_operator`  
**Cost**: 12 energy | **Duration**: 5 ticks

Exploits the BlueKeep RDP vulnerability in Windows 7 / Server 2008 R2. A pre-auth, wormable RCE that does not require any credentials. Particularly dangerous because RDP (port 3389) is often exposed for remote administration.

| Property | Value |
|----------|-------|
| Precondition | `can_route_to(target_ip)`, port 3389 reachable |
| Base success rate | 58% |
| Risk | Higher BSOD probability on real targets (modelled as `failure_noisy`) |
| SIEM footprint | Sysmon 3 (dst_port=3389), Event ID 4624 |

---

### `ExploitHTTP_RFI`
**MITRE**: T1190 — Exploit Public-Facing Application  
**Technique**: Remote File Inclusion via PHP  
**Agent**: `red_operator`  
**Cost**: 8 energy | **Duration**: 3 ticks

Exploits a Remote File Inclusion vulnerability in a web application. The attacker injects a URL into a vulnerable PHP `include()` call, causing the server to fetch and execute a remote webshell. These attacks are extremely common against PHP applications missing input validation.

| Property | Value |
|----------|-------|
| Precondition | Port 80/443 open, PHP service running |
| Base success rate | 65% |
| SIEM footprint | Sysmon 3 (dst_port=80), Event ID 4688 (php-cgi.exe → cmd.exe) |

---

### `ExploitRemoteService`
**MITRE**: T1059 — Command and Scripting Interpreter  
**Agent**: `red_operator`  
**Cost**: 8 energy | **Duration**: 4 ticks

Generic remote service exploitation — covers SSH brute force, telnet, or unpatched application-specific vulnerabilities. Lower base success rate than named CVEs but broadly applicable.

| Property | Value |
|----------|-------|
| Precondition | Any open service port |
| Base success rate | 55% |
| SIEM footprint | Sysmon 3 (dst_port=22), Event ID 4625 (failed auth attempts) |

---

## Privilege Escalation Phase

### `PrivilegeEscalate`
**MITRE**: T1068 — Exploitation for Privilege Escalation  
**Real tool**: JuicyPotato, MS16-032, getsystem  
**Agent**: `red_operator`  
**Cost**: 10 energy | **Duration**: 3 ticks

Elevates from a User-level shell to SYSTEM/root. Required before credential dumping. The most common Metasploit technique is `getsystem`, which tries multiple impersonation methods automatically.

| Property | Value |
|----------|-------|
| Precondition | Host compromised (`privilege == 'User'`) |
| Base success rate | 70% |
| SIEM footprint | Event ID 4688 (cmd.exe / powershell.exe suspicious chain), Sysmon 1 |

---

### `JuicyPotato`
**MITRE**: T1134.001 — Token Impersonation/Theft  
**CVE**: None (technique-based)  
**Agent**: `red_operator`

Windows-specific token impersonation exploit for escalating from `SeImpersonatePrivilege` (typical for service accounts) to SYSTEM. Highly reliable on older Windows versions.

---

### `V4L2KernelExploit`
**MITRE**: T1068 — Exploitation for Privilege Escalation  
**Platform**: Linux  
**Agent**: `red_operator`

Linux kernel Video4Linux2 (V4L2) race condition exploit. Targets Linux systems where standard `getsystem` tactics don't apply.

---

## Credential Access Phase

### `DumpLSASS`
**MITRE**: T1003.001 — OS Credential Dumping: LSASS Memory  
**Real tool**: Mimikatz (`sekurlsa::logonpasswords`), ProcDump  
**Agent**: `red_operator`  
**Cost**: 15 energy | **Duration**: 2 ticks

Dumps plaintext credentials and Kerberos tickets from the Windows LSASS process memory. This is the **critical bridge** to the Secure subnet — the stolen `Enterprise_Admin_Token` is what unlocks ZTNA routing.

| Property | Value |
|----------|-------|
| Precondition | `host.privilege == 'Root'` (SYSTEM access required to read lsass.exe memory) |
| Effect | Copies `host.cached_credentials` to `agent_inventory` |
| SIEM footprint | **Sysmon 10 (ProcessAccess targeting lsass.exe)** — high-fidelity indicator |
| Defender counter | `RotateKerberos` flushes stolen tokens from `agent_inventory` globally |

!!! warning "Highest-Fidelity SIEM Signal"
    `DumpLSASS` generates **Sysmon Event ID 10** — a process accessing lsass.exe with `GrantedAccess=0x1010`. This is one of the most reliable true-positive indicators in real SOC environments. A well-trained Blue LSTM that reads SIEM embeddings should learn to immediately respond to this event.

??? example "Authentic Mimikatz STDOUT"
    ```
    sekurlsa::logonpasswords

    Authentication Id : 0 ; 248731
    User Name        : Administrator
    Domain           : CORP
    Logon Server     : DC01
      [00000003] Primary
       * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
       * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
    ```

---

## Lateral Movement Phase

### `PassTheTicket`
**MITRE**: T1550.003 — Use Alternate Authentication Material: Pass the Ticket  
**Real tool**: Rubeus (`ptt`), Impacket  
**Agent**: `red_operator`  
**Cost**: 5 energy | **Duration**: 1 tick

Uses a stolen Kerberos TGT to authenticate to a target host **without knowing the password**. This is how Red breaches the Secure subnet — the ZTNA layer checks the `agent_inventory` for a valid token matching `host.system_tokens`.

| Property | Value |
|----------|-------|
| Precondition | Token in `agent_inventory` matches `host.system_tokens` |
| Effect | Sets `host.privilege = 'Root'` on target |
| SIEM footprint | Event ID 4768 (TGT request), Event ID 4648 (explicit credentials) |
| Defender counter | `RotateKerberos` invalidates all held tickets globally |

---

### `ShareIntelligence`
**MITRE**: T1005 — Data from Local System  
**Agent**: `red_commander`

Commander-level coordination — shares discovered host data and vulnerability information between Red Commander and Red Operator. Models the real APT practice of BloodHound enumeration data sharing between team members.

---

## Impact Phase

### `KillProcess`
**MITRE**: T1562.001 — Impair Defenses: Disable or Modify Tools  
**Real tool**: taskkill, SIGKILL  
**Agent**: `red_operator`

Terminates security monitoring processes (AV, EDR, SIEM forwarders) on a compromised host.

---

### `Impact`
**MITRE**: T1486 — Data Encrypted for Impact  
**Agent**: `red_operator`  
**Reward**: `+2,000` for Red

Deploys a ransomware payload against a compromised host. Models WannaCry/REvil-style ransomware operations that encrypt files and demand payment.

---

### `OverloadPLC`
**MITRE ICS**: T0882 — Theft of Operational Information  
**Platform**: OT/ICS (Secure subnet only)  
**Agent**: `red_operator`  
**Reward**: `+10,000` for Red / `-10,000` for Blue

The **most impactful action in the environment**. Sends malicious commands to a PLC controller in the Secure subnet, causing physical process disruption. Models Stuxnet, Triton/TRISIS.

!!! danger "Kinetic Impact"
    This action requires the full kill chain to execute (ZTNA breach via `PassTheTicket`). The ±10,000 reward creates a non-linear landscape that forces Red to choose between fast-but-cheap ransomware vs. expensive-but-maximal OT impact.

---

### `SpearPhishing`
**MITRE**: T1566.001 — Spearphishing Attachment  
**Real tool**: GoPhish, custom lures  
**Agent**: `red_commander`

Launches a targeted phishing campaign against a subnet. Success is probabilistic against `host.human_vulnerability_score`, bypassing technical controls entirely. Countered by Blue's `SecurityAwarenessTraining`.

| Property | Value |
|----------|-------|
| Formula | `success = random() < host.human_vulnerability_score * 0.85` |
| Blocked by | `SecurityAwarenessTraining` reduces score to 20% |
| SIEM footprint | No direct SIEM indicator — socially engineered access looks like legitimate logon |
