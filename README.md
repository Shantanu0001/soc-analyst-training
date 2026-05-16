# SOC Analyst Training — Home Lab

I'm building this repository as I learn SOC analysis from scratch.
Every project here is hands-on work done in a self-built VMware lab.
Real attacks, real logs, real detections. 
No CTF datasets, no pre-built environments.

## Lab Environment

| Machine | OS | Role |
|---|---|---|
| Host | Windows 11 | Analyst workstation, browser access |
| SIEM | Ubuntu Server 22.04 | Splunk Enterprise 10.2.3 |
| Target | Windows 10 (MSEdgeWin10) | Attack target, Sysmon + UF |
| IR Platform | Kali Linux | TheHive 5 in Docker |

## Projects

### Project 1 — Real Attack Detection with Splunk

Simulated 3 MITRE ATT&CK techniques using Atomic Red Team on a
Windows 10 VM. Detected each one using custom SPL queries in Splunk.
Documented full SOC investigations in TheHive.

**Attacks covered:** T1110.001 · T1003.001 · T1059.001

[→ View Project](projects/01_attack_detection_lab/README.md)