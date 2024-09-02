# <img src="hacker.png" alt="logo" width="50"/> VulndowsPen

<span style="color:#FF474C; font-size:24px; font-weight:bold;">VulndowsPen</span> is a comprehensive Python-based tool for configuring Windows vulnerabilities for penetration testing and educational purposes. It provides both a graphical user interface (GUI) and a command-line interface (CLI) for applying a wide range of vulnerability configurations to a Windows system. I created this tool for ease of use for whenever I wanted to spin up a purposely vulnerable virtual machine for penetration testing.

## Features

- GUI for easy configuration of vulnerabilities
- CLI support for scripting and automation
- Multiple difficulty presets (Babies Only, Easy, Somewhat Easy, Medium, Medium-ish, Hard, Harder, Epic)
- Extensive set of vulnerability options (70+)
- Logging system for tracking applied vulnerabilities
- Configuration file for persistent settings

## Prerequisites
1. Python 3.10+ [Download Python](https://www.python.org/ftp/python/3.10.0/python-3.10.0-amd64.exe) (md5: c3917c08a7fe85db7203da6dcaa99a70)
2. Git [Download Git](https://github.com/git-for-windows/git/releases/download/v2.46.0.windows.1/Git-2.46.0-64-bit.exe)

## Installation

1. Ensure you have Python 3.10+ installed on your system.
2. Clone this repository:
   ```
   git clone https://github.com/followthesapper/VulndowsPen.git
   cd VulndowsPen
   ```
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### GUI Mode

To run VulndowsPen in GUI mode, simply execute:

```
python main.py
```

### CLI Mode

To use VulndowsPen from the command line:

```
python main.py --cli --apply "Disable Windows Defender" "Disable Windows Firewall"
```

Replace the vulnerability names with the ones you want to apply.

## Vulnerability Options

VulndowsPen offers a wide range of vulnerability options, including but not limited to:

1. Disable Windows Defender
2. Disable Windows Firewall
3. Create Weak Password Policy
4. Enable LLMNR
5. Allow Unsigned PowerShell Scripts
6. Enable RDP with Weak Encryption
7. Lower UAC Settings
8. Configure Weak SMB Settings
9. Create Weak AD Password Policy
10. Disable Windows Updates
11. Enable Anonymous SID Enumeration
12. Disable SMB Signing
13. Enable WDigest Authentication
14. Disable PowerShell Script Block Logging
15. Enable Insecure LDAP Authentication
16. Disable Windows Defender Real-time Protection
17. Disable Windows Defender Cloud-delivered Protection
18. Disable Windows Defender Behavior Monitoring
19. Disable Windows Defender Network Protection
20. Enable SMBv1
21. Disable SMB Encryption
22. Enable Guest Account
23. Set Guest Account Password
24. Add Guest to Administrators Group
25. Allow Remote Assistance
26. Enable Telnet Server
27. Disable User Account Control (UAC)
28. Enable AutoRun for All Drives
29. Disable Windows SmartScreen
30. Enable Remote Desktop without Network Level Authentication
31. Disable Windows Defender Exploit Protection
32. Enable NetBIOS over TCP/IP
33. Disable IPv6
34. Enable Anonymous Share Access
35. Disable Windows Defender Antivirus
36. Disable Windows Defender Tamper Protection
37. Enable Weak SSL/TLS Protocols
38. Disable Windows Firewall Logging
39. Enable Weak Wireless Encryption (WEP)
40. Disable Windows Error Reporting
41. Enable File and Printer Sharing
42. Disable Windows Defender Application Guard
43. Enable Remote Registry
44. Disable Windows Defender Controlled Folder Access
45. Enable NTLM Authentication
46. Disable Windows Defender Network Inspection System
47. Enable Weak Kerberos Encryption Types
48. Disable Account Lockout
49. Enable Weak BitLocker Encryption
50. Disable Windows Defender Potentially Unwanted Application (PUA) Protection
51. Enable Autoplay for All Devices
52. Disable Windows Defender Malware and Spyware Scanning
53. Enable Weak DNS Security Extensions (DNSSEC)
54. Disable Windows Firewall Stealth Mode
55. Enable Anonymous Enumeration of SAM Accounts
56. Disable Windows Defender Real-time Protection for Removable Drives
57. Enable Weak Wi-Fi Protected Access (WPA) Encryption
58. Disable Windows Defender Scan of Downloaded Files and Attachments
59. Enable Weak IPsec Settings
60. Disable Windows Event Log
61. Enable Weak Group Policy Password Settings
62. Disable Windows Defender Smart App Control
63. Enable Weak Remote Desktop Protocol (RDP) Encryption
64. Disable Windows Defender Attack Surface Reduction Rules
65. Enable Weak NTFS Permissions
66. Disable Windows Defender Credential Guard
67. Enable Weak SMTP Authentication
68. Disable Windows Defender Device Guard
69. Enable Weak FTP Server Settings
70. Disable Windows Defender Memory Integrity
71. Enable Weak SNMP Community Strings
72. Disable Windows Defender Core Isolation
73. Enable Weak Remote Procedure Call (RPC) Settings

## Warning

This tool is intended for educational and penetration testing purposes only. Use it responsibly and only on systems you own or have explicit permission to test. Applying these vulnerabilities can severely weaken the security of a system and should never be done on production or personal systems without proper safeguards and recovery plans in place.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Created by FollowTheSapper - 2024

## Disclaimer

The authors of this tool are not responsible for any misuse or damage caused by this program. Use at your own risk.

<a href="https://www.flaticon.com/free-icons/hacker" title="hacker icons">Hacker icons created by Freepik - Flaticon</a>
