import subprocess
import logging
from config import load_config, save_config

logging.basicConfig(filename='vulndowspen.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

VULNERABILITY_OPTIONS = {
    "Basic": [
        "Disable Windows Defender",
        "Disable Windows Firewall",
        "Create Weak Password Policy",
        "Enable LLMNR",
        "Allow Unsigned PowerShell Scripts",
        "Enable RDP with Weak Encryption",
        "Lower UAC Settings",
        "Configure Weak SMB Settings",
    ],
    "Network": [
        "Disable SMB Signing",
        "Enable WDigest Authentication",
        "Enable Insecure LDAP Authentication",
        "Enable SMBv1",
        "Disable SMB Encryption",
        "Enable NetBIOS over TCP/IP",
        "Disable IPv6",
        "Enable Anonymous Share Access",
        "Enable Weak SSL/TLS Protocols",
        "Enable Weak IPsec Settings",
    ],
    "Advanced": [
        "Create Weak AD Password Policy",
        "Disable PowerShell Script Block Logging",
        "Enable Guest Account",
        "Set Guest Account Password",
        "Add Guest to Administrators Group",
        "Enable Telnet Server",
        "Disable User Account Control (UAC)",
        "Enable AutoRun for All Drives",
        "Disable Windows SmartScreen",
        "Enable Remote Desktop without Network Level Authentication",
        "Disable Account Lockout",
        "Enable Weak BitLocker Encryption",
    ],
    "Defender": [
        "Disable Windows Defender Real-time Protection",
        "Disable Windows Defender Cloud-delivered Protection",
        "Disable Windows Defender Behavior Monitoring",
        "Disable Windows Defender Network Protection",
        "Disable Windows Defender Antivirus",
        "Disable Windows Defender Tamper Protection",
        "Disable Windows Defender Application Guard",
        "Disable Windows Defender Controlled Folder Access",
        "Disable Windows Defender Network Inspection System",
        "Disable Windows Defender Potentially Unwanted Application (PUA) Protection",
        "Disable Windows Defender Malware and Spyware Scanning",
        "Disable Windows Defender Smart App Control",
        "Disable Windows Defender Attack Surface Reduction Rules",
        "Disable Windows Defender Credential Guard",
        "Disable Windows Defender Device Guard",
        "Disable Windows Defender Memory Integrity",
        "Disable Windows Defender Core Isolation",
    ],
    "Other": [
        "Disable Windows Updates",
        "Enable Anonymous SID Enumeration",
        "Allow Remote Assistance",
        "Disable Windows Automatic Updates",
        "Disable Windows Firewall for All Profiles",
        "Disable Windows Firewall Logging",
        "Enable Weak Wireless Encryption (WEP)",
        "Disable Windows Error Reporting",
        "Enable File and Printer Sharing",
        "Enable Remote Registry",
        "Enable NTLM Authentication",
        "Enable Weak Kerberos Encryption Types",
        "Enable Autoplay for All Devices",
        "Enable Weak DNS Security Extensions (DNSSEC)",
        "Disable Windows Firewall Stealth Mode",
        "Enable Anonymous Enumeration of SAM Accounts",
        "Disable Windows Defender Real-time Protection for Removable Drives", 
        "Enable Weak Wi-Fi Protected Access (WPA) Encryption",
        "Disable Windows Defender Scan of Downloaded Files and Attachments",
        "Disable Windows Event Log",
        "Enable Weak Group Policy Password Settings",
        "Enable Weak Remote Desktop Protocol (RDP) Encryption",
        "Enable Weak NTFS Permissions",
        "Enable Weak SMTP Authentication",
        "Enable Weak FTP Server Settings",
        "Enable Weak SNMP Community Strings",
        "Enable Weak Remote Procedure Call (RPC) Settings"
    ]
}

def apply_vulnerabilities(selected_vulns):
    config = load_config()
    
    if not selected_vulns:  # Insane mode: apply security measures
        apply_security_measures()
    else:
        for category, vulns in VULNERABILITY_OPTIONS.items():
            for vuln in vulns:
                if vuln in selected_vulns:
                    func_name = vuln.lower().replace(" ", "_").replace("(", "").replace(")", "")
                    if hasattr(VulnerabilityFunctions, func_name):
                        getattr(VulnerabilityFunctions, func_name)()
                        config['applied_vulnerabilities'].append(vuln)
                        logging.info(f"Applied vulnerability: {vuln}")
                    else:
                        logging.warning(f"Function not implemented for vulnerability: {vuln}")
    
    save_config(config)

def apply_security_measures():
    logging.info("Applying security measures (Insane mode)")
    SecurityMeasures.enable_windows_defender()
    SecurityMeasures.enable_windows_firewall()
    SecurityMeasures.create_strong_password_policy()
    SecurityMeasures.disable_llmnr()
    SecurityMeasures.block_unsigned_powershell_scripts()
    SecurityMeasures.enable_rdp_with_strong_encryption()
    SecurityMeasures.raise_uac_settings()
    SecurityMeasures.configure_strong_smb_settings()
    SecurityMeasures.create_strong_ad_password_policy()
    SecurityMeasures.enable_windows_updates()
    SecurityMeasures.disable_anonymous_sid_enumeration()
    SecurityMeasures.enable_smb_signing()
    SecurityMeasures.disable_wdigest_authentication()
    SecurityMeasures.enable_powershell_script_block_logging()
    SecurityMeasures.enable_secure_ldap_authentication()

class VulnerabilityFunctions:
    @staticmethod
    def disable_windows_defender():
        subprocess.run(["powershell", "Set-MpPreference", "-DisableRealtimeMonitoring", "$true"])

    @staticmethod
    def disable_windows_firewall():
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "off"])

    @staticmethod
    def create_weak_password_policy():
        subprocess.run(["net", "accounts", "/minpwlen:4", "/maxpwage:unlimited", "/minpwage:0", "/uniquepw:0"])

    @staticmethod
    def enable_llmnr():
        subprocess.run(["reg", "add", "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "EnableMulticast", "/t", "REG_DWORD", "/d", "1", "/f"])

    @staticmethod
    def allow_unsigned_powershell_scripts():
        subprocess.run(["powershell", "Set-ExecutionPolicy", "Unrestricted", "-Force"])

    @staticmethod
    def enable_rdp_with_weak_encryption():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f"])
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "/v", "MinEncryptionLevel", "/t", "REG_DWORD", "/d", "1", "/f"])

    @staticmethod
    def lower_uac_settings():
        subprocess.run(["reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "0", "/f"])

    @staticmethod
    def configure_weak_smb_settings():
        subprocess.run(["powershell", "Set-SmbServerConfiguration", "-EnableSMB1Protocol", "$true", "-Force"])
        subprocess.run(["powershell", "Set-SmbServerConfiguration", "-RequireSecuritySignature", "$false", "-Force"])

    @staticmethod
    def create_weak_ad_password_policy():
        subprocess.run(["powershell", "Import-Module", "ActiveDirectory"])
        subprocess.run(["powershell", "Set-ADDefaultDomainPasswordPolicy", "-ComplexityEnabled", "$false", "-MinPasswordLength", "4", "-LockoutThreshold", "0", "-MaxPasswordAge", "(New-TimeSpan -Days 0)", "-MinPasswordAge", "(New-TimeSpan -Days 0)", "-PasswordHistoryCount", "0"])

class SecurityMeasures:
    @staticmethod
    def enable_windows_defender():
        subprocess.run(["powershell", "Set-MpPreference", "-DisableRealtimeMonitoring", "$false"])

    @staticmethod
    def enable_windows_firewall():
        subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])

    @staticmethod
    def create_strong_password_policy():
        subprocess.run(["net", "accounts", "/minpwlen:14", "/maxpwage:42", "/minpwage:1", "/uniquepw:24"])

    @staticmethod
    def disable_llmnr():
        subprocess.run(["reg", "add", "HKLM\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "EnableMulticast", "/t", "REG_DWORD", "/d", "0", "/f"])

    @staticmethod
    def block_unsigned_powershell_scripts():
        subprocess.run(["powershell", "Set-ExecutionPolicy", "AllSigned", "-Force"])

    @staticmethod
    def enable_rdp_with_strong_encryption():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "1", "/f"])
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "/v", "MinEncryptionLevel", "/t", "REG_DWORD", "/d", "4", "/f"])

    @staticmethod
    def raise_uac_settings():
        subprocess.run(["reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"])
        subprocess.run(["reg", "add", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/v", "ConsentPromptBehaviorAdmin", "/t", "REG_DWORD", "/d", "2", "/f"])

    @staticmethod
    def configure_strong_smb_settings():
        subprocess.run(["powershell", "Set-SmbServerConfiguration", "-EnableSMB1Protocol", "$false", "-Force"])
        subprocess.run(["powershell", "Set-SmbServerConfiguration", "-RequireSecuritySignature", "$true", "-Force"])

    @staticmethod
    def create_strong_ad_password_policy():
        subprocess.run(["powershell", "Import-Module", "ActiveDirectory"])
        subprocess.run(["powershell", "Set-ADDefaultDomainPasswordPolicy", "-ComplexityEnabled", "$true", "-MinPasswordLength", "14", "-LockoutThreshold", "5", "-MaxPasswordAge", "(New-TimeSpan -Days 90)", "-MinPasswordAge", "(New-TimeSpan -Days 1)", "-PasswordHistoryCount", "24"])

    @staticmethod
    def enable_windows_updates():
        subprocess.run(["reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "/v", "NoAutoUpdate", "/t", "REG_DWORD", "/d", "0", "/f"])

    @staticmethod
    def disable_anonymous_sid_enumeration():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "/v", "RestrictAnonymous", "/t", "REG_DWORD", "/d", "1", "/f"])

    @staticmethod
    def enable_smb_signing():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "/v", "RequireSecuritySignature", "/t", "REG_DWORD", "/d", "1", "/f"])
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters", "/v", "EnableSecuritySignature", "/t", "REG_DWORD", "/d", "1", "/f"])

    @staticmethod
    def disable_wdigest_authentication():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "/v", "UseLogonCredential", "/t", "REG_DWORD", "/d", "0", "/f"])

    @staticmethod
    def enable_powershell_script_block_logging():
        subprocess.run(["reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging", "/v", "EnableScriptBlockLogging", "/t", "REG_DWORD", "/d", "1", "/f"])

    @staticmethod
    def enable_secure_ldap_authentication():
        subprocess.run(["reg", "add", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", "/v", "LDAPServerIntegrity", "/t", "REG_DWORD", "/d", "2", "/f"])