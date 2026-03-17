import json
import os
from typing import List, Dict, Any

def get_gtfobins():
    try:
        path = os.path.join(os.path.dirname(__file__), 'gtfobins.json')
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}
GTFOBINS = get_gtfobins()

class Finding:

    def __init__(self, title: str, description: str, severity: str, items: List[str], mitre_technique: str='', remediation: str='', confidence: float=1.0, exploitation: str=''):
        self.title = title
        self.description = description
        self.severity = severity
        self.items = items
        self.mitre_technique = mitre_technique
        self.remediation = remediation
        self.confidence = confidence
        self.exploitation = exploitation

class FindingGroup:

    def __init__(self, category_name: str, findings: List[Finding]):
        self.category_name = category_name
        self.findings = findings
        self.severity = self._calculate_severity()

    def _calculate_severity(self):
        if not self.findings:
            return 'Info'
        severities = [f.severity for f in self.findings]
        for s in ['Critical', 'High', 'Medium', 'Low']:
            if s in severities:
                return s
        return 'Info'

def format_linux_findings(parsed_data: Dict[str, Any]) -> List[FindingGroup]:
    groups = []
    suid_binaries = parsed_data.get('suid_binaries', [])
    if suid_binaries:
        findings = []
        for bin_path in suid_binaries:
            bin_name = bin_path.split('/')[-1]
            exploit_cmd = GTFOBINS.get(bin_name, '')
            exploitation = f'[bold green]Exploitation via GTFOBins ({bin_name}):[/bold green]\n{exploit_cmd}' if exploit_cmd else 'No specific GTFOBins payload known, but it may still be exploitable (e.g., via library injection).'
            findings.append(Finding(title=f'SUID Exception: {bin_name}', description=f'The binary at {bin_path} has the SUID bit set. If this binary can execute shell commands or read files, it could lead to privilege escalation.', severity='High' if any((x in bin_path for x in ['python', 'bash', 'sh', 'cp', 'mv', 'find', 'nano', 'vim', 'awk'])) else 'Medium', items=[bin_path], mitre_technique='T1548.001', remediation='Remove the SUID bit if not strictly necessary: chmod u-s <file>', exploitation=exploitation))
        groups.append(FindingGroup('File Permissions: SUID/SGID', findings))
    has_nopasswd = parsed_data.get('has_nopasswd', False)
    nopasswd_entries = parsed_data.get('nopasswd', [])
    if has_nopasswd and nopasswd_entries:
        for entry in nopasswd_entries:
            bin_path = entry.split()[0] if entry else ''
            bin_name = bin_path.split('/')[-1] if bin_path else ''
            exploit_cmd = GTFOBINS.get(bin_name, '')
            if exploit_cmd:
                exploit_cmd = f'sudo {exploit_cmd}'
            exploitation = f'[bold green]Exploitation via GTFOBins ({bin_name}):[/bold green]\n{exploit_cmd}' if exploit_cmd else 'No specific GTFOBins payload known for this sudo binary.'
            findings = [Finding(title=f'Sudo NOPASSWD Execution: {bin_name}', description=f'The current user can execute `{entry}` via sudo without providing a password. This is a direct privilege escalation vector.', severity='Critical', items=[entry], mitre_technique='T1548.003', remediation='Remove NOPASSWD directives from /etc/sudoers.', exploitation=exploitation)]
            groups.append(FindingGroup('Sudo Misconfigurations', findings))
    kernel_version = parsed_data.get('kernel_version', 0.0)
    kernel_str = parsed_data.get('kernel_version_str', '')
    if kernel_version > 0.0:
        severity = 'High' if kernel_version < 4.1 else 'Low'
        description = f'Kernel version {kernel_str} is running.'
        if severity == 'High':
            description += ' This kernel is heavily outdated and likely vulnerable to public exploits (e.g. DirtyCow, Polkit).'
        findings = [Finding(title='Kernel Version Analysis', description=description, severity=severity, items=[kernel_str], mitre_technique='T1068', remediation='Update the system kernel to the latest patched version.')]
        groups.append(FindingGroup('Kernel Vulnerabilities', findings))
    return groups

def format_windows_findings(parsed_data: Dict[str, Any]) -> List[FindingGroup]:
    groups = []
    if parsed_data.get('always_install_elevated', False):
        findings = [Finding(title='AlwaysInstallElevated is Enabled', description='The Windows registry has AlwaysInstallElevated set to 1. This allows any user (including unprivileged) to install MSI packages with NT AUTHORITY\\SYSTEM privileges.', severity='Critical', items=['HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer'], mitre_technique='T1548.002', remediation='Disable AlwaysInstallElevated in Group Policy.')]
        groups.append(FindingGroup('Registry Misconfigurations', findings))
    privileges = parsed_data.get('privileges', [])
    if privileges:
        high_value = ['SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeTcbPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege']
        matched = [p for p in privileges if p in high_value]
        if matched:
            findings = [Finding(title='Dangerous Token Privileges Enabled', description='The current user account has dangerous privileges assigned that can be abused to escalate to SYSTEM (e.g. via RoguePotato, PrintSpoofer).', severity='Critical', items=matched, mitre_technique='T1134', remediation='Revoke these privileges from standard user accounts via Local Security Policy.')]
            groups.append(FindingGroup('Token Privilege Misconfigurations', findings))
    return groups

def generate_findings(parsed_data: Dict[str, Any], platform: str) -> List[FindingGroup]:
    if platform.lower() == 'linux':
        return format_linux_findings(parsed_data)
    elif platform.lower() == 'windows':
        return format_windows_findings(parsed_data)
    return []
