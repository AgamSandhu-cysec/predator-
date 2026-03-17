import re
from utils.logger import get_logger
logger = get_logger('PEASParser')

def parse(peas_output: str) -> list[dict]:
    """
    Parses raw ANSI-colored PEAS output into structured findings.
    Looks for SUIDs, specific CVEs/Kernels, Writable files, and Sudo rules.
    """
    findings = []
    ansi_escape = re.compile('\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', peas_output)
    lines = clean_text.splitlines()
    current_section = None
    for line in lines:
        line_stripped = line.strip()
        if 'SUID - Check easy privesc' in line_stripped:
            current_section = 'suid'
        elif 'Linux Exploit Suggester' in line_stripped or 'CVEs Check' in line_stripped:
            current_section = 'kernel'
        elif "Checking 'sudo -l'" in line_stripped:
            current_section = 'sudo'
        if current_section == 'suid' and line_stripped.startswith('-rws'):
            parts = line_stripped.split()
            if len(parts) >= 9:
                binary_path = parts[-1]
                binary_name = binary_path.split('/')[-1]
                findings.append({'type': 'suid', 'data': binary_name, 'path': binary_path, 'severity': 'High', 'description': f'SUID binary found: {binary_path}'})
        elif current_section == 'kernel' and 'CVE-' in line_stripped and ('Vulnerable' in line_stripped):
            cve_match = re.search('(CVE-\\d{4}-\\d{4,7})', line_stripped)
            if cve_match:
                cve = cve_match.group(1)
                findings.append({'type': 'kernel', 'data': cve, 'severity': 'Critical', 'description': f'Kernel vulnerability detected: {cve}'})
        elif current_section == 'sudo' and 'NOPASSWD:' in line_stripped:
            parts = line_stripped.split('NOPASSWD:')
            if len(parts) > 1:
                cmd = parts[1].strip()
                cmd_name = cmd.split('/')[-1].split()[0]
                findings.append({'type': 'sudo', 'data': cmd_name, 'path': cmd, 'severity': 'High', 'description': f'NOPASSWD sudo access for: {cmd}'})
    logger.info(f'Parsed {len(findings)} actionable findings from PEAS output.')
    return findings

def extract_critical_findings(peas_output: str) -> list[dict]:
    """
    Parse the LinPEAS output and return a list of critical/high severity findings
    for the Quick Wins panel.
    Returns: list of dicts with title, severity, line, type, context.
    """
    findings = []
    lines_raw = peas_output.splitlines()
    ansi_escape = re.compile('\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])')
    current_section = 'General'
    for raw_line in lines_raw:
        clean_line = ansi_escape.sub('', raw_line).strip()
        if not clean_line:
            continue
        if clean_line.startswith('╔════') or clean_line.startswith('═'):
            continue
        header_match = re.search('\\[i\\]\\s*(.*)', clean_line)
        if header_match:
            current_section = header_match.group(1).strip()
            continue
        is_critical = '31;103m' in raw_line or '103;31m' in raw_line
        is_high = '31m' in raw_line and (not is_critical)
        if is_critical or is_high:
            finding_type = 'unknown'
            clean_lower = clean_line.lower()
            section_lower = current_section.lower()
            if 'cve-' in clean_lower:
                finding_type = 'cve'
            elif 'suid' in section_lower:
                finding_type = 'suid'
            elif 'nopasswd' in clean_line or 'sudo' in section_lower:
                finding_type = 'sudo'
            elif 'writable' in clean_lower or 'write' in section_lower:
                finding_type = 'writable'
            severity = 'Critical' if is_critical else 'High'
            title = clean_line[:80] + '...' if len(clean_line) > 80 else clean_line
            findings.append({'title': title, 'severity': severity, 'line': clean_line, 'type': finding_type, 'context': current_section})
    logger.info(f'Extracted {len(findings)} Quick Wins findings from PEAS output.')
    return findings

def extract_priv_esc_flags(peas_output: str) -> dict:
    """
    Scan LinPEAS output for high-value privilege-escalation signals.
    Returns a dict of bool flags used by predictor.py to boost exploit confidence.

    Flag                    → implies exploit
    dirtycow_possible       → dirtycow
    baron_samedit           → sudo_baron_samedit (CVE-2021-3156)
    ms17_010_possible       → eternalblue
    sudo_nopasswd           → sudo-based exploits
    suid_python             → suid_python
    suid_bash               → suid_bash
    se_impersonate          → hotpotato / juicypotato
    always_install_elevated → always_install_elevated
    unquoted_service        → unquoted_path
    writable_service        → service exploit
    cron_writable           → cron-based exploits
    """
    import re as _re
    ansi_escape = _re.compile('\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', peas_output).lower()
    flags = {'dirtycow_possible': 'cve-2016-5195' in clean, 'baron_samedit': 'cve-2021-3156' in clean, 'ms17_010_possible': 'ms17-010' in clean or 'eternalblue' in clean, 'sudo_nopasswd': 'nopasswd' in clean, 'suid_python': bool(_re.search('-rws.{3,30}/usr/\\S*python', clean)), 'suid_bash': bool(_re.search('-rws.{3,30}/usr/\\S*bash', clean)), 'se_impersonate': 'seimpersonateprivilege' in clean, 'always_install_elevated': 'alwaysinstallelevated' in clean, 'unquoted_service': 'unquoted' in clean and 'service' in clean, 'writable_service': 'writable' in clean and 'service' in clean, 'cron_writable': 'cron' in clean and 'writable' in clean}
    active = [k for k, v in flags.items() if v]
    logger.info(f"LinPEAS priv-esc flags detected: {active or ['none']}")
    return flags
