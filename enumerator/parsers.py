import re
import os

def parse_suid_binaries(output: str) -> dict:
    """Parses SUID binary paths from the raw find output."""
    _IGNORE = {'execve', 'permission', 'denied', '', 'find:'}
    binaries = []
    lines = output.strip().split('\n')
    for line in lines:
        line = line.strip()
        if line and line.startswith('/') and (' ' not in line) and ('Permission denied' not in line) and (os.path.basename(line) not in _IGNORE):
            binaries.append(line)
    unique_binaries = sorted(set(binaries))
    return {'suid_binaries': unique_binaries, 'count': len(unique_binaries)}

def parse_sudo_l(output: str) -> dict:
    """Parses the output of sudo -l for NOPASSWD or interesting entries."""
    nopasswd_entries = []
    lines = output.strip().split('\n')
    for line in lines:
        if 'NOPASSWD:' in line:
            parts = line.split('NOPASSWD:')
            if len(parts) > 1:
                cmd = parts[1].strip()
                nopasswd_entries.append(cmd)
            else:
                nopasswd_entries.append(line.strip())
    return {'nopasswd': nopasswd_entries, 'has_nopasswd': len(nopasswd_entries) > 0}

def parse_kernel_version(output: str) -> dict:
    """
    Extracts the numeric kernel version from uname -r or /proc/version output.

    Handles formats like:
      4.15.0-55-generic
      2.6.32-5-amd64
      Linux version 5.4.0-42-generic (builder@...)
    """
    import os as _os
    val = output.strip().splitlines()[0] if output.strip() else ''
    match = re.search('(\\d+)\\.(\\d+)(?:\\.(\\d+))?', val)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2))
        version = float(f'{major}.{minor}')
    else:
        version = 0.0
    return {'kernel_version_str': val, 'kernel_version': version}

def parse_always_install_elevated(output: str) -> dict:
    """Checks if AlwaysInstallElevated is set based on reg query output."""
    is_enabled = '0x1' in output
    return {'always_install_elevated': is_enabled}

def parse_whoami_priv(output: str) -> dict:
    """Parses token privilege assignments."""
    privs = []
    for line in output.split('\n'):
        if 'Enabled' in line or 'Disabled' in line:
            parts = line.split()
            if parts:
                privs.append(parts[0])
    return {'privileges': privs, 'has_impersonate': 'SeImpersonatePrivilege' in privs}
