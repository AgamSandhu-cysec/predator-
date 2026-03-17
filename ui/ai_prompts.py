"""
ui/ai_prompts.py — Prompt engineering for Predator AI Exploiter

Centralised prompt templates so they can be tuned without touching UI code.
"""
from __future__ import annotations
import json
import os

def build_analysis_prompt(raw_findings: dict, linpeas_output: str, parsed_findings: dict, os_type: str='linux') -> str:
    """
    Build a comprehensive privilege-escalation analysis prompt.

    Prioritises real findings:
      - parsed_findings (structured: suid_binaries, nopasswd, writable paths, kernel)
      - raw_findings (full enumeration command output dict)
      - linpeas_output (raw LinPEAS/WinPEAS text — truncated to 6000 chars for tokens)
    """
    pf = parsed_findings or {}
    rf = raw_findings or {}
    kernel_str = pf.get('kernel_version_str') or rf.get('kernel_version_str') or 'unknown'
    suid_list = pf.get('suid_binaries') or rf.get('suid_binaries') or []
    nopasswd = pf.get('nopasswd') or rf.get('nopasswd') or []
    w_passwd = pf.get('writable_passwd') or rf.get('writable_passwd') or False
    w_shadow = pf.get('writable_shadow') or rf.get('writable_shadow') or False
    cron_jobs = pf.get('cron_jobs') or rf.get('cron_jobs') or []
    caps_list = pf.get('capabilities') or rf.get('capabilities') or []
    nfs_squash = pf.get('nfs_no_root_squash') or rf.get('nfs_no_root_squash') or False
    sgid_list = pf.get('sgid_binaries') or rf.get('sgid_binaries') or []
    structured = f"Kernel: {kernel_str}\nSUID binaries: {(', '.join((str(s) for s in suid_list)) if suid_list else 'none')}\nSGID binaries: {(', '.join((str(s) for s in sgid_list)) if sgid_list else 'none')}\nSudo NOPASSWD entries: {(', '.join((str(n) for n in nopasswd)) if nopasswd else 'none')}\n/etc/passwd writable: {w_passwd}\n/etc/shadow writable: {w_shadow}\nCapabilities: {(', '.join((str(c) for c in caps_list)) if caps_list else 'none')}\nCron jobs: {(', '.join((str(c) for c in cron_jobs[:10])) if cron_jobs else 'none')}\nNFS no_root_squash: {nfs_squash}\n"
    _module_root = os.path.join(os.path.dirname(__file__), '..', 'exploits')
    available_mods = []
    for sub in ('linux', 'manual'):
        d = os.path.join(_module_root, sub)
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.py') and (not f.startswith('_')):
                    available_mods.append(f'{sub}/{f[:-3]}')
    mods_text = '\n'.join((f'  - {m}' for m in sorted(available_mods)))
    peas_excerpt = ''
    if linpeas_output:
        peas_excerpt = _extract_peas_sections(linpeas_output, max_chars=5000)
    raw_json = json.dumps(rf, default=str, indent=2)
    if len(raw_json) > 3000:
        raw_json = raw_json[:3000] + '\n... (truncated)'
    prompt = f"""You are PREDATOR-AI, an expert red team penetration tester.\nAnalyse the following {os_type.upper()} privilege escalation data and respond with a JSON array of exploit vectors.\n\n=== STRUCTURED ENUMERATION SUMMARY ===\n{structured}\n\n=== RAW ENUMERATION FINDINGS (JSON) ===\n{raw_json}\n\n=== LINPEAS/WINPEAS OUTPUT (KEY SECTIONS) ===\n{(peas_excerpt if peas_excerpt else '(not available — run PEAS first)')}\n\n=== AVAILABLE EXPLOIT MODULES ===\n{mods_text}\n\n=== INSTRUCTIONS ===\nAnalyse ALL the above findings carefully. Suggest ONLY techniques that are applicable given the ACTUAL findings.\nDO NOT suggest writable /etc/shadow if writable_shadow is False.\nDO NOT suggest DirtyCow if kernel version is above 4.0.\nDO reference module names from the Available Exploit Modules list when applicable.\n\nReturn ONLY a valid JSON array (no other text). Each element must have:\n{{\n  "name": "short_slug",           // snake_case identifier\n  "description": "one-line why",  // specific to the findings, not generic\n  "type": "module" or "command",  // "module" if in Available list, else "command"\n  "module": "linux/dirtycow",     // only if type=module (path as listed above)\n  "commands": ["cmd1","cmd2"],    // only if type=command; exact copy-paste commands\n  "confidence": "High" or "Medium" or "Low",\n  "prerequisites": "what is needed"\n}}\n\nRank by confidence descending. Maximum 8 entries.\nRespond with the JSON array ONLY — no markdown fences, no explanation.\n"""
    return prompt

def _extract_peas_sections(peas_output: str, max_chars: int=5000) -> str:
    """
    Pull only the most relevant sections from LinPEAS output to save tokens.
    Sections: SUID, Sudo, Cron, Capabilities, /etc/passwd, /etc/shadow, Kernel, NFS.
    """
    import re
    key_headers = ['SUID', 'Sudo', 'NOPASSWD', 'Cron', 'Capabilities', 'passwd', 'shadow', 'Kernel', 'NFS', 'Writable', 'interesting', 'CVE', 'capabilities', 'docker', 'lxd']
    lines = peas_output.splitlines()
    result_lines = []
    capture = False
    capture_count = 0
    MAX_SECTION_LINES = 30
    for line in lines:
        if any((kw.lower() in line.lower() for kw in key_headers)):
            capture = True
            capture_count = 0
        if capture:
            result_lines.append(line)
            capture_count += 1
            if capture_count >= MAX_SECTION_LINES:
                capture = False
    excerpt = '\n'.join(result_lines)
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars] + '\n...(truncated)'
    return excerpt or peas_output[:max_chars]

def build_self_debug_prompt(exploit_name: str, error: str, commands: list) -> str:
    """Prompt to ask AI for an alternative when an exploit fails."""
    return f"The exploit '{exploit_name}' failed with this error:\n{error}\n\nCommands attempted:\n" + '\n'.join((f'  $ {c}' for c in commands)) + '\n\nSuggest ONE alternative approach. Respond with a single JSON object (not an array): {name, description, type, commands or module, confidence, prerequisites}.'
