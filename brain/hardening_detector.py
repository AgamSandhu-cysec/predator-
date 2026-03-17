"""
brain/hardening_detector.py

Probes the target for active security mitigations and penalises
exploit scores accordingly.

Detected mechanisms:
  SELinux enforcing   — blocks most filesystem writes and setuid tricks
  AppArmor loaded     — restricts process capabilities
  ASLR enabled        — makes memory exploits harder
  NX bit active       — non-executable stack (affects shellcode)
  Ptrace scope > 0    — restricts process tracing (limits some exploits)
  Seccomp active      — restricts syscalls in current process
  SMEP / SMAP         — CPU kernel memory protections
"""
from utils.logger import get_logger
logger = get_logger('HardeningDetector')
_CHECKS = [('selinux', 'getenforce 2>/dev/null', lambda o: 'enforcing' in o.lower(), 0.25), ('apparmor', 'aa-status 2>/dev/null | head -3', lambda o: 'profiles are loaded' in o.lower() and '0 profiles are in enforce mode' not in o.lower(), 0.5), ('aslr', 'cat /proc/sys/kernel/randomize_va_space 2>/dev/null', lambda o: o.strip() in ('1', '2'), 0.6), ('nx_bit', "grep -q ' nx ' /proc/cpuinfo 2>/dev/null && echo YES || echo NO", lambda o: 'YES' in o, 0.85), ('ptrace_scope', 'cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null', lambda o: o.strip() not in ('0', ''), 0.7), ('seccomp', 'cat /proc/self/status 2>/dev/null | grep -i seccomp', lambda o: '2' in o, 0.6)]
_EXPLOIT_SENSITIVITY = {'selinux': {'writable_passwd', 'writable_shadow', 'cron_hijack', 'ld_preload', 'nfs_root_squash'}, 'apparmor': {'lxd_breakout', 'docker_escape', 'cron_hijack'}, 'aslr': {'dirtycow', 'dirtypipe', 'pkexec_pwnkit'}, 'nx_bit': {'dirtycow'}, 'ptrace_scope': {'dirtycow', 'dirtypipe'}, 'seccomp': {'dirtycow', 'dirtypipe', 'overlayfs'}}

class HardeningDetector:
    """
    Probe target for active security mitigations and penalise exploit scores.

    Usage
    -----
    detector = HardeningDetector()
    hardening = detector.probe(session)        # dict {mechanism: bool}
    recs = detector.penalise_scores(recs, hardening)
    report = detector.format_report(hardening)
    """

    def probe(self, session) -> dict:
        """
        Run all hardening checks against the target session.
        Returns {mechanism_name: bool} — True = active.
        """
        results: dict = {}
        for name, cmd, checker, _ in _CHECKS:
            try:
                out, _, _ = session.run_command(cmd, timeout=5)
                active = checker(out)
                results[name] = active
                if active:
                    logger.info(f'Hardening detected: {name}')
            except Exception as e:
                logger.debug(f'Hardening check failed ({name}): {e}')
                results[name] = False
        return results

    def penalise_scores(self, recs: list, hardening: dict) -> list:
        """
        Reduce confidence scores for exploits blocked by active hardening.
        Returns a re-sorted copy of *recs*.
        """
        penalised = []
        for rec in recs:
            mod = rec.get('module') or rec.get('exploit', '')
            score = float(rec.get('confidence', 0.5))
            for name, _, _, penalty in _CHECKS:
                if hardening.get(name) and mod in _EXPLOIT_SENSITIVITY.get(name, set()):
                    score *= penalty
                    logger.debug(f'Penalised {mod} by {name}: score → {score:.3f}')
            r = dict(rec)
            r['confidence'] = round(score, 3)
            if score < rec.get('confidence', score):
                r['hardening_note'] = ', '.join((k for k in hardening if hardening[k] and mod in _EXPLOIT_SENSITIVITY.get(k, set())))
            penalised.append(r)
        penalised.sort(key=lambda x: -x['confidence'])
        return penalised

    def format_report(self, hardening: dict) -> str:
        """Return a rich-markup string summarising detected hardening."""
        lines = ['[bold cyan]🛡  Hardening Report:[/bold cyan]']
        for name, _, _, _ in _CHECKS:
            active = hardening.get(name, False)
            icon = '[red]●[/red]' if active else '[green]○[/green]'
            lines.append(f"  {icon} {name.upper().replace('_', ' ')}")
        return '\n'.join(lines)

    def any_active(self, hardening: dict) -> bool:
        return any(hardening.values())
