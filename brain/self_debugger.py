"""
brain/self_debugger.py

Classifies exploit failures by pattern-matching error output,
suggests targeted fixes, and optionally applies auto-fixes.
"""
import re
from utils.logger import get_logger
logger = get_logger('SelfDebugger')
_PATTERNS = [('gcc.*not found|No such file.*gcc|gcc: command', 'missing_compiler', 'GCC not found on target — trying pre-compiled binary.'), ('python3?.*not found|No module named|python.*command not found', 'missing_python', 'Python not available — this exploit requires Python on the target.'), ('Permission denied|Operation not permitted|EPERM', 'permission_denied', 'Permission denied — target may be patched, or SELinux/AppArmor is enforcing.'), ('Segmentation fault|Segfault|core dumped|SIGSEGV', 'segfault', 'Exploit crashed (segfault) — possible architecture mismatch or kernel mitigations.'), ('GLIBC.*not found|version.*GLIBC|libc.*not found', 'glibc_mismatch', 'GLIBC version mismatch — use a statically compiled binary.'), ('command not found|No such file or directory', 'missing_dep', 'Required binary/file not found on PATH — verify exploit dependencies.'), ('File exists|already exists|Device or resource busy', 'idempotent_state', 'Exploit artifact already present — cleaning up and retrying.'), ('Connection refused|Network unreachable|ECONNREFUSED', 'network_error', 'Network error — verify listener is running and port is correct.'), ('timeout|Timed out|ETIMEDOUT', 'timeout', 'Exploit timed out — may need a longer timeout or the binary is stuck.'), ('syntax error|SyntaxError|IndentationError', 'syntax_error', 'Script syntax error — the uploaded exploit script has a Python error.'), ('not.*SUID|No SUID|suid.*not set', 'suid_not_set', 'SUID bit not set — target binary may have been patched since enumeration.'), ('sudo.*password|password.*required|no tty present', 'sudo_needs_password', 'Sudo requires a password for this binary — try a different sudo binary.')]
_AUTO_FIXABLE = {'missing_compiler': 'use_precompiled', 'idempotent_state': 'cleanup_artifacts'}
_FIX_HINTS = {'missing_compiler': 'Use pre-compiled binary (set precompiled_binary in exploit_kb.json), or cross-compile locally.', 'missing_python': 'Install python3 on target: apt-get install python3. Or use a non-Python exploit vector.', 'permission_denied': 'Check for AppArmor (aa-status) / SELinux (getenforce). Try disabling or using a bypass.', 'segfault': 'Verify target architecture (uname -m) and recompile for that arch. Check kernel mitigation flags.', 'glibc_mismatch': "Compile with 'musl-gcc -static' or download a musl-compiled binary.", 'missing_dep': "Run 'which <tool>' on target to confirm. Install missing dependency or embed it in exploit.", 'idempotent_state': 'Remove previous exploit artifacts: rm -f /tmp/.pred_*', 'network_error': 'Verify lhost/lport in config.yaml match your machine. Check firewall rules.', 'timeout': 'Increase exploit timeout in config.yaml:brain.exploit_timeout, or use a background job.', 'syntax_error': 'Check the generated exploit script for Python version compatibility.', 'suid_not_set': 'Re-run enumeration — SUID status may have changed. Try another SUID binary.', 'sudo_needs_password': "Run 'sudo -l' again. Look for other NOPASSWD entries or other sudo vectors."}

class SelfDebugger:
    """
    Classifies exploit failures and suggests (or applies) fixes.

    Usage:
        debugger = SelfDebugger(llm_advisor=None)
        diagnosis = debugger.diagnose("sudo_abuse", error_output)
        fixed_rec  = debugger.auto_fix(diagnosis["category"], rec, session)
    """

    def __init__(self, llm_advisor=None):
        self.llm = llm_advisor

    def diagnose(self, exploit_name: str, error_output: str) -> dict:
        """
        Classify the failure and return a structured diagnosis.

        Returns
        -------
        {
            category     : str,
            message      : str,
            fix_hint     : str,
            auto_fixable : bool,
        }
        """
        combined = error_output.strip()
        for pattern, category, message in _PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                logger.info(f'Diagnosed {exploit_name} failure: {category}')
                return {'category': category, 'message': message, 'fix_hint': _FIX_HINTS.get(category, ''), 'auto_fixable': category in _AUTO_FIXABLE}
        llm_hint = ''
        if self.llm:
            try:
                llm_hint = self.llm.explain_failure(exploit_name, error_output)
            except Exception:
                pass
        return {'category': 'unknown', 'message': 'Unrecognised failure pattern.', 'fix_hint': llm_hint or 'Review the error output above for clues.', 'auto_fixable': False}

    def auto_fix(self, category: str, exploit_rec: dict, session=None) -> dict | None:
        """
        Attempt automatic remediation.

        Returns a (possibly modified) exploit rec to retry, or None if unfixable.
        """
        if category not in _AUTO_FIXABLE:
            return None
        strategy = _AUTO_FIXABLE[category]
        if strategy == 'use_precompiled':
            precompiled = exploit_rec.get('precompiled_binary')
            if precompiled:
                logger.info(f'Auto-fix: switching to precompiled binary {precompiled}')
                rec = dict(exploit_rec)
                rec['use_precompiled'] = True
                return rec
            logger.warning('No precompiled binary registered — cannot auto-fix.')
            return None
        if strategy == 'cleanup_artifacts':
            if session:
                logger.info('Auto-fix: cleaning up previous exploit artifacts')
                session.run_command('rm -f /tmp/.pred_* /tmp/_baron* /tmp/pwn* 2>/dev/null')
            return exploit_rec
        return None

    def format_for_ui(self, diagnosis: dict) -> str:
        """Format diagnosis as a rich markup string for the TUI log."""
        cat = diagnosis['category']
        msg = diagnosis['message']
        hint = diagnosis['fix_hint']
        fixable = '✅ auto-fixable' if diagnosis['auto_fixable'] else '⚠ manual fix required'
        return f'[bold red]⚡ Self-Debugger:[/bold red] [yellow]{msg}[/yellow]\n   [dim]Category: {cat} | {fixable}[/dim]\n   [cyan]Fix: {hint}[/cyan]'
