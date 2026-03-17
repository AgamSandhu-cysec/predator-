import yaml
import os
import joblib
from utils.logger import get_logger
logger = get_logger('Predictor')
_FLAG_TO_EXPLOIT = {'dirtycow_possible': ('dirtycow', 'DirtyCow (CVE-2016-5195)', 'static'), 'baron_samedit': ('sudo_baron_samedit', 'Baron Samedit (CVE-2021-3156)', 'static'), 'sudo_nopasswd': ('sudo_abuse', 'Sudo NOPASSWD Abuse', 'manual'), 'suid_python': ('suid_python', 'SUID Python Exploit', 'static'), 'suid_bash': ('suid_bash', 'SUID Bash Exploit', 'static'), 'se_impersonate': ('hotpotato', 'Juicy Potato (SeImpersonatePriv)', 'static'), 'always_install_elevated': ('always_install', 'AlwaysInstallElevated', 'static'), 'unquoted_service': ('unquoted_path', 'Unquoted Service Path', 'static'), 'writable_service': ('writable_service', 'Writable Service Exploit', 'static'), 'ms17_010_possible': ('ms17_010', 'EternalBlue (MS17-010)', 'static')}

class ExploitPredictor:
    """Predicts the best exploits based on parsed enumeration commands."""

    def __init__(self, os_type, config_path='config.yaml'):
        self.os_type = os_type.lower()
        self.config_path = config_path
        self.model = None
        self.load_model()
        self.category_module_map = {'SUID Binaries': ('suid_python', 'SUID Python Exploit', 'static'), 'Sudo Misconfiguration': ('sudo_abuse', 'Sudo NOPASSWD Exploit', 'manual'), 'Kernel Exploits': ('dirtycow', 'DirtyCow Kernel Exploit', 'static'), 'Kernel Misconfiguration': ('dirtycow', 'Kernel Misconfiguration Exploit', 'static'), 'Service Misconfiguration': ('unquoted_path', 'Unquoted Service Path', 'static'), 'Registry Misconfiguration': ('always_install', 'AlwaysInstallElevated', 'static'), 'Registry Autorun': ('always_install', 'AlwaysInstallElevated', 'static'), 'File Permissions': ('hotpotato', 'Hot/Juicy Potato', 'static'), 'System Misconfiguration': ('hotpotato', 'System Misconfiguration', 'static')}

    def load_model(self):
        """Load the trained NLP model."""
        model_name = 'linux_model.joblib' if self.os_type == 'linux' else 'windows_model.joblib'
        model_path = os.path.join(os.path.dirname(__file__), 'models', model_name)
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                logger.info(f'Successfully loaded NLP ML model: {model_name}')
            else:
                logger.warning(f'ML model {model_path} not found. Will use fallback.')
        except Exception as e:
            logger.error(f'Failed to load ML model: {e}')

    def predict(self, commands, raw_results):
        """
        Takes enumeration commands and raw_results and predicts exploit categories
        using the ML NLP model on successful commands.
        """
        if not raw_results:
            import logging as _logging
            _logging.warning('predict() called with empty raw_results — using rule-based fallback')
            return self.rule_based_predict({})
        recommendations = []
        successful_texts = []
        for cmd in commands:
            cid = cmd.get('id')
            output = raw_results.get(cid, '')
            if output and output.strip():
                text = f"{cmd.get('command', '')} {cmd.get('description', '')}"
                successful_texts.append(text)
        if self.model and successful_texts:
            predictions = self.model.predict(successful_texts)
            try:
                probs = self.model.predict_proba(successful_texts)
                max_probs = [max(p) for p in probs]
            except:
                max_probs = [0.8] * len(predictions)
            seen_modules = set()
            for cat, conf in zip(predictions, max_probs):
                if cat in self.category_module_map:
                    mod_name, desc, src_type = self.category_module_map[cat]
                    if mod_name not in seen_modules:
                        recommendations.append({'name': desc, 'confidence': round(conf, 2), 'description': f"ML predicted category '{cat}' based on your findings.", 'module': mod_name, 'type': src_type})
                        seen_modules.add(mod_name)
        if not recommendations:
            recommendations.append({'name': f"{('LinPEAS' if self.os_type == 'linux' else 'WinPEAS')} Auto", 'confidence': 0.4, 'description': 'Run PEAS for deeper automated enumeration', 'module': 'linpeas' if self.os_type == 'linux' else 'winpeas', 'type': 'static'})
        recommendations.sort(key=lambda x: x['confidence'], reverse=True)
        return recommendations

    def rule_based_predict(self, findings: dict) -> list:
        """
        Offline rule-based fallback predictor.
        Produces high-confidence recommendations from known findings dict.
        Returns a list of recommendation dicts, highest confidence first.
        """
        recs = []
        seen = set()

        def add(name, module, src_type, conf, desc):
            if module not in seen:
                recs.append({'name': name, 'module': module, 'type': src_type, 'confidence': conf, 'description': desc})
                seen.add(module)
        if findings.get('writable_passwd'):
            add('Writable /etc/passwd', 'writable_passwd', 'manual', 0.99, 'World-writable /etc/passwd — inject passwordless root user')
        if findings.get('writable_shadow'):
            add('Writable /etc/shadow', 'writable_shadow', 'manual', 0.98, 'World-writable /etc/shadow — replace root hash')
        if findings.get('has_nopasswd'):
            add('Sudo NOPASSWD', 'sudo_abuse', 'manual', 0.97, f"Sudo NOPASSWD: {findings.get('nopasswd', ['?'])[0]}")
        suid_list = findings.get('suid_binaries', [])
        interesting = {'python', 'python3', 'bash', 'nmap', 'vim', 'find', 'perl', 'awk', 'ruby'}
        for s in suid_list:
            bn = s.split('/')[-1]
            if bn in interesting:
                add(f'SUID {bn}', f'suid_{bn}', 'static', 0.88, f'GTFOBins: SUID {bn} can be used for root shell')
        kv = findings.get('kernel_version', 0.0)
        if 0.0 < kv <= 3.9:
            add('DirtyCow (CVE-2016-5195)', 'dirtycow', 'static', 0.92, f"Kernel {findings.get('kernel_version_str', '?')} is vulnerable")
        elif 5.8 <= kv <= 5.16:
            add('DirtyPipe (CVE-2022-0847)', 'dirtypipe', 'static', 0.9, f"Kernel {findings.get('kernel_version_str', '?')} is vulnerable")
        add('LinPEAS Auto', 'linpeas', 'static', 0.4, 'Run LinPEAS for deeper automated enumeration')
        recs.sort(key=lambda x: x['confidence'], reverse=True)
        logger.info(f'Rule-based fallback generated {len(recs)} recommendations.')
        return recs

    def boost_with_linpeas_flags(self, recommendations: list, linpeas_output: str) -> list:
        """
        Cross-reference existing recommendations against LinPEAS flags.
        - Boosts confidence +0.3 (max 1.0) for exploits that match a flag.
        - Injects new high-confidence entries for flags not yet in the list.
        Returns a new sorted list.
        """
        try:
            from ml.linpeas_parser import extract_priv_esc_flags
            flags = extract_priv_esc_flags(linpeas_output)
        except Exception as e:
            logger.error(f'Flag extraction failed: {e}')
            return recommendations
        existing_modules = {r['module'] for r in recommendations}
        boosted = list(recommendations)
        for flag, is_set in flags.items():
            if not is_set:
                continue
            if flag not in _FLAG_TO_EXPLOIT:
                continue
            mod_name, display_name, src_type = _FLAG_TO_EXPLOIT[flag]
            if mod_name in existing_modules:
                for rec in boosted:
                    if rec['module'] == mod_name:
                        old_conf = float(rec['confidence'])
                        rec['confidence'] = round(min(1.0, old_conf + 0.3), 2)
                        rec['description'] += ' [LinPEAS confirmed ↑]'
            else:
                boosted.append({'name': display_name, 'confidence': 0.9, 'description': f'LinPEAS directly flagged: {flag}', 'module': mod_name, 'type': src_type})
                existing_modules.add(mod_name)
        boosted.sort(key=lambda x: x['confidence'], reverse=True)
        logger.info(f'After LinPEAS boost: {len(boosted)} recommendations.')
        return boosted
