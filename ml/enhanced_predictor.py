"""
Enhanced ML-based exploit predictor with specific exploit recommendations.

This module provides:
  - Specific exploit names (not just categories)
  - Multi-model ensemble for better accuracy
  - Feature importance and explainability
  - Confidence calibration
  - Rule-based fallbacks
"""
import yaml
import os
import joblib
import numpy as np
from collections import defaultdict
from utils.logger import get_logger
logger = get_logger('EnhancedPredictor')
EXPLOIT_SIGNATURES = {'dirtycow': {'keywords': ['dirty', 'cow', 'cve-2016-5195', 'kernel 2.', 'kernel 3.', 'kernel 4.4', 'kernel 4.8'], 'antipatterns': ['4.8.3', '4.9', '5.'], 'confidence_boost': 0.95, 'display_name': 'DirtyCow (CVE-2016-5195)', 'module': 'dirtycow'}, 'dirtypipe': {'keywords': ['dirtypipe', 'dirty pipe', 'cve-2022-0847', 'kernel 5.8', 'kernel 5.9', 'kernel 5.10', 'kernel 5.11', 'kernel 5.12', 'kernel 5.13', 'kernel 5.14', 'kernel 5.15', 'kernel 5.16'], 'antipatterns': ['5.16.11', '5.15.25', '5.10.102'], 'confidence_boost': 0.95, 'display_name': 'DirtyPipe (CVE-2022-0847)', 'module': 'dirtypipe'}, 'overlayfs_privesc': {'keywords': ['overlayfs', 'cve-2023-0386', 'cve-2021-3493', 'ubuntu 20.04', 'ubuntu 21'], 'antipatterns': [], 'confidence_boost': 0.88, 'display_name': 'OverlayFS PrivEsc (CVE-2023-0386)', 'module': 'overlayfs_privesc'}, 'sudo_baron_samedit': {'keywords': ['sudo', 'cve-2021-3156', 'baron', 'samedit', 'sudoedit'], 'antipatterns': ['sudo 1.9.5'], 'confidence_boost': 0.95, 'display_name': 'Sudo Baron Samedit (CVE-2021-3156)', 'module': 'sudo_baron_samedit'}, 'sudo_nopasswd': {'keywords': ['sudo.*nopasswd', 'sudoers', 'ALL.*ALL.*NOPASSWD'], 'antipatterns': [], 'confidence_boost': 0.88, 'display_name': 'Sudo NOPASSWD Abuse', 'module': 'sudo_nopasswd'}, 'suid_python': {'keywords': ['suid', 'python', 'python2', 'python3', '-perm.*4000.*python'], 'antipatterns': [], 'confidence_boost': 0.92, 'display_name': 'SUID Python Exploit', 'module': 'suid_python'}, 'suid_bash': {'keywords': ['suid', 'bash', '-perm.*4000.*bash'], 'antipatterns': [], 'confidence_boost': 0.9, 'display_name': 'SUID Bash Exploit', 'module': 'suid_bash'}, 'suid_nmap': {'keywords': ['suid.*nmap', 'nmap.*suid', '-perm.*4000.*nmap'], 'antipatterns': [], 'confidence_boost': 0.85, 'display_name': 'SUID Nmap Exploit', 'module': 'suid_nmap'}, 'pkexec_pwnkit': {'keywords': ['pkexec', 'polkit', 'cve-2021-4034', 'pwnkit'], 'antipatterns': [], 'confidence_boost': 0.94, 'display_name': 'PwnKit (CVE-2021-4034)', 'module': 'pkexec_pwnkit'}, 'cron_wildcard': {'keywords': ['cron', 'crontab', 'wildcard', 'tar.*--checkpoint', 'chown.*--reference'], 'antipatterns': [], 'confidence_boost': 0.8, 'display_name': 'Cron Job Wildcard Injection', 'module': 'cron_wildcard'}, 'writable_service': {'keywords': ['writable.*service', 'systemctl.*writable', 'servicefile.*world'], 'antipatterns': [], 'confidence_boost': 0.82, 'display_name': 'Writable Service File', 'module': 'writable_service'}, 'docker_breakout': {'keywords': ['docker', 'dockerenv', 'docker group', '/var/run/docker.sock'], 'antipatterns': [], 'confidence_boost': 0.88, 'display_name': 'Docker Group Breakout', 'module': 'docker_breakout'}, 'nfs_root_squash': {'keywords': ['nfs', 'no_root_squash', 'showmount', 'nfsd'], 'antipatterns': [], 'confidence_boost': 0.85, 'display_name': 'NFS no_root_squash Exploit', 'module': 'nfs_root_squash'}, 'writable_passwd': {'keywords': ['writable /etc/passwd', 'world-writable', 'passwd.*writable', '/etc/passwd.*w', '777.*passwd'], 'antipatterns': [], 'confidence_boost': 0.95, 'display_name': 'Writable /etc/passwd', 'module': 'writable_passwd', 'type': 'manual'}, 'sudo_abuse': {'keywords': ['nopasswd', 'sudo.*nopasswd', '(all).*nopasswd', 'sudoers.*nopasswd', 'sudo -l.*nopasswd'], 'antipatterns': [], 'confidence_boost': 0.92, 'display_name': 'Sudo NOPASSWD Abuse', 'module': 'sudo_abuse', 'type': 'manual'}, 'cron_hijack': {'keywords': ['writable cron', 'cron.*world', 'crontab.*writable', 'cron.*777', 'writable.*cron', '/etc/cron.*write'], 'antipatterns': [], 'confidence_boost': 0.88, 'display_name': 'Cron Job Script Hijack', 'module': 'cron_hijack', 'type': 'manual'}, 'cap_setuid': {'keywords': ['cap_setuid', 'getcap', 'capabilities.*setuid', 'setuid.*cap', 'cap_setuid+ep'], 'antipatterns': [], 'confidence_boost': 0.9, 'display_name': 'Capability cap_setuid Exploit', 'module': 'cap_setuid', 'type': 'manual'}, 'lxd_breakout': {'keywords': ['lxd', 'lxc', 'lxd group', 'lxd.*group', 'uid=.*lxd', 'groups.*lxd'], 'antipatterns': [], 'confidence_boost': 0.88, 'display_name': 'LXD Group Breakout', 'module': 'lxd_breakout', 'type': 'manual'}, 'hotpotato': {'keywords': ['seimpersonate', 'seassignprimary', 'juicy', 'potato'], 'antipatterns': [], 'confidence_boost': 0.93, 'display_name': 'Juicy Potato (SeImpersonate)', 'module': 'hotpotato'}, 'always_install': {'keywords': ['alwaysinstallelevated', 'reg.*installer'], 'antipatterns': [], 'confidence_boost': 0.9, 'display_name': 'AlwaysInstallElevated', 'module': 'always_install'}, 'unquoted_path': {'keywords': ['unquoted', 'service.*path', 'program files'], 'antipatterns': [], 'confidence_boost': 0.87, 'display_name': 'Unquoted Service Path', 'module': 'unquoted_path'}, 'printspoofer': {'keywords': ['print.*spoofer', 'spoolsv', 'cve-2020-1048'], 'antipatterns': [], 'confidence_boost': 0.92, 'display_name': 'PrintSpoofer', 'module': 'printspoofer'}, 'printnightmare': {'keywords': ['printnightmare', 'cve-2021-1675', 'cve-2021-34527', 'spooler', 'printdriver'], 'antipatterns': [], 'confidence_boost': 0.93, 'display_name': 'PrintNightmare (CVE-2021-1675)', 'module': 'printnightmare'}}
_LINUX_ONLY = {'dirtycow', 'dirtypipe', 'overlayfs_privesc', 'sudo_baron_samedit', 'sudo_nopasswd', 'suid_python', 'suid_bash', 'suid_nmap', 'pkexec_pwnkit', 'cron_wildcard', 'writable_service', 'docker_breakout', 'nfs_root_squash', 'writable_passwd', 'sudo_abuse', 'cron_hijack', 'cap_setuid', 'lxd_breakout'}
_WINDOWS_ONLY = {'hotpotato', 'always_install', 'unquoted_path', 'printspoofer', 'printnightmare'}

class EnhancedExploitPredictor:
    """
    Advanced exploit predictor with multiple strategies:
      1. Signature-based pattern matching (fastest, most reliable)
      2. ML model predictions (category-based)
      3. LinPEAS flag boosting
      4. Confidence calibration
      5. Feature importance for explainability
    """

    def __init__(self, os_type, config_path='config.yaml'):
        self.os_type = os_type.lower()
        self.config_path = config_path
        self.model = None
        self.feature_names = None
        self.load_model()
        self.category_module_map = {'SUID Binaries': [('suid_python', 'SUID Python', 0.85), ('suid_bash', 'SUID Bash', 0.8), ('suid_nmap', 'SUID Nmap', 0.75)], 'Sudo Misconfiguration': [('sudo_nopasswd', 'Sudo NOPASSWD', 0.88), ('sudo_baron_samedit', 'Baron Samedit', 0.85)], 'Kernel Exploits': [('dirtycow', 'DirtyCow', 0.9), ('dirtypipe', 'DirtyPipe', 0.88), ('pkexec_pwnkit', 'PwnKit', 0.85)], 'Cron Misconfiguration': [('cron_wildcard', 'Cron Wildcard', 0.8)], 'Service Misconfiguration': [('writable_service', 'Writable Service', 0.82), ('unquoted_path', 'Unquoted Service', 0.8)], 'Registry Misconfiguration': [('always_install', 'AlwaysInstallElevated', 0.9)], 'Token Privileges': [('hotpotato', 'Juicy Potato', 0.92), ('printspoofer', 'PrintSpoofer', 0.88), ('printnightmare', 'PrintNightmare', 0.9)]}

    def load_model(self):
        """Load the trained ML model and feature names if available."""
        model_name = f'{self.os_type}_model.joblib'
        model_path = os.path.join(os.path.dirname(__file__), 'models', model_name)
        feat_name = f'{self.os_type}_features.joblib'
        feat_path = os.path.join(os.path.dirname(__file__), 'models', feat_name)
        try:
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                logger.info(f'Loaded ML model: {model_name}')
            else:
                logger.warning(f'ML model not found: {model_path}. Using signatures only.')
        except Exception as e:
            logger.error(f'Failed to load ML model: {e}')
        try:
            if os.path.exists(feat_path):
                self.feature_names = joblib.load(feat_path)
                logger.info(f'Loaded {len(self.feature_names)} feature names for explainability.')
        except Exception as e:
            logger.warning(f'Could not load feature names: {e}')

    def predict(self, commands, raw_results, linpeas_output=None):
        """
        Multi-stage prediction pipeline:
          1. Signature-based matching (high confidence)
          2. ML model predictions (medium confidence)
          3. LinPEAS flag boosting
          4. Deduplication and ranking
        
        Returns: List of exploit recommendations with confidence scores.
        """
        recommendations = []
        seen_modules = set()
        sig_recs = self._signature_matching(commands, raw_results)
        for rec in sig_recs:
            if rec['module'] not in seen_modules:
                recommendations.append(rec)
                seen_modules.add(rec['module'])
        if self.model:
            ml_recs = self._ml_predictions(commands, raw_results, seen_modules)
            for rec in ml_recs:
                if rec['module'] not in seen_modules:
                    recommendations.append(rec)
                    seen_modules.add(rec['module'])
        if linpeas_output:
            recommendations = self._boost_with_linpeas(recommendations, linpeas_output, seen_modules)
        recommendations = self._calibrate_confidence(recommendations)
        recommendations.sort(key=lambda x: x['confidence'], reverse=True)
        if not recommendations:
            recommendations.append({'name': f"{('LinPEAS' if self.os_type == 'linux' else 'WinPEAS')} Auto", 'confidence': 0.35, 'description': 'No specific exploits matched. Run PEAS for deeper enumeration.', 'module': 'linpeas' if self.os_type == 'linux' else 'winpeas', 'type': 'static', 'reason': 'Fallback: No signatures or ML predictions matched.'})
        logger.info(f'Generated {len(recommendations)} exploit recommendations.')
        return recommendations

    def _signature_matching(self, commands, raw_results):
        """Pattern-based exploit detection using keyword signatures."""
        import re
        matches = []
        full_text = ''
        for cmd in commands:
            cid = cmd.get('id')
            output = raw_results.get(cid, '')
            if output and output.strip():
                full_text += f" {cmd.get('command', '')} {cmd.get('description', '')} {output} ".lower()
        for exploit_name, sig in EXPLOIT_SIGNATURES.items():
            if self.os_type == 'linux' and exploit_name in _WINDOWS_ONLY:
                continue
            if self.os_type == 'windows' and exploit_name in _LINUX_ONLY:
                continue
            keyword_matches = 0
            matched_keywords = []
            for kw in sig['keywords']:
                try:
                    if re.search(kw, full_text):
                        keyword_matches += 1
                        matched_keywords.append(kw)
                except re.error:
                    if kw in full_text:
                        keyword_matches += 1
                        matched_keywords.append(kw)
            antipattern_matches = sum((1 for ap in sig['antipatterns'] if ap in full_text))
            if keyword_matches > 0 and antipattern_matches == 0:
                confidence = min(sig['confidence_boost'], 0.7 + keyword_matches * 0.08)
                exploit_type = sig.get('type', 'static')
                matches.append({'name': sig['display_name'], 'confidence': round(confidence, 2), 'description': f'Signature match: {keyword_matches} keyword(s) detected', 'module': sig['module'], 'type': exploit_type, 'reason': f"Keywords matched: {', '.join(matched_keywords[:4])}"})
        return matches

    def _ml_predictions(self, commands, raw_results, exclude_modules):
        """Use ML model to predict exploit categories."""
        predictions = []
        successful_texts = []
        for cmd in commands:
            cid = cmd.get('id')
            output = raw_results.get(cid, '')
            if output and output.strip():
                text = f"{cmd.get('command', '')} {cmd.get('description', '')}"
                successful_texts.append(text)
        if not successful_texts:
            return predictions
        try:
            categories = self.model.predict(successful_texts)
            probs = self.model.predict_proba(successful_texts)
            max_probs = [max(p) for p in probs]
            for cat, conf in zip(categories, max_probs):
                if cat in self.category_module_map:
                    for mod_name, desc, base_conf in self.category_module_map[cat]:
                        if mod_name not in exclude_modules:
                            predictions.append({'name': desc, 'confidence': round(min(conf * base_conf, 0.95), 2), 'description': f"ML predicted category '{cat}'", 'module': mod_name, 'type': 'static', 'reason': f'ML model predicted category: {cat}'})
        except Exception as e:
            logger.error(f'ML prediction failed: {e}')
        return predictions

    def _boost_with_linpeas(self, recommendations, linpeas_output, seen_modules):
        """Cross-reference with LinPEAS flags to boost confidence — uses regex for CVE patterns."""
        import re
        try:
            from ml.linpeas_parser import extract_priv_esc_flags
            flags = extract_priv_esc_flags(linpeas_output)
        except Exception as e:
            logger.error(f'LinPEAS flag extraction failed: {e}')
            return recommendations
        boosted = list(recommendations)
        linpeas_lower = linpeas_output.lower()
        cve_patterns = {'cve-2016-5195': 'dirtycow', 'cve-2022-0847': 'dirtypipe', 'cve-2021-4034|pwnkit|polkit': 'pkexec_pwnkit', 'cve-2021-3156|baron.*samedit': 'sudo_baron_samedit', 'cve-2021-1675|cve-2021-34527|printnightmare': 'printnightmare', 'cve-2020-1048|printspoofer': 'printspoofer', 'cve-2023-0386|overlayfs': 'overlayfs_privesc'}
        for pattern, module_name in cve_patterns.items():
            if re.search(pattern, linpeas_lower):
                found = False
                for rec in boosted:
                    if rec['module'] == module_name:
                        old_conf = rec['confidence']
                        rec['confidence'] = round(min(0.98, old_conf + 0.3), 2)
                        rec['description'] += ' [LinPEAS CVE ✓]'
                        found = True
                        break
                if not found and module_name not in seen_modules:
                    sig = EXPLOIT_SIGNATURES.get(module_name, {})
                    boosted.append({'name': sig.get('display_name', module_name), 'confidence': 0.9, 'description': f'LinPEAS detected CVE pattern ({pattern}) in output', 'module': module_name, 'type': 'static', 'reason': f'LinPEAS CVE match: {pattern}'})
                    seen_modules.add(module_name)
        for rec in boosted:
            mod = rec['module']
            for flag, is_set in flags.items():
                if is_set and mod in flag.lower():
                    old_conf = rec['confidence']
                    new_conf = round(min(0.98, old_conf + 0.2), 2)
                    if new_conf > old_conf:
                        rec['confidence'] = new_conf
                        if 'LinPEAS' not in rec['description']:
                            rec['description'] += ' [LinPEAS Flag ✓]'
                    break
        return boosted

    def _calibrate_confidence(self, recommendations):
        """Apply statistical calibration to confidence scores."""
        for rec in recommendations:
            conf = rec['confidence']
            calibrated = 0.5 + 0.45 * np.tanh((conf - 0.7) * 3)
            rec['confidence'] = round(max(0.3, min(0.98, calibrated)), 2)
        return recommendations

    def explain(self, recommendation, top_n=5):
        """
        Provide human-readable explanation for why an exploit was recommended.
        If feature names are available (from saved TF-IDF features), show top contributing terms.
        """
        base_reason = recommendation.get('reason', 'No explanation available.')
        if self.model and self.feature_names is not None:
            try:
                calibrated = self.model.named_steps.get('clf')
                if calibrated and hasattr(calibrated, 'calibrated_classifiers_'):
                    base_rf = calibrated.calibrated_classifiers_[0].estimator
                    importances = base_rf.feature_importances_
                    top_indices = np.argsort(importances)[::-1][:top_n]
                    top_features = [(self.feature_names[i], round(importances[i], 4)) for i in top_indices]
                    feat_str = ', '.join((f"'{f}' ({v})" for f, v in top_features))
                    return f'{base_reason}\n  Top model features: {feat_str}'
            except Exception as e:
                logger.debug(f'Feature importance extraction failed: {e}')
        return base_reason

def predict_exploits(os_type, commands, raw_results, linpeas_output=None):
    """Convenience wrapper for the enhanced predictor."""
    predictor = EnhancedExploitPredictor(os_type)
    return predictor.predict(commands, raw_results, linpeas_output)
