"""
enumerator/feature_extractor.py

Full-featured extractor that converts raw enumeration/PEAS results
into the canonical 46-feature vector defined in brain/feature_schema.py.

Backward-compatible: get_feature_vector() still returns a dict,
but now includes all FEATURE_NAMES keys.
"""
import re
from utils.logger import get_logger
logger = get_logger('FeatureExtractor')

def _parse_kernel(kernel_str: str) -> tuple:
    """Parse '5.15.0-91-generic' → (major=5, minor=15)."""
    m = re.search('(\\d+)\\.(\\d+)', str(kernel_str))
    if m:
        return (int(m.group(1)), int(m.group(2)))
    return (0, 0)

def _version_lt(major: int, minor: int, ref_major: int, ref_minor: int) -> bool:
    if major < ref_major:
        return True
    if major == ref_major and minor < ref_minor:
        return True
    return False

class FeatureExtractor:
    """
    Converts parsed enumeration data into the canonical feature dict.

    Input (self.data) keys understood:
        kernel_version      str  e.g. "5.15.0-91-generic"
        has_nopasswd        bool
        sudo_version        str  e.g. "1.8.31"
        suid_binaries       list of str e.g. ["/usr/bin/python3", "/usr/bin/find"]
        groups              list of str
        capabilities        list of str  (output of getcap -r / 2>/dev/null)
        writable_files      list of str  (important writable paths)
        running_services    list of str
        has_gcc             bool
        has_python3         bool
        has_python2         bool
        has_curl            bool
        has_wget            bool
        has_nc              bool
        always_install_elevated  bool
        has_impersonate     bool
        unquoted_service_path    bool
        weak_service_perms  bool
        peas_output         str  (raw LinPEAS / WinPEAS output for fallback parsing)
    """

    def __init__(self, parsed_data: dict):
        self.data = parsed_data or {}
        self._peas = self.data.get('peas_output', '')

    def _kernel_features(self) -> dict:
        kv = self.data.get('kernel_version', '') or self._peas_grab('Linux version (\\S+)')
        major, minor = _parse_kernel(str(kv))
        return {'kernel_major': major, 'kernel_minor': minor, 'kernel_lt_4_8': _version_lt(major, minor, 4, 8), 'kernel_lt_5_13': _version_lt(major, minor, 5, 13), 'kernel_lt_5_16': _version_lt(major, minor, 5, 16)}

    def _sudo_features(self) -> dict:
        sudo_nopasswd = bool(self.data.get('has_nopasswd', False))
        if not sudo_nopasswd and self._peas:
            sudo_nopasswd = bool(re.search('NOPASSWD', self._peas, re.I))
        env_keep = bool(re.search('env_keep|env_reset\\s+bypass', self._peas, re.I))
        sv_str = str(self.data.get('sudo_version', '') or self._peas_grab('Sudo version (\\S+)'))
        sv_major, sv_minor = (0, 0)
        sv_m = re.search('(\\d+)\\.(\\d+)', sv_str)
        if sv_m:
            sv_major, sv_minor = (int(sv_m.group(1)), int(sv_m.group(2)))
        sudo_lt_1_9_5 = _version_lt(sv_major, sv_minor, 1, 9) or (sv_major == 1 and sv_minor == 9 and re.search('1\\.9\\.[0-4]', sv_str))
        return {'sudo_nopasswd': sudo_nopasswd, 'sudo_env_keep': env_keep, 'sudo_version_lt_1_9_5': bool(sudo_lt_1_9_5)}

    def _suid_features(self) -> dict:
        suid_list = self.data.get('suid_binaries', []) or []
        if not suid_list and self._peas:
            suid_list = re.findall('-rws\\S*\\s+\\S+\\s+\\S+\\s+(\\S+)', self._peas)
        suid_text = ' '.join(suid_list).lower()
        known = {'suid_python': 'python', 'suid_bash': '/bash', 'suid_find': '/find', 'suid_vim': '/vim', 'suid_nmap': '/nmap', 'suid_perl': '/perl', 'suid_ruby': '/ruby'}
        out = {k: v in suid_text for k, v in known.items()}
        known_words = {'python', 'bash', 'find', 'vim', 'nmap', 'perl', 'ruby'}
        other = sum((1 for b in suid_list if not any((kw in b.lower() for kw in known_words))))
        out['suid_other_count'] = other
        return out

    def _fs_features(self) -> dict:
        writable = self.data.get('writable_files', []) or []
        w_text = ' '.join(writable).lower() + ' ' + self._peas.lower()
        return {'writable_passwd': '/etc/passwd' in w_text, 'writable_shadow': '/etc/shadow' in w_text, 'writable_crontab': '/etc/cron' in w_text or 'crontab' in w_text, 'writable_init_d': '/etc/init.d' in w_text or '/etc/rc' in w_text, 'world_writable_path': bool(re.search('world.writable.*PATH|PATH.*world.writable', self._peas, re.I))}

    def _cap_features(self) -> dict:
        caps = ' '.join(self.data.get('capabilities', []) or []).lower()
        if not caps:
            m = re.findall('cap_\\w+', self._peas.lower())
            caps = ' '.join(m)
        return {'cap_setuid': 'cap_setuid' in caps, 'cap_net_raw': 'cap_net_raw' in caps, 'cap_net_bind': 'cap_net_bind' in caps, 'cap_sys_admin': 'cap_sys_admin' in caps}

    def _group_features(self) -> dict:
        raw_groups = ' '.join(self.data.get('groups', []) or []).lower() + ' ' + self._peas.lower()
        return {'in_lxd_group': 'lxd' in raw_groups, 'in_docker_group': 'docker' in raw_groups, 'in_adm_group': 'adm' in raw_groups, 'in_disk_group': 'disk' in raw_groups, 'in_video_group': 'video' in raw_groups}

    def _service_features(self) -> dict:
        services = ' '.join(self.data.get('running_services', []) or []).lower() + ' ' + self._peas.lower()
        return {'mysql_running': 'mysql' in services, 'docker_running': 'dockerd' in services or 'docker' in services, 'cron_writable_script': bool(self.data.get('cron_writable_script', False)), 'nfs_no_root_squash': 'no_root_squash' in services, 'ld_preload_possible': 'LD_PRELOAD' in self._peas or 'ld_preload' in services}

    def _env_features(self) -> dict:
        return {'has_gcc': bool(self.data.get('has_gcc', False)), 'has_python3': bool(self.data.get('has_python3', False)), 'has_python2': bool(self.data.get('has_python2', False)), 'has_curl': bool(self.data.get('has_curl', False)), 'has_wget': bool(self.data.get('has_wget', False)), 'has_nc': bool(self.data.get('has_nc', False))}

    def _win_features(self) -> dict:
        return {'always_install_elevated': bool(self.data.get('always_install_elevated', False)), 'se_impersonate': bool(self.data.get('has_impersonate', False)), 'unquoted_service_path': bool(self.data.get('unquoted_service_path', False)), 'weak_service_perms': bool(self.data.get('weak_service_perms', False))}

    def _peas_grab(self, pattern: str) -> str:
        """Extract a single value from PEAS output via regex."""
        m = re.search(pattern, self._peas)
        return m.group(1) if m else ''

    def get_feature_vector(self) -> dict:
        """
        Return the full canonical feature dict.
        Always contains every key in brain.feature_schema.FEATURE_NAMES.
        """
        features: dict = {}
        features.update(self._kernel_features())
        features.update(self._sudo_features())
        features.update(self._suid_features())
        features.update(self._fs_features())
        features.update(self._cap_features())
        features.update(self._group_features())
        features.update(self._service_features())
        features.update(self._env_features())
        features.update(self._win_features())
        high_sev = sum([features.get('sudo_nopasswd', False), features.get('writable_passwd', False), features.get('cap_setuid', False), features.get('always_install_elevated', False), features.get('se_impersonate', False)])
        features['high_severity_findings'] = high_sev
        return features
    extract = get_feature_vector
