"""
brain/feature_schema.py

Canonical ordered feature vector used by the Adaptive ML Engine.
Every component that reads or writes features MUST use this ordering.

Adding new features:
  1. Append to FEATURE_NAMES (never insert in the middle — breaks persisted models).
  2. Update FeatureExtractor.extract() in enumerator/feature_extractor.py.
  3. Bump SCHEMA_VERSION so stale persisted models are detected and discarded.
"""
SCHEMA_VERSION = 2
FEATURE_NAMES = ['kernel_major', 'kernel_minor', 'kernel_lt_4_8', 'kernel_lt_5_13', 'kernel_lt_5_16', 'sudo_nopasswd', 'sudo_env_keep', 'sudo_version_lt_1_9_5', 'suid_python', 'suid_bash', 'suid_find', 'suid_vim', 'suid_nmap', 'suid_perl', 'suid_ruby', 'suid_other_count', 'writable_passwd', 'writable_shadow', 'writable_crontab', 'writable_init_d', 'world_writable_path', 'cap_setuid', 'cap_net_raw', 'cap_net_bind', 'cap_sys_admin', 'in_lxd_group', 'in_docker_group', 'in_adm_group', 'in_disk_group', 'in_video_group', 'mysql_running', 'docker_running', 'cron_writable_script', 'nfs_no_root_squash', 'ld_preload_possible', 'has_gcc', 'has_python3', 'has_python2', 'has_curl', 'has_wget', 'has_nc', 'always_install_elevated', 'se_impersonate', 'unquoted_service_path', 'weak_service_perms']
LABEL_NAMES = ['writable_passwd', 'sudo_abuse', 'cap_setuid', 'lxd_breakout', 'docker_escape', 'suid_bash', 'suid_find', 'suid_vim', 'suid_python', 'suid_nmap', 'pkexec_pwnkit', 'sudo_baron_samedit', 'dirtycow', 'dirtypipe', 'overlayfs', 'cron_hijack', 'ld_preload', 'nfs_root_squash', 'always_install_elevated', 'hotpotato', 'printspoofer', 'unquoted_path', 'weak_service']
FAILED_LABEL = '__failed__'
ALL_CLASSES = LABEL_NAMES + [FAILED_LABEL]
N_FEATURES = len(FEATURE_NAMES)
