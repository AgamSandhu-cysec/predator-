import json
input_file = '/home/kali/Desktop/predator/tmp_dataset/linux_window_priv_escalation_datatset.jsonl'
output_file = '/home/kali/Desktop/predator/enumerator/enumeration_commands.json'
commands = []
linux_count = 0
windows_count = 0
with open(input_file, 'r') as f:
    for line in f:
        data = json.loads(line)
        platform = 'Linux' if data['platform'].lower() == 'linux' else 'Windows'
        converted = {'id': int(data['id']), 'platform': platform, 'command': data['command'], 'description': data['description'], 'category': data.get('category', 'General Enumeration'), 'subcategory': data.get('category', 'General Enumeration'), 'severity': data.get('severity', 'Medium'), 'mitre_technique': data.get('mapped_technique', 'T1082'), 'reference': data.get('reference', 'https://attack.mitre.org/'), 'parsing_hint': 'Analyze output for capability or misconfiguration flags.', 'depends_on': None, 'os_version': 'All' if platform == 'Linux' else 'Windows 10+', 'example_output': 'Pending Execution'}
        cmd_lower = data['command'].lower()
        if 'find / ' in cmd_lower and 'perm' in cmd_lower:
            converted['parsing_hint'] = 'List of binary paths, one per line.'
            converted['example_output'] = '/usr/bin/sudo\\n/bin/su'
        elif 'reg query' in cmd_lower:
            converted['parsing_hint'] = 'Check if value is present and configured insecurely.'
            converted['example_output'] = 'HKEY_LOCAL_MACHINE\\\\...    REG_DWORD    0x1'
        elif 'cat /etc/' in cmd_lower:
            converted['parsing_hint'] = 'Parse configuration file lines for misconfigured entries or passwords.'
            converted['example_output'] = 'root:x:0:0:root:/root:/bin/bash'
        elif 'sc query' in cmd_lower or 'get-service' in cmd_lower:
            converted['parsing_hint'] = 'Evaluate service state and permissions.'
            converted['example_output'] = 'SERVICE_NAME: vulnsvc\\nSTATE: 4 RUNNING'
        commands.append(converted)
        if platform == 'Linux':
            linux_count += 1
        else:
            windows_count += 1
with open(output_file, 'w') as f:
    json.dump(commands, f, indent=2)
print(f'Dataset generated successfully! Total commands: {len(commands)}')
print(f'Linux commands: {linux_count}')
print(f'Windows commands: {windows_count}')
