import colorama
from .base import BaseEnumerator
from .command_loader import CommandLoader
from .parsers import parse_always_install_elevated, parse_whoami_priv
from .feature_extractor import FeatureExtractor
colorama.init()

class WindowsEnumerator(BaseEnumerator):

    def __init__(self, session, command_loader: CommandLoader):
        super().__init__(session)
        self.commands = command_loader.get_commands_by_platform('Windows')
        self.pause_event = None

    def _execute_command(self, cmd_obj, update_callback=None, progress_str=''):
        """Runs a single system command and captures output via WinRM/SMB."""
        cmd = cmd_obj['command']
        msg = f'[*] Stalking prey with {progress_str}: {cmd}\n'
        if update_callback:
            update_callback(msg)
        else:
            print(f'{colorama.Fore.RED}[*]{colorama.Fore.WHITE} Stalking prey with {progress_str}: {cmd}')
        try:
            result = self.session.run_command(cmd, timeout=30)
            if len(result) == 3:
                stdout, stderr, exit_code = result
            else:
                stdout, stderr = result
                exit_code = 0 if not stderr else 1
            if exit_code == 0:
                success_msg = f"[+] Weakness exposed: {cmd_obj['category']}\n"
                if update_callback:
                    update_callback(success_msg)
                else:
                    print(f"{colorama.Fore.GREEN}[+]{colorama.Fore.WHITE} Weakness exposed: {cmd_obj['category']}")
            return (stdout, stderr, exit_code)
        except Exception as e:
            err_msg = f'[-] Hunt failed on this vector: {str(e)}\n'
            if update_callback:
                update_callback(err_msg)
            else:
                print(f'{colorama.Fore.RED}[-]{colorama.Fore.WHITE} Hunt failed on this vector: {str(e)}')
            return ('', str(e), -1)

    def run_all(self, update_callback=None, pause_event=None, findings_callback=None):
        self.pause_event = pause_event
        total_cmds = len(self.commands)
        for idx, cmd_obj in enumerate(self.commands, 1):
            progress_str = f'({idx}/{total_cmds})'
            if self.pause_event and (not self.pause_event.is_set()):
                if update_callback:
                    update_callback('[bold yellow][!] Enumeration paused...[/bold yellow]\n')
                self.pause_event.wait()
                if update_callback:
                    update_callback('[bold green][!] Enumeration resumed...[/bold green]\n')
            stdout, stderr, code = self._execute_command(cmd_obj, update_callback, progress_str)
            self.raw_results[cmd_obj['id']] = stdout
            if findings_callback and stdout:
                self.parse_results()
                findings_callback(self.parsed_data)
        return self.raw_results

    def run_category(self, category: str):
        pass

    def parse_results(self):
        for cmd_obj in self.commands:
            cid = cmd_obj['id']
            raw = self.raw_results.get(cid, '')
            if 'Registry' in cmd_obj['category']:
                self.parsed_data.update(parse_always_install_elevated(raw))
            elif 'Token Privileges' in cmd_obj['category']:
                self.parsed_data.update(parse_whoami_priv(raw))
        return self.parsed_data

    def extract_features(self):
        extractor = FeatureExtractor(self.parsed_data)
        return extractor.get_feature_vector()

    def get_structured_findings(self):
        self.parse_results()
        return self.parsed_data

    def get_features(self):
        return self.extract_features()
