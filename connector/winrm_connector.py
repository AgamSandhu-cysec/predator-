import winrm
from .base import BaseConnector
from utils.logger import get_logger
logger = get_logger('WinRMConnector')

class WinRMConnector(BaseConnector):
    """Connector for Windows targets using WinRM."""

    def __init__(self, host, username, password=None, keyfile=None, transport='ntlm'):
        super().__init__(host, username, password, keyfile)
        self.transport = transport
        self.session = None

    def connect(self):
        """Establish the WinRM session."""
        try:
            logger.info(f'[*] Attempting WinRM connection to {self.username}@{self.host} (transport: {self.transport})')
            self.session = winrm.Session(f'https://{self.host}:5986/wsman' if self.transport == 'ssl' else self.host, auth=(self.username, self.password), transport=self.transport, server_cert_validation='ignore')
            res = self.session.run_cmd('ipconfig', ['/all'])
            if res.status_code == 0:
                self.connected = True
                logger.info(f'[+] Successfully connected to {self.host} via WinRM')
                return True
            else:
                logger.error(f'[-] WinRM Connection test failed: {res.std_err.decode()}')
                return False
        except Exception as e:
            logger.error(f'[-] WinRM Connection error: {e}')
            return False

    def run_command(self, command, timeout=15):
        """Execute a command over WinRM."""
        if not self.connected or not self.session:
            raise Exception('Cannot run command, WinRM session is not connected.')
        try:
            logger.debug(f'[*] Executing WinRM (cmd/ps): {command}')
            if command.lower().startswith('powershell'):
                ps_cmd = command
                if '-c "' in command:
                    ps_cmd = command.split('-c "', 1)[1].rsplit('"', 1)[0]
                res = self.session.run_ps(ps_cmd)
            else:
                parts = command.split(' ', 1)
                exe = parts[0]
                args = [parts[1]] if len(parts) > 1 else []
                res = self.session.run_cmd(exe, args)
            out = res.std_out.decode('utf-8', errors='ignore').strip()
            err = res.std_err.decode('utf-8', errors='ignore').strip()
            return (out, err, res.status_code)
        except Exception as e:
            logger.error(f'[-] Command execution failed: {e}')
            return ('', str(e), -1)

    def upload_file(self, local_path, remote_path):
        """Upload a file using WinRM (very basic/slow implementation, usually script blocks)."""
        logger.warning('[-] File upload via WinRM is not natively fast. Consider using SMB/smbclient instead.')
        return False

    def interactive_session(self):
        """Pseudo-interactive shell over WinRM (best effort – WinRM has no real PTY)."""
        if not self.connected:
            return
        print('\r\n\x1b[93m[!] WinRM does not support a true interactive PTY.\x1b[0m')
        print("\x1b[93m[!] Commands run independently; 'cd' state is NOT preserved between commands.\x1b[0m")
        print("\x1b[92m[*] Type 'exit' to quit the shell and return to Predator.\x1b[0m\r\n")
        logger.info('[+] Entering pseudo-interactive WinRM shell.')
        try:
            cwd = 'C:\\'
            while True:
                try:
                    cmd = input(f'predator-winrm {cwd}> ')
                except (EOFError, KeyboardInterrupt):
                    break
                if cmd.strip().lower() in ['exit', 'quit']:
                    break
                if not cmd.strip():
                    continue
                if cmd.strip().lower().startswith('cd '):
                    cd_target = cmd.strip()[3:].strip().strip('"').strip("'")
                    if cd_target == '..':
                        cwd = '\\'.join(cwd.rstrip('\\').split('\\')[:-1]) or 'C:\\'
                    else:
                        full_cmd = f'cmd /c "cd /d {cwd} && cd {cd_target} && cd"'
                        out, err, code = self.run_command(full_cmd)
                        if code == 0 and out:
                            cwd = out.strip()
                        else:
                            print(f"cd: {err or 'Path not found'}")
                    continue
                wrapped = f'cmd /c "cd /d {cwd} && {cmd}"'
                out, err, code = self.run_command(wrapped)
                if out:
                    print(out)
                if err:
                    print(f'\x1b[91m{err}\x1b[0m')
        except KeyboardInterrupt:
            pass
        finally:
            logger.info('[*] Exited pseudo-interactive WinRM shell.')

    def disconnect(self):
        self.connected = False
        self.session = None
        logger.info(f'[*] Disconnected from {self.host}')
