import paramiko
import time
from .base import BaseConnector
from utils.logger import get_logger
logger = get_logger('SSHConnector')

class SSHConnector(BaseConnector):
    """Connector for Linux targets using SSH."""

    def __init__(self, host, username, password=None, keyfile=None, port=22, timeout=10):
        super().__init__(host, username, password, keyfile)
        self.port = port
        self.timeout = timeout
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self):
        """Establish the SSH connection. Falls back to legacy key types for old targets."""
        try:
            logger.info(f'[*] Attempting SSH connection to {self.username}@{self.host}:{self.port}')
            if self.keyfile:
                self.client.connect(hostname=self.host, port=self.port, username=self.username, key_filename=self.keyfile, timeout=self.timeout)
            else:
                self.client.connect(hostname=self.host, port=self.port, username=self.username, password=self.password, timeout=self.timeout)
            self.connected = True
            logger.info(f'[+] Successfully connected to {self.host} via SSH')
            return True
        except paramiko.AuthenticationException:
            logger.error(f'[-] Authentication failed for {self.username}@{self.host}')
            return False
        except Exception as e:
            logger.warning(f'[!] Standard SSH failed ({e}), trying legacy key types (ssh-rsa/ssh-dss)...')
            try:
                t = paramiko.Transport((self.host, self.port))
                t.connect(username=self.username, password=self.password)
                new_client = paramiko.SSHClient()
                new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                new_client._transport = t
                self.client = new_client
                self.connected = True
                logger.info(f'[+] Connected to {self.host} via legacy SSH transport')
                return True
            except Exception as e2:
                logger.error(f'[-] SSH Connection error (all methods failed): {e2}')
                return False

    def run_command(self, command, timeout=15):
        """Execute a command over SSH."""
        if not self.connected:
            raise Exception('Cannot run command, SSH session is not connected.')
        try:
            logger.debug(f'[*] Executing SSH: {command}')
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            out = []
            err = []
            start_time = time.time()
            while not stdout.channel.exit_status_ready():
                if stdout.channel.recv_ready():
                    out.append(stdout.channel.recv(4096).decode('utf-8', errors='ignore'))
                if stderr.channel.recv_stderr_ready():
                    err.append(stderr.channel.recv_stderr(4096).decode('utf-8', errors='ignore'))
                time.sleep(0.1)
                if time.time() - start_time > timeout:
                    logger.warning(f'[-] Command timed out after {timeout}s: {command}')
                    return (''.join(out), 'Command timed out', -1)
            while stdout.channel.recv_ready():
                out.append(stdout.channel.recv(4096).decode('utf-8', errors='ignore'))
            while stderr.channel.recv_stderr_ready():
                err.append(stderr.channel.recv_stderr(4096).decode('utf-8', errors='ignore'))
            out_str = ''.join(out).strip()
            err_str = ''.join(err).strip()
            exit_code = stdout.channel.recv_exit_status()
            return (out_str, err_str, exit_code)
        except Exception as e:
            logger.error(f'[-] Command execution failed: {e}')
            return ('', str(e), -1)

    def upload_file(self, local_path, remote_path):
        """Upload a file using SFTP, fallback to stdin piping if SFTP is unavailable."""
        if not self.connected:
            return False
        try:
            sftp = self.client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            logger.info(f'[+] Uploaded {local_path} to {remote_path} via SFTP')
            return True
        except Exception as e:
            logger.warning(f'[-] SFTP upload failed: {e}. Falling back to SSH stdin transfer...')
            try:
                cmd = f'cat > {remote_path}'
                stdin, stdout, stderr = self.client.exec_command(cmd)
                with open(local_path, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        stdin.write(chunk)
                stdin.close()
                exit_code = stdout.channel.recv_exit_status()
                err = stderr.read().decode().strip()
                if exit_code == 0:
                    logger.info(f'[+] Uploaded {local_path} to {remote_path} via SSH stdin')
                    return True
                else:
                    logger.error(f'[-] SSH stdin upload failed (code {exit_code}): {err}')
                    return False
            except Exception as inner_e:
                logger.error(f'[-] Fallback upload failed completely: {inner_e}')
                return False

    def interactive_session(self):
        """Drop into a fully interactive PTY shell on the remote target."""
        if not self.connected:
            return
        logger.info('[+] Entering fully interactive SSH shell (PTY).')
        try:
            channel = self.client.invoke_shell(term='xterm-256color', width=220, height=50)
            import sys
            import select
            import termios
            import tty
            oldtty = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                channel.settimeout(0.0)
                while True:
                    r, _w, _e = select.select([channel, sys.stdin], [], [], 0.1)
                    if channel in r:
                        try:
                            data = channel.recv(4096)
                            if not data:
                                break
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        except Exception:
                            break
                    if sys.stdin in r:
                        data = sys.stdin.buffer.read(1)
                        if not data:
                            break
                        channel.send(data)
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
                print('\r\n')
                logger.info('[*] Exited interactive SSH shell, TTY restored.')
        except Exception as e:
            logger.error(f'[-] Shell error: {e}')

    def disconnect(self):
        if self.client:
            self.client.close()
            self.connected = False
            logger.info(f'[*] Disconnected from {self.host}')
