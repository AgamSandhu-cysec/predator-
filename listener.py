"""
listener.py — TCP reverse-shell listener for Predator.

Usage:
    from listener import start_listener
    socket_session = start_listener(lhost="0.0.0.0", lport=4444, timeout=60)
    if socket_session:
        socket_session.interactive_session()
"""
import socket
import time
from connector.socket_session import SocketSession
from utils.logger import get_logger
logger = get_logger('Listener')

def start_listener(lhost: str='0.0.0.0', lport: int=4444, timeout: int=60, update_callback=None) -> SocketSession | None:
    """
    Start a TCP listener and wait for one incoming connection.

    Args:
        lhost:   IP to bind on (use 0.0.0.0 to accept from any interface).
        lport:   TCP port to listen on.
        timeout: Seconds to wait for a connection before giving up.
        update_callback: Optional callable for TUI log messages.

    Returns:
        A SocketSession wrapping the accepted socket, or None on failure/timeout.
    """

    def log(msg):
        if update_callback:
            update_callback(msg + '\n')
        logger.info(msg.strip())
    log(f'[cyan][*] Listener started on {lhost}:{lport} — waiting {timeout}s for shell...[/cyan]')
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((lhost, lport))
        srv.listen(1)
        srv.settimeout(timeout)
        conn, addr = srv.accept()
        log(f'[bold green][+] Reverse shell received from {addr[0]}:{addr[1]}![/bold green]')
        conn.settimeout(None)
        return SocketSession(conn, addr[0])
    except socket.timeout:
        log(f'[bold red][-] Listener timed out after {timeout}s — no connection received.[/bold red]')
        return None
    except Exception as e:
        log(f'[red][-] Listener error: {e}[/red]')
        return None
    finally:
        try:
            srv.close()
        except Exception:
            pass
