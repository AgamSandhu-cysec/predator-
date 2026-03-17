"""
ui/terminal_screen.py — PREDATOR Terminal Tab (v3 — fixed PTY reader)

Key fix: The RichLog.write() signature is:
  write(content, width=None, expand=False, shrink=True, scroll_end=None, animate=False)
There is NO markup parameter. Old code called write(line, False) which set width=False —
this caused silent failures in call_from_thread. Fix: use lambda wrapper.

PTY commands now properly stream to the log.
"""
from __future__ import annotations
import importlib
import re
import threading
import time
import pathlib
from datetime import datetime
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Button, Input, RichLog, Static
_ANSI = re.compile('\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])')
_LOG = pathlib.Path(__file__).parent.parent / 'predator.log'
_EDIRS = [pathlib.Path(__file__).parent.parent / 'exploits' / d for d in ('linux', 'manual', 'windows')]

def _strip_ansi(text: str) -> str:
    return _ANSI.sub('', text)

class TerminalScreen(Container):
    """
    Interactive PTY terminal + Predator !internal commands.

    session_connector is read from self.app.session_connector.
    connected flag: self.app.session_connector.connected (bool).
    PTY: session_connector.client.invoke_shell() → paramiko channel.
    """
    BINDINGS = [('up', 'hist_up', 'History ↑'), ('down', 'hist_down', 'History ↓')]

    def compose(self) -> ComposeResult:
        with Vertical(id='terminal_panel'):
            with Horizontal(id='terminal_controls', classes='header_row'):
                yield Button('⚡ Connect Shell', id='term_connect_btn', variant='error')
                yield Button('✖ Disconnect', id='term_disconnect_btn', variant='warning', disabled=True)
                yield Static('[dim]Not connected — go to Connection tab first[/dim]', id='term_status_label')
            yield RichLog(id='terminal_log', markup=True, auto_scroll=True, wrap=True)
            with Horizontal(id='terminal_input_row', classes='header_row'):
                yield Static('[bold red] ❯ [/bold red]', id='term_prompt_label')
                yield Input(placeholder='command or !help …', id='terminal_input')

    def on_mount(self) -> None:
        self._channel = None
        self._running = False
        self._reader: threading.Thread | None = None
        self._history: list[str] = []
        self._hist_pos = -1
        self._log('PREDATOR Terminal — click [bold]⚡ Connect Shell[/bold] after connecting via the [bold]Connection[/bold] tab.')
        self._log('Type [bold]!help[/bold] for internal commands. Everything else → remote shell.')
        self.query_one('#terminal_input', Input).focus()

    def action_hist_up(self) -> None:
        if not self._history:
            return
        self._hist_pos = max(0, self._hist_pos - 1)
        self.query_one('#terminal_input', Input).value = self._history[self._hist_pos]

    def action_hist_down(self) -> None:
        if not self._history:
            return
        self._hist_pos = min(len(self._history) - 1, self._hist_pos + 1)
        self.query_one('#terminal_input', Input).value = self._history[self._hist_pos]

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == 'term_connect_btn':
            threading.Thread(target=self._open_pty, daemon=True).start()
        elif bid == 'term_disconnect_btn':
            threading.Thread(target=self._close_pty, daemon=True).start()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        event.input.value = ''
        if not cmd:
            return
        if not self._history or self._history[-1] != cmd:
            self._history.append(cmd)
        self._hist_pos = len(self._history)
        ts = datetime.now().strftime('%H:%M:%S')
        self._log(f'[bold red][{ts}]❯[/bold red] [white]{cmd}[/white]')
        if cmd.startswith('!'):
            parts = cmd[1:].strip().split()
            threading.Thread(target=self._dispatch, args=(parts,), daemon=True).start()
        else:
            self._send(cmd)

    def _open_pty(self) -> None:
        raw = getattr(self.app, 'session_connector', None)
        if raw is None:
            self._err('session_connector is None — please connect on the Connection tab first.')
            return
        if not getattr(raw, 'connected', False):
            self._err(f"session_connector.connected = {getattr(raw, 'connected', 'missing')} — reconnect on the Connection tab.")
            return
        client = getattr(raw, 'client', None)
        if client is None:
            self._err('session_connector.client is None — SSH client not initialised.')
            return
        if self._channel and (not self._channel.closed):
            self._info('PTY already open.')
            return
        try:
            self._channel = client.invoke_shell(term='xterm-256color', width=220, height=50)
            self._channel.settimeout(0.5)
            self._running = True
            self._reader = threading.Thread(target=self._reader_loop, daemon=True, name='pty-reader')
            self._reader.start()
            host = getattr(raw, 'host', '?')
            user = getattr(raw, 'username', '?')
            self._ok(f'PTY shell opened → [bold]{user}@{host}[/bold]')
            self._set_status(f'[green]● CONNECTED[/green]  {user}@{host}')
            self.app.call_from_thread(self._toggle_btns, True)
        except Exception as e:
            self._err(f'invoke_shell() failed: {e}')

    def _close_pty(self) -> None:
        self._running = False
        try:
            if self._channel:
                self._channel.send(b'exit\n')
                time.sleep(0.3)
                self._channel.close()
        except Exception:
            pass
        self._channel = None
        self._set_status('[red]● DISCONNECTED[/red]')
        self.app.call_from_thread(self._toggle_btns, False)

    def _toggle_btns(self, connected: bool) -> None:
        try:
            self.query_one('#term_connect_btn', Button).disabled = connected
            self.query_one('#term_disconnect_btn', Button).disabled = not connected
        except Exception:
            pass

    def _reader_loop(self) -> None:
        """
        Background thread: reads raw bytes from PTY channel and writes
        to the RichLog via call_from_thread.

        KEY FIX: use a lambda wrapper for call_from_thread instead of
        passing method + args, to avoid positional argument mismatches
        with RichLog.write().
        """
        pending = ''
        while self._running:
            try:
                if self._channel is None or self._channel.closed:
                    break
                raw = self._channel.recv(4096)
                if not raw:
                    break
                text = raw.decode('utf-8', errors='replace')
                text = _strip_ansi(text)
                pending += text
                while '\n' in pending:
                    line, pending = pending.split('\n', 1)
                    line = line.rstrip('\r')
                    if line:
                        _line = line
                        self.app.call_from_thread(lambda l=_line: self.query_one('#terminal_log', RichLog).write(l))
            except TimeoutError:
                continue
            except OSError:
                continue
            except Exception as e:
                if self._running:
                    self._err(f'PTY read error: {e}')
                break
        if pending.strip():
            _p = pending.strip()
            self.app.call_from_thread(lambda l=_p: self.query_one('#terminal_log', RichLog).write(l))
        self._log('[bold red][!] PTY session ended.[/bold red]')

    def _send(self, cmd: str) -> None:
        if self._channel and (not self._channel.closed):
            self._channel.send((cmd + '\n').encode('utf-8'))
        else:
            self._err('No active PTY — click [bold]⚡ Connect Shell[/bold].')

    def _dispatch(self, parts: list[str]) -> None:
        if not parts:
            return
        sub = parts[0].lower()
        args = parts[1:]
        _h = {'help': self._cmd_help, 'exploit': self._cmd_exploit, 'exploits': self._cmd_list_exploits, 'peas': self._cmd_peas, 'switch': self._cmd_switch, 'shell': self._cmd_shell, 'findings': self._cmd_findings, 'logs': self._cmd_logs, 'status': self._cmd_status, 'verify': self._cmd_verify, 'cleanup': self._cmd_cleanup, 'clear': self._cmd_clear, 'exit': self._cmd_exit}
        fn = _h.get(sub)
        if fn:
            fn(args)
        else:
            self._err(f'Unknown internal command: !{sub}  (try !help)')

    def _cmd_help(self, _):
        lines = ['', '[bold red]╔═══════════ PREDATOR TERMINAL COMMANDS ═══════════╗[/bold red]', '[bold red]║[/bold red]  [cyan]!help[/cyan]              This menu', '[bold red]║[/bold red]  [cyan]!exploit <name>[/cyan]    Run exploit module', '[bold red]║[/bold red]  [cyan]!exploits[/cyan]          List available modules', '[bold red]║[/bold red]  [cyan]!peas[/cyan]              Re-run LinPEAS/WinPEAS', '[bold red]║[/bold red]  [cyan]!switch <tab>[/bold red]  Switch tab', '[bold red]║[/bold red]  [cyan]!shell[/cyan]             Full-screen shell', '[bold red]║[/bold red]  [cyan]!findings[/cyan]          Dump findings dict', '[bold red]║[/bold red]  [cyan]!logs [n][/cyan]          Last n lines of log', '[bold red]║[/bold red]  [cyan]!status[/cyan]            Session info', '[bold red]║[/bold red]  [cyan]!verify[/cyan]            Check uid=0?', '[bold red]║[/bold red]  [cyan]!cleanup[/cyan]           Remove temp files', '[bold red]║[/bold red]  [cyan]!clear[/cyan]             Clear output', '[bold red]║[/bold red]  [cyan]!exit[/bold red]  [cyan]          Close PTY', '[bold red]╚═══════════════════════════════════════════════════╝[/bold red]', '[dim]↑↓ = command history · anything else → remote shell[/dim]', '']
        for l in lines:
            self._log(l)

    def _cmd_exploit(self, args: list[str]) -> None:
        if not args:
            self._err('Usage: !exploit <module_name>')
            return
        name = args[0].lower()
        if hasattr(self.app, 'run_exploit_by_name'):
            self._info(f'Running exploit: {name}')
            ok = self.app.run_exploit_by_name(name, log_cb=self._log)
            if ok:
                self._ok(f'{name} succeeded! Run !verify to confirm root.')
            else:
                self._err(f'{name} did not achieve root.')
            return
        sess = getattr(self.app, 'session_connector', None)
        if not sess:
            self._err('Not connected.')
            return
        for ns in ('exploits.linux', 'exploits.manual', 'exploits.windows'):
            try:
                mod = importlib.import_module(f'{ns}.{name}')
                self._info(f'Running {ns}.{name}…')
                ok = mod.run(sess, update_callback=self._log)
                self._ok(f'Succeeded!') if ok else self._err('Did not achieve root.')
                return
            except ImportError:
                continue
            except Exception as e:
                self._err(f'Error: {e}')
                return
        self._err(f"Module '{name}' not found. Try !exploits")

    def _cmd_list_exploits(self, _) -> None:
        self._log('[bold yellow]Available modules:[/bold yellow]')
        for d in _EDIRS:
            if d.exists():
                mods = [f.stem for f in sorted(d.glob('*.py')) if not f.name.startswith('_')]
                if mods:
                    self._log(f"  [red]{d.name}/[/red]: {', '.join(mods)}")

    def _cmd_peas(self, _) -> None:
        self._info('Triggering PEAS…')
        try:
            self.app.call_from_thread(self.app.handle_run_peas)
        except Exception as e:
            self._err(str(e))

    def _cmd_switch(self, args: list[str]) -> None:
        if not args:
            self._err('Usage: !switch <tab>')
            return
        tab_id = f'tab-{args[0]}' if not args[0].startswith('tab-') else args[0]
        try:
            self.app.call_from_thread(lambda: setattr(self.app.query_one('#main_tabs'), 'active', tab_id))
            self._ok(f'Switched to {tab_id}')
        except Exception as e:
            self._err(str(e))

    def _cmd_shell(self, _) -> None:
        self._info('Suspending TUI for full-screen shell in 1s…')
        time.sleep(1)
        self.app.call_from_thread(self.app.suspend_and_shell)

    def _cmd_findings(self, _) -> None:
        f = getattr(self.app, 'parsed_findings', None) or {}
        if not f:
            self._err('No findings yet — run Enumeration first.')
            return
        self._log('[bold yellow]═══ Findings ═══[/bold yellow]')
        for k, v in f.items():
            self._log(f'  [cyan]{k}[/cyan]: {v}')

    def _cmd_logs(self, args: list[str]) -> None:
        n = int(args[0]) if args and args[0].isdigit() else 30
        try:
            lines = open(_LOG).readlines()[-n:]
            self._log(f'[yellow]═══ Last {n} log lines ═══[/yellow]')
            for l in lines:
                self._log(l.rstrip())
        except Exception as e:
            self._err(f'Log: {e}')

    def _cmd_status(self, _) -> None:
        raw = getattr(self.app, 'session_connector', None)
        ok = raw and getattr(raw, 'connected', False)
        pty = bool(self._channel and (not self._channel.closed))
        f = getattr(self.app, 'parsed_findings', {}) or {}
        self._log(f"[bold yellow]═══ Status ═══[/bold yellow]\n  SSH : [{('green' if ok else 'red')}]{('CONNECTED' if ok else 'DISCONNECTED')}[/{('green' if ok else 'red')}]\n  PTY : [{('green' if pty else 'red')}]{('ACTIVE' if pty else 'CLOSED')}[/{('green' if pty else 'red')}]\n  Host: {(getattr(raw, 'host', 'N/A') if raw else 'N/A')}  User: {(getattr(raw, 'username', 'N/A') if raw else 'N/A')}\n  Kernel: {f.get('kernel_version_str', 'unknown')}")

    def _cmd_verify(self, _=None) -> None:
        raw = getattr(self.app, 'session_connector', None)
        if not raw or not getattr(raw, 'connected', False):
            self._err('Not connected.')
            return
        try:
            uid, _, _ = raw.run_command('id -u 2>/dev/null', timeout=5)
            who, _, _ = raw.run_command('whoami 2>/dev/null', timeout=5)
            uid, who = (uid.strip(), who.strip())
            if uid == '0':
                self._log(f'[bold green]🏆 ROOT! uid=0 ({who})[/bold green]')
            else:
                self._log(f'[yellow]uid={uid} ({who}) — not root[/yellow]')
        except Exception as e:
            self._err(str(e))

    def _cmd_cleanup(self, _) -> None:
        raw = getattr(self.app, 'session_connector', None)
        if not raw:
            self._err('Not connected.')
            return
        for p in ['/tmp/.dirtycow_bin', '/tmp/passwd.bak', '/tmp/.svcbash', '/tmp/.cronbash', '/tmp/.wb', '/tmp/.svc_payload.c']:
            raw.run_command(f'rm -f {p} 2>/dev/null')
        self._ok('Cleanup complete.')

    def _cmd_clear(self, _) -> None:
        self.app.call_from_thread(self.query_one('#terminal_log', RichLog).clear)

    def _cmd_exit(self, _) -> None:
        threading.Thread(target=self._close_pty, daemon=True).start()

    def _log(self, msg: str) -> None:
        """Thread-safe write to terminal_log. Always uses lambda to avoid arg binding issues."""
        try:
            if threading.current_thread().name == 'MainThread':
                self.query_one('#terminal_log', RichLog).write(msg)
            else:
                _m = msg
                self.app.call_from_thread(lambda m=_m: self.query_one('#terminal_log', RichLog).write(m))
        except Exception:
            pass

    def _ok(self, m):
        self._log(f'[bold green][+][/bold green] {m}')

    def _err(self, m):
        self._log(f'[bold red][-][/bold red] {m}')

    def _info(self, m):
        self._log(f'[bold cyan][*][/bold cyan] {m}')

    def _set_status(self, msg: str) -> None:
        try:
            if threading.current_thread().name == 'MainThread':
                self.query_one('#term_status_label', Static).update(msg)
            else:
                _m = msg
                self.app.call_from_thread(lambda m=_m: self.query_one('#term_status_label', Static).update(m))
        except Exception:
            pass
