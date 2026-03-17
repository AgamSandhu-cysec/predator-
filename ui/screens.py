from textual.app import ComposeResult
from textual.widgets import Input, Select, Button, Static, DataTable, Tree, RichLog
from textual.containers import Vertical, Horizontal, Container
import os
from connector.ssh_connector import SSHConnector
from connector.winrm_connector import WinRMConnector
from enumerator.linux_enumerator import LinuxEnumerator
from enumerator.windows_enumerator import WindowsEnumerator
from ml.predictor import ExploitPredictor
from .auto_exploit_screen import AutoExploitScreen

class ConnectionScreen(Container):
    """Screen for connecting to the target."""

    def compose(self) -> ComposeResult:
        with Vertical(id='connection_form', classes='box'):
            yield Static('Target Connection Setup', id='conn_title', classes='title')
            yield Input(placeholder='Target IP', id='target_ip')
            yield Input(placeholder='Username', id='username')
            yield Input(placeholder='Password', password=True, id='password')
            yield Select([('Linux', 'linux'), ('Windows', 'windows')], prompt='OS', id='os')
            yield Button('Connect', id='connect_btn', variant='primary')
            yield Static('', id='conn_status')

class EnumerationScreen(Container):
    """Screen for displaying enumeration results."""

    def compose(self) -> ComposeResult:
        with Horizontal(id='enum_container'):
            with Vertical(id='enum_tree_panel'):
                yield Static('Quick Wins (Critical Findings)', classes='title')
                yield DataTable(id='quick_wins_table', cursor_type='row')
            with Vertical(id='enum_log_panel'):
                with Horizontal(id='enum_log_header', classes='header_row'):
                    yield Static('Live Output Log', classes='title')
                    yield Button('Pause', id='pause_resume_btn', variant='warning', disabled=True)
                yield RichLog(id='enum_log', markup=True)

class ExploitsScreen(Container):
    """Screen for showing and selecting exploits."""

    def compose(self) -> ComposeResult:
        with Vertical(id='exploits_panel'):
            yield Static('Recommended Exploits', classes='title')
            yield DataTable(id='exploits_table', cursor_type='row')
            yield Static('[dim]⬆ Select an exploit above, then click Run[/dim]', id='exploit_info_label')
            with Horizontal(id='exploit_action_row', classes='header_row'):
                yield Button('▶  Run Selected Exploit', id='run_exploit_btn', variant='error')
                yield Button('🔍  Refresh SearchSploit', id='refresh_searchsploit_btn', variant='warning')

class ShellScreen(Container):
    """Screen for the interactive shell."""

    def compose(self) -> ComposeResult:
        with Vertical(id='shell_panel'):
            yield Static('Interactive Shell', classes='title')
            yield RichLog(id='shell_log', markup=True)
