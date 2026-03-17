"""
brain/manual_recorder.py

Records shell session commands, then auto-generates a Python exploit
module from the transcript.  Prompts the user after shell exit.

How it works:
  1. ManualRecorder.start()   — called when Shell tab opens
  2. ManualRecorder.record()  — called per command (hook in connector)
  3. ManualRecorder.stop()    — called when shell exits
  4. ManualRecorder.generate_module() — creates exploits/user_defined/<name>.py
     and registers it in the KnowledgeGraph
"""
import datetime
import os
import re
import textwrap
from utils.logger import get_logger
logger = get_logger('ManualRecorder')

class ManualRecorder:
    """Records an interactive shell session and converts it to a reusable exploit module."""

    def __init__(self, output_dir: str='exploits/user_defined', llm_advisor=None):
        self.output_dir = output_dir
        self.llm = llm_advisor
        self._buffer: list = []
        self._recording: bool = False
        os.makedirs(output_dir, exist_ok=True)

    def start(self):
        self._buffer.clear()
        self._recording = True
        logger.info('Shell-session recording started.')

    def stop(self):
        self._recording = False
        logger.info(f'Recording stopped — {len(self._buffer)} command(s) captured.')

    def record(self, command: str, output: str=''):
        if not self._recording:
            return
        ts = datetime.datetime.utcnow().isoformat()
        self._buffer.append((ts, command.strip(), output.strip()))

    def get_session(self) -> list:
        return list(self._buffer)

    def has_data(self) -> bool:
        return bool(self._buffer)

    def _infer_preconditions(self) -> list:
        """
        Heuristically detect likely preconditions from the transcript.
        Falls back to LLM if available.
        """
        transcript = '\n'.join((cmd for _, cmd, _ in self._buffer))
        if self.llm:
            try:
                return self.llm.suggest_preconditions(transcript) or ['user_shell']
            except Exception:
                pass
        preconds = {'user_shell'}
        kw_map = {'sudo': 'sudo_nopasswd', '/etc/passwd': 'writable_passwd', 'lxd': 'in_lxd_group', 'docker': 'in_docker_group', 'setuid': 'cap_setuid', 'capsh': 'cap_setuid', '/etc/cron': 'cron_writable_script', 'LD_PRELOAD': 'ld_preload_possible', 'nfs': 'nfs_no_root_squash', 'suid': 'suid_other_count'}
        for _, cmd, _ in self._buffer:
            for keyword, feature in kw_map.items():
                if keyword.lower() in cmd.lower():
                    preconds.add(feature)
        return sorted(preconds)

    def generate_module(self, module_name: str, description: str, preconditions: list | None=None, effects: list | None=None) -> str:
        """
        Write a Python exploit module from the recorded session.

        Returns the absolute path to the generated file.
        """
        if effects is None:
            effects = ['root_shell']
        if preconditions is None:
            preconditions = self._infer_preconditions()
        safe_name = re.sub('[^a-z0-9_]', '_', module_name.lower()).strip('_')
        out_path = os.path.join(self.output_dir, f'{safe_name}.py')
        transcript_lines = '\n'.join((f'    # [{ts}]  $ {cmd}' for ts, cmd, _ in self._buffer))
        commands_list = ',\n        '.join((f'"{cmd.replace(chr(34), chr(92) + chr(34))}"' for _, cmd, _ in self._buffer if cmd))
        code = textwrap.dedent(f'            """\n            Auto-generated exploit module: {safe_name}\n            Description : {description}\n            Generated   : {datetime.date.today().isoformat()}\n\n            Session transcript:\n            {transcript_lines}\n            """\n            from utils.logger import get_logger\n\n            logger = get_logger("{safe_name}")\n\n            # Planner metadata — used by brain/planner.py for chain planning\n            PLANNER_META = {{\n                "name":          "{safe_name}",\n                "preconditions": {preconditions!r},\n                "effects":       {effects!r},\n                "cost":          2,\n            }}\n\n\n            def run(session, update_callback=None, config=None):\n                def log(msg):\n                    if update_callback:\n                        update_callback(msg + "\\n")\n                    logger.info(msg.strip())\n\n                log("[bold magenta][*] User-defined exploit: {safe_name}[/bold magenta]")\n\n                # ── Recorded command sequence ────────────────────────────────\n                commands = [\n                    {commands_list},\n                ]\n\n                for cmd in commands:\n                    out, err, code = session.run_command(cmd, timeout=20)\n                    log(f"[cyan]$ {{cmd}}[/cyan]")\n                    combined = (out + err).strip()\n                    if combined:\n                        log(f"[dim]{{combined[:300]}}[/dim]")\n\n                # ── Verify outcome ───────────────────────────────────────────\n                uid_out, _, _ = session.run_command("id -u 2>/dev/null")\n                if uid_out.strip() == "0":\n                    log("[bold green][+] Root confirmed (uid=0)![/bold green]")\n                    return True\n                else:\n                    log(f"[yellow][-] uid={{uid_out.strip()}} — "\n                        "may need manual adjustment.[/yellow]")\n                    return False\n        ')
        with open(out_path, 'w') as f:
            f.write(code)
        logger.info(f'Module generated: {out_path}')
        return os.path.abspath(out_path)

    def prompt_and_save(self, knowledge_graph=None) -> str | None:
        """
        Ask the operator (via stdin) whether to save the session.
        Returns the file path if saved, else None.
        """
        if not self.has_data():
            return None
        try:
            ans = input('\n\x1b[93m[?] Save this session as an exploit module? [y/N]: \x1b[0m').strip().lower()
            if ans != 'y':
                return None
            name = input('\x1b[93m[?] Module name (no spaces): \x1b[0m').strip() or 'user_exploit'
            desc = input('\x1b[93m[?] Description: \x1b[0m').strip()
            preconds_raw = input('\x1b[93m[?] Preconditions (space-separated, e.g. sudo_nopasswd): \x1b[0m').strip()
            preconds = preconds_raw.split() if preconds_raw else None
            path = self.generate_module(name, desc, preconds)
            print(f'\x1b[92m[+] Module saved: {path}\x1b[0m')
            if knowledge_graph:
                effective_preconds = preconds or self._infer_preconditions()
                knowledge_graph.add_exploit(name, path, effective_preconds, ['root_shell'], technique='user_defined', success_count=1)
                print('\x1b[92m[+] Registered in knowledge graph.\x1b[0m')
            return path
        except (KeyboardInterrupt, EOFError):
            print()
            return None
