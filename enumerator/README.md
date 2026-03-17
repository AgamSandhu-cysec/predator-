# Predator 🦅 Enumeration Module

The core enumeration engine for "Predator", an automated privilege escalation tool.

## Structure

- `base.py`: Abstract BaseEnumerator class for platforms to inherit.
- `linux_enumerator.py`: Implements `run_all()` sending Linux specific commands and building a structured output.
- `windows_enumerator.py`: Implements `run_all()` sending Windows specific PowerShell/cmd commands and building output.
- `command_loader.py`: Singleton that ingests the JSON enumeration dataset and serves filtered queries.
- `parsers.py`: Custom string parsers based on category mappings (SUID, Kernel, Registry, etc.).
- `feature_extractor.py`: Converts normalized parsed findings to fixed-width ML feature vectors.
- `exceptions.py`: Enumeration module errors.

## The Hunting Dataset
Commands are fed through `enumeration_commands.json` (created via `generate_commands.py`) containing 300+ vectors mapping MITRE tactics, Categories, and Serverity parameters that the UI parses automatically.

## Integration

The module is designed to hook into the Predator TUI App which provides an `update_callback(msg)` method that prints output asynchronously to Textual `Log` widgets using Predator's Red/Black/Green theme logic.

Run tests:
```bash
python3 -m unittest test_enumerator.py
```
