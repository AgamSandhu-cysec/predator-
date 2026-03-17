import json
from pathlib import Path
from .exceptions import CommandLoadError

class CommandLoader:

    def __init__(self, dataset_path: str):
        self.dataset_path = dataset_path
        self.commands = self._load_dataset()

    def _load_dataset(self):
        try:
            path = Path(self.dataset_path)
            if not path.exists():
                raise CommandLoadError(f'Dataset not found: {self.dataset_path}')
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            raise CommandLoadError(f'Failed to load commands: {str(e)}')

    def get_commands_by_platform(self, platform: str):
        return [cmd for cmd in self.commands if cmd.get('platform', '').lower() == platform.lower()]

    def get_commands_by_category(self, platform: str, category: str):
        cmds = self.get_commands_by_platform(platform)
        return [cmd for cmd in cmds if cmd.get('category', '').lower() == category.lower()]
