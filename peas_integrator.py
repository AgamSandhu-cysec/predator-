import os
import yaml
from utils.logger import get_logger
logger = get_logger('PEASIntegrator')

def load_config(config_path='config.yaml'):
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f'Failed to load config from {config_path}: {e}')
        return {}

def find_local_peas(platform: str, config: dict=None) -> str:
    """
    Locate the PEAS script on the local Kali system.
    - platform: 'linux' or 'windows'
    - config: generic config dict loaded from config.yaml
    Search common locations if not found in config.
    Raise FileNotFoundError if not found.
    """
    if config is None:
        config = load_config()
    peas_conf = config.get('peas', {})
    configured_path = peas_conf.get(platform)
    if configured_path and os.path.exists(configured_path):
        return configured_path
    common_paths = []
    if platform == 'linux':
        common_paths = ['/usr/share/peas/linpeas.sh', '/usr/share/linpeas/linpeas.sh', '/opt/peas/linpeas.sh', '~/tools/peas/linpeas.sh', '/usr/share/peass/linpeas/linpeas.sh']
    else:
        common_paths = ['/usr/share/peas/winpeas.bat', '/usr/share/winpeas/winpeas.bat', '/opt/peas/winpeas.bat', '~/tools/peas/winpeas.bat', '/usr/share/peass/winpeas/winpeas.bat']
    for path in common_paths:
        expanded_path = os.path.expanduser(path)
        if os.path.exists(expanded_path):
            return expanded_path
    raise FileNotFoundError(f'Could not find PEAS script for platform {platform}.')

def run_peas(connector, platform: str) -> str:
    """
    Transfer and execute PEAS on the target based on platform OS.
    - connector: instance of SSHConnector or WinRMConnector
    - platform: 'linux' or 'windows'
    Returns the full output (including ANSI codes) as a string.
    """
    config = load_config()
    local_path = find_local_peas(platform, config)
    logger.info(f'Found local PEAS script for {platform} at {local_path}')
    if platform == 'linux':
        remote_path = '/tmp/linpeas.sh'
        exec_cmd = f'chmod +x {remote_path} && {remote_path} -a'
        cleanup_cmd = f'rm -f {remote_path}'
    else:
        remote_path = 'C:\\Windows\\Temp\\winpeas.bat'
        exec_cmd = f'cmd.exe /c {remote_path} -a'
        cleanup_cmd = f'del /f /q {remote_path}'
    logger.info(f'Attempting to upload {local_path} to {remote_path}')
    if not connector.upload_file(local_path, remote_path):
        raise Exception(f'Failed to upload PEAS script to {remote_path}')
    logger.info(f'Executing PEAS script on {platform} target...')
    stdout, stderr, exit_code = ('', '', -1)
    try:
        stdout, stderr, exit_code = connector.run_command(exec_cmd, timeout=900)
        logger.info(f'PEAS execution completed with exit code {exit_code}')
    except Exception as e:
        logger.error(f'Error executing PEAS on target: {e}')
        stderr += f'\nExecution exception: {e}'
    finally:
        logger.info('Cleaning up remote PEAS script...')
        try:
            connector.run_command(cleanup_cmd, timeout=30)
        except Exception as e:
            logger.warning(f'Failed to clean up remote PEAS script: {e}')
    if exit_code != 0 and (not stdout):
        return f'[red]PEAS Execution encountered an error:\n{stderr.strip()}[/red]'
    return stdout + ('\n' + '-' * 40 + '\nSTDERR:\n' + stderr if stderr.strip() else '')
