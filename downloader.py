"""
downloader.py — Auto-download exploit sources for Predator.

Priority order for resolving a named exploit:
  1. Already present in project exploits/linux/bin/ or exploits/windows/bin/
  2. Found by searchsploit (local ExploitDB mirror)
  3. Fetch raw file from a trusted GitHub URL
  4. Fetch from exploit-db.com raw endpoint

Downloads are cached in ~/.predator/exploits/ so repeated runs are instant.
"""
import os
import subprocess
import json
import hashlib
import urllib.request
import urllib.error
from utils.logger import get_logger
logger = get_logger('Downloader')
CACHE_DIR = os.path.expanduser('~/.predator/exploits')
_KNOWN_SOURCES: dict[str, dict] = {'dirtycow': {'type': 'github', 'url': 'https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c', 'filename': 'dirtycow.c'}, 'dirtycow_precomp_x86_64': {'type': 'github', 'url': 'https://github.com/FireFart/dirtycow/releases/download/master/dirtycow', 'filename': 'dirtycow_x86_64'}, 'sudo_baron_samedit': {'type': 'exploitdb', 'id': '49521', 'filename': 'baron_samedit.py'}, 'pkexec_pwnkit': {'type': 'github', 'url': 'https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c', 'filename': 'pwnkit.c'}, 'sudo_cve_2019_14287': {'type': 'exploitdb', 'id': '47502', 'filename': 'sudo_bypass.sh'}, 'ms17_010': {'type': 'github', 'url': 'https://raw.githubusercontent.com/helviojunior/MS17-010/master/send_and_execute.py', 'filename': 'ms17_010.py'}, 'printspoofer': {'type': 'github', 'url': 'https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe', 'filename': 'PrintSpoofer.exe'}, 'juicypotato': {'type': 'github', 'url': 'https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe', 'filename': 'JuicyPotato.exe'}, 'roguepotato': {'type': 'github', 'url': 'https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip', 'filename': 'RoguePotato.zip'}, 'godpotato': {'type': 'github', 'url': 'https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe', 'filename': 'GodPotato.exe'}}

def _ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)

def _cached_path(filename: str) -> str:
    return os.path.join(CACHE_DIR, filename)

def _is_cached(filename: str) -> bool:
    p = _cached_path(filename)
    return os.path.exists(p) and os.path.getsize(p) > 0

def _download_url(url: str, dest: str, update_callback=None) -> bool:
    """Download `url` to `dest`. Returns True on success."""

    def log(msg):
        if update_callback:
            update_callback(msg + '\n')
        logger.info(msg)
    try:
        log(f'[cyan][*] Downloading: {url}[/cyan]')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as r, open(dest, 'wb') as f:
            f.write(r.read())
        log(f'[green][+] Saved to {dest}[/green]')
        return True
    except urllib.error.HTTPError as e:
        log(f'[red][-] HTTP {e.code} fetching {url}[/red]')
        return False
    except Exception as e:
        log(f'[red][-] Download failed: {e}[/red]')
        return False

def searchsploit_query(query: str) -> list[dict]:
    """
    Run `searchsploit --json <query>` and return list of result dicts.
    Returns [] if searchsploit is not installed or query fails.
    """
    try:
        result = subprocess.run(['searchsploit', '--json', query], capture_output=True, text=True, timeout=15)
        data = json.loads(result.stdout)
        return data.get('RESULTS_EXPLOIT', [])
    except FileNotFoundError:
        logger.warning('searchsploit not found — skipping local ExploitDB lookup')
        return []
    except Exception as e:
        logger.error(f'searchsploit_query failed: {e}')
        return []

def download_from_exploitdb(exploit_id: str, filename: str, update_callback=None) -> str | None:
    """
    Download raw exploit from exploit-db.com/raw/<id>.
    Returns local path on success, None on failure.
    """
    _ensure_cache_dir()
    dest = _cached_path(filename)
    if _is_cached(filename):
        return dest
    url = f'https://www.exploit-db.com/raw/{exploit_id}'
    return dest if _download_url(url, dest, update_callback) else None

def download_from_github(raw_url: str, filename: str, update_callback=None) -> str | None:
    """
    Download a raw file from GitHub (or any direct URL).
    Returns local path on success, None on failure.
    """
    _ensure_cache_dir()
    dest = _cached_path(filename)
    if _is_cached(filename):
        return dest
    return dest if _download_url(raw_url, dest, update_callback) else None

def ensure_exploit(name: str, update_callback=None) -> str | None:
    """
    High-level helper: given a named exploit, ensure a source/binary file
    is available locally (in cache or project bin/).  Returns local file
    path on success, None if all methods fail.

    Resolution order:
      1. Project bin/ directories
      2. Cache already exists
      3. Known source dict → GitHub / ExploitDB download
      4. searchsploit query → copy from local exploitDB mirror
    """

    def log(msg):
        if update_callback:
            update_callback(msg + '\n')
        logger.info(msg)
    _ensure_cache_dir()
    for bin_dir in [os.path.join('exploits', 'linux', 'bin'), os.path.join('exploits', 'windows', 'bin')]:
        for f in [name, f'{name}.c', f'{name}.py', f'{name}.exe']:
            candidate = os.path.join(bin_dir, f)
            if os.path.exists(candidate):
                log(f'[green][+] Found local: {candidate}[/green]')
                return candidate
    for ext in ['', '.c', '.py', '.exe']:
        candidate = _cached_path(name + ext)
        if os.path.exists(candidate) and os.path.getsize(candidate) > 0:
            log(f'[green][+] Cache hit: {candidate}[/green]')
            return candidate
    if name in _KNOWN_SOURCES:
        src = _KNOWN_SOURCES[name]
        filename = src['filename']
        if src['type'] == 'github':
            return download_from_github(src['url'], filename, update_callback)
        elif src['type'] == 'exploitdb':
            return download_from_exploitdb(src['id'], filename, update_callback)
    log(f"[cyan][*] Querying searchsploit for '{name}'...[/cyan]")
    results = searchsploit_query(name)
    if results:
        match = results[0]
        path = match.get('Path', '')
        if path and os.path.exists(path):
            log(f'[green][+] Found via searchsploit: {path}[/green]')
            return path
        eid = match.get('EDB-ID')
        if eid:
            fname = f'{name}_{eid}.py'
            return download_from_exploitdb(str(eid), fname, update_callback)
    log(f"[red][-] Could not locate exploit source for '{name}'.[/red]")
    return None
