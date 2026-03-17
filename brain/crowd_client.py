"""
brain/crowd_client.py

Opt-in crowdsourced intelligence client.
Uploads anonymised exploit outcomes and downloads global success rates.

Privacy guarantees:
  - Disabled by default (brain.crowd.enabled: false in config.yaml)
  - Never transmits: IP, hostname, username, passwords, or file contents
  - Target is identified only as sha256(ip+user)[:16] — not reversible
  - Feature vectors are stored only as SHA-256 hashes
"""
import datetime
import hashlib
import json
import os
from utils.logger import get_logger
logger = get_logger('CrowdClient')
try:
    import requests as _req
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
_LAST_UPLOAD_FILE = 'brain/data/.last_crowd_upload'

class CrowdClient:
    """
    Upload anonymised exploit outcomes to a community server and
    download aggregated global success rates.
    """

    def __init__(self, config: dict):
        self.enabled = config.get('enabled', False) and _HAS_REQUESTS
        self.endpoint = config.get('endpoint', '').rstrip('/')
        self.interval_days = config.get('upload_interval_days', 7)
        if self.enabled:
            logger.info(f'Crowd client enabled — endpoint={self.endpoint}')

    def _should_upload(self) -> bool:
        if not os.path.exists(_LAST_UPLOAD_FILE):
            return True
        try:
            with open(_LAST_UPLOAD_FILE) as f:
                last = datetime.datetime.fromisoformat(f.read().strip())
            return (datetime.datetime.utcnow() - last).days >= self.interval_days
        except Exception:
            return True

    def _mark_uploaded(self):
        os.makedirs(os.path.dirname(_LAST_UPLOAD_FILE), exist_ok=True)
        with open(_LAST_UPLOAD_FILE, 'w') as f:
            f.write(datetime.datetime.utcnow().isoformat())

    def upload(self, feedback_logger) -> bool:
        """
        Upload anonymised attempts to the community server.
        Returns True on success, False on failure or if not due.
        """
        if not self.enabled:
            return False
        if not self._should_upload():
            logger.info('Crowd upload skipped — not due yet.')
            return False
        records = feedback_logger.export_anonymised(n=200)
        if not records:
            logger.info('No records to upload.')
            return False
        success_count = 0
        for rec in records:
            try:
                r = _req.post(f'{self.endpoint}/api/v1/submit', json=rec, timeout=5)
                if r.status_code == 200:
                    success_count += 1
            except Exception as e:
                logger.warning(f'Upload record failed: {e}')
        self._mark_uploaded()
        logger.info(f'Crowd upload: {success_count}/{len(records)} records sent.')
        return success_count > 0

    def download_stats(self) -> dict:
        """
        Download global exploit success rates from the community server.
        Returns {exploit_name: {"success_rate": float, "total": int}}.
        """
        if not self.enabled:
            return {}
        try:
            r = _req.get(f'{self.endpoint}/api/v1/stats', timeout=10)
            r.raise_for_status()
            data = r.json()
            logger.info(f'Downloaded global stats for {len(data)} exploits.')
            return data
        except Exception as e:
            logger.warning(f'Download stats failed: {e}')
            return {}

    def merge_global_rates(self, local_counts: dict, global_stats: dict, global_weight: float=0.3) -> dict:
        """
        Merge local Thompson counts with global community success rates.

        local_counts  : {exploit: (success_count, failure_count)}
        global_stats  : {exploit: {"success_rate": float, "total": int}}
        global_weight : 0.0–1.0 — how much to trust community data

        Returns {exploit: merged_rate}.
        """
        merged = {}
        all_exploits = set(local_counts) | set(global_stats)
        for exploit in all_exploits:
            s, f = local_counts.get(exploit, (0, 0))
            local_rate = (s + 1) / (s + f + 2)
            global_rate = global_stats.get(exploit, {}).get('success_rate', local_rate)
            merged[exploit] = (1.0 - global_weight) * local_rate + global_weight * global_rate
        return merged
