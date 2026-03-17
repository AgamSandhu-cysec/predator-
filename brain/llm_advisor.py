"""
brain/llm_advisor.py

LLM-based reasoning via Ollama (local models: mistral, llama3, etc.).
Disabled by default — set brain.llm.enabled: true in config.yaml and
ensure Ollama is running (ollama serve).
"""
import json
import re
from utils.logger import get_logger
logger = get_logger('LLMAdvisor')
try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
_ANALYSE_SYSTEM = 'You are an expert Linux/Windows privilege escalation specialist. Analyse the system enumeration output and identify the 3 most promising escalation vectors. For each, output a JSON object with keys: "vector" (short name), "commands" (list of shell commands), "confidence" (0.0-1.0), "explanation" (one sentence). Output a JSON array only — no markdown, no prose.'

class LLMAdvisor:
    """
    Sends enumeration output to a local Ollama model and parses
    structured exploit suggestions from the response.

    Usage
    -----
    advisor = LLMAdvisor(config["brain"]["llm"])
    suggestions = advisor.analyse(linpeas_output)  # list of dicts
    explanation = advisor.explain_failure("dirtycow", error_text)
    """

    def __init__(self, config: dict):
        self.enabled = config.get('enabled', False) and _HAS_REQUESTS
        self.endpoint = config.get('endpoint', 'http://localhost:11434/api/generate')
        self.model = config.get('model', 'mistral')
        self.timeout = config.get('timeout', 90)
        if self.enabled:
            logger.info(f'LLM advisor enabled — model={self.model}')
        else:
            logger.info('LLM advisor disabled (set brain.llm.enabled: true to enable).')

    def _query(self, prompt: str, system: str='') -> str:
        """Send a prompt to Ollama and return the response text."""
        if not self.enabled:
            return ''
        full_prompt = f'{system}\n\n{prompt}' if system else prompt
        payload = {'model': self.model, 'prompt': full_prompt, 'stream': False, 'options': {'temperature': 0.2}}
        try:
            resp = _requests.post(self.endpoint, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            return resp.json().get('response', '')
        except Exception as e:
            logger.warning(f'Ollama request failed: {e}')
            return ''

    def analyse(self, enum_output: str) -> list:
        """
        Analyse enumeration output and return escalation suggestions.

        Returns list of dicts: [{vector, commands, confidence, explanation}]
        """
        if not self.enabled:
            return []
        truncated = enum_output[:6000]
        raw = self._query(truncated, system=_ANALYSE_SYSTEM)
        if not raw:
            return []
        match = re.search('\\[.*\\]', raw, re.DOTALL)
        if not match:
            logger.warning('LLM response did not contain a JSON array.')
            return []
        try:
            suggestions = json.loads(match.group(0))
            result = []
            for s in suggestions:
                if not isinstance(s, dict):
                    continue
                result.append({'name': s.get('vector', 'llm_suggestion'), 'module': s.get('vector', 'llm_suggestion'), 'commands': s.get('commands', []), 'confidence': float(s.get('confidence', 0.5)), 'explanation': s.get('explanation', ''), 'source': 'llm', 'type': 'llm'})
            logger.info(f'LLM returned {len(result)} suggestions.')
            return result
        except json.JSONDecodeError as e:
            logger.warning(f'LLM JSON parse error: {e}')
            return []

    def explain_failure(self, exploit_name: str, error_output: str) -> str:
        """
        Ask the LLM to diagnose a failed exploit attempt in one sentence.
        Returns empty string if LLM is disabled or fails.
        """
        if not self.enabled:
            return ''
        prompt = f"Exploit '{exploit_name}' failed. Error output:\n{error_output[:800]}\n\nIn ONE sentence explain the most likely cause and the best fix. Plain text only, no markdown."
        resp = self._query(prompt)
        first_line = resp.strip().split('\n')[0]
        return first_line[:300]

    def suggest_preconditions(self, transcript: str) -> list:
        """
        Given a shell session transcript, suggest which feature flags
        from brain.feature_schema.FEATURE_NAMES are likely preconditions.
        Returns a list of feature name strings.
        """
        from brain.feature_schema import FEATURE_NAMES
        prompt = f'Shell session transcript:\n{transcript[:2000]}\n\nAvailable feature names:\n{json.dumps(FEATURE_NAMES)}\n\nList the feature names that were likely REQUIRED for these commands to work. Reply with a JSON array of strings only.'
        raw = self._query(prompt)
        match = re.search('\\[.*?\\]', raw, re.DOTALL)
        if not match:
            return ['user_shell']
        try:
            candidates = json.loads(match.group(0))
            return [c for c in candidates if c in FEATURE_NAMES]
        except Exception:
            return ['user_shell']

    def generate_custom_exploit(self, feature_summary: str, cve_id: str='') -> dict:
        """
        Ask the LLM to generate a custom shell command sequence for a given CVE
        or feature set. Returns {commands: list, explanation: str}.
        """
        if not self.enabled:
            return {}
        cve_clause = f'exploiting {cve_id}' if cve_id else 'achieving privilege escalation'
        prompt = f'Target system features:\n{feature_summary}\n\nGenerate a shell command sequence for {cve_clause}. Reply with JSON: {{"commands": ["cmd1","cmd2"], "explanation": "..."}}'
        raw = self._query(prompt)
        match = re.search('\\{.*\\}', raw, re.DOTALL)
        if not match:
            return {}
        try:
            return json.loads(match.group(0))
        except Exception:
            return {}
