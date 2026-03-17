"""
ui/ai_providers.py — Predator AI provider adapters

Handles all 6 providers with correct auth/format:
  - OpenAI, DeepSeek, NVIDIA  → openai SDK (OpenAI-compatible)
  - Claude                    → requests (Anthropic Messages API)
  - Gemini                    → requests (Google generateContent API)
  - Ollama                    → requests (local, no auth)

Each provider's call() method returns the raw text content string.
Errors raise ProviderError with a human-readable message.

Usage:
    from ui.ai_providers import get_provider
    prov = get_provider("deepseek", api_key="sk-…", base_url="…", model="deepseek-chat")
    text = prov.call(messages=[{"role":"user","content":"…"}])
"""
from __future__ import annotations
import time
import json
try:
    from openai import OpenAI as _OpenAI
    _HAS_OPENAI = True
except ImportError:
    _HAS_OPENAI = False
try:
    import requests as _req
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

class ProviderError(Exception):
    """Raised on API connectivity or authentication failures."""

def _retry(fn, retries: int=3, base_delay: float=2.0):
    """Call fn() with exponential back-off on rate-limit errors."""
    last_exc = None
    for attempt in range(retries):
        try:
            return fn()
        except ProviderError:
            raise
        except Exception as e:
            msg = str(e).lower()
            if 'rate' in msg or '429' in msg or 'timeout' in msg:
                wait = base_delay * 2 ** attempt
                time.sleep(wait)
                last_exc = e
            else:
                raise
    raise last_exc or RuntimeError('All retries exhausted')

class _BaseProvider:

    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.model = model

    def call(self, messages: list, max_tokens: int=3000, temperature: float=0.1) -> str:
        raise NotImplementedError

    def stream_call(self, messages: list, on_chunk=None, max_tokens: int=3000) -> str:
        """Streaming call; yields chunks via on_chunk(text). Returns full text."""
        raise NotImplementedError

class OpenAICompatProvider(_BaseProvider):
    """Uses the official openai SDK (works for DeepSeek and NVIDIA too)."""

    def __init__(self, api_key: str, base_url: str, model: str):
        super().__init__(api_key, base_url, model)
        if not _HAS_OPENAI:
            raise ProviderError('openai SDK not installed — run: pip install openai')
        self._client = _OpenAI(api_key=api_key or 'ollama', base_url=base_url + '/')

    def call(self, messages: list, max_tokens: int=3000, temperature: float=0.1) -> str:

        def _do():
            resp = self._client.chat.completions.create(model=self.model, messages=messages, max_tokens=max_tokens, temperature=temperature)
            return resp.choices[0].message.content or ''
        try:
            return _retry(_do)
        except Exception as e:
            raise ProviderError(f'{self.model}: {e}') from e

    def stream_call(self, messages: list, on_chunk=None, max_tokens: int=3000) -> str:
        full = []
        try:
            with self._client.chat.completions.create(model=self.model, messages=messages, max_tokens=max_tokens, temperature=0.1, stream=True) as stream:
                for chunk in stream:
                    delta = chunk.choices[0].delta.content or ''
                    if delta:
                        full.append(delta)
                        if on_chunk:
                            on_chunk(delta)
        except Exception as e:
            raise ProviderError(f'Stream {self.model}: {e}') from e
        return ''.join(full)

class OllamaProvider(_BaseProvider):
    """Ollama local API — no auth, different endpoint format."""

    def call(self, messages: list, max_tokens: int=3000, temperature: float=0.1) -> str:
        if not _HAS_REQUESTS:
            raise ProviderError('requests not installed — pip install requests')

        def _do():
            r = _req.post(f'{self.base_url}/api/chat', json={'model': self.model, 'messages': messages, 'stream': False, 'options': {'temperature': temperature, 'num_predict': max_tokens}}, timeout=180)
            if r.status_code != 200:
                raise ProviderError(f'Ollama HTTP {r.status_code}: {r.text[:200]}')
            data = r.json()
            return data.get('message', {}).get('content', '')
        try:
            return _retry(_do)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f'Ollama: {e}') from e

    def stream_call(self, messages: list, on_chunk=None, max_tokens: int=3000) -> str:
        if not _HAS_REQUESTS:
            raise ProviderError('requests not installed')
        full = []
        try:
            with _req.post(f'{self.base_url}/api/chat', json={'model': self.model, 'messages': messages, 'stream': True}, stream=True, timeout=180) as r:
                for line in r.iter_lines():
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        text = obj.get('message', {}).get('content', '')
                        if text:
                            full.append(text)
                            if on_chunk:
                                on_chunk(text)
                    except Exception:
                        pass
        except Exception as e:
            raise ProviderError(f'Ollama stream: {e}') from e
        return ''.join(full)

class ClaudeProvider(_BaseProvider):

    def call(self, messages: list, max_tokens: int=3000, temperature: float=0.1) -> str:
        if not _HAS_REQUESTS:
            raise ProviderError('requests not installed')
        if not self.api_key:
            raise ProviderError('Claude requires an API key (sk-ant-…)')
        system_msg = ''
        chat_msgs = []
        for m in messages:
            if m['role'] == 'system':
                system_msg = m['content']
            else:
                chat_msgs.append(m)
        payload: dict = {'model': self.model, 'messages': chat_msgs, 'max_tokens': max_tokens}
        if system_msg:
            payload['system'] = system_msg

        def _do():
            r = _req.post(f'{self.base_url}/messages', headers={'x-api-key': self.api_key, 'anthropic-version': '2023-06-01', 'content-type': 'application/json'}, json=payload, timeout=90)
            if r.status_code == 401:
                raise ProviderError('Claude: invalid API key (sk-ant-…)')
            if r.status_code != 200:
                raise ProviderError(f'Claude HTTP {r.status_code}: {r.text[:200]}')
            return r.json()['content'][0]['text']
        try:
            return _retry(_do)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f'Claude: {e}') from e

    def stream_call(self, messages: list, on_chunk=None, max_tokens: int=3000) -> str:
        return self.call(messages, max_tokens)

class GeminiProvider(_BaseProvider):

    def call(self, messages: list, max_tokens: int=3000, temperature: float=0.1) -> str:
        if not _HAS_REQUESTS:
            raise ProviderError('requests not installed')
        if not self.api_key:
            raise ProviderError('Gemini requires an API key (AIza…)')
        combined = '\n\n'.join((f"[{m['role'].upper()}]\n{m['content']}" for m in messages))

        def _do():
            r = _req.post(f'{self.base_url}/models/{self.model}:generateContent?key={self.api_key}', json={'contents': [{'parts': [{'text': combined}]}], 'generationConfig': {'maxOutputTokens': max_tokens, 'temperature': temperature}}, timeout=90)
            if r.status_code == 400:
                raise ProviderError(f'Gemini 400: {r.text[:300]}')
            if r.status_code == 403:
                raise ProviderError('Gemini: invalid API key (AIza…)')
            if r.status_code != 200:
                raise ProviderError(f'Gemini HTTP {r.status_code}: {r.text[:200]}')
            candidates = r.json().get('candidates', [])
            if not candidates:
                raise ProviderError('Gemini: empty response (no candidates)')
            return candidates[0]['content']['parts'][0]['text']
        try:
            return _retry(_do)
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f'Gemini: {e}') from e

    def stream_call(self, messages: list, on_chunk=None, max_tokens: int=3000) -> str:
        return self.call(messages, max_tokens)

def get_provider(provider: str, api_key: str, base_url: str, model: str) -> _BaseProvider:
    """
    Return the appropriate provider adapter.

    provider: "ollama" | "openai" | "deepseek" | "nvidia" | "claude" | "gemini"
    """
    p = provider.lower()
    if p == 'ollama':
        return OllamaProvider(api_key='', base_url=base_url, model=model)
    elif p in ('openai', 'deepseek', 'nvidia'):
        if not api_key and p != 'ollama':
            raise ProviderError(f'{provider} requires an API key.')
        return OpenAICompatProvider(api_key=api_key, base_url=base_url, model=model)
    elif p == 'claude':
        return ClaudeProvider(api_key=api_key, base_url=base_url, model=model)
    elif p == 'gemini':
        return GeminiProvider(api_key=api_key, base_url=base_url, model=model)
    else:
        raise ProviderError(f'Unknown provider: {provider}')
