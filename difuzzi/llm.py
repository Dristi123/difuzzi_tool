"""Client for the Kimi (Moonshot) and Gemini chat-completions APIs.

Configuration (environment variables), needed only when an input generator has to be written:
  DIFUZZI_LLM_MODEL   model name (default: "Kimi K2.5", the model of the bundled examples' generators);
                      names starting with "kimi" use the Kimi API, names starting with "gemini" the Gemini API
  DIFUZZI_LLM_API_KEY API key of that provider
"""

from __future__ import annotations

import json
import os
import re
import time

import requests

DEFAULT_MODEL = "Kimi K2.5"

# Both providers offer an OpenAI-compatible chat-completions endpoint; the model name picks the provider.
PROVIDERS = {
    "kimi": "https://api.moonshot.ai/v1/chat/completions",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
}


class LLMError(RuntimeError):
    pass


def endpoint(model: str) -> tuple[str, str]:
    """(url, model id sent to the API) for a supported model name."""
    name = model.strip().lower()
    for prefix, url in PROVIDERS.items():
        if name.startswith(prefix):
            return url, (name.replace(" ", "-") if prefix == "kimi" else model.strip())
    raise LLMError(f"Unsupported model '{model}': use a Kimi model (e.g. kimi-k2.5) or a Gemini model "
                   "(e.g. gemini-3.8-flash).")


def config(require_key: bool = True):
    """(url, model, key) for the configured model."""
    model = os.environ.get("DIFUZZI_LLM_MODEL", DEFAULT_MODEL)
    key = os.environ.get("DIFUZZI_LLM_API_KEY")
    url, _ = endpoint(model) if require_key else (None, None)
    if require_key and not key:
        raise LLMError("An LLM is needed to write the input generator for these programs: set "
                       "DIFUZZI_LLM_API_KEY and DIFUZZI_LLM_MODEL (a Kimi or Gemini model).")
    return url, model, key


def chat(prompt: str, *, temperature: float = 0.1, timeout: int = 300, retries: int = 3) -> str:
    """Send one user message and return the reply text (reasoning blocks removed)."""
    url, model, key = config()
    body = {"model": endpoint(model)[1], "temperature": temperature, "stream": True,
            "messages": [{"role": "user", "content": prompt}]}
    last = None
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(url, headers={"Authorization": f"Bearer {key}"},
                                 json=body, timeout=timeout, stream=True)
            if resp.status_code >= 400:
                raise LLMError(f"HTTP {resp.status_code} from {url}: {resp.text[:500]}")
            parts, raw = [], []
            for line in resp.iter_lines(decode_unicode=True):
                if line is None:
                    continue
                raw.append(line)
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if payload == "[DONE]":
                    break
                try:
                    delta = json.loads(payload)["choices"][0].get("delta", {})
                except (ValueError, KeyError, IndexError):
                    continue
                if delta.get("content"):
                    parts.append(delta["content"])
            answer = "".join(parts)
            if not answer.strip():  # endpoint answered with a plain JSON body
                try:
                    answer = json.loads("\n".join(raw))["choices"][0]["message"]["content"]
                except Exception:
                    pass
            if not answer.strip():
                raise LLMError("empty response")
            return re.sub(r"<think>.*?</think>", "", answer, flags=re.S)
        except Exception as e:  # retry transient failures
            last = e
            if attempt < retries:
                time.sleep(min(2 ** attempt, 30))
    raise LLMError(f"LLM call failed after {retries} attempts: {last}")


def extract_code(reply: str) -> str:
    """The longest fenced code block in the reply, or the whole reply if there is none."""
    blocks = re.findall(r"```[\w+-]*[ \t]*\n(.*?)```", reply, re.S)
    return (max(blocks, key=len) if blocks else reply).strip() + "\n"
