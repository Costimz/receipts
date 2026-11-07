"""OpenAI-compatible client for Vultr Serverless Inference. Stdlib only."""
import json
import os
import re
import time
import urllib.error
import urllib.request

THINK_RE = re.compile(r"<think>.*?</think>", re.S)


class LLMError(RuntimeError):
    pass


def configured():
    return bool(os.environ.get("INFERENCE_API_KEY"))


# Reasoning counts against max_tokens on these models, and a low limit gets used up before any answer appears.
DEFAULT_MAX_TOKENS = 8000


def chat(messages, model=None, max_tokens=DEFAULT_MAX_TOKENS, temperature=0.1, retries=2):
    base = os.environ.get("INFERENCE_BASE_URL", "https://api.vultrinference.com/v1").rstrip("/")
    key = os.environ.get("INFERENCE_API_KEY", "")
    if not key:
        raise LLMError("INFERENCE_API_KEY is not set")
    body = json.dumps({
        "model": model or os.environ.get("MODEL_CODE", "glm-5.3"),
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        # Left to its default, glm-5.3 reasoned through 8000 tokens and 4 minutes per script. Low took 2.5 seconds.
        "reasoning_effort": os.environ.get("REASONING_EFFORT", "low"),
    }).encode()
    last = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(f"{base}/chat/completions", data=body, headers={
            "Authorization": f"Bearer {key}", "Content-Type": "application/json", "User-Agent": "receipts/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode())
            text = THINK_RE.sub("", data["choices"][0]["message"].get("content") or "").strip()
            if text:
                return text
            last = f"empty reply (finish_reason={data['choices'][0].get('finish_reason')})"
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code not in (408, 429, 500, 502, 503, 504):
                break
        except (urllib.error.URLError, TimeoutError, KeyError, IndexError, ValueError) as e:
            last = type(e).__name__
        time.sleep(1.5 * (attempt + 1))
    raise LLMError(f"inference failed: {last}")


def extract_json(text):
    """Pull the first JSON object out of a model reply, with or without a code fence."""
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        text = fence.group(1)
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in reply")
    obj, _ = json.JSONDecoder().raw_decode(text[start:])
    return obj


def extract_code(text):
    """Pull Python out of a fenced block; if there is no fence, treat the reply as code."""
    fence = re.search(r"```(?:python|py)?\s*\n(.*?)```", text, re.S)
    return (fence.group(1) if fence else text).strip()
