from typing import Optional
import requests

from llm.redaction import redact_text


class LLMClient:
    def __init__(self, endpoint_url: Optional[str] = None, timeout: int = 5):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    @property
    def is_available(self) -> bool:
        # Health check only - carries no prompt/user/security content, so
        # it is explicitly exempt from the content-redaction boundary
        # below (see PHASE_4_TD_SPECS.md TD #15, "Health check مستثنى").
        if not self.endpoint_url:
            return False

        try:
            resp = requests.get(
                f"{self.endpoint_url.rstrip('/')}/api/tags",
                timeout=self.timeout,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def generate_summary_observation(self, prompt: str) -> Optional[str]:
        if not self.endpoint_url:
            return None

        # TD #15: LLMClient is the single enforcement boundary - every
        # prompt is redacted before it can leave the process. Redaction
        # failure is fail-closed: no request is sent with unredacted
        # content, and the failure itself is never logged with raw
        # prompt data (see the bare `except Exception` below).
        try:
            safe_prompt = redact_text(prompt)
        except Exception:
            return None

        try:
            payload = {
                "model": "llama3",
                "prompt": safe_prompt,
                "stream": False,
            }

            resp = requests.post(
                f"{self.endpoint_url.rstrip('/')}/api/generate",
                json=payload,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                raw_response = data.get("response", "").strip()
                # Output redaction: the LLM's own response is redacted
                # before it can reach the report/downstream. Fail-closed
                # here too - a redaction failure never returns raw text.
                try:
                    return redact_text(raw_response)
                except Exception:
                    return None

        except Exception:
            return None

        return None
