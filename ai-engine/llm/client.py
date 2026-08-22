from typing import Optional
import requests


class LLMClient:
    def __init__(self, endpoint_url: Optional[str] = None, timeout: int = 5):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    @property
    def is_available(self) -> bool:
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

        try:
            payload = {
                "model": "llama3",
                "prompt": prompt,
                "stream": False,
            }

            resp = requests.post(
                f"{self.endpoint_url.rstrip('/')}/api/generate",
                json=payload,
                timeout=self.timeout,
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", "").strip()

        except Exception:
            return None

        return None
