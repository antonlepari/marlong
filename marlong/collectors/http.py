"""A thin, polite HTTP wrapper used by every collector.

Centralises the user-agent, timeout, inter-request delay and a simple
backoff so individual collectors don't each reinvent rate limiting.
"""
from __future__ import annotations

import email.utils
import logging
import time
from typing import Iterable, Optional

import requests

log = logging.getLogger("marlong.http")

# Transient server-side errors worth retrying with backoff. Many free APIs
# (crt.sh especially) return these sporadically under load even for valid
# queries, so a single attempt is unreliable.
DEFAULT_RETRY_STATUSES = (500, 502, 503, 504)


class HttpClient:
    def __init__(self, user_agent: str, delay: float = 1.0, timeout: float = 20.0):
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self._last_call = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_call = time.monotonic()

    def get(
        self,
        url: str,
        *,
        params=None,
        headers=None,
        max_retries: int = 3,
        retry_statuses: Iterable[int] = DEFAULT_RETRY_STATUSES,
    ) -> Optional[requests.Response]:
        retry_statuses = set(retry_statuses)
        for attempt in range(1, max_retries + 1):
            self._throttle()
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                log.warning("request error (%s/%s): %s", attempt, max_retries, exc)
                time.sleep(min(2 ** attempt, 30))
                continue

            # Respect explicit rate-limit signals (GitHub, etc.)
            if resp.status_code in (403, 429):
                reset = resp.headers.get("Retry-After") or resp.headers.get("X-RateLimit-Reset")
                wait = 60
                if resp.headers.get("X-RateLimit-Remaining") == "0" and reset:
                    try:
                        wait = max(1, int(float(reset)) - int(time.time()))
                    except ValueError:
                        wait = 60
                elif reset:
                    try:
                        # Retry-After is either a delta-seconds integer or an HTTP-date string
                        wait = int(reset)
                    except ValueError:
                        try:
                            parsed_ts = email.utils.parsedate_to_datetime(reset).timestamp()
                            wait = max(1, int(parsed_ts) - int(time.time()))
                        except Exception:
                            wait = 60
                wait = min(wait, 90)
                log.warning("rate limited (%s); waiting %ss", resp.status_code, wait)
                time.sleep(wait)
                continue

            # Transient server errors: back off and retry rather than giving up.
            if resp.status_code in retry_statuses and attempt < max_retries:
                wait = min(2 ** attempt, 30)
                log.warning("server error (%s/%s): HTTP %s, retrying in %ss",
                            attempt, max_retries, resp.status_code, wait)
                time.sleep(wait)
                continue
            return resp
        return None
