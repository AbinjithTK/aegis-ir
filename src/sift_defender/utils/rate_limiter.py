"""Rate limiter for Vertex AI API calls — prevents 429 errors.

Strategy:
- Token bucket rate limiter (configurable RPM)
- Exponential backoff on 429 with jitter
- Wraps the ADK runner to add delays between LLM calls
- Configurable per-model limits

For Vertex AI gemini-2.5-flash:
- Free tier: 10 RPM, 250K TPM
- Paid Tier 1: 200 RPM, 4M TPM  
- DSQ (recommended): No hard limits, best-effort
"""

import asyncio
import time
import random
from typing import Optional


class RateLimiter:
    """Token bucket rate limiter for LLM API calls."""

    def __init__(self, requests_per_minute: int = 8, burst: int = 3):
        """
        Args:
            requests_per_minute: Max sustained requests per minute (default 8 = safe for free tier 10 RPM)
            burst: Max burst above sustained rate
        """
        self.rpm = requests_per_minute
        self.burst = burst
        self._interval = 60.0 / requests_per_minute  # Seconds between requests
        self._last_request_time = 0.0
        self._tokens = burst
        self._max_tokens = burst
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until a request token is available."""
        async with self._lock:
            now = time.time()
            elapsed = now - self._last_request_time

            # Refill tokens based on elapsed time
            self._tokens = min(
                self._max_tokens,
                self._tokens + elapsed / self._interval
            )

            if self._tokens < 1.0:
                # Wait for next token
                wait_time = (1.0 - self._tokens) * self._interval
                await asyncio.sleep(wait_time)
                self._tokens = 1.0

            self._tokens -= 1.0
            self._last_request_time = time.time()


class RetryWithBackoff:
    """Exponential backoff for 429 errors from Vertex AI.
    
    Usage:
        retry = RetryWithBackoff()
        
        async def make_request():
            # ... your LLM call
            pass
        
        result = await retry.execute(make_request)
    """

    def __init__(
        self,
        max_retries: int = 5,
        initial_delay: float = 2.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self._retry_count = 0
        self._total_retries = 0

    async def execute(self, func, *args, **kwargs):
        """Execute function with retry on 429/RESOURCE_EXHAUSTED errors."""
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                result = await func(*args, **kwargs)
                if attempt > 0:
                    self._retry_count = 0  # Reset on success
                return result
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str:
                    last_error = e
                    if attempt < self.max_retries:
                        delay = min(
                            self.initial_delay * (self.backoff_factor ** attempt),
                            self.max_delay,
                        )
                        # Add jitter (±25%)
                        jitter = delay * 0.25 * (2 * random.random() - 1)
                        wait = delay + jitter
                        self._retry_count += 1
                        self._total_retries += 1
                        print(f"  ⏳ Rate limited (attempt {attempt+1}/{self.max_retries}). Waiting {wait:.1f}s...")
                        await asyncio.sleep(wait)
                    else:
                        raise
                else:
                    raise

        raise last_error

    @property
    def stats(self) -> dict:
        return {
            "total_retries": self._total_retries,
            "current_retry_streak": self._retry_count,
        }


# Global rate limiter instance (configured for safe Vertex AI usage)
_global_limiter: Optional[RateLimiter] = None


def get_rate_limiter(rpm: int = 8) -> RateLimiter:
    """Get or create the global rate limiter.
    
    Args:
        rpm: Requests per minute (default 8 = safe for free tier)
             Set to 150 for paid Tier 1
             Set to 1000 for DSQ/enterprise
    """
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(requests_per_minute=rpm)
    return _global_limiter
