"""
Rate Limiter & Brute-Force Protection.
Enforces sliding-window request throttling and tracks failed attempt velocities.
"""
import time
import threading
from typing import Dict, List, Tuple

class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 600, lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.lock = threading.Lock()
        # Key: identifier (e.g. ip or email) -> list of failure timestamps
        self.failures: Dict[str, List[float]] = {}
        # Key: identifier -> lockout until timestamp
        self.lockouts: Dict[str, float] = {}

    def is_locked(self, identifier: str) -> Tuple[bool, int]:
        """Checks if identifier is currently locked out. Returns (is_locked, remaining_seconds)."""
        now = time.time()
        with self.lock:
            if identifier in self.lockouts:
                until = self.lockouts[identifier]
                if now < until:
                    return True, int(until - now)
                else:
                    del self.lockouts[identifier]
            return False, 0

    def record_failure(self, identifier: str) -> Tuple[bool, int]:
        """Records a failed attempt. If threshold exceeded, triggers lockout."""
        now = time.time()
        with self.lock:
            history = self.failures.get(identifier, [])
            # Purge entries outside window
            history = [t for t in history if now - t < self.window_seconds]
            history.append(now)
            self.failures[identifier] = history

            if len(history) >= self.max_attempts:
                lockout_until = now + self.lockout_seconds
                self.lockouts[identifier] = lockout_until
                return True, self.lockout_seconds
            return False, 0

    def record_success(self, identifier: str):
        """Clears failure history on legitimate successful authentication."""
        with self.lock:
            self.failures.pop(identifier, None)
            self.lockouts.pop(identifier, None)

    def clear_all(self):
        """Resets all tracked failures and active lockouts."""
        with self.lock:
            self.failures.clear()
            self.lockouts.clear()

    def get_recent_failure_count(self, identifier: str, window_seconds: int = 900) -> int:
        """Returns the number of failures in the specified sliding window for ML feature extraction."""
        now = time.time()
        with self.lock:
            history = self.failures.get(identifier, [])
            return sum(1 for t in history if now - t < window_seconds)

rate_limiter = RateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=900)
