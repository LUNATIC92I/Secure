import time
from collections import defaultdict, deque
from threading import Lock


class SlidingWindowLimiter:
    """In-process sliding-window limiter. For multi-instance deployments put a shared
    limiter (e.g. at the reverse proxy or Redis) in front; this one still bounds each worker."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()
