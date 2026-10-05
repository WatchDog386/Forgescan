"""A small request limiter held in memory (FR-49). One process only; use a shared store if the backend is scaled out."""
import time
from collections import defaultdict, deque

from fastapi import HTTPException, status


class RateLimiter:
    def __init__(self) -> None:
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, per_minute: int) -> None:
        now, hits = time.monotonic(), self.hits[key]
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= per_minute:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "The request limit has been exceeded. Try again in a minute.")
        hits.append(now)


limiter = RateLimiter()
