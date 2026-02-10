"""
Redis connection utility for caching on-call schedules and real-time state.
"""
import os
import json
import logging
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_pool: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        host = os.getenv("REDIS_HOST", "localhost")
        port = int(os.getenv("REDIS_PORT", "6379"))
        _pool = aioredis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            max_connections=20,
        )
    return _pool


async def cache_set(key: str, value: dict, ttl: int = 300):
    r = await get_redis()
    await r.setex(key, ttl, json.dumps(value))


async def cache_get(key: str) -> Optional[dict]:
    r = await get_redis()
    data = await r.get(key)
    if data:
        return json.loads(data)
    return None


async def cache_delete(key: str):
    r = await get_redis()
    await r.delete(key)


async def publish_event(channel: str, data: dict):
    """Publish real-time event via Redis Pub/Sub."""
    r = await get_redis()
    await r.publish(channel, json.dumps(data))
