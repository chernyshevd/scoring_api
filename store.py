import json
import logging

from redis import Redis, RedisError
from redis.backoff import ExponentialBackoff
from redis.retry import Retry

logger = logging.getLogger('store')


class StoreError(Exception):
    pass


class Store:
    """
    Client for Redis server.

    Args:
        host: str, host at which Redis server is running (default: localhost)
        port: int, port at which Redis server is running (default: 6379)
        timeout: float, time in seconds to wait on heavy operations (default: 1 seconds)
        retries: int, times to retry heavy operations (default: 10 times)
    """

    def __init__(self, host: str = 'localhost', port: int = 6379,
                 timeout: float = 3., retries: int = 10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries

        self.cache_connection = None
        self.db_connection = None

    def connect(self, timeout: float = 10.):
        """
        Connection to Redis server

        Args:
            timeout: float, time in seconds to wait until connection is established (default: 10 seconds)
        """
        self.cache_connection = Redis(self.host, self.port, decode_responses=True,
                                       socket_connect_timeout=timeout / 2)
        self.db_connection = Redis(self.host, self.port, decode_responses=True,
                                       socket_connect_timeout=timeout / 2,
                                       socket_timeout=self.timeout,
                                       retry_on_timeout=True,
                                       retry_on_error=[RedisError],
                                       retry=Retry(ExponentialBackoff(self.timeout, 1.), self.retries))
        logger.info("Connected to Redis server at %s:%d", self.host, self.port)

    def disconnect(self):
        """
        Disconnect from Redis server.
        """
        self.cache_connection.close()
        self.db_connection.close()
        self.cache_connection, self.db_connection = None, None
        logger.info("Disconnected from Redis server at %s:%d", self.host, self.port)

    def cache_get(self, key: str):
        """
        Read value from Redis server by key and decode it as JSON string. If server is unavailable, returns None.

        Args:
            key: str, key for resource

        Returns:
            None if server unavailable or no value is stored for key, decoded value otherwise
        """
        try:
            value = self.cache_connection.get(key)
        except RedisError:
            logger.exception("An error occurred while trying to read from Redis cache at %s:%d", self.host, self.port)
            value = None

        if value is not None:
            return json.loads(value)
        else:
            return None

    def cache_set(self, key, value, ttl):
        """
        Write JSON-encoded value to server by key with TTL. If server is unavailable, does nothing.

        Args:
            key: str, key for resource
            value: value to store
            ttl: time-to-live in seconds

        Returns:
            None
        """
        try:
            self.cache_connection.set(key, json.dumps(value), ex=ttl)
        except RedisError:
            logger.exception("An error occurred while trying to write to Redis cache at %s:%d", self.host, self.port)

    def get(self, key):
        """
        Read value from Redis server by key and decode it as JSON string. If server is unavailable, raises an exception.

        Args:
            key: str, key for resource

        Raises:
            StoreError if server is unavailable

        Returns:
            None if no value is stored for key, decoded value otherwise
        """
        try:
            value = self.db_connection.get(key)
        except RedisError as e:
            logger.exception(
                "An error occurred while trying to read from Redis persistent storage at %s:%d", self.host, self.port
            )
            raise StoreError(
                f"An error occurred while trying to read from Redis persistent storage at {self.host}:{self.port}"
            ) from e

        if value is not None:
            return json.loads(value)
        else:
            return None
