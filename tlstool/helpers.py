import time
import random
import logging
from functools import wraps

from sqlalchemy.exc import OperationalError, DatabaseError

logger = logging.getLogger(__name__)


def jitter_sleep(min_seconds: float, max_seconds: float):
    """
    Sleep for a random amount of time between min_seconds and max_seconds.
    Logs the sleep duration for observability.
    """
    sleep_time = random.uniform(min_seconds, max_seconds)
    logger.info(f"Sleeping for {sleep_time:.1f}s (jitter)")
    time.sleep(sleep_time)

def retry_db_transaction(max_retries=3, min_sleep=1, max_sleep=3, allowed_exceptions=None):
    """
    Decorator to retry a DB transaction function on transient failures.

    Parameters:
        max_retries (int): Maximum number of retries before giving up.
        min_sleep (float): Minimum seconds to sleep between retries.
        max_sleep (float): Maximum seconds to sleep between retries.
        allowed_exceptions (tuple): Exceptions that should trigger a retry.
    """
    if allowed_exceptions is None:
        # Common transient SQLAlchemy exceptions
        allowed_exceptions = (OperationalError, DatabaseError)

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except allowed_exceptions as e:
                    attempt += 1
                    if attempt > max_retries:
                        logger.exception(f"Max retries reached for {func.__name__}. Raising exception.")
                        raise
                    sleep_time = random.uniform(min_sleep, max_sleep)
                    logger.warning(f"Transient DB error in {func.__name__}: {e}. "
                                   f"Retrying in {sleep_time:.1f}s (attempt {attempt}/{max_retries})")
                    time.sleep(sleep_time)
        return wrapper
    return decorator
