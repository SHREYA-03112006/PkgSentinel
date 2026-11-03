import logging
import time
import sys
from engine.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("pkgsentinel.worker")


def start_worker():
    """
    Entrypoint placeholder for the Redis Stream consumer worker.
    Listens on stream:scan-jobs using consumer group engine-workers.
    """
    logger.info("Initializing PkgSentinel Security Engine Worker...")
    logger.info(f"Target Redis: {settings.redis_host}:{settings.redis_port}")
    logger.info(f"Consumer Group: {settings.consumer_group} | Consumer: {settings.consumer_name}")
    logger.info("Worker placeholder ready. Detection modules will be attached in Phase 1B.")


if __name__ == "__main__":
    start_worker()

