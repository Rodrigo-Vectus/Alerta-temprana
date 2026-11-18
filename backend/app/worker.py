import logging
import os
import time

from app.collectors.kev import run_once
from app.db import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(levelname)s %(message)s")
INTERVAL = int(os.getenv("KEV_INTERVAL_MIN", "15")) * 60


def main():
    init_db()
    logging.info("Worker iniciado - KEV cada %s min", INTERVAL // 60)
    while True:
        logging.info("KEV: %s", run_once())
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
