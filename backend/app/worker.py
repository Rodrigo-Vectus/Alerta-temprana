import logging
import os
import time

from app.collectors.kev import run_once
from app.db import SessionLocal, init_db
from app.scoring import process_pending, refresh_incomplete, seed_watchlist

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
INTERVAL = int(os.getenv("KEV_INTERVAL_MIN", "15")) * 60


def main():
    init_db()
    with SessionLocal() as db:
        seed_watchlist(db)
    logging.info("Worker iniciado - ciclo cada %s min", INTERVAL // 60)
    while True:
        try:
            logging.info("KEV: %s", run_once())
            logging.info("Puntaje: %s", process_pending())
            r = refresh_incomplete()
            if r.get("refreshed"):
                logging.info("Reintento NVD: %s", r)
        except Exception:
            logging.exception("Error en el ciclo del worker")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
