import logging
import time
from sqlalchemy import text
from app.db import engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(levelname)s %(message)s")
INTERVAL = 60

def main():
    logging.info("Worker iniciado")
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(text("select 1"))
            logging.info("heartbeat ok - db conectada")
        except Exception as exc:
            logging.error("error de db: %s", exc)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
