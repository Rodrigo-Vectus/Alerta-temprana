import logging
import os
import time

from app.collectors.kev import run_once
from app.comms.automation import dispatch_due, schedule_for_results
from app.db import SessionLocal, init_db
from app.scoring import process_pending, refresh_incomplete, seed_watchlist
from app.comms.soc_brief import notify_new_cases
from app.usecases import ensure_for_communications

logging.basicConfig(level=logging.INFO, format="%(asctime)s [worker] %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)
INTERVAL = int(os.getenv("KEV_INTERVAL_MIN", "15")) * 60
TICK = 30   # cada cuánto se revisan los comunicados programados


def kev_cycle():
    logging.info("KEV: %s", run_once())
    result = process_pending()
    logging.info("Puntaje: %s", result)
    programados = schedule_for_results(result.get("alerts", []))
    if programados:
        logging.info("Comunicados programados: %s", programados)
    r = refresh_incomplete()
    if r.get("refreshed"):
        logging.info("Reintento NVD: %s", r)


def main():
    init_db()
    with SessionLocal() as db:
        seed_watchlist(db)
        faltantes = ensure_for_communications(db)
        if faltantes:
            logging.info("Casos de uso creados para comunicados que no tenían: %s", faltantes)
    logging.info("Worker iniciado - KEV cada %s min, envíos programados cada %s s", INTERVAL // 60, TICK)
    next_kev = 0.0
    while True:
        if time.monotonic() >= next_kev:
            try:
                kev_cycle()
            except Exception:
                logging.exception("Error en el ciclo KEV")
            next_kev = time.monotonic() + INTERVAL
        try:
            for r in dispatch_due():
                logging.info("Envío: %s", r)
        except Exception:
            logging.exception("Error despachando comunicados")
        try:
            pb = notify_new_cases()
            if pb:
                logging.info("Playbook enviado al SOC: %s", pb)
        except Exception:
            logging.exception("Error enviando playbooks al SOC")
        time.sleep(TICK)


if __name__ == "__main__":
    main()
