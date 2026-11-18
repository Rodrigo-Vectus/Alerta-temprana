"""Conversión DOCX -> PDF con Gotenberg (LibreOffice en un contenedor aparte)."""
import os

import httpx

GOTENBERG_URL = os.getenv("GOTENBERG_URL", "http://gotenberg:3000").rstrip("/")
DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


class PdfError(RuntimeError):
    pass


def docx_to_pdf(docx: bytes, filename: str = "informe.docx") -> bytes:
    try:
        r = httpx.post(f"{GOTENBERG_URL}/forms/libreoffice/convert",
                       files={"files": (filename, docx, DOCX_MIME)},
                       data={"updateIndexes": "true"}, timeout=120)
    except httpx.HTTPError as exc:
        raise PdfError(f"No se pudo conectar con el conversor de PDF: {exc}") from exc
    if r.status_code != 200:
        raise PdfError(f"El conversor de PDF respondió {r.status_code}: {r.text[:200]}")
    return r.content
