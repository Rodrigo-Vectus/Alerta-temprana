"""Informe de impacto en DOCX con el formato Vectus (carátula, encabezado con número de página,
pie institucional, índice y secciones numeradas). El PDF se obtiene convirtiendo este DOCX con Gotenberg."""
import io
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

from app.comms.content import fecha_larga

ASSETS = Path(__file__).parent / "assets"
NAVY = RGBColor(0x1F, 0x38, 0x64)
HEAD = RGBColor(0x2F, 0x54, 0x96)
LABEL = RGBColor(0x5B, 0x9B, 0xD5)
GREY = RGBColor(0x7F, 0x7F, 0x7F)
TABLE_HEAD = "1F3864"
TABLE_LABEL = "EAF0F8"

SECTIONS = [
    "Resumen Ejecutivo", "Descripción de la Vulnerabilidad", "Estado Actual y Explotación",
    "Impacto en Ciberseguridad", "Productos Afectados", "Recomendaciones para el Cliente",
    "Cómo te Protege Fortinet", "Próximos Pasos y Soporte", "Referencias",
]


# ---------------------------------------------------------------- utilidades XML
def _field(paragraph, instr, placeholder=""):
    """Inserta un campo de Word (PAGE, TOC…) con un resultado provisorio."""
    def r(tag, **attrs):
        run = OxmlElement("w:r")
        el = OxmlElement(tag)
        for k, v in attrs.items():
            el.set(qn(k), v)
        run.append(el)
        return run
    p = paragraph._p
    p.append(r("w:fldChar", **{"w:fldCharType": "begin"}))
    instr_run = OxmlElement("w:r")
    t = OxmlElement("w:instrText")
    t.set(qn("xml:space"), "preserve")
    t.text = f" {instr} "
    instr_run.append(t)
    p.append(instr_run)
    p.append(r("w:fldChar", **{"w:fldCharType": "separate"}))
    if placeholder:
        res = OxmlElement("w:r")
        tt = OxmlElement("w:t")
        tt.text = placeholder
        res.append(tt)
        p.append(res)
    p.append(r("w:fldChar", **{"w:fldCharType": "end"}))


def _shade(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tcPr.append(shd)


def _cell_margins(table, top=90, bottom=90, left=110, right=110):
    tblPr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side, val in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(val))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tblPr.append(mar)


def _borders(table, color="BFBFBF"):
    tblPr = table._tbl.tblPr
    b = OxmlElement("w:tblBorders")
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:color"), color)
        b.append(el)
    tblPr.append(b)


def _widths(table, cms):
    """Anchos fijos de columna (Word usa tcW, LibreOffice usa tblGrid: se setean ambos)."""
    table.autofit = False
    tblPr = table._tbl.tblPr
    w = OxmlElement("w:tblW")
    w.set(qn("w:w"), str(int(sum(cms) * 567)))
    w.set(qn("w:type"), "dxa")
    for old in tblPr.findall(qn("w:tblW")):
        tblPr.remove(old)
    tblPr.append(w)
    layout = OxmlElement("w:tblLayout")
    layout.set(qn("w:type"), "fixed")
    tblPr.append(layout)
    grid = table._tbl.tblGrid
    for gc, cm in zip(grid.findall(qn("w:gridCol")), cms):
        gc.set(qn("w:w"), str(int(cm * 567)))
    for row in table.rows:
        for cell, cm in zip(row.cells, cms):
            cell.width = Cm(cm)
            for par in cell.paragraphs:
                par.paragraph_format.space_after = Pt(0)
                par.paragraph_format.space_before = Pt(0)


def _font(run, name="Calibri", size=11, bold=None, color=None, italic=None):
    run.font.name = name
    run._element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), name)
    run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    if color is not None:
        run.font.color.rgb = color
    return run


def _para(doc, text="", size=11, bold=False, color=None, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=6, italic=False, style=None):
    p = doc.add_paragraph(style=style) if style else doc.add_paragraph()
    p.alignment = align
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.line_spacing = 1.15
    if text:
        _font(p.add_run(text), size=size, bold=bold, color=color, italic=italic)
    return p


def _heading(doc, n, text):
    p = doc.add_paragraph(style="Heading 1")
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after = Pt(8)
    p.paragraph_format.keep_with_next = True
    _font(p.add_run(f"{n}. {text}"), name="Cambria", size=16, bold=False, color=HEAD)
    return p


def _subheading(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    _font(p.add_run(text), size=12, bold=True, color=NAVY)
    return p


def _bullets(doc, items, style="List Bullet"):
    for it in items:
        p = doc.add_paragraph(style=style)
        p.paragraph_format.space_after = Pt(3)
        p.paragraph_format.line_spacing = 1.15
        _font(p.add_run(it), size=11)


def _fld(tag_type):
    run = OxmlElement("w:r")
    el = OxmlElement("w:fldChar")
    el.set(qn("w:fldCharType"), tag_type)
    run.append(el)
    return run


def _toc(doc):
    """Índice como campo TOC de Word. El resultado provisorio lista las secciones; Word/LibreOffice
    lo actualiza con los números de página (Gotenberg lo hace al convertir a PDF)."""
    paras = []
    for i, name in enumerate(SECTIONS, 1):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(5)
        p.paragraph_format.tab_stops.add_tab_stop(Cm(16), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
        paras.append(p)
    first = paras[0]._p
    instr = OxmlElement("w:r")
    t = OxmlElement("w:instrText")
    t.set(qn("xml:space"), "preserve")
    t.text = ' TOC \\o "1-1" \\h \\z \\u '
    instr.append(t)
    first.append(_fld("begin"))
    first.append(instr)
    first.append(_fld("separate"))
    for i, (p, name) in enumerate(zip(paras, SECTIONS), 1):
        _font(p.add_run(f"{i}. {name}\t"), size=11)
    paras[-1]._p.append(_fld("end"))


# ---------------------------------------------------------------- documento
def build_docx(c: dict) -> bytes:
    doc = Document()

    # Estilo base
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    normal.element.get_or_add_rPr().get_or_add_rFonts().set(qn("w:eastAsia"), "Calibri")
    doc.core_properties.title = f"Informe de impacto - {c['title']}"
    doc.core_properties.author = "Grupo Vectus"
    doc.core_properties.subject = c.get("technical", {}).get("cve", "")

    # ---------- Sección 1: carátula a página completa ----------
    s1 = doc.sections[0]
    s1.page_width, s1.page_height = Cm(21), Cm(29.7)
    for attr in ("left_margin", "right_margin", "top_margin", "bottom_margin", "header_distance", "footer_distance"):
        setattr(s1, attr, Cm(0))
    cover = doc.paragraphs[0] if doc.paragraphs else doc.add_paragraph()
    cover.paragraph_format.space_after = Pt(0)
    cover.paragraph_format.space_before = Pt(0)
    cover.add_run().add_picture(str(ASSETS / "cover.jpg"), width=Cm(21), height=Cm(29.65))

    # ---------- Sección 2: contenido ----------
    s2 = doc.add_section(WD_SECTION.NEW_PAGE)
    # mover el salto de sección al párrafo de la carátula para no generar una página en blanco
    body = doc.element.body
    sect_par = body.findall(qn("w:p"))[-1]
    sectPr = sect_par.find(qn("w:pPr")).find(qn("w:sectPr"))
    cover._p.get_or_add_pPr().append(sectPr)
    body.remove(sect_par)

    s2 = doc.sections[1]
    s2.top_margin, s2.bottom_margin = Cm(2.5), Cm(4.0)
    s2.left_margin, s2.right_margin = Cm(2.5), Cm(2.5)
    s2.header_distance, s2.footer_distance = Cm(1.2), Cm(0.6)
    s2.header.is_linked_to_previous = False
    s2.footer.is_linked_to_previous = False

    hp = s2.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _font(hp.add_run("|"), size=10, color=GREY)
    _field(hp, "PAGE", "2")
    for r in hp.runs:
        _font(r, size=10, color=GREY)

    fp = s2.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp.add_run().add_picture(str(ASSETS / "footer.jpg"), width=Cm(16.5))

    # Portada interna
    _para(doc, "", after=24)
    _para(doc, "INFORME DE IMPACTO DE CIBERSEGURIDAD", size=13, bold=True, color=NAVY, align=WD_ALIGN_PARAGRAPH.CENTER, after=30)
    for label, value in (("CAUSA:", c["title"]), ("Fecha:", fecha_larga(c.get("emitted"))),
                         ("Clasificación:", c.get("classification", "")), ("Referencia:", f"{c['technical']['cve']} · {c.get('meta', {}).get('alert_code', '')}")):
        p = _para(doc, align=WD_ALIGN_PARAGRAPH.LEFT, after=10)
        _font(p.add_run(f"{label} "), size=11.5, bold=True, color=LABEL)
        _font(p.add_run(value), size=11.5)

    _para(doc, "", after=6)
    _para(doc, "Contenido", size=11.5, color=LABEL, align=WD_ALIGN_PARAGRAPH.LEFT, after=4)
    _toc(doc)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    # 1. Resumen
    _heading(doc, 1, SECTIONS[0])
    _para(doc, c["executive_summary"])
    clients = c.get("affected_clients_note")
    if clients:
        _para(doc, clients)

    # 2. Descripción
    _heading(doc, 2, SECTIONS[1])
    _para(doc, c["what_happened"])
    _subheading(doc, "Datos técnicos")
    t = c["technical"]
    rows = [("CVE", t["cve"]), ("Fabricante", t["vendor"]), ("Producto", t["product"]), ("CVSS", t["cvss"]),
            ("Vector CVSS", t["vector"]), ("EPSS (probabilidad de explotación)", t["epss"]), ("CWE", t["cwe"]),
            ("Incorporada a CISA KEV", t["date_added"]), ("Plazo de remediación CISA", t["due_date"]),
            ("Uso en ransomware", t["ransomware"])]
    tbl = doc.add_table(rows=0, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(tbl)
    _cell_margins(tbl)
    for k, v in rows:
        cells = tbl.add_row().cells
        _shade(cells[0], TABLE_LABEL)
        _font(cells[0].paragraphs[0].add_run(k), size=10, bold=True, color=NAVY)
        _font(cells[1].paragraphs[0].add_run(str(v)), size=10)
    _widths(tbl, [5.5, 10.5])
    if c.get("original_description"):
        _subheading(doc, "Descripción publicada por CISA (original en inglés)")
        _para(doc, c["original_description"], size=10, italic=True, color=GREY)

    # 3. Estado
    _heading(doc, 3, SECTIONS[2])
    _bullets(doc, c["status_items"])

    # 4. Impacto
    _heading(doc, 4, SECTIONS[3])
    _para(doc, c.get("impact_intro", ""))
    tbl = doc.add_table(rows=1, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(tbl)
    _cell_margins(tbl, 110, 110, 120, 120)
    hdr = tbl.rows[0].cells
    for cell, text in zip(hdr, ("Área de Riesgo", "Descripción e Impacto")):
        _shade(cell, TABLE_HEAD)
        _font(cell.paragraphs[0].add_run(text), size=10.5, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    for row in c["impact_rows"]:
        cells = tbl.add_row().cells
        _font(cells[0].paragraphs[0].add_run(row["area"]), size=10.5, bold=True)
        cells[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        _font(cells[1].paragraphs[0].add_run(row["text"]), size=10.5)
    _widths(tbl, [4.6, 11.4])

    # 5. Productos
    _heading(doc, 5, SECTIONS[4])
    _para(doc, "Según la información publicada por NVD y el fabricante, se ven afectados:")
    _bullets(doc, c["affected_products"])
    _para(doc, "Verifique la versión instalada en su entorno contra el aviso oficial del fabricante.", size=10, italic=True, color=GREY)

    # 6. Recomendaciones
    _heading(doc, 6, SECTIONS[5])
    _subheading(doc, "Acciones inmediatas")
    for i, a in enumerate(c["actions"], 1):
        p = _para(doc, align=WD_ALIGN_PARAGRAPH.JUSTIFY, after=4)
        p.paragraph_format.left_indent = Cm(0.8)
        p.paragraph_format.first_line_indent = Cm(-0.8)
        _font(p.add_run(f"{i}.\t"), size=11, bold=True, color=NAVY)
        _font(p.add_run(a), size=11)
    _subheading(doc, "Recomendaciones de hardening")
    _bullets(doc, c["hardening"])
    if c.get("important"):
        p = _para(doc, after=6)
        p.paragraph_format.space_before = Pt(8)
        _font(p.add_run("Importante: "), bold=True, color=NAVY)
        _font(p.add_run(c["important"]))

    # 7. Fortinet
    _heading(doc, 7, SECTIONS[6])
    _para(doc, c.get("fortinet_intro", "") + ":")
    cards = [f for f in c.get("fortinet", []) if f.get("included", True)]
    tbl = doc.add_table(rows=1, cols=2)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(tbl)
    _cell_margins(tbl, 110, 110, 120, 120)
    for cell, text in zip(tbl.rows[0].cells, ("Solución Fortinet", "Control recomendado")):
        _shade(cell, TABLE_HEAD)
        _font(cell.paragraphs[0].add_run(text), size=10.5, bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    for f in cards:
        cells = tbl.add_row().cells
        _font(cells[0].paragraphs[0].add_run(f["product"]), size=10.5, bold=True, color=NAVY)
        _font(cells[1].paragraphs[0].add_run(f["text"]), size=10.5)
    _widths(tbl, [5.2, 10.8])

    # 8. Próximos pasos
    _heading(doc, 8, SECTIONS[7])
    _para(doc, c["next_steps"])
    p = _para(doc, after=6)
    _font(p.add_run("En Grupo Vectus te ayudamos "), bold=True, color=NAVY)
    _font(p.add_run("a evaluar tu exposición y activar estas protecciones hoy. Contactá a tu ejecutivo de cuenta."))

    # 9. Referencias
    _heading(doc, 9, SECTIONS[8])
    for r in c.get("references", []):
        p = _para(doc, align=WD_ALIGN_PARAGRAPH.LEFT, after=2)
        _font(p.add_run(f"{r['label']}: "), size=10, bold=True)
        _font(p.add_run(r["url"]), size=10, color=HEAD)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()
