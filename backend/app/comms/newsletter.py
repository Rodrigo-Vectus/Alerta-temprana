"""Newsletter de alerta (cuerpo del mail), réplica del flyer Vectus.

HTML pensado para clientes de correo: maquetación con tablas y estilos en línea.
Las imágenes se referencian por CID al enviar el mail, o como data URI para la vista previa.
"""
import base64
from pathlib import Path

from jinja2 import Environment, select_autoescape

from app.comms.content import fecha_corta

ASSETS = Path(__file__).parent / "assets"
FONT = "'Segoe UI',Inter,Helvetica,Arial,sans-serif"
NAVY, BLUE, LIGHT, RED, TEXT, MUTED, BORDER, BG = "#1f3c88", "#2f4fa3", "#3b6fc4", "#d9534f", "#2d3340", "#7a8299", "#d6e0f0", "#f3f6fb"

IMAGES = ["logo.png", "logo_t.png", "icon_check.png", "icon_shield.png", "icon_mail.png", "icon_monitor.png",
          "icon_search.png", "icon_globe.png", "icon_network.png"]

TEMPLATE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ c.title }}</title></head>
<body style="margin:0;padding:0;background:{{ BG }};">
<div style="display:none;max-height:0;overflow:hidden;">{{ c.subtitle }} — {{ c.what_happened[:140] }}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{{ BG }};">
<tr><td style="height:10px;background:{{ BLUE }};font-size:0;line-height:0;">&nbsp;</td></tr>
<tr><td align="center" style="padding:28px 12px;">
<table role="presentation" width="720" cellpadding="0" cellspacing="0" style="width:100%;max-width:720px;font-family:{{ FONT }};color:{{ TEXT }};">

  <!-- Encabezado -->
  <tr><td>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td valign="top">
        <span style="display:inline-block;background:{{ RED }};color:#ffffff;font-size:13px;font-weight:600;letter-spacing:.3px;padding:7px 12px;border-radius:4px;">{{ c.badge }}</span>
        <span style="font-size:12px;color:{{ MUTED }};padding-left:8px;">Emitido: {{ emitted }}</span>
        <div style="font-size:32px;line-height:1.12;font-weight:800;color:{{ NAVY }};margin:14px 0 10px;letter-spacing:-.5px;">{{ c.title }}</div>
        <div style="font-size:15px;color:{{ LIGHT }};">{{ c.subtitle }}</div>
      </td>
      <td width="110" align="right" valign="top"><img src="{{ img['logo_t.png'] }}" width="96" height="96" alt="Grupo Vectus" style="display:block;border:0;"></td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:18px 0;"><div style="border-top:1px solid {{ BORDER }};font-size:0;line-height:0;">&nbsp;</div></td></tr>

  <!-- ¿Qué pasó? -->
  <tr><td style="border-left:4px solid {{ BLUE }};padding:0 0 0 10px;font-size:21px;font-weight:800;color:{{ NAVY }};">¿QUÉ PASÓ?</td></tr>
  <tr><td style="padding:12px 0 20px 14px;font-size:14px;line-height:1.65;color:{{ TEXT }};">{{ c.what_happened }}</td></tr>

  <!-- ¿Qué hacer? -->
  <tr><td style="background:#ffffff;border:1px solid {{ BORDER }};border-left:5px solid {{ BLUE }};border-radius:8px;padding:20px 22px;">
    <div style="font-size:21px;font-weight:800;color:{{ NAVY }};margin-bottom:12px;">¿QUÉ HACER?</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    {% for a in c.actions %}
      <tr>
        <td width="44" valign="top" style="padding:8px 0;"><span style="display:inline-block;background:#e6edf9;color:{{ NAVY }};font-size:12px;font-weight:700;border-radius:12px;padding:4px 7px;">{{ '%02d' % loop.index }}</span></td>
        <td valign="top" style="padding:8px 0;font-size:14px;line-height:1.55;color:{{ TEXT }};">{{ a }}</td>
      </tr>
    {% endfor %}
    </table>
  </td></tr>

  <!-- Fortinet -->
  <tr><td style="padding:28px 0 0;">
    <div style="border-left:4px solid {{ BLUE }};padding-left:10px;font-size:21px;font-weight:800;color:{{ NAVY }};">CÓMO TE PROTEGE FORTINET</div>
    <div style="font-size:13px;color:{{ MUTED }};padding:6px 0 12px 2px;">{{ c.fortinet_intro }}</div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
    {% for row in cards|batch(2) %}
      <tr>
      {% for f in row %}
        <td width="50%" valign="top" style="padding:0 {{ '6px' if loop.first else '0' }} 12px {{ '0' if loop.first else '6px' }};">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid {{ BORDER }};border-radius:8px;">
            <tr>
              <td width="52" valign="top" style="padding:16px 0 16px 16px;"><img src="{{ img['icon_' + f.icon + '.png'] }}" width="34" height="34" alt="" style="display:block;border:0;"></td>
              <td valign="top" style="padding:14px 16px 16px 10px;">
                <div style="font-size:16px;font-weight:700;color:{{ NAVY }};margin-bottom:5px;">{{ f.product }}</div>
                <div style="font-size:13px;line-height:1.5;color:{{ TEXT }};">{{ f.text }}</div>
              </td>
            </tr>
          </table>
        </td>
      {% endfor %}
      {% if row|length == 1 %}<td width="50%"></td>{% endif %}
      </tr>
    {% endfor %}
    </table>
  </td></tr>

  <!-- Banner Vectus -->
  <tr><td style="padding:10px 0 0;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{{ BLUE }};border-radius:8px;">
      <tr>
        <td width="62" valign="middle" style="padding:20px 0 20px 18px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr><td width="42" height="42" align="center" valign="middle" style="background:#5b78c2;border-radius:21px;"><img src="{{ img['icon_check.png'] }}" width="20" height="20" alt="" style="display:block;border:0;"></td></tr></table>
        </td>
        <td valign="middle" style="padding:18px 20px 18px 12px;color:#ffffff;">
          <div style="font-size:19px;font-weight:800;letter-spacing:.2px;margin-bottom:6px;">EN GRUPO VECTUS TE AYUDAMOS</div>
          <div style="font-size:14px;line-height:1.5;">a evaluar tu exposición y activar estas protecciones hoy.<br><b>Contactá a tu ejecutivo de cuenta.</b></div>
        </td>
      </tr>
    </table>
  </td></tr>

  <!-- Importante / Referencias -->
  <tr><td style="padding:22px 0 0;">
    <div style="border-left:4px solid {{ BLUE }};padding-left:10px;font-size:15px;font-weight:800;color:{{ NAVY }};">IMPORTANTE</div>
    <div style="font-size:13px;color:{{ TEXT }};padding:8px 0 16px 14px;">{{ c.important }}</div>
    <div style="border-left:4px solid {{ BLUE }};padding-left:10px;font-size:15px;font-weight:800;color:{{ NAVY }};">REFERENCIAS</div>
    <div style="font-size:11.5px;line-height:1.7;color:{{ MUTED }};padding:8px 0 0 14px;">
      {% for r in c.references %}{{ r.label }}: <a href="{{ r.url }}" style="color:{{ MUTED }};text-decoration:none;">{{ r.url | replace('https://','') | replace('http://','') }}</a><br>{% endfor %}
    </div>
  </td></tr>

  <!-- Pie -->
  <tr><td style="padding:20px 0;"><div style="border-top:1px solid {{ BORDER }};font-size:0;line-height:0;">&nbsp;</div></td></tr>
  <tr><td>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="96" valign="top"><table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="background:#ffffff;border-radius:6px;padding:8px;"><img src="{{ img['logo.png'] }}" width="72" height="72" alt="Vectus" style="display:block;border:0;"></td></tr></table></td>
      <td valign="top" style="padding-left:16px;font-size:12px;line-height:1.55;color:{{ TEXT }};">
        <a href="https://www.vectus.la" style="font-size:14px;font-weight:700;color:{{ NAVY }};text-decoration:none;">www.vectus.la</a><br>
        <span style="color:{{ LIGHT }};font-size:13px;">Córdoba Capital</span><br>
        Av. La Voz del Interior N°8851, Edificio Clúster –<br>Torre 2 Piso 2, Parque Empresarial Aeropuerto<br>
        <span style="color:{{ LIGHT }};font-size:13px;">Santiago de Chile</span><br>
        Avenida Providencia N°1650, Oficina 1506
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="padding:22px 0 6px;font-size:11px;color:{{ MUTED }};">Grupo VECTUS · Tecnología y ciberseguridad · Ref. {{ c.meta.alert_code }}</td></tr>

</table>
</td></tr></table>
</body></html>"""

_env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
_tpl = _env.from_string(TEMPLATE)


def _data_uri(name):
    return "data:image/png;base64," + base64.b64encode((ASSETS / name).read_bytes()).decode()


def render_newsletter(content: dict, mode: str = "data") -> str:
    """mode='data' incrusta las imágenes (vista previa); mode='cid' las referencia como adjuntos inline (mail)."""
    img = {n: (f"cid:{n}" if mode == "cid" else _data_uri(n)) for n in IMAGES}
    cards = [f for f in content.get("fortinet", []) if f.get("included", True)]
    return _tpl.render(c=content, cards=cards, img=img, emitted=fecha_corta(content.get("emitted")),
                       FONT=FONT, NAVY=NAVY, BLUE=BLUE, LIGHT=LIGHT, RED=RED, TEXT=TEXT, MUTED=MUTED, BORDER=BORDER, BG=BG)


def inline_images():
    """Imágenes que se adjuntan inline al mail (CID = nombre de archivo)."""
    return [(n, (ASSETS / n).read_bytes()) for n in IMAGES]
