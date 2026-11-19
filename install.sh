#!/usr/bin/env bash
# =============================================================================
#  Vectus SAT · Sistema de Alerta Temprana — instalador interactivo
#
#  Genera el archivo .env haciendo preguntas (las claves se escriben sin
#  mostrarse), levanta los contenedores y verifica que todo funcione.
#
#  Uso:   ./install.sh            instalación / reconfiguración guiada
#         ./install.sh --no-start  solo genera el .env, no levanta nada
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

NO_START=0
[[ "${1:-}" == "--no-start" ]] && NO_START=1

# ---------- presentación ------------------------------------------------------
if [[ -t 1 ]]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'
else
  B=""; D=""; R=""; G=""; Y=""; C=""; N=""
fi
title() { printf "\n${B}${C}── %s ${N}\n" "$1"; }
info()  { printf "  ${D}%s${N}\n" "$1"; }
ok()    { printf "  ${G}✔${N} %s\n" "$1"; }
warn()  { printf "  ${Y}!${N} %s\n" "$1"; }
fail()  { printf "  ${R}✘ %s${N}\n" "$1" >&2; }
die()   { fail "$1"; exit 1; }

# ask VAR "Pregunta" "default"
ask() {
  local __var=$1 __q=$2 __def=${3:-} __ans
  if [[ -n "$__def" ]]; then
    read -r -p "  $__q [${__def}]: " __ans || true
  else
    read -r -p "  $__q: " __ans || true
  fi
  __ans="${__ans:-$__def}"
  printf -v "$__var" '%s' "$__ans"
}

# ask_required VAR "Pregunta" "default"
ask_required() {
  local __var=$1
  while true; do
    ask "$@"
    [[ -n "${!__var}" ]] && return
    warn "Este dato es obligatorio."
  done
}

# ask_email VAR "Pregunta" "default"
ask_email() {
  local __var=$1
  while true; do
    ask "$@"
    [[ "${!__var}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && return
    warn "No parece un correo válido."
  done
}

# ask_secret VAR "Pregunta" [confirmar=0|1] [obligatorio=1|0]
ask_secret() {
  local __var=$1 __q=$2 __confirm=${3:-0} __req=${4:-1} __a __b
  while true; do
    read -r -s -p "  $__q: " __a || true; echo
    if [[ -z "$__a" ]]; then
      [[ "$__req" == "0" ]] && { printf -v "$__var" '%s' ""; return; }
      warn "No puede quedar vacío."; continue
    fi
    [[ "$__a" == *"'"* ]] && { warn "No puede contener comillas simples (')."; continue; }
    if [[ "$__confirm" == "1" ]]; then
      read -r -s -p "  Repetila: " __b || true; echo
      [[ "$__a" != "$__b" ]] && { warn "No coinciden, probá de nuevo."; continue; }
    fi
    printf -v "$__var" '%s' "$__a"; return
  done
}

# yes_no "Pregunta" s|n  -> 0 si es sí
yes_no() {
  local __ans __def=${2:-s}
  read -r -p "  $1 [$( [[ $__def == s ]] && echo S/n || echo s/N )]: " __ans || true
  __ans="${__ans:-$__def}"
  [[ "${__ans,,}" =~ ^(s|si|sí|y|yes)$ ]]
}

# choose VAR "Pregunta" default opción1 opción2 ...  -> número elegido
choose() {
  local __var=$1 __q=$2 __def=$3; shift 3
  local i=1 __ans
  for opt in "$@"; do printf "    ${B}%d)${N} %s\n" "$i" "$opt"; i=$((i+1)); done
  while true; do
    read -r -p "  $__q [$__def]: " __ans || true
    __ans="${__ans:-$__def}"
    if [[ "$__ans" =~ ^[0-9]+$ ]] && (( __ans >= 1 && __ans <= $# )); then
      printf -v "$__var" '%s' "$__ans"; return
    fi
    warn "Elegí un número entre 1 y $#."
  done
}

randstr() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-40}" || true; }
mask()    { [[ -z "$1" ]] && echo "(vacío)" || echo "•••••••• (${#1} caracteres)"; }
env_get() { [[ -f .env ]] && grep -E "^$1=" .env | tail -1 | cut -d= -f2- | sed -E "s/^'(.*)'$/\1/" || true; }

compose() { docker compose "$@"; }

# Carpeta desde la que corre una instalación con ese nombre de proyecto (vacío si no existe)
project_dir() {
  docker ps -a --filter "label=com.docker.compose.project=$1" \
    --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null | sort -u | head -1
}

# port_busy PUERTO PROYECTO -> 0 si lo usa algo que no es esta misma instalación
port_busy() {
  command -v ss >/dev/null 2>&1 || return 1
  ss -ltnH "sport = :$1" 2>/dev/null | grep -q . || return 1
  docker ps --filter "label=com.docker.compose.project=$2" --format '{{.Ports}}' 2>/dev/null | grep -q ":$1->" && return 1
  return 0
}

# row "etiqueta" "valor" ...  (alinea bien aunque haya tildes)
row() {
  local n
  while (( $# >= 2 )); do
    n=$(printf '%s' "$1" | LC_ALL=C.UTF-8 wc -m)
    printf "  %s%*s %s\n" "$1" $((24 - n)) "" "$2"; shift 2
  done
}

# ---------- 0. requisitos -----------------------------------------------------
printf "\n${B}Vectus SAT · Sistema de Alerta Temprana${N}\n${D}Instalador interactivo${N}\n"

title "Requisitos"
command -v docker >/dev/null 2>&1 || die "Docker no está instalado. Ver README › Requisitos."
docker compose version >/dev/null 2>&1 || die "Falta el plugin 'docker compose' (v2)."
if [[ $NO_START -eq 0 ]]; then
  docker info >/dev/null 2>&1 || die "No se puede usar Docker con este usuario (probá con sudo o agregalo al grupo docker)."
fi
command -v curl >/dev/null 2>&1 || warn "curl no está instalado: no se podrá verificar la API al final."
ok "Docker $(docker version --format '{{.Client.Version}}' 2>/dev/null || echo '') y Compose disponibles"

# ---------- .env existente -----------------------------------------------------
KEEP_DB_PASS=""; KEEP_JWT=""; KEEP_DB_USER=""; KEEP_DB_NAME=""
if [[ -f .env ]]; then
  title "Configuración existente"
  info "Ya hay un archivo .env en esta carpeta."
  choose ENV_ACTION "¿Qué querés hacer?" 1 \
    "Mantenerlo y solo levantar / actualizar los contenedores" \
    "Reconfigurar (se conservan la clave de la base de datos y la sesión)" \
    "Salir sin tocar nada"
  case $ENV_ACTION in
    1)
      [[ $NO_START -eq 1 ]] && { ok "Nada que hacer."; exit 0; }
      SKIP_CONFIG=1 ;;
    2)
      SKIP_CONFIG=0
      KEEP_DB_USER=$(env_get POSTGRES_USER); KEEP_DB_NAME=$(env_get POSTGRES_DB)
      KEEP_DB_PASS=$(env_get POSTGRES_PASSWORD); KEEP_JWT=$(env_get JWT_SECRET)
      cp .env ".env.bak.$(date +%Y%m%d%H%M%S)"; ok "Copia de respaldo del .env anterior creada" ;;
    *) exit 0 ;;
  esac
else
  SKIP_CONFIG=0
  if [[ -d data/postgres ]] && [[ -n "$(ls -A data/postgres 2>/dev/null)" ]]; then
    warn "Existe data/postgres pero no hay .env: la base vieja no va a abrir con una clave nueva."
    warn "Si es una instalación desde cero, borrá la carpeta data/ antes de seguir."
    yes_no "¿Continuar igual?" n || exit 1
  fi
fi

if [[ $SKIP_CONFIG -eq 0 ]]; then
  # ---------- 1. instancia ------------------------------------------------------
  title "1/5 · Instancia"
  info "Nombre interno de los contenedores. Cambialo solo si vas a tener más de una instalación en el mismo servidor."
  DEF_PROJECT=$(env_get COMPOSE_PROJECT_NAME)
  [[ -z "$DEF_PROJECT" ]] && DEF_PROJECT=$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')
  [[ -z "$DEF_PROJECT" ]] && DEF_PROJECT=vectus-sat
  while true; do
    ask_required PROJECT "Nombre de la instalación" "$DEF_PROJECT"
    PROJECT=$(echo "$PROJECT" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')
    OTHER=$(project_dir "$PROJECT")
    if [[ -n "$OTHER" && "$OTHER" != "$PWD" ]]; then
      fail "El nombre '$PROJECT' ya lo usa la instalación de $OTHER."
      info "Si siguieras, sus contenedores se reemplazarían por los de esta carpeta. Elegí otro nombre."
      DEF_PROJECT="$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')"
      [[ "$DEF_PROJECT" == "$PROJECT" ]] && DEF_PROJECT="$PROJECT-2"
      continue
    fi
    break
  done

  DEF_PORT=$(env_get HTTP_PORT); DEF_PORT=${DEF_PORT:-80}
  while port_busy "$DEF_PORT" "$PROJECT"; do DEF_PORT=$(( DEF_PORT == 80 ? 8080 : DEF_PORT + 1 )); done
  while true; do
    ask_required HTTP_PORT "Puerto web de la consola" "$DEF_PORT"
    [[ "$HTTP_PORT" =~ ^[0-9]+$ ]] && (( HTTP_PORT > 0 && HTTP_PORT < 65536 )) || { warn "Puerto inválido."; continue; }
    if port_busy "$HTTP_PORT" "$PROJECT"; then
      warn "El puerto $HTTP_PORT ya está en uso (otra instalación u otro programa)."
      yes_no "¿Usarlo igual?" n || continue
    fi
    break
  done

  IP=$(hostname -I 2>/dev/null | awk '{print $1}'); IP=${IP:-localhost}
  DEF_URL="http://$IP"; [[ "$HTTP_PORT" != "80" ]] && DEF_URL="$DEF_URL:$HTTP_PORT"
  info "Dirección con la que el equipo SOC abre la consola (se usa en los links de los avisos)."
  [[ "$(env_get HTTP_PORT)" == "$HTTP_PORT" ]] && DEF_URL=$(env_get PUBLIC_URL | grep . || echo "$DEF_URL")
  ask_required PUBLIC_URL "URL de la consola" "$DEF_URL"
  PUBLIC_URL=${PUBLIC_URL%/}
  ask_required TZ_VAL "Zona horaria" "$(env_get TZ | grep . || echo America/Argentina/Buenos_Aires)"

  # ---------- 2. administrador ---------------------------------------------------
  title "2/5 · Usuario administrador"
  info "Se crea solo la primera vez que arranca el sistema (si la base no tiene usuarios)."
  ask_email ADMIN_EMAIL "Correo del administrador" "$(env_get ADMIN_EMAIL)"
  info "Contraseña inicial (mínimo 10 caracteres). Se pide cambiarla en el primer ingreso."
  info "Dejala vacía para generar una al azar y mostrarla al final."
  while true; do
    ask_secret ADMIN_PASS "Contraseña inicial" 1 0
    if [[ -z "$ADMIN_PASS" ]]; then ADMIN_PASS=$(randstr 16); ADMIN_PASS_GEN=1; break; fi
    (( ${#ADMIN_PASS} >= 10 )) && { ADMIN_PASS_GEN=0; break; }
    warn "Tiene que tener al menos 10 caracteres."
  done

  # ---------- 3. SOC ------------------------------------------------------------
  title "3/5 · Equipo SOC"
  info "Reciben cada comunicado antes que los clientes y pueden cancelarlo en la ventana de revisión."
  info "Varios correos separados por coma. Se pueden cambiar después en Configuración."
  while true; do
    ask_required SOC_EMAILS "Correos del SOC" "$(env_get SOC_EMAILS | grep . || echo "$ADMIN_EMAIL")"
    SOC_EMAILS=$(echo "$SOC_EMAILS" | tr -d ' ')
    bad=0; IFS=',' read -ra _l <<< "$SOC_EMAILS"
    for e in "${_l[@]}"; do [[ "$e" =~ ^[^@]+@[^@]+\.[^@]+$ ]] || { warn "Correo inválido: $e"; bad=1; }; done
    [[ $bad -eq 0 ]] && break
  done

  # ---------- 4. correo -----------------------------------------------------------
  title "4/5 · Envío de correo"
  info "Cuenta desde la que salen los comunicados a clientes y los avisos al SOC."
  choose MAIL_OPT "Proveedor" 1 \
    "Gmail / Google Workspace (contraseña de aplicación)" \
    "Microsoft 365 con Microsoft Graph (OAuth, recomendado para M365)" \
    "Microsoft 365 / Outlook por SMTP (usuario y contraseña)" \
    "Otro servidor SMTP" \
    "Configurar más tarde (no se envían correos)"

  MAIL_PROVIDER=smtp; SMTP_HOST=""; SMTP_PORT=587; SMTP_SECURITY=starttls
  SMTP_USER=""; SMTP_PASSWORD=""; SMTP_FROM=""
  GRAPH_TENANT_ID=""; GRAPH_CLIENT_ID=""; GRAPH_CLIENT_SECRET=""; GRAPH_SENDER=""
  case $MAIL_OPT in
    1)
      SMTP_HOST=smtp.gmail.com
      ask_email SMTP_USER "Cuenta de Gmail que envía"
      info "Se genera en myaccount.google.com › Seguridad › Contraseñas de aplicaciones (requiere 2FA)."
      while true; do
        ask_secret SMTP_PASSWORD "Contraseña de aplicación (16 letras, no se muestra)"
        SMTP_PASSWORD=$(echo "$SMTP_PASSWORD" | tr -d ' ')
        [[ ${#SMTP_PASSWORD} -eq 16 ]] && break
        warn "Las contraseñas de aplicación de Google tienen 16 letras (tiene ${#SMTP_PASSWORD})."
        yes_no "¿Usarla igual?" n && break
      done
      SMTP_FROM=$SMTP_USER
      info "Gmail siempre envía como la cuenta autenticada: el remitente será $SMTP_USER." ;;
    2)
      MAIL_PROVIDER=graph
      info "Requiere una app registrada en Entra ID con el permiso de aplicación Mail.Send."
      ask_required GRAPH_TENANT_ID "Tenant ID (Directory ID)"
      ask_required GRAPH_CLIENT_ID "Client ID (Application ID)"
      ask_secret GRAPH_CLIENT_SECRET "Client secret (no se muestra)"
      ask_email GRAPH_SENDER "Buzón que envía (ej. alertas@empresa.com)"
      SMTP_FROM=$GRAPH_SENDER ;;
    3)
      SMTP_HOST=smtp.office365.com
      warn "Microsoft está deshabilitando SMTP AUTH con contraseña; si falla, usá la opción 2 (Graph)."
      ask_email SMTP_USER "Cuenta que envía"
      ask_secret SMTP_PASSWORD "Contraseña (no se muestra)"
      SMTP_FROM=$SMTP_USER ;;
    4)
      ask_required SMTP_HOST "Servidor SMTP"
      choose SEC_OPT "Seguridad" 1 "STARTTLS (puerto 587)" "SSL/TLS directo (puerto 465)" "Sin cifrado (solo red interna)"
      case $SEC_OPT in 1) SMTP_SECURITY=starttls; DP=587;; 2) SMTP_SECURITY=ssl; DP=465;; 3) SMTP_SECURITY=none; DP=25;; esac
      ask_required SMTP_PORT "Puerto" "$DP"
      ask SMTP_USER "Usuario (vacío si el servidor no pide autenticación)" ""
      [[ -n "$SMTP_USER" ]] && ask_secret SMTP_PASSWORD "Contraseña (no se muestra)"
      ask_email SMTP_FROM "Dirección del remitente" "${SMTP_USER}" ;;
    5)
      warn "Sin correo configurado: el sistema detecta y arma comunicados, pero no envía nada." ;;
  esac
  SMTP_FROM_NAME="Vectus · Alertas de Seguridad"
  [[ $MAIL_OPT != 5 ]] && ask_required SMTP_FROM_NAME "Nombre visible del remitente" "$SMTP_FROM_NAME"

  # ---------- 5. opcionales ---------------------------------------------------------
  title "5/5 · Opciones"
  info "API key de NVD (gratis en nvd.nist.gov/developers/request-an-api-key): acelera la consulta de CVSS."
  ask_secret NVD_API_KEY "NVD API key (Enter para omitir)" 0 0
  ALERT_THRESHOLD=60; MONITOR_THRESHOLD=40; KEV_INTERVAL_MIN=15
  if yes_no "¿Ajustar umbrales e intervalo de consulta a CISA? (los valores por defecto andan bien)" n; then
    ask_required ALERT_THRESHOLD "Puntaje mínimo para alertar y notificar" 60
    ask_required MONITOR_THRESHOLD "Puntaje mínimo para dejar en monitoreo" 40
    ask_required KEV_INTERVAL_MIN "Minutos entre consultas a CISA KEV" 15
  fi

  # ---------- resumen ---------------------------------------------------------------
  title "Resumen"
  row "Instalación" "$PROJECT" "Consola" "$PUBLIC_URL (puerto $HTTP_PORT)" \
    "Zona horaria" "$TZ_VAL" "Administrador" "$ADMIN_EMAIL" \
    "Contraseña inicial" "$( [[ $ADMIN_PASS_GEN == 1 ]] && echo 'generada al azar (se muestra al final)' || mask "$ADMIN_PASS")" \
    "SOC" "$SOC_EMAILS"
  case $MAIL_OPT in
    2) row "Correo" "Microsoft Graph · $GRAPH_SENDER" "Client secret" "$(mask "$GRAPH_CLIENT_SECRET")" ;;
    5) row "Correo" "sin configurar" ;;
    *) row "Correo" "$SMTP_HOST:$SMTP_PORT ($SMTP_SECURITY) · $SMTP_FROM" "Contraseña SMTP" "$(mask "$SMTP_PASSWORD")" ;;
  esac
  row "NVD API key" "$(mask "$NVD_API_KEY")" "Umbrales" "alerta ≥ $ALERT_THRESHOLD · monitoreo ≥ $MONITOR_THRESHOLD" \
    "Consulta a CISA" "cada $KEV_INTERVAL_MIN min"
  echo
  yes_no "¿Guardar esta configuración?" s || { warn "No se guardó nada."; exit 1; }

  # ---------- escribir .env ------------------------------------------------------------
  DB_USER=${KEEP_DB_USER:-vectus}; DB_NAME=${KEEP_DB_NAME:-vectus_sat}
  DB_PASS=${KEEP_DB_PASS:-$(randstr 32)}; JWT=${KEEP_JWT:-$(randstr 64)}
  umask 077
  cat > .env <<EOF
# =============================================================================
#  Vectus SAT — configuración generada por install.sh el $(date '+%Y-%m-%d %H:%M')
#  Contiene secretos: NO se sube a git (está en .gitignore). Permisos 600.
#  Para cambiarla: ./install.sh  (opción "Reconfigurar") o editar y luego
#  docker compose up -d
# =============================================================================

# --- Instancia ---
COMPOSE_PROJECT_NAME=$PROJECT
HTTP_PORT=$HTTP_PORT
PUBLIC_URL=$PUBLIC_URL
TZ=$TZ_VAL

# --- Base de datos (generada al azar; no cambiar una vez creada la base) ---
POSTGRES_USER=$DB_USER
POSTGRES_PASSWORD=$DB_PASS
POSTGRES_DB=$DB_NAME

# --- Sesiones de la consola ---
JWT_SECRET=$JWT
JWT_EXPIRE_HOURS=8

# --- Administrador inicial (la contraseña se borra de aquí tras el primer arranque) ---
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_INITIAL_PASSWORD='$ADMIN_PASS'

# --- Equipo SOC (destinatarios del aviso previo; editable desde Configuración) ---
SOC_EMAILS=$SOC_EMAILS

# --- Correo: smtp | graph ---
MAIL_PROVIDER=$MAIL_PROVIDER
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_SECURITY=$SMTP_SECURITY
SMTP_USER=$SMTP_USER
SMTP_PASSWORD='$SMTP_PASSWORD'
SMTP_FROM=$SMTP_FROM
SMTP_FROM_NAME="$SMTP_FROM_NAME"
GRAPH_TENANT_ID=$GRAPH_TENANT_ID
GRAPH_CLIENT_ID=$GRAPH_CLIENT_ID
GRAPH_CLIENT_SECRET='$GRAPH_CLIENT_SECRET'
GRAPH_SENDER=$GRAPH_SENDER

# --- Detección ---
NVD_API_KEY='$NVD_API_KEY'
ALERT_THRESHOLD=$ALERT_THRESHOLD
MONITOR_THRESHOLD=$MONITOR_THRESHOLD
KEV_INTERVAL_MIN=$KEV_INTERVAL_MIN
EOF
  chmod 600 .env
  umask 022
  ok ".env guardado (permisos 600)"
fi

[[ $NO_START -eq 1 ]] && { ok "Listo. Para levantar: docker compose up -d --build"; exit 0; }

# ---------- levantar ---------------------------------------------------------------------
PORT=$(env_get HTTP_PORT); PORT=${PORT:-80}
PROJ=$(env_get COMPOSE_PROJECT_NAME); PROJ=${PROJ:-vectus-sat}
OTHER=$(project_dir "$PROJ")
if [[ -n "$OTHER" && "$OTHER" != "$PWD" ]]; then
  die "La instalación de $OTHER ya usa el nombre '$PROJ'. Ejecutá ./install.sh › Reconfigurar y elegí otro nombre."
fi
title "Levantando los contenedores"
info "La primera vez descarga imágenes y compila la consola: puede tardar unos minutos."
mkdir -p data backups
compose up -d --build

title "Verificando"
printf "  Esperando la API"
for i in $(seq 1 60); do
  if curl -fsS "http://localhost:$PORT/api/health" >/dev/null 2>&1; then echo; ok "API respondiendo en http://localhost:$PORT"; API_OK=1; break; fi
  printf "."; sleep 3
done
[[ "${API_OK:-0}" == 1 ]] || { echo; fail "La API no respondió. Revisá: docker compose logs backend --tail 50"; exit 1; }
compose ps --format 'table {{.Service}}\t{{.Status}}'

DBU=$(env_get POSTGRES_USER); DBN=$(env_get POSTGRES_DB)
sql() { compose exec -T db psql -U "$DBU" -d "$DBN" -tAc "$1" 2>/dev/null | tr -d '[:space:]'; }

# Contraseña inicial: una vez creado el admin, se quita del .env
if [[ -n "$(env_get ADMIN_INITIAL_PASSWORD)" ]] && [[ "$(sql 'select count(*) from users')" -ge 1 ]] 2>/dev/null; then
  sed -i 's/^ADMIN_INITIAL_PASSWORD=.*/ADMIN_INITIAL_PASSWORD=/' .env
  ok "Administrador creado; contraseña inicial quitada del .env"
fi

# Correo
if [[ -n "$(env_get SMTP_HOST)$(env_get GRAPH_TENANT_ID)" ]]; then
  title "Correo"
  if compose exec -T backend python -m app.comms.mailer --check; then
    ADM=$(env_get ADMIN_EMAIL)
    if yes_no "¿Enviar un mail de prueba a $ADM?" s; then
      compose exec -T backend python -m app.comms.mailer --send "$ADM" || warn "No se pudo enviar la prueba."
    fi
  else
    warn "Revisá los datos de correo con ./install.sh › Reconfigurar. El resto del sistema funciona igual."
  fi
fi

# Carga inicial
title "Catálogo CISA KEV"
printf "  Esperando la primera descarga del catálogo"
for i in $(seq 1 60); do
  n=$(sql 'select count(*) from kev_vulnerabilities'); [[ "${n:-0}" -gt 0 ]] 2>/dev/null && break
  printf "."; sleep 5
done
echo
if [[ "${n:-0}" -gt 0 ]] 2>/dev/null; then
  ok "$n vulnerabilidades cargadas como línea base (no generan avisos)"
  info "Opcional: evaluar las KEV de los últimos días para tener alertas desde el inicio."
  info "No envía comunicados a nadie; solo las deja visibles en la consola."
  ask DAYS "¿Cuántos días hacia atrás? (0 = ninguno)" 0
  if [[ "$DAYS" =~ ^[0-9]+$ ]] && (( DAYS > 0 )); then
    compose exec -T backend python -m app.scoring --backfill "$DAYS" || warn "La carga retroactiva falló; se puede repetir más tarde."
  fi
else
  warn "Todavía no se descargó el catálogo (¿el servidor tiene salida a internet?)."
  info "Ver: docker compose logs worker --tail 30"
fi

# ---------- final -------------------------------------------------------------------------
title "Instalación completa"
printf "  Consola:        ${B}%s${N}\n" "$(env_get PUBLIC_URL)"
printf "  Usuario:        ${B}%s${N}\n" "$(env_get ADMIN_EMAIL)"
if [[ "${ADMIN_PASS_GEN:-0}" == 1 ]]; then
  printf "  Contraseña:     ${B}%s${N}   ${Y}← anotala ahora: no se vuelve a mostrar${N}\n" "$ADMIN_PASS"
elif [[ -n "${ADMIN_PASS:-}" ]]; then
  printf "  Contraseña:     la que ingresaste\n"
fi
info "En el primer ingreso la consola pide cambiar la contraseña."
info "Siguiente paso: cargar clientes y contactos en la sección Clientes."
echo
