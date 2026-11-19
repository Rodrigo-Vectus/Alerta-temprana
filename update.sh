#!/usr/bin/env bash
# =============================================================================
#  Vectus SAT — actualizar aplicando solo lo que cambió
#
#  ./update.sh /tmp/cambio.bundle   aplica un bundle, lo sube a GitHub y actualiza
#  ./update.sh                      baja lo último de GitHub y actualiza
#  ./update.sh --todo               reconstruye y reinicia todo (sin bajar nada)
#
#  Según los archivos modificados:
#    backend/          → recompila la imagen de la API y reinicia API + worker
#    frontend/         → recompila solo la consola web
#    nginx/            → reinicia solo nginx (sin compilar)
#    docker-compose.yml, Dockerfiles, requirements, package.json → todo
#    README, docs, install.sh, update.sh → nada que reiniciar
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'
step() { printf "\n${B}── %s${N}\n" "$1"; }
ok()   { printf "  ${G}✔${N} %s\n" "$1"; }
warn() { printf "  ${Y}!${N} %s\n" "$1"; }
die()  { printf "  ${R}✘ %s${N}\n" "$1" >&2; exit 1; }
T0=$(date +%s)

PORT=$(grep -E '^HTTP_PORT=' .env 2>/dev/null | cut -d= -f2); PORT=${PORT:-80}

# ---------- 1. traer cambios --------------------------------------------------
OLD=$(git rev-parse HEAD)
FULL=0
if [[ "${1:-}" == "--todo" ]]; then
  FULL=1
elif [[ -n "${1:-}" ]]; then
  [[ -f "$1" ]] || die "No existe el archivo $1 (¿lo copiaste a /tmp?)"
  step "Aplicando $(basename "$1")"
  git pull --ff-only "$1" main
  if git push -q 2>/dev/null; then ok "Subido a GitHub"; else warn "No se pudo subir a GitHub (se puede repetir con: git push)"; fi
else
  step "Bajando cambios de GitHub"
  git pull --ff-only
fi
NEW=$(git rev-parse HEAD)

if [[ $FULL -eq 0 ]]; then
  if [[ "$OLD" == "$NEW" ]]; then ok "Ya estaba actualizado ($(git log --oneline -1))"; exit 0; fi
  CHANGED=$(git diff --name-only "$OLD" "$NEW")
  echo "$CHANGED" | sed 's/^/    /'
fi

has() { [[ $FULL -eq 1 ]] || grep -qE "$1" <<<"$CHANGED"; }

# ---------- 2. decidir qué actualizar -----------------------------------------
if has '^(docker-compose\.yml|backend/Dockerfile|backend/requirements\.txt|frontend/Dockerfile|frontend/package(-lock)?\.json)$'; then
  step "Cambió la estructura: se reconstruye todo"
  docker compose up -d --build
else
  BUILT=0
  if has '^backend/'; then
    step "API y worker"
    docker compose build -q backend
    docker compose up -d --no-deps backend worker
    BUILT=1
  fi
  if has '^frontend/'; then
    step "Consola web"
    docker compose build -q nginx
    docker compose up -d --no-deps nginx
    BUILT=1
  elif has '^nginx/'; then
    step "nginx (configuración)"
    docker compose up -d --no-deps --force-recreate nginx
    BUILT=1
  fi
  [[ $BUILT -eq 0 ]] && { ok "Solo cambió documentación: no hace falta reiniciar nada"; exit 0; }
fi

# ---------- 3. verificar -------------------------------------------------------
step "Verificando"
for i in $(seq 1 40); do
  if curl -fsS "http://localhost:$PORT/api/health" >/dev/null 2>&1; then
    ok "API respondiendo · $(git log --oneline -1)"
    ok "Listo en $(( $(date +%s) - T0 )) s. Recargá la consola con Ctrl+F5."
    # Borra solo las imágenes viejas de esta instalación (no toca otros proyectos del servidor)
    PROJ=$(grep -E '^COMPOSE_PROJECT_NAME=' .env 2>/dev/null | cut -d= -f2); PROJ=${PROJ:-vectus-sat}
    docker image prune -f --filter "label=com.docker.compose.project=$PROJ" >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 1
done
die "La API no respondió. Revisá: docker compose logs backend --tail 50"
