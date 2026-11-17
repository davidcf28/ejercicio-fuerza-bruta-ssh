#!/usr/bin/env bash
# vigia_ssh.sh - Detector de fuerza bruta SSH con alertas por webhook (Ejercicio 3, fase 1)
#
# Uso: ./vigia_ssh.sh [-f fichero.jsonl] [-u umbral] [-w ventana_min] [-c cooldown_min]
#                     [-s estado.json] [-d URL_webhook] [-n]
set -euo pipefail

umbral=5          # intentos fallidos desde los que se alerta
ventana=5         # minutos hacia atrás que se analizan
cooldown=10       # minutos sin repetir alerta para la misma IP
fichero=""        # si se omite, se lee de journalctl
estado="estado.json"
webhook="${WEBHOOK_URL:-}"   # URL del canal "alertas" (o con -d)
dry=0             # -n: no envía, solo imprime la alerta

uso() {
  cat >&2 <<EOF
Uso: $0 [-f fichero] [-u umbral] [-w ventana_min] [-c cooldown_min] [-s estado.json] [-d webhook] [-n]
  -f  leer de un fichero JSON Lines en vez de journalctl
  -u  umbral de intentos por IP (defecto $umbral)
  -w  ventana en minutos (defecto $ventana)
  -c  minutos sin repetir alerta de la misma IP (defecto $cooldown)
  -s  fichero de estado (defecto $estado)
  -d  URL del webhook (o variable WEBHOOK_URL)
  -n  simulación: imprime la alerta en lugar de enviarla
EOF
  exit 1
}

while getopts ":f:u:w:c:s:d:nh" op; do
  case $op in
    f) fichero=$OPTARG ;;
    u) umbral=$OPTARG ;;
    w) ventana=$OPTARG ;;
    c) cooldown=$OPTARG ;;
    s) estado=$OPTARG ;;
    d) webhook=$OPTARG ;;
    n) dry=1 ;;
    *) uso ;;
  esac
done

for v in "$umbral" "$ventana" "$cooldown"; do
  [[ $v =~ ^[0-9]+$ ]] || { echo "Error: '$v' no es un entero positivo" >&2; exit 1; }
done
command -v jq >/dev/null || { echo "Error: falta jq" >&2; exit 1; }
if (( ! dry )) && [[ -z $webhook ]]; then
  echo "Error: indica el webhook con -d o WEBHOOK_URL (o usa -n)" >&2; exit 1
fi

ahora=$(date +%s)
desde=$(( ahora - ventana * 60 ))
host=$(hostname)
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Estado: {"IP": epoch_ultima_alerta}; se recrea si falta o está corrupto
jq -e type "$estado" >/dev/null 2>&1 || echo '{}' > "$estado"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
# Purga entradas ya caducadas
jq --argjson lim "$(( ahora - cooldown * 60 ))" 'with_entries(select(.value > $lim))' \
  "$estado" > "$tmp" && mv "$tmp" "$estado"

# --- 1. Lectura de eventos
if [[ -n $fichero ]]; then
  [[ -r $fichero ]] || { echo "Error: no se puede leer $fichero" >&2; exit 1; }
  leer() { cat "$fichero"; }
else
  leer() { journalctl -u ssh -o json --since "-${ventana} min" --no-pager; }
fi

# --- 2 y 3. Filtrar Failed password, extraer usuario/IP y agrupar por IP
# Una línea JSON por IP que supera el umbral: {"ip":..,"intentos":..,"usuarios":[..]}
candidatas=$(leer | jq -cs --argjson desde "$desde" --argjson umbral "$umbral" '
  [ .[]
    | select((.__REALTIME_TIMESTAMP | tonumber) / 1e6 >= $desde)
    | select((.MESSAGE | type) == "string" and (.MESSAGE | test("^Failed password")))
    | .MESSAGE
    | capture("for (invalid user )?(?<usuario>\\S+) from (?<ip>[0-9a-f.:]+)")
  ]
  | group_by(.ip)
  | map({ip: .[0].ip, intentos: length, usuarios: (map(.usuario) | unique)})
  | map(select(.intentos >= $umbral))
  | sort_by(-.intentos)
  | .[]')

[[ -n $candidatas ]] || { echo "[$ts] Sin IPs por encima del umbral ($umbral)" >&2; exit 0; }

# --- 4 y 5. Alertar (con antirrepetición)
while IFS= read -r fila; do
  ip=$(jq -r '.ip' <<<"$fila")
  ultimo=$(jq -r --arg ip "$ip" '.[$ip] // 0' "$estado")

  if (( ahora - ultimo < cooldown * 60 )); then
    echo "[$ts] $ip ya alertada hace $(( (ahora - ultimo) / 60 )) min, se omite" >&2
    continue
  fi

  alerta=$(jq -nc --arg host "$host" --arg ts "$ts" --argjson f "$fila" \
                  --argjson v "$ventana" --argjson u "$umbral" '
    {tipo: "alerta_ssh", host: $host, ts: $ts, ip: $f.ip, intentos: $f.intentos,
     ventana_min: $v, usuarios: $f.usuarios,
     severidad: (if $f.intentos >= 2 * $u then "alta" else "media" end)}')

  if (( dry )); then
    echo "$alerta"
  elif curl -fsS -m 10 -X POST -H 'Content-Type: application/json' \
            -d "$alerta" "$webhook" </dev/null >/dev/null; then
    echo "[$ts] Alerta enviada para $ip" >&2
  else
    echo "[$ts] ERROR enviando alerta de $ip; no se registra en el estado" >&2
    continue   # se reintentará en la próxima ejecución
  fi

  # Registrar solo tras enviar con éxito (o en simulación)
  jq --arg ip "$ip" --argjson t "$ahora" '. + {($ip): $t}' "$estado" > "$tmp" && mv "$tmp" "$estado"
done <<<"$candidatas"
