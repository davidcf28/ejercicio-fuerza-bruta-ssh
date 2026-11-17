
#!/usr/bin/env bash
# genera_muestra.sh - log de prueba con el formato de journalctl -o json (Ejercicio 3)
# Crea muestra_ssh.jsonl con: ataques desde varias IPs, accesos legítimos desde .10
# y un ataque que termina con acceso conseguido desde .23 (caso crítico).
set -euo pipefail

ahora=$(date +%s)
linea() {   # linea <segundos_atrás> <mensaje>
  jq -nc --arg t "$(( ahora - $1 ))000000" --arg m "$2" \
    '{__REALTIME_TIMESTAMP: $t, _COMM: "sshd", MESSAGE: $m}'
}

{
  linea 290 "Accepted password for kali from 192.168.56.10 port 40100 ssh2"
  for i in $(seq 1 36); do
    ip="192.168.56.$(shuf -n1 -e 20 21 21 22 22 22 23 23)"
    user=$(shuf -n1 -e root admin kali test oracle)
    linea $(( 280 - i * 7 )) "Failed password for invalid user $user from $ip port $(( RANDOM + 30000 )) ssh2"
  done
  linea 15 "Accepted password for kali from 192.168.56.10 port 40200 ssh2"
  linea 5  "Accepted password for kali from 192.168.56.23 port 41999 ssh2"
} > muestra_ssh.jsonl

echo "Generado muestra_ssh.jsonl ($(wc -l < muestra_ssh.jsonl) eventos)"
