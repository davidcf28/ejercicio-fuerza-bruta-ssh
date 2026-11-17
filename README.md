chmod +x vigia_ssh.sh
./genera_muestra.sh
./vigia_ssh.sh -f muestra_ssh.jsonl -n            # simulación: imprime las alertas
WEBHOOK_URL="https://..." ./vigia_ssh.sh -f muestra_ssh.jsonl   # envío real
./vigia_ssh.sh -u 8 -w 10                         # journalctl en vivo, umbral 8, ventana 10 min
