#!/usr/bin/env bash
# Lanza una captura filtrada de Wireshark (o tcpdump si no hay Wireshark/GUI)
# y guarda el archivo automaticamente en la carpeta evidencia/ correspondiente.
#
# Uso:
#   ./fase2/capturar.sh casa7 [interfaz] [--cli]
#   ./fase2/capturar.sh casa5 [interfaz] [--cli]
#
# Ejemplos:
#   ./fase2/capturar.sh casa7              # Captura puerto 7777 (defensa Casa 7)
#   ./fase2/capturar.sh casa5              # Captura puerto 6005 (trafico Casa 5)
#   ./fase2/capturar.sh casa7 lo --cli     # Fuerza tcpdump en loopback para probar en casa

set -euo pipefail

OBJETIVO="${1:-}"
INTERFAZ="any"
FORZAR_CLI="false"

shift || true
for arg in "$@"; do
  if [[ "$arg" == "--cli" ]]; then
    FORZAR_CLI="true"
  else
    INTERFAZ="$arg"
  fi
done

RAIZ_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARCA_TIEMPO="$(date -u +%Y%m%d_%H%M%S)"

case "$OBJETIVO" in
  casa7)
    PUERTO=7777
    DIR_SALIDA="$RAIZ_REPO/fase2/defensa_casa7/evidencia"
    PREFIJO="captura_defensa_casa7"
    ;;
  casa5)
    PUERTO=6005
    DIR_SALIDA="$RAIZ_REPO/ataque/evidencia"
    PREFIJO="captura_casa5"
    ;;
  *)
    echo "Uso: $0 <casa7|casa5> [interfaz] [--cli]"
    echo "  casa7 -> captura TCP puerto 7777 en fase2/defensa_casa7/evidencia/"
    echo "  casa5 -> captura TCP puerto 6005 en ataque/evidencia/"
    exit 1
    ;;
esac

mkdir -p "$DIR_SALIDA"
FILTRO="tcp port $PUERTO"

if [[ "$FORZAR_CLI" == "false" && -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]] && command -v wireshark >/dev/null 2>&1; then
  ARCHIVO="$DIR_SALIDA/${PREFIJO}_${MARCA_TIEMPO}.pcapng"
  echo "[Captura] Abriendo Wireshark en interfaz '$INTERFAZ' con filtro '$FILTRO'"
  echo "[Captura] Guardando en: $ARCHIVO"
  exec wireshark -i "$INTERFAZ" -k -f "$FILTRO" -w "$ARCHIVO"
elif command -v tcpdump >/dev/null 2>&1; then
  ARCHIVO="$DIR_SALIDA/${PREFIJO}_${MARCA_TIEMPO}.pcap"
  echo "[Captura] Iniciando tcpdump en interfaz '$INTERFAZ' con filtro '$FILTRO'"
  echo "[Captura] Guardando en: $ARCHIVO (Ctrl+C para detener)"
  exec sudo tcpdump -i "$INTERFAZ" -s 0 -w "$ARCHIVO" "$FILTRO"
else
  echo "[Error] No se encontro ni 'wireshark' ni 'tcpdump' en el sistema." >&2
  exit 1
fi
