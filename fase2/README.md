# Fase 2 — El Asedio (Casa 7)

## Enfrentamiento asignado (Trío cíclico)

`Casa 5 → Casa 6 → Casa 7 → Casa 5`

- **Rol atacante:** Casa 7 ataca a **Casa 5** (`ataque_casa5/`).
- **Rol defensor:** Casa 7 defiende su Bóveda KOOPIS ante **Casa 6** (`defensa_casa7/`).

## Estructura

```text
fase2/
├── README.md
├── ataque_casa5/
│   ├── exploits/           # Scripts / PoCs reproducibles contra Casa 5
│   └── evidencia/          # Capturas de Wireshark y salidas del ataque
└── defensa_casa7/
    └── evidencia/          # Copias de alertas_red.log y capturas de defensa
```

## Lista de verificación antes y durante el Asedio

1. **Captura de tráfico en la Bóveda (Casa 7):** mientras la Bóveda escucha en `10.1.138.56:7777`, correr en paralelo una captura para complementar `servidor/datos/alertas_red.log`:
   ```bash
   sudo tcpdump -i any tcp port 7777 -w fase2/defensa_casa7/evidencia/trafico_defensa_casa7.pcap
   ```
2. **Confidencialidad:** nunca compartir ni filtrar los defectos fatídicos propios (`-50%` de penalización).
3. **Entregables finales (50 % de la nota total):**
   - Informe de ataque + exploit reproducible (`ataque_casa5/exploits/`) + evidencia Wireshark (`ataque_casa5/evidencia/`).
   - Post-mortem de defensa respaldado por `servidor/datos/alertas_red.log` y capturas de red.
