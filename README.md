# TRIPAUL3 — RAT modular para Windows con configuración y plugins cifrados en el overlay

**Publicado:** 2026-10-20 · **Reporte completo:** [TRIPAUL3: Anatomía de un RAT modular para Windows](https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html) · **TLP:CLEAR**

## Resumen

TRIPAUL3 es un RAT para Windows x64 (C++, MSVC) que se identifica como versión 3.0. Su núcleo es pequeño: descifra la configuración, aplica opcionalmente evasión y persistencia, se registra en el C2 y atiende un bucle de *polling* de 30 segundos con nueve comandos. Toda la capacidad ofensiva vive en seis plugins DLL (keylogger, VNC, HVNC, stealer, gestor de ficheros y shell/sysinfo) que viajan cifrados con AES-256-GCM y HMAC-SHA256 en 1,5 MB de overlay, y que se cargan mediante mapeo manual de PE sin tocar disco.

El fallo de diseño es de base: la clave AES viaja en claro en la cabecera del overlay y es la misma para la configuración y los plugins. Eso permite recuperar de forma estática el C2 real (HTTP plano en el puerto 8443) y los seis módulos. El panel `Tripaul C2` incluye un medidor de cupo mensual de bots, indicio de un modelo de malware como servicio.

## Muestra

| Campo | Valor |
|---|---|
| Fichero | `tripaul.exe` |
| SHA-256 | `FD57BBF23D51BB7D2869EC6F72D39EB809995F27CE5B9BC1141D7CC6F81D83F4` |
| MD5 | `5B8699306F031DB256AA6EB2DD4C15F7` |
| Imphash | `9A5858B29CB5D7C41C10E4B098209C42` |
| Compilación | 2026-10-16 08:06:49 UTC |
| C2 | `hxxp://31.56.19[.]150:8443` |
| Familia | No atribuida (sin referencias públicas) |

## Hallazgos clave

- **Overlay:** marcador `TRIPAUL3` (última aparición) + versión 3 + longitud + clave AES-256 en claro + nonce + ciphertext + tag.
- **Evasión inerte en esta build:** anti-debug (cinco comprobaciones, incluidos registros `Dr0`–`Dr3`), anti-VM, anti-sandbox y anti-EDR (unhooking de `ntdll`, parches de ETW y AMSI), todos con su flag a `false`.
- **Persistencia triple** bajo el nombre `WindowsSecurity`: Run key, tarea programada ONLOGON y acceso directo en Startup. También se instala bajo demanda con el comando `persist`.
- **C2:** HTTP/1.1 + JSON vía `WinHttp`, cabecera `X-Bot-ID`, endpoints `/bot/register`, `/bot/poll`, `/bot/result`, `/plugin/get`.
- **Living-off-the-land:** `certutil -urlcache` para la auto-actualización (`t3upd.exe`) y `t3del.bat` para el auto-borrado.

## Contenido del repositorio

| Fichero | Contenido | Validación |
|---|---|---|
| [`iocs/`](iocs) | Núcleo y seis plugins, C2, persistencia, artefactos. Incluye `iocs.csv`, listas por tipo (`hashes.txt`, `network.txt`, `host.txt`) y bundle STIX 2.1 | STIX validado |
| [`attack.csv`](attack.csv) | ATT&CK Enterprise | — |
| [`yara/tripaul3_windows.yar`](yara/tripaul3_windows.yar) | Núcleo, overlay cifrado, plugins | Compilan |
| [`sigma/`](sigma) | Run key, tarea programada (4698), cadena certutil | Cargan en pySigma |
| [`suricata/tripaul3_windows.rules`](suricata/tripaul3_windows.rules) | Registro, polling, descarga de plugins, IP del C2 | Revisión de sintaxis |
| [`tools/tripaul3_extract.py`](tools/tripaul3_extract.py) | Extractor estático de config y plugins | Probado contra un overlay sintético con el mismo formato |

### Cambios respecto a las reglas del blog

- **YARA:** se añadieron los bloques `meta` que faltaban en las reglas de overlay y plugins; la condición del overlay se simplificó a `$hdr in (...)`, que ya cubre el caso `at`.
- **Sigma:** se añadieron `id`, `status`, `description`, `author`, `date`, `tags` y `falsepositives`, necesarios para que las reglas pasen la validación de pySigma y de SigmaHQ.
- **Suricata:** reglas en una sola línea, con `reference` y `metadata`, más una regla nueva (SID 1000013) para la IP:puerto del C2.
- **Extractor:** unifica los dos scripts del blog (que perdió la indentación al publicarse) en uno con dependencia única (`cryptography`); guarda los plugins con extensión `.dll.bin` para evitar ejecuciones accidentales.

### Pendiente en el blog

La fila **Estado en VirusTotal** de la sección 2 sigue mostrando `[COMPLETAR]`.

## Verificación dinámica

Ejecución pública del build con la persistencia forzada en ANY.RUN: [7b654fd2-06f6-4d97-b6bd-b93eab31cf14](https://app.any.run/tasks/7b654fd2-06f6-4d97-b6bd-b93eab31cf14).

## Licencia

Reglas, IOCs y documentación bajo [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); código bajo MIT. Ver [LICENSE](LICENSE).

---

**Mihari Threat Research** · [Blog](https://mihari-intelligence.blogspot.com/) · [mihari-intelligence.com](https://mihari-intelligence.com) · TLP:CLEAR
Este repositorio no contiene muestras de malware, solo hashes.
