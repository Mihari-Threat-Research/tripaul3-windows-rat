#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tripaul3_extract.py - Extractor estatico de configuracion y plugins de TRIPAUL3 v3.

Mihari Threat Research - MIT License
Reporte: https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html

La muestra NUNCA se ejecuta: el script solo lee el fichero.

Formato del overlay (ultima aparicion del marcador):
    +0x00  8 B    magic   "TRIPAUL3"
    +0x08  4 B    version (uint32 LE, debe ser 3)
    +0x0C  4 B    N       (longitud del ciphertext)
    +0x10  32 B   clave AES-256 (en claro; es tambien la plugin_key)
    +0x30  12 B   nonce GCM
    +0x3C  N B    ciphertext (JSON de configuracion)
    +0x3C+N 16 B  tag GCM

    packed_plugins[nombre] = base64( nonce(12) | ct | tag(16) | HMAC-SHA256(key, nonce|ct|tag) )

Uso:
    pip install cryptography
    python3 tripaul3_extract.py tripaul.exe                    # imprime la config
    python3 tripaul3_extract.py tripaul.exe -o out --dump-plugins
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    sys.exit("[!] Falta la dependencia: pip install cryptography")

MAGIC = b"TRIPAUL3"
HDR_LEN = 0x3C
TAG_LEN = 16
MAC_LEN = 32
NONCE_LEN = 12


def decrypt_config(data: bytes) -> dict:
    off = data.rfind(MAGIC)  # la ultima aparicion es la cabecera real (la primera esta en .rdata)
    if off < 0:
        raise ValueError("marcador TRIPAUL3 no encontrado")
    if off + HDR_LEN > len(data):
        raise ValueError("cabecera truncada")

    version, n = struct.unpack_from("<II", data, off + 8)
    if version != 3:
        raise ValueError(f"version de overlay no soportada: {version}")

    key = data[off + 0x10: off + 0x30]
    nonce = data[off + 0x30: off + 0x3C]
    ct_tag = data[off + HDR_LEN: off + HDR_LEN + n + TAG_LEN]
    if len(ct_tag) != n + TAG_LEN:
        raise ValueError("ciphertext o tag truncados")

    plaintext = AESGCM(key).decrypt(nonce, ct_tag, None)
    return {"offset": off, "version": version, "key": key, "config": json.loads(plaintext)}


def decrypt_plugin(b64: str, key: bytes):
    blob = base64.b64decode(b64)
    if len(blob) < NONCE_LEN + TAG_LEN + MAC_LEN:
        raise ValueError("blob demasiado corto")
    body, mac = blob[:-MAC_LEN], blob[-MAC_LEN:]
    hmac_ok = hmac.compare_digest(hmac.new(key, body, hashlib.sha256).digest(), mac)
    dll = AESGCM(key).decrypt(body[:NONCE_LEN], body[NONCE_LEN:], None)
    return dll, hmac_ok


def redact_config(cfg: dict) -> dict:
    """Copia de la config sin los blobs de plugins, para imprimirla legible."""
    out = dict(cfg)
    if isinstance(out.get("packed_plugins"), dict):
        out["packed_plugins"] = {k: f"<{len(v)} bytes base64>" for k, v in out["packed_plugins"].items()}
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Extractor estatico de TRIPAUL3 v3")
    ap.add_argument("sample", help="Ruta a la muestra (PE)")
    ap.add_argument("-o", "--out", help="Directorio de salida para config.json y plugins")
    ap.add_argument("--dump-plugins", action="store_true", help="Escribir los plugins descifrados a disco")
    args = ap.parse_args()

    with open(args.sample, "rb") as fh:
        data = fh.read()

    try:
        res = decrypt_config(data)
    except (ValueError, InvalidTag) as exc:
        print(f"[!] No se pudo descifrar la configuracion: {exc}", file=sys.stderr)
        return 1

    cfg, key = res["config"], res["key"]
    print(f"[*] Overlay TRIPAUL3 v{res['version']} en offset 0x{res['offset']:X}")
    print(json.dumps(redact_config(cfg), indent=2, ensure_ascii=False))

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "config.json"), "w", encoding="utf-8") as fh:
            json.dump(redact_config(cfg), fh, indent=2, ensure_ascii=False)

    plugins = cfg.get("packed_plugins") or {}
    if plugins:
        print(f"\n[*] {len(plugins)} plugins empaquetados")
    for name, b64 in plugins.items():
        try:
            dll, ok = decrypt_plugin(b64, key)
        except (ValueError, InvalidTag) as exc:
            print(f"  [ERROR] {name}: {exc}")
            continue
        sha = hashlib.sha256(dll).hexdigest()
        print(f"  [{'OK ' if ok else 'BAD'} HMAC] {name:<14} {len(dll):>8} B  sha256={sha}")
        if args.dump_plugins:
            if not args.out:
                print("  [!] --dump-plugins requiere -o/--out", file=sys.stderr)
                return 2
            # Los plugins se guardan con extension .bin para evitar ejecuciones accidentales
            with open(os.path.join(args.out, f"{name}.dll.bin"), "wb") as fh:
                fh.write(dll)
    return 0


if __name__ == "__main__":
    sys.exit(main())
