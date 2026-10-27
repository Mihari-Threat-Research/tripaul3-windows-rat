/*
   Mihari Threat Research - TRIPAUL3 Windows RAT
   Reporte: https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html
   Muestra de referencia (nucleo):
     SHA-256 fd57bbf23d51bb7d2869ec6f72d39eb809995f27ce5b9bc1141d7cc6f81d83f4
   TLP:CLEAR - CC BY 4.0
*/

import "pe"

rule Win_TRIPAUL3_Loader
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-17"
        description = "Nucleo del RAT modular TRIPAUL3 v3: endpoints C2, respuestas del dispatcher y artefactos de update/uninstall"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html"
        hash        = "fd57bbf23d51bb7d2869ec6f72d39eb809995f27ce5b9bc1141d7cc6f81d83f4"
        tlp         = "CLEAR"

    strings:
        $m1 = "TRIPAUL3" ascii
        $u1 = "/bot/register" ascii
        $u2 = "/bot/poll?bot_id=%s" ascii
        $u3 = "/plugin/get?name=" ascii
        $h1 = "X-Bot-ID: " ascii
        $r1 = "\"pong v3\"" ascii
        $r2 = "\"decrypt/map failed\"" ascii
        $f1 = "t3del.bat" ascii
        $f2 = "t3upd.exe" ascii
        $c1 = "packed_plugins" ascii
        $e1 = "PluginInit" ascii
        $i1 = "\"installed\"" ascii

    condition:
        uint16(0) == 0x5A4D and $m1 and
        5 of ($u*, $h1, $r*, $f*, $c*, $e*, $i*)
}

rule Win_TRIPAUL3_Encrypted_Overlay
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-17"
        description = "PE con overlay que contiene la cabecera TRIPAUL3 version 3 (config y plugins cifrados con AES-256-GCM)"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html"
        hash        = "fd57bbf23d51bb7d2869ec6f72d39eb809995f27ce5b9bc1141d7cc6f81d83f4"
        tlp         = "CLEAR"

    strings:
        $hdr = { 54 52 49 50 41 55 4C 33 03 00 00 00 }   // "TRIPAUL3" + uint32 version = 3

    condition:
        uint16(0) == 0x5A4D and pe.overlay.size > 0x4C and
        $hdr in (pe.overlay.offset .. pe.overlay.offset + pe.overlay.size)
}

rule Win_TRIPAUL3_Plugin
{
    meta:
        author      = "Mihari Threat Research"
        date        = "2026-10-17"
        description = "Plugin DLL de TRIPAUL3 (contrato PluginInit/Main/Task/Stop) tras descifrarse del overlay o en memoria"
        reference   = "https://mihari-intelligence.blogspot.com/2026/10/tripaul3-anatomia-rat-modular-windows.html"
        tlp         = "CLEAR"

    strings:
        $p1 = "/bot/log" ascii
        $p2 = "/bot/vnc_frame" ascii
        $p3 = "/bot/stealer_log" ascii
        $p4 = "\"keylogger_dump\"" ascii
        $p5 = "\"hvnc browser launched\"" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.exports("PluginInit") and pe.exports("PluginMain") and
        pe.exports("PluginTask") and pe.exports("PluginStop") and
        1 of ($p*)
}
