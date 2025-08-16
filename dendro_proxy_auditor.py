#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DENDRO Proxy Auditor
Autor: DENDRO – Keith Fernández
Propiedad: DENDRO | Intelligence | Dendro.pe

Funciones:
- Comprobación HTTPS y HTTP (CONNECT) por proxy.
- Anonimato: transparente / anónimo / elite.
- Velocidad estimada (KB/s) descargando N bytes.
- GeoIP opcional (país/ciudad/ISP) del IP de salida.
- Exportaciones: TXT, CSV y JSON con metadatos de propiedad.

Requisitos opcionales:
    pip install "requests[socks]"
    pip install colorama   # para colores en Windows
"""

import os
import re
import csv
import json
import time
import random
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# BRANDING / APARIENCIA
# =========================
TOOL_NAME = "DENDRO Proxy Auditor"
OWNER = "DENDRO – Keith Fernández"
SLOGAN = 'Dendro | Intelligence – "Transformamos datos en decisiones."'

# Colores base + ORANGE (#ff8500)
try:
    from colorama import init as colorama_init, Style
    colorama_init()
    RESET = Style.RESET_ALL
    BOLD  = Style.BRIGHT
except Exception:
    RESET = "\033[0m"
    BOLD  = "\033[1m"

try:
    from colorama import init as colorama_init, Style
    colorama_init()
    RESET = Style.RESET_ALL
    BOLD  = Style.BRIGHT
except Exception:
    RESET = "\033[0m"
    BOLD  = "\033[1m"

def _supports_truecolor() -> bool:
    """Detecta soporte 24-bit True Color."""
    ct = os.environ.get("COLORTERM", "").lower()
    if "truecolor" in ct or "24bit" in ct:
        return True
    # Windows Terminal, VSCode terminal, etc.
    if os.name == "nt" and (
        os.environ.get("WT_SESSION") or
        os.environ.get("TERM_PROGRAM") == "vscode" or
        os.environ.get("ANSICON") or
        os.environ.get("ConEmuANSI") == "ON"
    ):
        return True
    return False

def _rgb_to_ansi256(r: int, g: int, b: int) -> int:
    """Aproxima un color RGB al cubo 6x6x6 de ANSI-256."""
    def q(x):  # 0..255 -> 0..5
        return int(round((x / 255) * 5))
    return 16 + 36 * q(r) + 6 * q(g) + q(b)

def _parse_hex(hexcolor: str) -> tuple[int, int, int]:
    """Convierte '#RRGGBB' o '#RGB' a (r,g,b)."""
    s = hexcolor.lstrip("#")
    if len(s) == 3:  # #RGB
        r, g, b = (int(c * 2, 16) for c in s)
    elif len(s) == 6:  # #RRGGBB
        r = int(s[0:2], 16); g = int(s[2:4], 16); b = int(s[4:6], 16)
    else:
        raise ValueError(f"Hex inválido: {hexcolor}")
    return r, g, b

def rgb_hex(hexcolor: str, *, background: bool = False) -> str:
    """
    Devuelve secuencia ANSI para color #RRGGBB / #RGB.
    Si background=True, usa color de fondo.
    """
    try:
        r, g, b = _parse_hex(hexcolor)
    except Exception:
        return ""  # sin color si falla

    if _supports_truecolor():
        return f"\033[{48 if background else 38};2;{r};{g};{b}m"

    # Fallback a 256 colores
    idx = _rgb_to_ansi256(r, g, b)
    return f"\033[{48 if background else 38};5;{idx}m"

def rgb_bg_hex(hexcolor: str) -> str:
    """Atajo para fondo con #RRGGBB/#RGB."""
    return rgb_hex(hexcolor, background=True)

# --- Color corporativo ---
ORANGE = rgb_hex("#ff8500")

# Símbolos/labels en naranja
CHECK  = f"{ORANGE}✓{RESET}"
CROSS  = f"{ORANGE}✗{RESET}"
BULLET = f"{ORANGE}>{RESET}"

# ====== Banner D E N D R O (6 líneas, tu versión) ======
DENDRO_BANNER = [
    "██████╗    ███████╗   ███╗   ██╗  ██████╗    ██████╗     ██████╗ ",
    "██╔══██╗   ██╔════╝   ████╗  ██║  ██╔══██╗   ██╔══██╗   ██╔═══██╗",
    "██║  ██║   █████╗     ██╔██╗ ██║  ██║  ██║   ██████╔╝   ██║   ██║",
    "██║  ██║   ██╔══╝     ██║╚██╗██║  ██║  ██║   ██╔══██╗   ██║   ██║",
    "██║  ██║   ███████╗   ██║ ╚████║  ██║  ██║   ██║  ██║   ╚██████╔╝",
    "██████╔╝   ╚══════╝   ╚═╝  ╚═══╝  ██████╔╝   ╚═╝  ╚═╝    ╚═════╝ "
]

def banner(sep=False, pad_top=1, indent=0, sep_char="─",
           show_name=True, show_mode=True, show_owner=False, show_slogan=False):
    """Muestra el banner DENDRO y, debajo, el nombre de la herramienta."""
    left = " " * max(0, int(indent))
    if pad_top > 0:
        print("\n" * int(pad_top), end="")

    # (sin separador por defecto)
    if sep:
        width = max(len(s) for s in DENDRO_BANNER)
        print(ORANGE + left + (sep_char * width) + RESET)

    # ASCII de 6 líneas
    for line in DENDRO_BANNER:
        print(ORANGE + left + line + RESET)

    # Sub-título con el nombre de la herramienta (y modo)
    if show_name:
        name_line = TOOL_NAME 
        print(ORANGE + BOLD + left + name_line + RESET)

    if show_owner:
        print(ORANGE + left + f"Propiedad: {OWNER}" + RESET)
    if show_slogan:
        print(ORANGE + left + SLOGAN + RESET)

    print()  # salto final



def print_info(msg):  print(f"{ORANGE}[INFO]{RESET} {msg}")
def print_ok(msg):    print(f"{ORANGE}[OK]{RESET}   {msg}")
def print_warn(msg):  print(f"{ORANGE}[WARN]{RESET} {msg}")
def print_err(msg):   print(f"{ORANGE}[ERR]{RESET}  {msg}")
def nowstamp():
    return time.strftime("%Y%m%d-%H%M%S")

def sanitize(line: str) -> str:
    # Oculta password al imprimir (user:***@host:port)
    if "@" in line and ":" in line.split("@", 1)[0]:
        user, rest = line.split("@", 1)
        u = user.split(":", 1)[0]
        return f"{u}:***@{rest}"
    return line

def parse_host_port(line: str):
    # Extrae puerto para heurística; soporta IPv6 [::1]:8080 y user:pass@
    s = line
    if "://" in s:
        s = s.split("://", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[1]
    if s.startswith("["):
        try:
            host, port = s.split("]:", 1)
            port = int(port.strip())
            return host.strip("[]"), port
        except Exception:
            return None, None
    if s.count(":") >= 1:
        try:
            host, port = s.rsplit(":", 1)
            return host.strip(), int(port.strip())
        except Exception:
            return None, None
    return None, None

def build_uri(base_proto: str, line: str) -> str:
    # Respeta esquema si ya viene; si no, antepone base_proto
    return line if "://" in line else f"{base_proto}://{line}"

PORT_GUESS = {
    "http":  {80, 8080, 8000, 8001, 8888, 3128, 1981, 9091, 8448},
    "socks": {1080, 9050},
}

def guess_proto_from_port(line: str) -> str:
    _, port = parse_host_port(line)
    if not port: return "http"
    if port in PORT_GUESS["socks"]: return "socks5h"
    if port in PORT_GUESS["http"]:  return "http"
    return "http"

# =========================
# CONFIG PREDETERMINADA
# =========================
DEFAULT_HTTP_TEST_URLS  = ["http://httpbin.org/ip"]
DEFAULT_HTTPS_TEST_URLS = ["https://icanhazip.com/", "https://api.ipify.org/"]
SPEED_URLS = ["https://speed.cloudflare.com/__down?bytes={bytes}"]
DEFAULT_CONNECT_TIMEOUT = 6
DEFAULT_READ_TIMEOUT = 10
DEFAULT_RETRIES = 1
DEFAULT_BACKOFF_BASE = 0.35
DEFAULT_VERIFY_TLS = True
DEFAULT_CONCURRENCY = min(64, max(8, (os.cpu_count() or 8) * 5))
DEFAULT_SPEED_BYTES = 256 * 1024  # 256 KB

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15",
]

# =========================
# RED / TESTS
# =========================
def request_with_retries(session, url, proxies=None, stream=False, extra_headers=None,
                         timeouts=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT),
                         verify=DEFAULT_VERIFY_TLS, retries=DEFAULT_RETRIES,
                         backoff_base=DEFAULT_BACKOFF_BASE, user_agents=USER_AGENTS):
    last_err = None
    for attempt in range(retries + 1):
        try:
            session.headers.update({"User-Agent": random.choice(user_agents)})
            if extra_headers:
                session.headers.update(extra_headers)
            start = time.perf_counter()
            r = session.get(url, proxies=proxies, timeout=timeouts, verify=verify, stream=stream)
            elapsed = (time.perf_counter() - start) * 1000.0
            return r, round(elapsed, 1)
        except Exception as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(backoff_base * (attempt + 1))
    raise RuntimeError(last_err or "unknown error")

def classify_anonymity(direct_ip: str, exit_ip: str, headers: dict) -> str:
    h = {k.lower(): v for k, v in (headers or {}).items()}
    xff = h.get("x-forwarded-for", "") or h.get("forwarded", "")
    via = h.get("via", "")
    xreal = h.get("x-real-ip", "")
    if direct_ip and (direct_ip in str(xff) or direct_ip == xreal):
        return "transparente"
    if any([xff, via, h.get("proxy-connection"), h.get("x-proxy-id"), h.get("x-true-client-ip")]):
        return "anónimo"
    return "elite"

def geo_lookup(session, ip: str, timeouts=(3, 6)):
    try:
        r = session.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,query",
                        timeout=timeouts)
        if r.ok:
            j = r.json()
            if j.get("status") == "success":
                return {"country": j.get("country"), "region": j.get("regionName"),
                        "city": j.get("city"), "isp": j.get("isp")}
    except Exception:
        pass
    return {}

def speed_test(session, proxies, bytes_to_get=DEFAULT_SPEED_BYTES,
               verify_tls=DEFAULT_VERIFY_TLS,
               timeouts=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)):
    # 1) Cloudflare speed endpoint
    for tmpl in SPEED_URLS:
        try:
            url = tmpl.format(bytes=bytes_to_get)
        except Exception:
            url = tmpl
        try:
            start = time.perf_counter()
            r = session.get(url, proxies=proxies, timeout=timeouts, verify=verify_tls, stream=True)
            dl = 0
            for data in r.iter_content(chunk_size=16 * 1024):
                if not data:
                    break
                dl += len(data)
                if dl >= bytes_to_get:
                    break
            elapsed = time.perf_counter() - start
            if dl > 0 and elapsed > 0:
                kbps = (dl / 1024.0) / elapsed
                return round(kbps, 1)
        except Exception:
            continue
    # 2) Fallback con Range
    fallbacks = [
        "https://speed.hetzner.de/100MB.bin",
        "https://ipv4.download.thinkbroadband.com/5MB.zip",
    ]
    hdr = {"Range": f"bytes=0-{bytes_to_get-1}"}
    for url in fallbacks:
        try:
            start = time.perf_counter()
            r = session.get(url, proxies=proxies, timeout=timeouts, verify=verify_tls, headers=hdr, stream=True)
            dl = 0
            for data in r.iter_content(chunk_size=16 * 1024):
                if not data:
                    break
                dl += len(data)
                if dl >= bytes_to_get:
                    break
            elapsed = time.perf_counter() - start
            if dl > 0 and elapsed > 0:
                kbps = (dl / 1024.0) / elapsed
                return round(kbps, 1)
        except Exception:
            continue
    return None

def check_proxy(line, base_proto, http_urls, https_urls, do_geo, bytes_speed,
                session, direct_ip, timeouts, verify_tls, retries, backoff_base, user_agents):
    # Determinar esquema base (respeta si la línea ya lo trae)
    scheme = base_proto if base_proto != "auto" else guess_proto_from_port(line)
    proxy_uri = build_uri(scheme, line)
    proxies = {"http": proxy_uri, "https": proxy_uri}

    # 1) HTTPS -> IP salida
    exit_ip = None
    latency_https = None
    status_https = None
    last_err = None
    for url in https_urls:
        try:
            r, latency_https = request_with_retries(session, url, proxies=proxies,
                                                    timeouts=timeouts, verify=verify_tls,
                                                    retries=retries, backoff_base=backoff_base,
                                                    user_agents=user_agents)
            status_https = r.status_code
            if r.ok and r.text:
                exit_ip = r.text.strip().split()[0]
                break
            else:
                last_err = f"HTTPS {status_https}"
        except Exception as e:
            last_err = str(e)
            continue
    if not exit_ip:
        return {"line": line, "proxy_uri": proxy_uri, "ok": False, "error": last_err or "sin salida https"}

    # 2) HTTP (saber si también sirve para http://)
    http_ok = False
    latency_http = None
    for url in http_urls:
        try:
            r, latency_http = request_with_retries(session, url, proxies=proxies,
                                                   timeouts=timeouts, verify=verify_tls,
                                                   retries=retries, backoff_base=backoff_base,
                                                   user_agents=user_agents)
            http_ok = r.ok
            break
        except Exception:
            continue

    # 3) Cabeceras -> anonimato
    headers = {}
    try:
        r, _ = request_with_retries(session, "https://httpbin.org/headers", proxies=proxies,
                                    timeouts=timeouts, verify=verify_tls,
                                    retries=retries, backoff_base=backoff_base,
                                    user_agents=user_agents)
        if r.ok:
            headers = r.json().get("headers", {})
    except Exception:
        pass
    anonymity = classify_anonymity(direct_ip, exit_ip, headers)

    # 4) Geo opcional
    geo = geo_lookup(session, exit_ip, timeouts=(3, 6)) if do_geo else {}

    # 5) Velocidad
    kbps = speed_test(session, proxies, bytes_speed, verify_tls, timeouts)

    return {
        "line": line,
        "proxy_uri": proxy_uri,
        "ok": True,
        "exit_ip": exit_ip,
        "latency_https_ms": latency_https,
        "http_ok": bool(http_ok),
        "latency_http_ms": latency_http if http_ok else None,
        "anonymity": anonymity,
        "speed_kbps": kbps,
        **({"geo": geo} if geo else {}),
    }

def get_direct_ip(session, https_urls, timeouts, verify_tls, retries, backoff_base, user_agents):
    for url in https_urls:
        try:
            r, _ = request_with_retries(session, url,
                                        timeouts=timeouts, verify=verify_tls,
                                        retries=retries, backoff_base=backoff_base,
                                        user_agents=user_agents)
            if r.ok and r.text:
                return r.text.strip().split()[0]
        except Exception:
            continue
    return None

# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} — {OWNER}",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--input", help="Ruta del archivo de proxys (uno por línea).")
    parser.add_argument("--proto", default="auto", choices=["auto", "http", "https", "socks4", "socks5", "socks5h"],
        help="Protocolo base si la línea no trae esquema.")
    parser.add_argument("-c", "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrencia (hilos).")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Reintentos por URL.")
    parser.add_argument("--connect-timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT, help="Timeout de conexión.")
    parser.add_argument("--read-timeout", type=int, default=DEFAULT_READ_TIMEOUT, help="Timeout de lectura.")
    parser.add_argument("--insecure", action="store_true", help="No verificar TLS (verify=False).")
    parser.add_argument("--geo", action="store_true", help="Hacer GeoIP (más lento).")
    parser.add_argument("--speed-bytes", type=int, default=DEFAULT_SPEED_BYTES, help="Bytes para test de velocidad.")
    parser.add_argument("--save-prefix", default=f"dendro_proxys_{nowstamp()}", help="Prefijo de archivos de salida.")
    parser.add_argument("--no-json", action="store_true", help="No guardar JSON.")
    parser.add_argument("--no-csv", action="store_true", help="No guardar CSV.")
    parser.add_argument("--only-alive", action="store_true", help="Imprimir solo vivos mientras corre.")
    args = parser.parse_args()

    # Banner + branding
    banner(show_name=True, show_mode=True)  # ahora verás "DENDRO Proxy Auditor — \"Matrix mode\""
    print_info(f"Propiedad: {OWNER}")
    print_info(f"Inicio: {time.ctime()}")


    base_proto = args.proto
    concurrency = max(1, args.concurrency)
    retries = max(0, args.retries)
    timeouts = (args.connect_timeout, args.read_timeout)
    verify_tls = not args.insecure
    do_geo = bool(args.geo)
    bytes_speed = max(32 * 1024, args.speed_bytes)
    save_prefix = args.save_prefix

    # Entrada (interactivo si no se pasa -i)
    if not args.input:
        print(f"{BULLET} {BOLD}Modo interactivo{RESET}")
        print(f"{ORANGE}[x] http  [y] socks4  [z] socks5h  [w] https  [a] auto{RESET}")
        proto_in = input('Tipo ->: ').strip().lower()
        mapping = {'x': 'http', 'y': 'socks4', 'z': 'socks5h', 'w': 'https', 'a': 'auto'}
        base_proto = mapping.get(proto_in, base_proto)
        ruta = input('Ruta del archivo (ubicacion dentro del dispositivo)->: ').strip()
        nombre = input('Nombre del archivo ->: ').strip()
        path = os.path.join(ruta, nombre)
    else:
        path = args.input

    # Leer entradas
    with open(path, encoding='utf-8', errors='ignore') as f:
        raw = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith('#')]
    lines = list(dict.fromkeys(raw))
    total = len(lines)
    if total == 0:
        print_err("No hay líneas válidas en el archivo.")
        return

    # Sesión
    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})

    # IP directa
    print_info("Obteniendo IP directa para evaluar anonimato…")
    direct_ip = get_direct_ip(session,
                              DEFAULT_HTTPS_TEST_URLS,
                              timeouts,
                              verify_tls,
                              retries,
                              DEFAULT_BACKOFF_BASE,
                              USER_AGENTS)
    if direct_ip:
        print_ok(f"IP directa: {BOLD}{direct_ip}{RESET}")
    else:
        print_warn("No se pudo obtener IP directa. La clasificación será aproximada.")

    http_urls = DEFAULT_HTTP_TEST_URLS
    https_urls = DEFAULT_HTTPS_TEST_URLS

    vivos, muertos = [], []
    print_info(f"Cargando {total} proxies… Comprobando…\n")

    processed = 0
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = {
                ex.submit(
                    check_proxy,
                    line,
                    base_proto,
                    http_urls,
                    https_urls,
                    do_geo,
                    bytes_speed,
                    session,
                    direct_ip,
                    timeouts,
                    verify_tls,
                    retries,
                    DEFAULT_BACKOFF_BASE,
                    USER_AGENTS
                ): line
                for line in lines
            }
            for fut in as_completed(futures):
                res = fut.result()
                processed += 1
                if res.get("ok"):
                    vivos.append(res)
                    if args.only_alive:
                        sp = f", {res['speed_kbps']} kbps" if res.get("speed_kbps") else ""
                        print(f"{ORANGE}[VIVO]{RESET} [{processed}/{total}] {sanitize(res['line'])} "
                              f"→ {BOLD}{res['exit_ip']}{RESET} "
                              f"({res['latency_https_ms']} ms, {res['anonymity']}{sp})")
                else:
                    muertos.append(res["line"])
                    if not args.only_alive:
                        print(f"{ORANGE}[MUERTO]{RESET} [{processed}/{total}] {sanitize(res['line'])} "
                              f"→ {res.get('error','error')}")
    except KeyboardInterrupt:
        print_warn("Interrumpido por el usuario.")

    # Ordenar vivos por latencia y velocidad
    if vivos:
        vivos.sort(key=lambda x: (x["latency_https_ms"] or 1e9, -(x["speed_kbps"] or 0)))

    # Guardar resultados (con cabeceras de propiedad)
    stamp = nowstamp()
    alive_txt = f"{save_prefix}_vivos.txt"
    dead_txt  = f"{save_prefix}_muertos.txt"
    alive_csv = f"{save_prefix}_vivos.csv"
    alive_json = f"{save_prefix}_vivos.json"

    if vivos:
        with open(alive_txt, "w", encoding="utf-8") as f:
            f.write(f"# {TOOL_NAME} — Propiedad: {OWNER} — {stamp}\n")
            for it in vivos:
                f.write(it["line"] + "\n")

        if not args.no_csv:
            with open(alive_csv, "w", newline="", encoding="utf-8") as f:
                f.write(f"# {TOOL_NAME} — Propiedad: {OWNER} — {stamp}\n")
                w = csv.writer(f)
                cols = ["proxy", "proto_uri", "exit_ip", "latency_https_ms", "http_ok", "latency_http_ms",
                        "anonymity", "speed_kbps", "country", "region", "city", "isp"]
                w.writerow(cols)
                for it in vivos:
                    geo = it.get("geo", {})
                    w.writerow([
                        it["line"], it["proxy_uri"], it["exit_ip"], it["latency_https_ms"],
                        it["http_ok"], it.get("latency_http_ms"),
                        it["anonymity"], it.get("speed_kbps"),
                        geo.get("country",""), geo.get("region",""), geo.get("city",""), geo.get("isp",""),
                    ])

        if not args.no_json:
            meta = {
                "generated_by": TOOL_NAME,
                "owner": OWNER,
                "timestamp": stamp,
                "slogan": SLOGAN,
                "total_input": total,
                "total_alive": len(vivos),
            }
            with open(alive_json, "w", encoding="utf-8") as f:
                json.dump({"meta": meta, "results": vivos}, f, ensure_ascii=False, indent=2)

    if muertos:
        with open(dead_txt, "w", encoding="utf-8") as f:
            f.write(f"# {TOOL_NAME} — Propiedad: {OWNER} — {stamp}\n")
            for line in muertos:
                f.write(line + "\n")

    # Resumen con marco en naranja
    border_top = f"{ORANGE}{BOLD}╔" + "═"*54 + "╗" + RESET
    border_mid = f"{ORANGE}{BOLD}╠" + "═"*54 + "╣" + RESET
    border_bot = f"{ORANGE}{BOLD}╚" + "═"*54 + "╝" + RESET
    print("\n" + border_top)
    print(f"{ORANGE}{BOLD}║{RESET}  {BOLD}RESUMEN{RESET}".ljust(55) + f"{ORANGE}{BOLD}║{RESET}")
    print(border_mid)
    line_counts = f"  Entradas: {total:<5}  Vivos: {len(vivos):<5}  Muertos: {len(muertos):<5}     "
    print(f"{ORANGE}{BOLD}║{RESET}" + line_counts.ljust(55) + f"{ORANGE}{BOLD}║{RESET}")
    print(border_bot + "\n")

    if vivos:
        print(f"{BOLD}TOP 10 (latencia/velocidad){RESET}")
        for it in vivos[:10]:
            sp = f", {it['speed_kbps']} kbps" if it.get("speed_kbps") else ""
            print(f"{CHECK} {sanitize(it['line'])} → {BOLD}{it['exit_ip']}{RESET} "
                  f"({it['latency_https_ms']} ms, {it['anonymity']}{sp})")

        print(f"\n{ORANGE}Guardados en:{RESET}")
        print(f"  • {alive_txt}")
        if vivos and not args.no_csv:  print(f"  • {alive_csv}")
        if vivos and not args.no_json: print(f"  • {alive_json}")
        if muertos:                    print(f"  • {dead_txt}")
    else:
        print_warn("No se encontró ningún proxy vivo.")

    print_info("Fin.\n")

if __name__ == "__main__":
    main()
