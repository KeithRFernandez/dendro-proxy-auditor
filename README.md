# DENDRO Proxy Auditor

**Autor:** DENDRO – Keith Fernández  
**Propiedad:** DENDRO | Intelligence  
**Eslogan:** *“Transformamos datos en decisiones.”*

---

## ¿Qué es?
**DENDRO Proxy Auditor** es una herramienta de verificación masiva de proxys. En minutos identifica cuáles están **vivos**, qué **latencia** y **velocidad** tienen, su **nivel de anonimato** y desde **qué país/ISP** salen a Internet.

Ideal para **scraping**, **automatización**, **QA/Infra**, **seguridad** y cualquier flujo que dependa de proxys confiables.

---

## ¿Por qué usarlo?
- **Ahorra tiempo/dinero:** elimina proxys caídos y lentos.
- **Rendimiento superior:** prioriza por latencia y velocidad.
- **Control de anonimato:** *transparente* / *anónimo* / *elite*.
- **Contexto geográfico:** país/ciudad/ISP opcionales.
- **Salidas listas para integrar:** TXT/CSV/JSON con metadatos.

---

## Funcionalidades
1. **Chequeo HTTPS y HTTP** (CONNECT) por proxy.  
2. **IP de salida**: la huella pública real a través del proxy.  
3. **Latencia** por petición (ms).  
4. **Clasificación de anonimato** (encabezados estándar).  
5. **Velocidad** (KB/s) descargando N bytes.  
6. **GeoIP opcional** (país/ciudad/ISP).  
7. **TOP 10** por latencia/velocidad.  
8. **Exportaciones**: `*_vivos.txt`, `*_muertos.txt`, `*_vivos.csv`, `*_vivos.json`.

---

## Instalación
Requisitos opcionales (recomendados):
```bash
pip install "requests[socks]"
pip install colorama
```

---

## Formato del archivo de entrada (proxys)
Una línea por proxy. Se aceptan comentarios que empiezan con `#` y líneas en blanco (se ignoran).  
Puedes **mezclar** formatos, con o sin esquema.

### Sin esquema (usa `--proto` o `--proto auto`)
```
IP:PUERTO
usuario:contraseña@HOST:PUERTO
[IPv6]:PUERTO
```
**Ejemplos:**
```
196.1.93.16:80
47.91.115.179:9091
user123:secret@34.23.45.223:8080
[2001:db8:85a3::8a2e:370:7334]:8080
```

### Con esquema (recomendado para listas mixtas)
```
http://IP:PUERTO
https://IP:PUERTO
socks4://IP:PUERTO
socks5://IP:PUERTO         # DNS resuelto por el cliente
socks5h://IP:PUERTO        # DNS resuelto por el proxy (evita fugas)
```
**Ejemplos:**
```
http://196.1.93.16:80
http://user:pass@93.127.215.97:3128
https://141.147.9.254:443
socks5h://user:pwd@[2001:db8::10]:9050
```

> Si no pones esquema, `--proto auto` intentará adivinar por el puerto: `1080` → SOCKS, `80/3128/8080` → HTTP.

---

## Uso rápido

**Modo interactivo**
```bash
python dendro_proxy_auditor.py
```

**Archivo con mezcla de tipos (auto)**
```bash
python dendro_proxy_auditor.py -i proxies.txt --proto auto --only-alive
```

**GeoIP + velocidad 512 KB + concurrencia alta**
```bash
python dendro_proxy_auditor.py -i proxies.txt --geo --speed-bytes 524288 -c 200
```

**TLS sin verificar (cert no estándar)**
```bash
python dendro_proxy_auditor.py -i proxies.txt --insecure
```

**Solo TXT (sin CSV/JSON)**
```bash
python dendro_proxy_auditor.py -i proxies.txt --no-csv --no-json
```

---

## Principales flags
- `-i, --input` Ruta del archivo con proxys.
- `--proto {auto,http,https,socks4,socks5,socks5h}` Protocolo base si no hay esquema.
- `-c, --concurrency` Hilos en paralelo (p. ej. 100–300).
- `--retries` Reintentos por URL.
- `--connect-timeout`, `--read-timeout` Timeouts.
- `--insecure` No verificar TLS (`verify=False`).
- `--geo` Obtener país/ciudad/ISP (más lento).
- `--speed-bytes` Bytes a descargar para medir velocidad.
- `--save-prefix` Prefijo de archivos de salida.
- `--no-json`, `--no-csv` Desactivar formatos.
- `--only-alive` Mostrar solo proxys funcionales en tiempo real.

---

## Salida
Se generan archivos con prefijo (por defecto `dendro_proxys_<YYYYMMDD-HHMMSS>`):

- `*_vivos.txt` → Solo proxys funcionales.
- `*_muertos.txt` → Proxys fallidos.
- `*_vivos.csv` → Datos tabulares (IP de salida, latencias, anonimato, velocidad, GeoIP).
- `*_vivos.json` → Estructura completa + bloque `meta`.

---

## Ejemplo del banner (CLI)
```text
██████╗    ███████╗   ███╗   ██╗  ██████╗    ██████╗     ██████╗ 
██╔══██╗   ██╔════╝   ████╗  ██║  ██╔══██╗   ██╔══██╗   ██╔═══██╗
██║  ██║   █████╗     ██╔██╗ ██║  ██║  ██║   ██████╔╝   ██║   ██║
██║  ██║   ██╔══╝     ██║╚██╗██║  ██║  ██║   ██╔══██╗   ██║   ██║
██║  ██║   ███████╗   ██║ ╚████║  ██║  ██║   ██║  ██║   ╚██████╔╝
██████╔╝   ╚══════╝   ╚═╝  ╚═══╝  ██████╔╝   ╚═╝  ╚═╝    ╚═════╝ 
```

---

## Legal / Ética
Usa proxys de manera responsable, respetando **leyes locales**, **términos de servicio** y **robots** de los sitios. No emplees la herramienta para actividades no autorizadas.

---

## Créditos
DENDRO – Keith Fernández • Dendro | Intelligence — *“Transformamos datos en decisiones.”*
