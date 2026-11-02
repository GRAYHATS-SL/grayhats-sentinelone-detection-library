#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
c2c_beaconing_analyzer.py — Análisis de beaconing C2 por regularidad de intervalos (jitter).

GrayHats Detection Team — herramienta de apoyo DFIR.

Qué hace
--------
Toma una exportación de eventos de conexión de red (uno por conexión, NO agregados)
y, para cada tupla (endpoint, proceso, IP destino, puerto), calcula la regularidad
temporal de las conexiones. Un beacon C2 se delata por una desviación muy baja en
los intervalos (coeficiente de variación bajo); el tráfico humano o el polling
irregular tienen desviación alta. El polling legítimo (svchost, updaters...) es
regular pero se descarta por reputación/proceso, no por regularidad.

Métrica principal: CV = desviación_estándar(intervalos) / media(intervalos).
    CV < 0.05  -> beacon casi perfecto (sin jitter)
    CV < 0.20  -> beacon probable (jitter típico de Cobalt Strike/Sliver)
    CV > 0.50  -> irregular, probablemente benigno

Entrada
-------
CSV o JSON con una fila por evento IP Connect. Columnas esperadas (nombres por
defecto, configurables con --col-*):
    - Endpoint Name        (endpoint.name)
    - Source Process Name  (src.process.name)
    - Destination IP       (dst.ip.address)
    - Destination Port     (dst.port.number)
    - event.time           (epoch en ms o s, o fecha ISO)

PowerQuery para generar la exportación RAW (sin | group), luego exportar a CSV:
    event.type = 'IP Connect' and event.network.direction = 'OUTGOING'
    | columns event.time, endpoint.name, src.process.name, dst.ip.address, dst.port.number
    | sort event.time

Uso
---
    python c2c_beaconing_analyzer.py --input eventos.csv
    python c2c_beaconing_analyzer.py --input eventos.json --min-conn 15 --cv-max 0.25
    python c2c_beaconing_analyzer.py --demo            # genera datos de ejemplo y corre
    python c2c_beaconing_analyzer.py --input e.csv --plot-top 5 --outdir ./resultados

Requisitos: pandas, numpy, matplotlib
"""

import argparse
import ipaddress
import os
import sys
from datetime import datetime

import numpy as np
import pandas as pd

# matplotlib sin display (entornos headless / servidores)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


# ---------------------------------------------------------------------------
# Configuración por defecto
# ---------------------------------------------------------------------------

# Procesos-servicio que hacen polling legítimo con frecuencia. NO se excluyen
# por defecto (un atacante puede suplantar el nombre), pero se marcan para que
# el analista los baje de prioridad. Amplía según el entorno del cliente.
KNOWN_NOISY_PROCESSES = {
    "svchost.exe", "chrome.exe", "msedge.exe", "firefox.exe", "coredns.exe",
    "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "teams.exe",
    "slack.exe", "outlook.exe", "sentinelagent.exe", "sentinelctl.exe",
    "msmpeng.exe", "updater.exe", "googleupdate.exe", "software_reporter_tool.exe",
}

# LOLBins / intérpretes que casi nunca deberían "balizar". Presencia aquí = sube prioridad.
HIGH_RISK_PROCESSES = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
    "msbuild.exe", "installutil.exe", "wmic.exe",
}


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def parse_epoch(series: pd.Series) -> pd.Series:
    """Convierte una columna de tiempo a datetime, tolerando:
    - epoch en milisegundos (>1e12) o segundos (>1e9)
    - strings con separador de miles español ('1.783.693.918.544')
    - fechas ISO ('2026-07-10T14:00:00Z')
    Devuelve una Series de pandas datetime64 (UTC-naive)."""
    # Si ya es numérico, decidir unidad por magnitud
    if pd.api.types.is_numeric_dtype(series):
        vals = series.astype("float64")
    else:
        s = series.astype(str).str.strip()
        # ¿Parece fecha ISO? (contiene '-' y ':' o 'T')
        looks_iso = s.str.contains(r"\d{4}-\d{2}-\d{2}", regex=True, na=False)
        if looks_iso.mean() > 0.5:
            return pd.to_datetime(s, errors="coerce", utc=True).dt.tz_localize(None)
        # Numérico con posibles separadores de miles: quitar puntos y comas de miles.
        # Solo eliminamos '.' si NO hay parte decimal real (epoch es entero).
        cleaned = s.str.replace(".", "", regex=False).str.replace(",", "", regex=False)
        vals = pd.to_numeric(cleaned, errors="coerce")

    # Detectar unidad por magnitud de la mediana
    med = np.nanmedian(vals.values if hasattr(vals, "values") else vals)
    if med > 1e17:      # nanosegundos
        unit = "ns"
    elif med > 1e14:    # microsegundos
        unit = "us"
    elif med > 1e11:    # milisegundos
        unit = "ms"
    elif med > 1e8:     # segundos
        unit = "s"
    else:
        unit = "s"
    return pd.to_datetime(vals, unit=unit, errors="coerce")


def is_internal_ip(ip_str: str) -> bool:
    """True si la IP es privada (RFC1918), loopback, link-local o no válida."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return True  # si no parsea, la tratamos como no-analizable -> fuera
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


def classify(cv: float, n: int, mean_interval_s: float,
             noisy: bool, high_risk: bool) -> tuple:
    """Devuelve (etiqueta, prioridad_0a100, motivo)."""
    reasons = []
    # Regularidad
    if cv < 0.05:
        reg = "muy regular (sin jitter)"
        reg_score = 45
    elif cv < 0.20:
        reg = "regular (jitter bajo)"
        reg_score = 35
    elif cv < 0.50:
        reg = "semi-regular"
        reg_score = 15
    else:
        reg = "irregular"
        reg_score = 0
    reasons.append(f"CV={cv:.3f} ({reg})")

    # Volumen de conexiones -> confianza
    vol_score = min(20, int(n / 5))
    reasons.append(f"{n} conexiones")

    # Intervalo en rango típico de C2 (30s - 1h)
    band_score = 15 if 30 <= mean_interval_s <= 3600 else 0
    if band_score:
        reasons.append(f"intervalo ~{mean_interval_s:.0f}s (rango C2)")

    # Proceso
    proc_score = 0
    if high_risk:
        proc_score = 20
        reasons.append("proceso de alto riesgo (LOLBin/intérprete)")
    if noisy:
        proc_score -= 30
        reasons.append("proceso de polling conocido (probable FP)")

    score = max(0, min(100, reg_score + vol_score + band_score + proc_score))

    if noisy and cv < 0.20:
        label = "BENIGNO PROBABLE (polling)"
    elif cv < 0.20 and score >= 60:
        label = "BEACON PROBABLE"
    elif cv < 0.20:
        label = "SOSPECHOSO"
    elif cv < 0.50:
        label = "REVISAR"
    else:
        label = "BENIGNO PROBABLE"

    return label, score, "; ".join(reasons)


# ---------------------------------------------------------------------------
# Núcleo del análisis
# ---------------------------------------------------------------------------

def analyze(df: pd.DataFrame, cols: dict, min_conn: int) -> pd.DataFrame:
    ep, pr, ip, pt, tm = cols["endpoint"], cols["process"], cols["ip"], cols["port"], cols["time"]

    # Parsear tiempo y ordenar
    df = df.copy()
    df["_ts"] = parse_epoch(df[tm])
    df = df.dropna(subset=["_ts"])
    df = df.sort_values("_ts")

    rows = []
    grouped = df.groupby([ep, pr, ip, pt], dropna=False)
    for (endpoint, process, dst_ip, dst_port), g in grouped:
        n = len(g)
        if n < min_conn:
            continue
        internal = is_internal_ip(dst_ip)

        ts = g["_ts"].values.astype("datetime64[ns]")
        # deltas entre conexiones consecutivas, en segundos
        deltas = np.diff(ts).astype("timedelta64[s]").astype(float)
        deltas = deltas[deltas >= 0]
        if len(deltas) < 2:
            continue

        mean_i = float(np.mean(deltas))
        median_i = float(np.median(deltas))
        std_i = float(np.std(deltas))
        mad_i = float(np.median(np.abs(deltas - median_i)))
        cv = std_i / mean_i if mean_i > 0 else np.inf
        duration_s = float((ts[-1] - ts[0]) / np.timedelta64(1, "s"))

        proc_l = str(process).lower()
        noisy = proc_l in KNOWN_NOISY_PROCESSES
        high_risk = proc_l in HIGH_RISK_PROCESSES

        label, score, reason = classify(cv, n, mean_i, noisy, high_risk)
        # Penalización fuerte para IPs internas (no son C2 externo)
        if internal:
            label = "INTERNO (excluido)"
            score = 0

        rows.append({
            "endpoint": endpoint,
            "proceso": process,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "interna": internal,
            "conexiones": n,
            "duracion_s": round(duration_s, 1),
            "intervalo_medio_s": round(mean_i, 1),
            "intervalo_mediana_s": round(median_i, 1),
            "std_s": round(std_i, 2),
            "mad_s": round(mad_i, 2),
            "cv": round(cv, 4),
            "jitter_pct": round(cv * 100, 1),
            "clasificacion": label,
            "prioridad": score,
            "motivo": reason,
            "_ts": ts,  # para el plot
        })

    if not rows:
        return pd.DataFrame()

    res = pd.DataFrame(rows)
    res = res.sort_values(["prioridad", "cv"], ascending=[False, True]).reset_index(drop=True)
    return res


# ---------------------------------------------------------------------------
# Visualización
# ---------------------------------------------------------------------------

def plot_candidate(row: pd.Series, outpath: str):
    """Genera una figura de 2 paneles: timeline de conexiones + histograma de intervalos."""
    ts = pd.to_datetime(row["_ts"])
    deltas = np.diff(ts.values).astype("timedelta64[s]").astype(float)

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11, 6.5),
                                   gridspec_kw={"height_ratios": [1, 1.4]})

    title = (f'{row["proceso"]}  →  {row["dst_ip"]}:{row["dst_port"]}   '
             f'[{row["endpoint"]}]')
    subtitle = (f'{row["conexiones"]} conexiones · intervalo medio '
                f'{row["intervalo_medio_s"]:.0f}s · CV={row["cv"]:.3f} '
                f'(jitter {row["jitter_pct"]:.1f}%) · {row["clasificacion"]}')
    fig.suptitle(title, fontsize=12, fontweight="bold", y=0.99)
    ax1.set_title(subtitle, fontsize=9.5, color="#444", pad=8)

    # Panel 1: timeline (cada conexión = una marca vertical)
    ax1.vlines(ts, 0, 1, color="#c0392b", alpha=0.7, linewidth=1)
    ax1.set_ylim(0, 1)
    ax1.set_yticks([])
    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax1.set_xlabel("Tiempo (línea temporal de conexiones)", fontsize=9)
    ax1.grid(axis="x", alpha=0.25)

    # Panel 2: histograma de intervalos (un beacon = pico estrecho)
    if len(deltas) > 0:
        bins = min(50, max(10, int(len(deltas) / 3)))
        ax2.hist(deltas, bins=bins, color="#2980b9", alpha=0.8, edgecolor="white")
        ax2.axvline(row["intervalo_medio_s"], color="#e67e22", linestyle="--",
                    linewidth=1.6, label=f'media {row["intervalo_medio_s"]:.0f}s')
        ax2.axvline(row["intervalo_mediana_s"], color="#27ae60", linestyle=":",
                    linewidth=1.6, label=f'mediana {row["intervalo_mediana_s"]:.0f}s')
        ax2.legend(fontsize=8)
    ax2.set_xlabel("Intervalo entre conexiones consecutivas (segundos)", fontsize=9)
    ax2.set_ylabel("Frecuencia", fontsize=9)
    ax2.grid(axis="y", alpha=0.25)

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(outpath, dpi=130, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Datos de demostración
# ---------------------------------------------------------------------------

def make_demo(n_events_scale: int = 1) -> pd.DataFrame:
    """Genera un dataset sintético con un beacon claro, un beacon con jitter,
    polling benigno y ruido irregular. Base epoch en ms (como SentinelOne)."""
    rng = np.random.default_rng(42)
    base = int(datetime(2026, 7, 10, 9, 0, 0).timestamp() * 1000)  # ms
    records = []

    def add(host, proc, ip, port, start_ms, interval_s, count, jitter_frac):
        t = start_ms
        for _ in range(count):
            records.append([host, proc, ip, port, int(t)])
            step = interval_s * 1000 * (1 + rng.normal(0, jitter_frac))
            t += max(1000, step)

    # 1) Beacon casi perfecto (C2) — rundll32, 60s, jitter ínfimo
    add("WS-CORDOBA-07", "rundll32.exe", "185.149.242.236", 443, base, 60, 110, 0.01)
    # 2) Beacon con jitter tipo Cobalt Strike — powershell, 120s, ~15% jitter
    add("WS-CORDOBA-07", "powershell.exe", "89.108.119.28", 8443, base, 120, 60, 0.15)
    # 3) Polling BENIGNO regular — svchost a Microsoft, 300s (debe marcarse benigno)
    add("SRV-DC01", "svchost.exe", "20.190.160.14", 443, base, 300, 24, 0.03)
    # 4) Navegación humana irregular — chrome, muy irregular
    add("WS-USER-11", "chrome.exe", "142.250.185.14", 443, base, 90, 40, 0.9)
    # 5) Tráfico interno (loopback / RFC1918) — debe excluirse
    add("FD011-ETIQUET", "NiceLabelProxy.exe", "127.0.0.1", 1947, base, 125, 56, 0.02)

    df = pd.DataFrame(records, columns=[
        "Endpoint Name", "Source Process Name", "Destination IP",
        "Destination Port", "event.time"])
    return df


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Análisis de beaconing C2 por regularidad de intervalos (jitter).")
    ap.add_argument("--input", help="CSV o JSON con eventos IP Connect (uno por fila).")
    ap.add_argument("--demo", action="store_true",
                    help="Usar datos sintéticos de demostración.")
    ap.add_argument("--min-conn", type=int, default=10,
                    help="Mínimo de conexiones por tupla para analizar (def. 10).")
    ap.add_argument("--cv-max", type=float, default=0.25,
                    help="Umbral de CV para destacar candidatos (def. 0.25).")
    ap.add_argument("--include-internal", action="store_true",
                    help="No excluir IPs internas/loopback (por defecto se excluyen).")
    ap.add_argument("--plot-top", type=int, default=6,
                    help="Nº de candidatos a graficar (def. 6).")
    ap.add_argument("--outdir", default="./beacon_out",
                    help="Directorio de salida (def. ./beacon_out).")
    # Mapeo de columnas
    ap.add_argument("--col-endpoint", default="Endpoint Name")
    ap.add_argument("--col-process", default="Source Process Name")
    ap.add_argument("--col-ip", default="Destination IP")
    ap.add_argument("--col-port", default="Destination Port")
    ap.add_argument("--col-time", default="event.time")
    args = ap.parse_args()

    if not args.input and not args.demo:
        ap.error("Indica --input <fichero> o usa --demo.")

    if args.demo:
        df = make_demo()
        print("[i] Modo demo: dataset sintético generado.")
    else:
        if not os.path.exists(args.input):
            sys.exit(f"[!] No existe el fichero: {args.input}")
        if args.input.lower().endswith(".json"):
            df = pd.read_json(args.input)
        else:
            # sep=None + engine python autodetecta ; o ,
            df = pd.read_csv(args.input, sep=None, engine="python")

    cols = {"endpoint": args.col_endpoint, "process": args.col_process,
            "ip": args.col_ip, "port": args.col_port, "time": args.col_time}

    missing = [c for c in cols.values() if c not in df.columns]
    if missing:
        sys.exit(f"[!] Faltan columnas {missing}. Columnas disponibles: {list(df.columns)}\n"
                 f"    Usa --col-* para mapearlas.")

    res = analyze(df, cols, args.min_conn)
    if res.empty:
        print("[i] Sin tuplas con suficientes conexiones para analizar.")
        return

    if not args.include_internal:
        res = res[~res["interna"]].reset_index(drop=True)

    os.makedirs(args.outdir, exist_ok=True)

    # Tabla de resultados (sin la columna de timestamps cruda)
    table = res.drop(columns=["_ts"])
    csv_path = os.path.join(args.outdir, "beacon_candidatos.csv")
    table.to_csv(csv_path, index=False)

    # Salida por consola
    pd.set_option("display.max_colwidth", 40)
    pd.set_option("display.width", 200)
    show_cols = ["endpoint", "proceso", "dst_ip", "dst_port", "conexiones",
                 "intervalo_medio_s", "cv", "jitter_pct", "clasificacion", "prioridad"]
    print("\n=== Candidatos a beaconing (ordenados por prioridad) ===\n")
    print(table[show_cols].to_string(index=False))
    print(f"\n[i] Tabla completa: {csv_path}")

    # Gráficos de los top N (excluyendo benignos evidentes si hay mejores)
    to_plot = res.head(args.plot_top)
    plotted = []
    for i, (_, row) in enumerate(to_plot.iterrows(), 1):
        safe_ip = str(row["dst_ip"]).replace(":", "_").replace(".", "-")
        fname = f"{i:02d}_{row['proceso']}_{safe_ip}_{row['dst_port']}.png"
        fpath = os.path.join(args.outdir, fname)
        plot_candidate(row, fpath)
        plotted.append(fpath)
    print(f"[i] {len(plotted)} gráficos de periodicidad en: {args.outdir}/")

    # Resumen ejecutivo
    beacons = table[table["clasificacion"].str.contains("BEACON")]
    if not beacons.empty:
        print(f"\n[!] {len(beacons)} candidato(s) clasificado(s) como BEACON PROBABLE:")
        for _, b in beacons.iterrows():
            print(f"    - {b['proceso']} -> {b['dst_ip']}:{b['dst_port']} "
                  f"({b['conexiones']} conex, cada ~{b['intervalo_medio_s']:.0f}s, "
                  f"CV={b['cv']:.3f}) en {b['endpoint']}")
    else:
        print("\n[i] Ningún candidato alcanza el umbral de BEACON PROBABLE.")


if __name__ == "__main__":
    main()