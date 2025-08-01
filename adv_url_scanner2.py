#!/usr/bin/env python3
import subprocess
import sys

# --- Auto Install Dependencies ---
def install_dependencies():
    required = ["requests", "rich", "aiohttp", "aiodns", "python-whois", "shodan"]
    for pkg in required:
        try:
            __import__(pkg if pkg != "python-whois" else "whois")
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

install_dependencies()

# --- Imports ---
import asyncio
import aiohttp
import argparse
import base64
import json
import sqlite3
import whois
import shodan
import socket
import requests
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# ===== API KEYS =====
VT_API_KEY = "a65b02d5a3a10ac2e5a7912e4e69114f518ec86e9db6912ee1777f881822b37d"
GSB_API_KEY = "AIzaSyBBN2w07Pny_6siTz_QxQ6ZFqaa9Ie-700"
SHODAN_API_KEY = "hbMBwclNmB4Z8vHmgoRNxjkLHoW1a8aY"
HYBRID_API_KEY = "jbvxib449d3283bb9blxg5zseee8ffa82h8edq4odaadd57cpqhbw4hmd38945f8"

VT_URL = "https://www.virustotal.com/api/v3/urls"
GSB_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
HYBRID_SUBMIT = "https://www.hybrid-analysis.com/api/v2/quick-scan/url"
HYBRID_REPORT = "https://www.hybrid-analysis.com/api/v2/report/"
HYBRID_SEARCH = "https://www.hybrid-analysis.com/api/v2/search/terms"
HYBRID_HEADERS = {"api-key": HYBRID_API_KEY, "User-Agent": "Falcon Sandbox"}

DB_FILE = "scan_cache.db"
console = Console()

# --- Database for caching ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS cache (
                   url TEXT PRIMARY KEY, result TEXT)""")
    conn.commit()
    conn.close()

# --- VirusTotal ---
async def scan_virustotal(session, url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    async with session.get(f"{VT_URL}/{url_id}", headers=headers) as resp:
        if resp.status == 200:
            data = await resp.json()
            attrs = data["data"]["attributes"]
            stats = attrs.get("last_analysis_stats", {})
            return {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "vendors": {
                    v: d.get("category") for v, d in attrs.get("last_analysis_results", {}).items()
                },
                "reputation": attrs.get("reputation", "N/A"),
                "tags": attrs.get("tags", []),
                "status": "Malicious" if stats.get("malicious", 0) > 0 else
                          "Suspicious" if stats.get("suspicious", 0) > 0 else "Safe",
            }
        return {"error": f"VirusTotal {resp.status}"}

# --- Google Safe Browsing ---
async def scan_gsb(session, url):
    payload = {
        "client": {"clientId": "multi-api-scanner", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    async with session.post(GSB_URL, json=payload) as resp:
        data = await resp.json()
        return {"matches": data.get("matches", [])}

# --- Shodan with fallback ---
def scan_shodan(domain):
    try:
        ip = socket.gethostbyname(domain)
        api = shodan.Shodan(SHODAN_API_KEY)
        info = api.host(ip)
        return {
            "ip": info.get("ip_str"),
            "org": info.get("org"),
            "os": info.get("os"),
            "ports": info.get("ports", []),
        }
    except shodan.APIError as e:
        if "403" in str(e):
            # Fallback to InternetDB
            try:
                ip = socket.gethostbyname(domain)
                resp = requests.get(f"https://internetdb.shodan.io/{ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "ip": data.get("ip"),
                        "org": "Limited data (InternetDB)",
                        "ports": data.get("ports", []),
                    }
                else:
                    return {"error": f"InternetDB {resp.status_code}"}
            except Exception as ex:
                return {"error": str(ex)}
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}

# --- Hybrid Analysis with fallback ---
async def scan_hybrid(session, url):
    data = {"url": url, "scan_type": "all"}
    async with session.post(HYBRID_SUBMIT, headers=HYBRID_HEADERS, data=data) as resp:
        if resp.status == 200:
            j = await resp.json()
            job_id = j.get("job_id")
            if not job_id:
                # fallback to static search
                async with session.post(HYBRID_SEARCH, headers=HYBRID_HEADERS, data={"term": url}) as search_resp:
                    if search_resp.status == 200:
                        result = await search_resp.json()
                        if result:
                            first = result[0]
                            return {
                                "job_id": "N/A",
                                "threat_score": first.get("threat_score"),
                                "verdict": first.get("verdict"),
                                "tags": first.get("tags", []),
                                "note": "Static search result (limited access)"
                            }
                        else:
                            return {"error": "No static results found"}
                    return {"error": f"Hybrid static {search_resp.status}"}
            # Poll for report
            for _ in range(10):
                await asyncio.sleep(5)
                async with session.get(HYBRID_REPORT + job_id, headers=HYBRID_HEADERS) as report_resp:
                    if report_resp.status == 200:
                        report = await report_resp.json()
                        if report.get("status") == "completed":
                            return {
                                "job_id": job_id,
                                "threat_score": report.get("threat_score"),
                                "verdict": report.get("verdict"),
                                "tags": report.get("tags", []),
                            }
            return {"error": "Hybrid Analysis report not ready"}
        return {"error": f"Hybrid {resp.status}"}

# --- WHOIS ---
def whois_info(domain):
    try:
        w = whois.whois(domain)
        return {"registrar": str(w.registrar), "created": str(w.creation_date)}
    except:
        return {"registrar": "N/A", "created": "N/A"}

# --- Display results ---
def display_results(url, vt, gsb, sh, hyb, who):
    table = Table(title="Multi-Source URL Security Report", style="cyan")
    table.add_column("Source")
    table.add_column("Status/Score")
    table.add_column("Details")

    table.add_row("VirusTotal", vt.get("status", "N/A"),
                  f"Malicious: {vt.get('malicious', 0)}, Suspicious: {vt.get('suspicious', 0)}")
    table.add_row("Google Safe Browsing",
                  "Threats" if gsb["matches"] else "Clean",
                  json.dumps(gsb["matches"], indent=1) if gsb["matches"] else "-")
    table.add_row("Shodan", sh.get("org", "N/A"),
                  f"IP: {sh.get('ip', '-')}, Ports: {sh.get('ports', '-')}" if "error" not in sh else sh["error"])
    table.add_row("Hybrid Analysis",
                  hyb.get("verdict", "N/A"),
                  f"Score: {hyb.get('threat_score', '-')}, Tags: {', '.join(hyb.get('tags', []))}" +
                  (f" | Note: {hyb.get('note')}" if "note" in hyb else "") if "error" not in hyb else hyb["error"])
    table.add_row("WHOIS", "-", f"Registrar: {who['registrar']}, Created: {who['created']}")
    console.print(Panel(table, border_style="bright_blue"))

    vt_vendors = "\n".join([f"{vendor}: {status}" for vendor, status in vt.get("vendors", {}).items()])
    console.print(Panel(vt_vendors or "No detections", title="VirusTotal Vendor Detections", border_style="bright_yellow"))

    final_report = f"""
🔍 URL: {url}

VirusTotal: {vt.get("status", "N/A")} (Malicious: {vt.get("malicious", 0)}, Suspicious: {vt.get("suspicious", 0)})
Google Safe Browsing: {"Threats found" if gsb["matches"] else "Clean"}
Shodan: {sh if "error" in sh else f"IP {sh.get('ip')}, Org: {sh.get('org')}, Ports: {sh.get('ports', [])}"}
Hybrid Analysis: Verdict={hyb.get('verdict', 'N/A')}, Threat Score={hyb.get('threat_score', 'N/A')}
WHOIS: Registrar={who['registrar']}, Created={who['created']}

Tags:
VT: {', '.join(vt.get('tags', []))}
Hybrid: {', '.join(hyb.get('tags', []))}
    """
    console.print(Panel(final_report, title="Final Processed Report", border_style="green"))

# --- Main ---
async def main(urls):
    async with aiohttp.ClientSession() as session:
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.hostname or url

            vt_task = scan_virustotal(session, url)
            gsb_task = scan_gsb(session, url)
            hyb_task = scan_hybrid(session, url)

            vt, gsb, hyb = await asyncio.gather(vt_task, gsb_task, hyb_task)
            sh = scan_shodan(domain)
            who = whois_info(domain)

            display_results(url, vt, gsb, sh, hyb, who)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-API Advanced URL Scanner")
    parser.add_argument("urls", nargs="+", help="URLs to scan (space separated)")
    args = parser.parse_args()

    init_db()
    asyncio.run(main(args.urls))
