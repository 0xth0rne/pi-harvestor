import sqlite3
import requests
import socket
import json 
import time 
import logging 
import os
from dotenv import load_dotenv
from logger import setup_logger

load_dotenv()
setup_logger()
log = logging.getLogger()
DB_PATH = "db/threat_intel.db"

# API
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", None)
ENRICH_IP = os.getenv("ENABLE_ENRICHMENT_IPV4", "True") == "True"
ENRICH_DOMAIN = os.getenv("ENABLE_ENRICHMENT_DOMAIN", "False") == "True"
ENRICH_URL = os.getenv("ENABLE_ENRICHMENT_URL", "False") == "True"
USE_ABUSEIPDB = os.getenv("ENABLE_ABUSEIPDB", "False") == "True"

# GET UN-ENRICHED IOCs
def get_unenriched_iocs():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute('''
        SELECT i.id, i.value, i.type
        FROM ioc i
        LEFT JOIN ioc_metadata m ON i.id = m.ioc_id
        WHERE m.ioc_id IS NULL
    ''')
    rows = cur.fetchall()
    conn.close()
    return rows

# ENRICH IOC
def enrich_ip(ioc_id, ip):
    # Initialize variables
    geo = "Unknown"
    asn = "Unknown"
    abuse_score = None
    reverse_dns = None

    # Reverse DNS
    try:
        reverse_dns = socket.gethostbyaddr(ip)[0]
        log.info(f"[RDNS] {ip} -> {reverse_dns}")
    except Exception:
        reverse_dns = "N/A"

    # GeoIP / ASN
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json")
        if r.status_code == 200:
            data = r.json()
            geo = data.get("country_name", "Unknown")
            asn = data.get("org", "Unknown")
        else:
            log.warning(f"[GEO-IP] Failed for {ip}: {r.status_code}")
    except Exception as e:
        log.warning(f"[GEO-IP] Exception: {e}")

    # AbuseIPDB
    if USE_ABUSEIPDB and ABUSEIPDB_API_KEY:
        try:
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            r = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
                headers=headers)
            data = r.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", None)
        except Exception as e:
            log.warning(f"[ABUSEIPDB] Failed for {ip}: {e}")
    else:
        log.info(f"[ABUSEIPDB] Skipped for {ip} (disabled or missing API key)")

    
    # Insert into DB
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        INSERT INTO ioc_metadata (ioc_id, geo, asn, abuse_score, reverse_dns)
        VALUES (?, ?, ?, ?, ?)
    ''', (ioc_id, geo, asn, abuse_score, reverse_dns))
    conn.commit()
    conn.close()

    log.info(f"[ENRICHED] {ip} -> Geo: {geo}, ASN: {asn}, Abuse Score: {abuse_score}")

# Run Enrichment
def run_enrichment():
    unenriched = get_unenriched_iocs()
    if not unenriched:
        log.info("No IOCs to enrich")
        return 

    log.info(f"[+] Found {len(unenriched)} IOCs needing enrichment!")

    for ioc_id, value, ioc_type in unenriched:
        if ioc_type == "ipv4" and ENRICH_IP:
            enrich_ip(ioc_id, value)
        elif ioc_type == "domain" and ENRICH_DOMAIN:
            log.info(f"[SKIP] domain enrichment not implemented yet: {value}")
        elif ioc_type == "url" and ENRICH_URL:
            log.info(f"[SKIP] url enrichment not implemented yet: {value}")
        else:
            log.info(f"[SKIP] {ioc_type} enrichment is disabled or unsupported: {value}")
        time.sleep(1)  # API safety delay

    log.info("[✓] IOC Enrichment Complete")

if __name__ == "__main__":
    run_enrichment()