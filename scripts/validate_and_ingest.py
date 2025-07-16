import os
import csv
import json 
import uuid
import time
import logging
from datetime import datetime
import sqlite3
import pandas as pd
from dateutil import parser as dtparser

from logger import setup_logger

# Init Logging
setup_logger()
log = logging.getLogger()

# Configuration
FEEDS_JSON_PATH = 'config/feeds.json'
VALIDATED_DIR = 'feeds/validated_data_files'
DB_PATH = 'db/threat_intel.db'

# Load Patterns 
INDICATOR_PATTERNS = {
    "ipv4": "^(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]?\\d)){3}$",
    "domain": "^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}$",
    "url": "^(https?:\\/\\/)([\\w.-]+)(:[0-9]{1,5})?(\\/[^\\s]*)?$",
    "sha1": "^[a-fA-F0-9]{40}$",
    "sha256": "^[a-fA-F0-9]{64}$",
    "md5": "^[a-fA-F0-9]{32}$"
}

# LOAD FEED.JSON METADATA
def load_feeds_metadata():
    # If FEEDS.JSON doesnt exit, create itt
    if not os.path.exists(FEEDS_JSON_PATH):
        log.warning("feeds.json does not exist. Creating now...")
        return []
    # Open FEEDS.JSON and read from it
    with open(FEEDS_JSON_PATH, 'r') as f:
        return json.load(f)
    
# SAVE TO FEEDS.JSON METADATA
def save_feeds_metadata(data):
    with open(FEEDS_JSON_PATH, 'w') as f:
        json.dump(data, f, indent=4)

# DETECT IOC TYPE
def detect_type(value):
    import re 
    for ioc_type, pattern in INDICATOR_PATTERNS.items():
        if re.match(pattern, value):
            return ioc_type
    return None

# CHECK: FEED ALREADY INGESTED 
def is_already_ingested(feeds, filename):
    return any(feed["name"] == filename for feed in feeds)

# GET FEED BY NAME
def get_feed_by_name(feeds, filename):
    return next((f for f in feeds if f["name"] == filename), None)

# WRITE VALIDATED CSV
def write_validated_csv(valid_rows, validated_path):
    # Create Validated CSV file
    os.makedirs(os.path.dirname(validated_path), exist_ok=True)
    # Append to a file
    with open(validated_path, 'a', newline='') as f:
        writer = csv.writer(f)
        for row in valid_rows:
            writer.writerow(row)

# Update FEEDS.JSON file
def update_feeds_json(feeds, source, validated_path, ioc_count):
    # Get current time, and check if the feed exists
    now = datetime.now().isoformat()
    existing = get_feed_by_name(feeds, source)

    if existing:
        log.info(f"Updaing metadata for existing feed: {source}")
        existing['ioc_count'] += ioc_count
        existing['last_updated'] = now 
    else:
        log.info(f"Adding new feed to feeds.json: {source}")
        feeds.append({
            "uuid": str(uuid.uuid4()),
            "name": source,
            "path": validated_path,
            "source": source,
            "validated_at": now,
            "ioc_count": ioc_count,
            "last_updated": now
        })
    save_feeds_metadata(feeds)

# INGEST DATA INTO DATABASE
def ingest_into_db(valid_rows, source_name):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Grab the SOURCE ID, insert into SOURCE table
    source_id = str(uuid.uuid4())
    cur.execute("INSERT OR IGNORE INTO source (id, name, url, ingest_type) VALUES (?, ?, ?, ?)",
                (source_id, source_name, source_name, 'csv'))
    
    # Iterate through ingested IOCs and add them to ioc Table
    ingested_count = 0
    for value, ioc_type in valid_rows:
        # Generate IOC ID and current time
        ioc_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        try:
            cur.execute("SELECT COUNT(*) FROM ioc WHERE value = ?", (value,))
            if cur.fetchone()[0] == 0:
                cur.execute('''
                    INSERT INTO ioc (id, value, type, first_seen, created_at, source_id)
                    VALUES (?, ?, ?, ?, ?, ?)            
                ''', (ioc_id, value, ioc_type, now, now, source_id))
                ingested_count += 1
        except Exception as e:
            log.error(f"Failed to inserte {value}: {e}")
            continue

    # Update the feed_ingestion_log database table
    cur.execute('''
        INSERT INTO feed_ingestion_log (source_id, filename, total_iocs, ingested_at, status, message)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (source_id, source_name, ingested_count, datetime.now().isoformat(), 'success', 'CSV ingestion'))

    conn.commit()
    conn.close()

    log.info(f"[DB] Ingested {ingested_count} new indicators into SQLite")
    return ingested_count

# Validate and Process CSV
def validate_and_process_file(filepath):
    log.info(f"Processing file: {filepath}")
    time.sleep(0.5)

    # Get filename from os.path, and load feed.json metadata file
    filename = os.path.basename(filepath)
    feeds = load_feeds_metadata()

    # Get validated file path from os.path, and set the seen indicators
    validated_path = os.path.join(VALIDATED_DIR, filename)
    seen_indicators = set()

    # If the Validated CSV was seen, compare for new indicators
    if os.path.exists(validated_path):
        log.info(f"'{validated_path}' metadata already within feeds.json. Comapring for new indicators...")
        time.sleep(1)
        with open(validated_path, 'r')as vf:
            seen_indicators = set([row[0] for row in csv.reader(vf)])
    
    # Initialize variables to count indicator information
    valid_rows = []
    discarded = 0
    added = 0

    with open(filepath, 'r') as f:
        reader = csv.reader(f)

        # Iterate through rows
        for row in reader:
            value = row[0].strip()
            # Auto-detect IOC type
            ioc_type = detect_type(value)

            if not ioc_type:
                log.warning(f"[WARN] Discarded: {value} | Reason: Invalid Type Match")
                discarded += 1
                continue
                
            if value in seen_indicators:
                log.warning(f"[WARN] Discarded: {value} | Reason: Duplicate")
                discarded += 1
                continue

            valid_rows.append((value, ioc_type))
            seen_indicators.add(value)
            added += 1

    if not valid_rows:
        log.info("[INFO] No new indicators to process. Exiting")
        return
    
    # Write Validated CSV, Updated Feeds metadata, ingest into DB
    write_validated_csv(valid_rows, validated_path)
    update_feeds_json(feeds, filename, validated_path, len(valid_rows))
    ingest_into_db(valid_rows, filename)

    log.info(f"[SUCCESS] Completed: {added} added, {discarded} discarded.\n")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate and Ingest IOC Feed")
    parser.add_argument('--input', required=True, help='Path to raw data file')
    args = parser.parse_args()

    validate_and_process_file(args.input)