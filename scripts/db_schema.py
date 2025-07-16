import sqlite3
import uuid

def init_db():
    conn = sqlite3.connect('db/threat_intel.db')
    cur = conn.cursor()

    # IOC Table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc (
            id TEXT PRIMARY KEY,
            value TEXT,
            type TEXT,
            first_seen DATETIME,
            last_seen DATETIME,
            source_id TEXT,
            context TEXT,
            created_at DATETIME
        )         
    ''')

    # IOC Metadata
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc_metadata (
            ioc_id TEXT,
            geo TEXT,
            asn TEXT,
            abuse_score INTEGER, 
            whois TEXT,
            reverse_dns TEXT,
            extra TEXT
        )         
    ''')

    # Source
    cur.execute('''
        CREATE TABLE IF NOT EXISTS source (
            id TEXT PRIMARY KEY,
            name TEXT,
            url TEXT,
            api_key TEXT,
            requires_auth BOOLEAN,
            ingest_type TEXT
        )         
    ''')

    # Campaign
    cur.execute('''
        CREATE TABLE IF NOT EXISTS campaign (
            id TEXt PRIMARY KEY,
            name TEXT,
            url TEXT,
            api_key TEXT,
            requires_auth BOOLEAN,
            ingest_type TEXT
        )         
    ''')

    # IOC Campaign
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc_campaign (
            ioc_id TEXT,
            campaign_id TEXT
        )         
    ''')

    # Tag
    cur.execute('''
        CREATE TABLE IF NOT EXISTS tag (
            id TEXT PRIMARY KEY,
            name TEXT
        )         
    ''')

    # IOC Tag
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc_tag (
            ioc_id TEXT,
            tag_id TEXT
        )         
    ''')

    # Threat Actor
    cur.execute('''
        CREATE TABLE IF NOT EXISTS threat_actor (
            id TEXT PRIMARY KEY,
            name TEXT,
            aliases TEXT,
            description TEXT
        )         
    ''')

    # IOC Actor
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc_actor (
            ioc_id TEXT,
            actor_id TEXT
        )         
    ''')

    # IOC History
    cur.execute('''
        CREATE TABLE IF NOT EXISTS ioc_history (
            id TEXT PRIMARY KEY,
            ioc_id TEXT,
            field_changed TEXT,
            old_value TEXT,
            new_value TEXT,
            changed_at DATETIME
        )         
    ''')

    # Feed Ingestion Log
    cur.execute('''
        CREATE TABLE IF NOT EXISTS feed_ingestion_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id TEXT,
            filename TEXT,
            total_iocs INTEGER,
            ingested_at DATETIME,
            status TEXT,
            message TEXT
        )         
    ''')

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    