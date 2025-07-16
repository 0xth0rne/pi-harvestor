# Threat Feed Ingestor

## Overview

hreat Feed Ingestor is an automated IOC validation and enrichment pipeline tailored for embedded systems like the Raspberry Pi. It ingests threat intelligence feeds in various formats, validates and normalizes the indicators, stores enriched context, and provides a structured SQLite3 backend with a web dashboard for browsing and analysis.

## Features

- Auto-detects indicator types (IP, domain, URL, hash, etc.)
- Deduplicates indicators and logs invalid entries
- Validates IOC format via regex patterns
- Tracks metadata and enrichment (GeoIP, ASN, Abuse Score, Reverse DNS)
- Persists feeds in a structured `feeds.json` registry
- Supports enrichment and correlation with campaigns, tags, and threat actors
- Stores all IOCs and metadata in a normalized SQLite3 schema
- Includes ingestion audit trails for traceability

## Workflow Summary

1. User provides a raw IOC file
2. System checks if file was already processed (`feeds.json`)
3. If new or updated:
   - Validates each IOC and detects its type
   - Logs invalid entries
   - Appends new valid IOCs to the corresponding validated CSV
   - Updates the metadata in `feeds.json`
4. Validated IOCs are ingested into the SQLite3 database with enrichment
5. Feed ingestion activity is logged

Refer to `docs/` for full flowchart of the ingestion pipeline.

## Database Schema (SQLite3)

| Table              | Purpose                                            |
| ------------------ | -------------------------------------------------- |
| `ioc`              | Stores core normalized indicators                  |
| `ioc_metadata`     | Stores enriched contextual data per indicator      |
| `source`           | Threat feed metadata and config                    |
| `campaign`         | Campaign tracking metadata                         |
| `ioc_campaign`     | Links IOCs to campaigns (many-to-many)            |
| `tag`              | IOC classification tags                            |
| `ioc_tag`          | Links IOCs to tags (many-to-many)                 |
| `threat_actor`     | Adversary or group profiles                        |
| `ioc_actor`        | Links IOCs to threat actors                        |
| `ioc_history`      | Tracks updates or changes to IOC records           |
| `feed_ingestion_log` | Tracks ingestion events and results               |

### feeds.json Format

Each validated feed is registered with metadata:

```json
{
  "uuid": "9e6a7c24-80f4-4c62-a8ff-17c9b44e5a9c",
  "name": "test.csv",
  "path": "feeds/validated_data_files/test.csv",
  "source": "test.csv",
  "validated_at": "2025-07-15T10:45:34.114916",
  "ioc_count": 5,
  "last_updated": "2025-07-15T10:47:23.187490"
}
```

### Directory Structure
```
pitw-threatfeed/
├── config/                  # Regex patterns and source configs
├── feeds/                  # Raw and validated IOC CSV files
│   └── validated_data_files/
├── db/                      # SQLite3 database
├── scripts/                 # Validation and ingestion logic
├── logs/                    # Verbose logging output
├── dashboard/               # Flask UI (optional)
└── feeds.json               # Feed registry metadata
```

### Usage
```
python3 scripts/validate.py --input feeds/raw/test.csv
python3 scripts/ingest.py --input feeds/validated_data_files/test.csv
```

### Requirements
- Python 3.10+
- SQLite3


### Notes

- All enrichment is currently offline/local or deferred to manual execution
- API-based feeds or enrichments should be rate-limited and secured
- Data should be sanitized prior to ingesting into production databases