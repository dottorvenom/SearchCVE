import re
import sqlite3
import argparse
import asyncio
import os
from telethon import TelegramClient

api_id = 1234
api_hash = "xxxxxxxxxxxxx"

channel = "cve_mitre_org"
DB = "cve_database.db"

cve_pattern = re.compile(r'CVE-\d{4}-\d+')


product_patterns = [

    re.compile(
        r'identified in\s+(.+?)(?:\s+up to|\s+before|\s+on|\.)',
        re.IGNORECASE
    ),

    re.compile(
        r'found in\s+(.+?)(?:\s+on|\s+and|\.)',
        re.IGNORECASE
    ),

    re.compile(
        r'affects\s+(.+?)(?:\s+before|\s+up to|\.)',
        re.IGNORECASE
    )
]

vuldb_pattern = re.compile(
    r'https://vuldb\.com/\?product\.[^\s)]+',
    re.IGNORECASE
)


def extract_product(text):

    for pattern in product_patterns:

        m = pattern.search(text)

        if m:
            return m.group(1).strip()

    return "Unknown"
    
    
def clean_markdown(text):
    return re.sub(r'\[(.*?)\]\((.*?)\)', r'\1', text)


def classify_os(system, text):

    t = (system + " " + text).lower()

    if "windows" in t:
        return "Windows"

    if any(x in t for x in [
        "linux","ubuntu","debian","redhat","kernel","centos"
    ]):
        return "Linux"

    if any(x in t for x in [
        "android","ios","macos","apple","iphone","ipad"
    ]):
        return "Mobile"

    return "Other"
    
    

def classify_access(text):

    t = text.lower()

    if any(x in t for x in ["remote","rce","network"]):
        return "Remote"

    if any(x in t for x in ["local","privilege escalation"]):
        return "Local"

    return "Unknown"


def init_db():

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cve(
        cve TEXT PRIMARY KEY,
        system TEXT,
        os TEXT,
        access TEXT,
        vuldb TEXT,
        message_id INTEGER,
        link TEXT
    )
    """)

    conn.commit()
    conn.close()


async def update_db():

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT MAX(message_id) FROM cve")
    last_id = cur.fetchone()[0] or 0

    client = TelegramClient("cve_session", api_id, api_hash)

    try:

        async with client:

            async for message in client.iter_messages(channel, min_id=last_id):

                print("Analyzing message:", message.id)

                if not message.text:
                    continue

                raw_text = message.text
                text = clean_markdown(raw_text)

                cve_match = cve_pattern.search(text)

                if not cve_match:
                    continue

                cve = cve_match.group(0)

                vuldb_match = vuldb_pattern.search(raw_text)

                system = extract_product(text)
                vuldb_link = vuldb_match.group(0) if vuldb_match else ""

                os_type = classify_os(system, text)
                
                access = classify_access(text)

                msg_id = message.id
                link = f"https://t.me/{channel}/{msg_id}"

                try:

                    cur.execute(
                        "INSERT INTO cve VALUES (?,?,?,?,?,?,?)",
                        (cve, system, os_type, access, vuldb_link, msg_id, link)
                    )

                    print("Added:", cve)

                except sqlite3.IntegrityError:
                    pass

    except (KeyboardInterrupt, asyncio.CancelledError):

        print("\nExiting...")

    finally:

        conn.commit()
        conn.close()


def query_db(os=None, access=None, cve=None, system=None, year=None):

    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    query = "SELECT * FROM cve WHERE 1=1"
    params = []

    if os:
        query += " AND os=?"
        params.append(os)

    if access:
        query += " AND access=?"
        params.append(access)

    if cve:
        query += " AND cve=?"
        params.append(cve)

    if system:
        query += " AND system LIKE ?"
        params.append(f"%{system}%")
    
    if year:
        query += " AND cve LIKE ?"
        params.append(f"CVE-{year}-%")
    
    rows = cur.execute(query, params).fetchall()

    for row in rows:

        print("\nCVE:", row[0])
        print("System:", row[1])
        print("OS:", row[2])
        print("Access:", row[3])
        print("VulDB:", row[4])
        print("Message ID:", row[5])
        print("Link:", row[6])
        print("-"*60)

    if not rows:
        print("No result")

    conn.close()


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument("--update", action="store_true",
                        help="Upgrade DB")

    parser.add_argument("--os",
                        help="Windows/Linux/Mobile/Other")

    parser.add_argument("--access",
                        help="Remote/Local")

    parser.add_argument("--cve",
                        help="Search a CVE")

    parser.add_argument("--system",
                    help="Search a system")
                    
    parser.add_argument("--year",
                    help="filter CVE by year (example: 2026)")
                    
    args = parser.parse_args()

    init_db()

    if args.update:

        if os.path.exists(DB):

            answer = input(
                "Database already exists. Reindexing will delete the current database. Continue? (y/N): "
            ).strip().lower()

            if answer != "y":
                print("Exiting...")
                return

            os.remove(DB)
            print("Old database removed. Reindexing...")

        init_db()

        try:
            asyncio.run(update_db())
            print("Database updated")
        except KeyboardInterrupt:
            print("\nExiting...")    

    else:

        query_db(args.os, args.access, args.cve, args.system, args.year)


if __name__ == "__main__":
    main()