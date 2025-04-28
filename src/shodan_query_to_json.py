"""
shodan_query_to_json.py

Performs Shodan searches based on user input or a predefined query
and saves new results to a JSON file.

Usage:
- Directly: prompts for a search term and saves results to a JSON file
"""

import os
import json
import time
import re

import shodan
from dotenv import load_dotenv

# Settings
DEFAULT_QUERY = "product:Pulse Secure country:FI"
DATA_DIR = "data"

# Load .env
default_env_loaded = load_dotenv()
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

if not SHODAN_API_KEY:
    raise ValueError("SHODAN_API_KEY not found in .env file!")

api = shodan.Shodan(SHODAN_API_KEY)

def sanitize_filename(text):
    """Converts the search term into a valid filename."""
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = text.strip("_")
    return text + ".json"

def load_previous_results(filepath):
    """Loads previous JSON results if the file exists."""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def run_shodan_query():
    """Performs a Shodan search and saves new results to a file."""
    user_query = input("Enter search term (press Enter to use default): ").strip()
    query = user_query if user_query else DEFAULT_QUERY

    filename = sanitize_filename(query)
    filepath = os.path.join(DATA_DIR, filename)

    all_results = load_previous_results(filepath)
    seen_ip_ports = {f"{entry.get('ip_str')}:{entry.get('port')}" for entry in all_results}

    print(f"🔍 Searching: {query}")
    new_results = []

    try:
        results = api.search(query, limit=150)
        for result in results["matches"]:
            ip = result["ip_str"]
            port = result.get("port", 0)
            key = f"{ip}:{port}"
            if key not in seen_ip_ports:
                new_results.append(result)
                seen_ip_ports.add(key)
        time.sleep(2)

    except shodan.APIError as error:
        print(f"⚠️ Shodan error: {error}")
    except Exception as error:
        print(f"⚠️ General error: {error}")

    if new_results:
        all_results.extend(new_results)
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2)

        print(f"✅ Added {len(new_results)} new results to file '{filepath}'.")
    else:
        print("ℹ️ No new results to add.")

if __name__ == "__main__":
    run_shodan_query()
