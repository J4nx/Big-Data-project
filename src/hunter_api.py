import requests
from pymongo import MongoClient
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB settings
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "pulse_secure_db"
COLLECTION_NAME = "hunter_enrichment"

# Hunter API key
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")

if not HUNTER_API_KEY:
    raise ValueError("❌ HUNTER_API_KEY is missing. Please set it in your .env file.")


def create_domain_index():
    """
    Create a unique index on the 'domain' field if it doesn't exist yet.
    """
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
        indexes = collection.index_information()
        if "domain_1" not in indexes:
            result = collection.create_index([("domain", 1)], unique=True)
            print(f"✅ Domain index created.")
        else:
            print("ℹ️ Domain index already exists.")
    except Exception as e:
        print(f"❌ MongoDB error while creating index: {e}")


def fetch_hunter_data(domain):
    """
    Fetch Hunter.io data for a single domain and organize selected fields.
    
    Args:
        domain (str): The domain to query from Hunter.io API.

    Returns:
        dict or None: Structured domain data or None if the request failed.
    """
    url = "https://api.hunter.io/v2/companies/find"

    params = {
        "domain": domain,
        "api_key": HUNTER_API_KEY
    }

    try:
        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "domain": domain,
                "site": {
                    "phoneNumbers": data.get("site", {}).get("phoneNumbers", []),
                    "emailAddresses": data.get("site", {}).get("emailAddresses", [])
                },
                "tags": data.get("tags", []),
                "description": data.get("description"),
                "founded_year": data.get("foundedYear"),
                "location": data.get("location"),
                "linkedin_handle": data.get("linkedin", {}).get("handle"),
                "twitter_handle": data.get("twitter", {}).get("handle"),
                "employees": data.get("metrics", {}).get("employees"),
                "timestamp": datetime.utcnow()
            }
        else:
            print(f"⚠️ Hunter.io request failed for domain '{domain}', status_code={response.status_code}")
            return None
    except Exception as e:
        print(f"❌ Error fetching data for domain '{domain}': {e}")
        return None


def fetch_and_store_hunter_data(domains, enrich=True, force=False):
    """
    Fetch Hunter.io data for a list of domains and store/update them in MongoDB.

    Args:
        domains (list): List of domain names.
        enrich (bool): Whether to fetch new data if not present in MongoDB.
        force (bool): If True, force fetching new data even if domain exists in MongoDB.
    """
    try:
        client = MongoClient(MONGO_URI)
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        return

    if not enrich:
        print("ℹ️ Skipping Hunter.io enrichment. Using existing MongoDB data only.")
        return

    for domain in domains:
        existing_doc = collection.find_one({"domain": domain})

        if existing_doc and not force:
            print(f"ℹ️ Domain '{domain}' already exists in MongoDB. Skipping API fetch.")
            continue  # Skip fetching if already exists and not forcing refresh

        # Fetch fresh data from Hunter.io
        data = fetch_hunter_data(domain)
        if data:
            try:
                result = collection.update_one(
                    {"domain": domain},
                    {"$set": data},
                    upsert=True
                )
                if result.upserted_id:
                    print(f"✅ New document inserted for domain: {domain}")
                else:
                    print(f"🔄 Document updated for domain: {domain}")
            except Exception as e:
                print(f"❌ MongoDB error while saving domain '{domain}': {e}")

    print("✅ All domains have been processed.")


