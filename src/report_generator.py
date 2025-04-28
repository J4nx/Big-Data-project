import pandas as pd
from pymongo import MongoClient
from dotenv import load_dotenv


def generate_top_report(
    filtered_df,
    top_n=3,
    mongo_uri="mongodb://localhost:27017/",
    db_name="pulse_secure_db",
    collection_name="hunter_enrichment",
    output_file="top_report.csv",
    save_to_csv=True
):
    """
    Generate a report of the Top N potentially vulnerable companies by merging Spark and MongoDB data.
    
    Args:
        filtered_df: Spark DataFrame filtered for Pulse Secure targets.
        top_n: Number of top domains to include in the report (default=3).
        mongo_uri: MongoDB URI.
        db_name: MongoDB database name.
        collection_name: MongoDB collection name.
        output_file: CSV file name to save the report.
        
    Returns:
        Pandas DataFrame containing the final report.
    """

    # --- Select Top N ---
    top_df = filtered_df.limit(top_n)
    top_df = top_df.withColumn("domain", filtered_df["domains"].getItem(0))

    # Spark -> Pandas
    top_pandas = top_df.select(
        "ip_str",
        "org",
        "product",
        "version",
        "domain",
        "timestamp"  # Shodan scan timestamp must be present
    ).toPandas()

    if top_pandas.empty:
        print(f"⚠️ No records found in the top {top_n} selection.")
        return None

    # --- Fetch Hunter.io enrichment data from MongoDB ---
    load_dotenv()
    client = MongoClient(mongo_uri)
    db = client[db_name]
    collection = db[collection_name]

    hunter_data = list(collection.find({"domain": {"$in": top_pandas["domain"].tolist()}}))
    hunter_pandas = pd.DataFrame(hunter_data)

    if hunter_pandas.empty:
        print("⚠️ No Hunter.io enriched data found for the selected domains.")
        return None

    # --- Merge Shodan and Hunter.io data ---
    merged = top_pandas.merge(hunter_pandas, on="domain", how="left")

    # --- Build the final report ---
    final_report = merged[[
        "org",             # Organization
        "product",         # Product
        "version",         # Version
        "site",            # Emails (Hunter)
        "location",        # Location (Hunter)
        "employees",       # Employee count (Hunter)
        "timestamp_x",     # Shodan timestamp
        "timestamp_y"      # Hunter timestamp
    ]]

    final_report.columns = [
        "Company",
        "Product",
        "Version",
        "Emails",
        "Location",
        "EmployeeCount",
        "ShodanScanDate",
        "HunterScanDate"
    ]

    # Format email addresses
    final_report.loc[:, "Emails"] = final_report["Emails"].apply(
        lambda x: ", ".join(x.get("emailAddresses", [])) if isinstance(x, dict) else None
        )

    # Format dates
    final_report.loc[:, "ShodanScanDate"] = pd.to_datetime(final_report["ShodanScanDate"]).dt.date
    final_report.loc[:, "HunterScanDate"] = pd.to_datetime(final_report["HunterScanDate"]).dt.date

    if save_to_csv:
        final_report.to_csv(output_file, index=False)
        print(f"✅ Top {top_n} report successfully saved to {output_file} (emails formatted, dates formatted)")
    else:
        print(f"ℹ️ Top {top_n} report generated but not saved to file.")

    return final_report
