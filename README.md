# Big Data Pulse Secure Analysis

This project analyzes potential vulnerabilities in Pulse Secure VPN devices by combining Shodan search results, data enrichment from Hunter.io, and processing with Apache Spark. MongoDB is used for enrichment data storage.

---

## Features

- 🔍 Search Pulse Secure devices via Shodan API
- ⚡ Process large JSON datasets with Apache Spark
- 🛡️ Assess device vulnerability based on firmware versions
- 📈 Enrich organization info using Hunter.io API
- 🗄️ Store enriched data in MongoDB
- 📝 Generate detailed vulnerability reports (Top N targets)

---

## Project Structure

```
Big_data_project/ 
├── data/                       # Raw Shodan search results (JSON) 
├── src/                        # Python source code 
│ ├── analysis.py               # Spark-based data processing and vulnerability assessment 
│ ├── data_loader.py            # Loading Shodan JSON data into Spark 
│ ├── enrichment.py             # Extract top N domains for enrichment 
│ ├── hunter_api.py             # Hunter.io integration and MongoDB storage 
│ ├── report_generator.py       # Generate final Top N vulnerability reports 
│ └── shodan_query_to_json.py   # Query Shodan API and store results 
├── pulse_secure.ipynb          # Main notebook orchestrating the workflow 
├── .env                        # Environment variables (API keys, Mongo URI) - not committed 
├── .gitignore                  # Files/folders to exclude from Git tracking 
├── requirements.txt            # Requirements
└── README.md                   # Project documentation
```

---

## Requirements

- Python 3.8+
- Apache Spark
- MongoDB
- Shodan API Key
- Hunter.io API Key
- Python Libraries:
  - pyspark
  - pandas
  - pymongo
  - requests
  - python-dotenv

Install requirements with:

```bash
pip install -r requirements.txt
```

---

## Environment Setup

Create a `.env` file in the project root with the following contents:

```dotenv
SHODAN_API_KEY=your_shodan_api_key
HUNTER_API_KEY=your_hunter_api_key
MONGO_URI=mongodb://localhost:27017/
```

---

## How to Run

1. **Start a local MongoDB instance.**

2. **Run Shodan queries** to fetch new device data:

```bash
python src/shodan_query_to_json.py
```

3. **Run the main pipeline** inside the pulse_secure.ipynb notebook.

### Workflow Steps:

1. **Load** Shodan search results
2. **Analyze** vulnerability risks
3. **Fetch** Hunter.io enrichment data (only missing domains, unless forced)
4. **Generate and display** Top N report

---

## Notes

- `.env` file should **not** be committed to GitHub.
- `.gitignore` ensures that `.env` and `data/` folders are excluded from Git tracking.
- You can skip Hunter.io enrichment if needed by setting the parameter `enrich=False` when calling the `fetch_and_store_hunter_data` function.

---

## License

This project is licensed under the Apache License 2.0.