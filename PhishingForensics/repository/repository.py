import sqlite3
import pandas as pd
import json

# Loaded the scraped data
file_path = '../data/Scraped_data_output/Cleaned_data.csv'
scraped_data = pd.read_csv(file_path)

# Function to create and populate the SQLite database
def create_evidence_repository(data, db_path='evidence_repository.db'):
    """
    Create a SQLite database to store phishing evidence with structured tables.
    """
    # Connect to SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Websites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            ip_address TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            suspicious_links_count INTEGER,
            cluster INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Metadata (
            website_id INTEGER,
            meta_tags TEXT,
            FOREIGN KEY (website_id) REFERENCES Websites (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Forms (
            website_id INTEGER,
            form_action TEXT,
            form_method TEXT,
            input_fields TEXT,
            FOREIGN KEY (website_id) REFERENCES Websites (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ExternalLinks (
            website_id INTEGER,
            external_link TEXT,
            FOREIGN KEY (website_id) REFERENCES Websites (id)
        )
    ''')

    # Inserted data into Websites table
    for _, row in data.iterrows():
        # Calculated the number of suspicious links
        suspicious_links_count = 0
        if pd.notna(row['suspicious_links']):
            try:
                suspicious_links_count = len(json.loads(row['suspicious_links'].replace("'", '"')))
            except Exception:
                pass

        # Inserted into Websites table
        cursor.execute('''
            INSERT INTO Websites (url, ip_address, country, region, city, risk_level, risk_score, suspicious_links_count, cluster)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            row['url'],
            row.get('ip_address', None),
            row.get('country', None),
            row.get('region', None),
            row.get('city', None),
            row.get('risk_level', None),
            row.get('risk_score', None),
            suspicious_links_count,
            row.get('cluster', None)
        ))

        # Get the inserted website's ID
        website_id = cursor.lastrowid

        # Insert metadata
        if pd.notna(row['meta_tags']):
            cursor.execute('''
                INSERT INTO Metadata (website_id, meta_tags)
                VALUES (?, ?)
            ''', (website_id, row['meta_tags']))

        # Insert forms
        if pd.notna(row['forms']):
            try:
                forms = json.loads(row['forms'].replace("'", '"'))
                for form in forms:
                    form_action = form.get('action', None)
                    form_method = form.get('method', None)
                    input_fields = json.dumps([input_.get('name', '') for input_ in form.get('inputs', [])])
                    cursor.execute('''
                        INSERT INTO Forms (website_id, form_action, form_method, input_fields)
                        VALUES (?, ?, ?, ?)
                    ''', (website_id, form_action, form_method, input_fields))
            except Exception:
                pass

        # Insert external links
        if pd.notna(row['external_links']):
            try:
                external_links = json.loads(row['external_links'].replace("'", '"'))
                for link in external_links:
                    cursor.execute('''
                        INSERT INTO ExternalLinks (website_id, external_link)
                        VALUES (?, ?)
                    ''', (website_id, link))
            except Exception:
                pass

    # Commit changes and close connection
    conn.commit()
    conn.close()
    print(f"Evidence repository created and populated at {db_path}")


# Function to query the repository
def query_repository(db_path='evidence_repository.db'):
    """
    Query the evidence repository for meaningful insights.
    """
    # Connect to SQLite database
    conn = sqlite3.connect(db_path)

    # Example queries
    print("\n### High-Risk Websites ###")
    high_risk_websites = pd.read_sql_query('''
        SELECT url, ip_address, risk_score, country, region
        FROM Websites
        WHERE risk_level = 'High'
        ORDER BY risk_score DESC
    ''', conn)
    print(high_risk_websites)

    print("\n### Most Common Hosting Regions ###")
    common_regions = pd.read_sql_query('''
        SELECT region, COUNT(*) AS website_count
        FROM Websites
        GROUP BY region
        ORDER BY website_count DESC
        LIMIT 10
    ''', conn)
    print(common_regions)

    print("\nWebsites with Sensitive Form Fields")
    sensitive_forms = pd.read_sql_query('''
        SELECT W.url, F.form_action, F.form_method, F.input_fields
        FROM Websites W
        JOIN Forms F ON W.id = F.website_id
        WHERE F.input_fields LIKE '%password%' OR F.input_fields LIKE '%creditcard%' OR F.input_fields LIKE '%ssn%'
    ''', conn)
    print(sensitive_forms)

    print("\n### Countries with Most Suspicious Links ###")
    suspicious_links = pd.read_sql_query('''
        SELECT country, SUM(suspicious_links_count) AS total_links
        FROM Websites
        GROUP BY country
        ORDER BY total_links DESC
        LIMIT 10
    ''', conn)
    print(suspicious_links)

    # Close connection
    conn.close()


# Main script
create_evidence_repository(scraped_data)
query_repository()
