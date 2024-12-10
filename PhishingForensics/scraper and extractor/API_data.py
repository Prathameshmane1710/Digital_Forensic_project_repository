import requests
import pandas as pd
from urllib.parse import urlparse


def fetch_phishtank_data():
    api_url = "https://data.phishtank.com/data/online-valid.csv"
    response = requests.get(api_url)
    if response.status_code == 200:
        with open("../data/phishing_urls.csv", "wb") as PH_data:
            PH_data.write(response.content)
        print("Phishing URLs saved to phishing_urls.csv")
    else:
        print("Failed to fetch data. Status Code:", response.status_code)


def validate_urls(input_csv_path,output_csv_path):
    # Load URLs from CSV
    df = pd.read_csv(input_csv_path)
    valid_urls = []

    # Validate URLs
    for url in df["url"]:
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]):
                valid_urls.append(url)
        except Exception as e:
            print(f"Invalid URL {url}: {e}")

    # Save valid URLs to new CSV
    valid_df = pd.DataFrame(valid_urls, columns=["url"])
    valid_df.to_csv(output_csv_path, index=False)
    print(f"Validated {len(valid_urls)} URLs and saved to {output_csv_path}")


# Input and output file paths
input_file = "../data/phishing_urls.csv"
output_file = "../data/valid_phishing_urls.csv"


if __name__ == "__main__":
    fetch_phishtank_data()
    validate_urls(input_file,output_file)
