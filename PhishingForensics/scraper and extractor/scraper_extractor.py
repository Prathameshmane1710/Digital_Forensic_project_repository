# import subprocess
# subprocess.run(["python", "API_data.py"])

import requests
from bs4 import BeautifulSoup
import pandas as pd
import socket
from urllib.parse import urlparse
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import random
import time

IPINFO_API_TOKEN = "7318cd88c56042"


# Function to get a session with retries
def get_session_with_retries():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


# Function to check if a domain is resolvable
def is_resolvable(domain):
    try:
        if not domain or len(domain) > 253:
            print(f"Invalid domain: {domain}")
            return False
        socket.gethostbyname(domain)
        return True
    except (socket.error, UnicodeError) as e:
        print(f"Domain resolution error for {domain}: {e}")
        return False


# Function to get geolocation from IP address
def get_geolocation(ip_address):
    """
    Querying the ipinfo.io API for geolocation data.
    """
    try:
        url = f"https://ipinfo.io/{ip_address}?token={IPINFO_API_TOKEN}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        return {
            "country": data.get("country", "N/A"),
            "region": data.get("region", "N/A"),
            "city": data.get("city", "N/A"),
            "latitude": data.get("loc", "N/A").split(",")[0] if "loc" in data else "N/A",
            "longitude": data.get("loc", "N/A").split(",")[1] if "loc" in data else "N/A",
        }
    except Exception as e:
        print(f"Error fetching geolocation for {ip_address}: {e}")
        return {
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "latitude": "N/A",
            "longitude": "N/A",
        }


# Extract redirection chains from responses
def extract_redirection_chains(url, session):
    try:
        response = session.get(url, timeout=10, allow_redirects=True)
        redirections = [resp.url for resp in response.history]
        if response.url != url:
            redirections.append(response.url)
        return redirections
    except Exception as e:
        print(f"Error following redirections for {url}: {e}")
        return []


# Extract hidden elements or obfuscated content
def detect_hidden_elements(soup):
    hidden_elements = soup.find_all(style=lambda x: x and "display:none" in x)
    return [element.get_text(strip=True) for element in hidden_elements]


# Analyze third-party resources
def extract_third_party_resources(soup, domain):
    resources = {
        "scripts": [],
        "stylesheets": [],
        "images": []
    }
    for script in soup.find_all("script", src=True):
        src = script.get("src")
        if src and domain not in src:
            resources["scripts"].append(src)
    for link in soup.find_all("link", href=True, rel=lambda x: x and "stylesheet" in x):
        href = link.get("href")
        if href and domain not in href:
            resources["stylesheets"].append(href)
    for img in soup.find_all("img", src=True):
        src = img.get("src")
        if src and domain not in src:
            resources["images"].append(src)
    return resources


# Function to scrape a website
def scrape_website(url):
    session = get_session_with_retries()
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.strip()

    if not is_resolvable(domain):
        print(f"Skipping {url}: Domain is invalid or not resolvable.")
        return None

    try:
        # Measure response time
        start_time = time.time()
        response = session.get(url, timeout=10)
        response_time = time.time() - start_time
        response.raise_for_status()

        # Parse the HTML content
        soup = BeautifulSoup(response.content, "html.parser")

        # Extract form elements with additional details
        forms = []
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action"),
                "method": form.get("method"),
                "inputs": [
                    {
                        "type": input_.get("type"),
                        "name": input_.get("name"),
                        "placeholder": input_.get("placeholder"),
                    }
                    for input_ in form.find_all("input")
                ],
            }
            forms.append(form_data)

        # Extract metadata
        ip_address = socket.gethostbyname(domain)
        geolocation = get_geolocation(ip_address)
        title = soup.title.string if soup.title else "N/A"
        status_code = response.status_code
        num_forms = len(forms)
        page_size = len(response.content)
        response_time = round(response_time, 2)

        # Extract external links and suspicious links
        external_links = [
            link.get("href")
            for link in soup.find_all("a", href=True)
            if urlparse(link.get("href")).netloc not in [domain, ""]
        ]
        suspicious_links = [
            link for link in external_links if any(kw in link.lower() for kw in ["login", "verify", "secure"])
        ]

        # Extract button texts
        buttons = [button.get_text(strip=True) for button in soup.find_all("button")]

        # Extract meta tags
        meta_tags = {meta.get("name", "N/A"): meta.get("content", "N/A") for meta in soup.find_all("meta", attrs={"name": True})}

        # Check for inline styles
        inline_styles = [style.get_text(strip=True) for style in soup.find_all("style")]

        redirection_chain = extract_redirection_chains(url, session)

        hidden_elements = detect_hidden_elements(soup)

        third_party_resources = extract_third_party_resources(soup, domain)

        return {
            "url": url,
            "ip_address": ip_address,
            "country": geolocation["country"],
            "region": geolocation["region"],
            "city": geolocation["city"],
            "latitude": geolocation["latitude"],
            "longitude": geolocation["longitude"],
            "status_code": status_code,
            "domain": domain,
            "title": title,
            "num_forms": num_forms,
            "forms": forms,
            "page_size": page_size,
            "response_time": response_time,
            "external_links": external_links,
            "suspicious_links": suspicious_links,
            "buttons": buttons,
            "meta_tags": meta_tags,
            "redirection_chain": redirection_chain,
            "hidden_elements": hidden_elements,
            "third_party_resources": third_party_resources,
            "inline_styles": inline_styles,
        }

    except Exception as e:
        print(f"Error scraping {url}: {e}")
        return None


# Function to load URLs from the CSV file
def load_urls(csv_path):
    df = pd.read_csv(csv_path)
    return df["url"].tolist()


# Function to save scraped data to a CSV file
def save_scraped_data(data, output_path):
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"Data saved to {output_path}")


# Main function to scrape phishing websites
def main():
    urls = load_urls("../data/valid_phishing_urls.csv")
    random.shuffle(urls)
    scraped_data = []
    success_count = 0

    for url in urls:
        if success_count >= 1000:
            break
        print(f"Scraping {url}...")
        result = scrape_website(url)
        if result:
            scraped_data.append(result)
            success_count += 1
            print(f"Successfully scraped {success_count} URLs.")

    save_scraped_data(scraped_data, "../data/Scraped_data_output/scraped_data_1000_more_advanced.csv")
    save_scraped_data(scraped_data, "../data/Scraped_data_output/scraped_data_1000_more_advanced.json")


# Run the script
if __name__ == "__main__":
    main()