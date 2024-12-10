import pandas as pd
from collections import Counter
import json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
# import matplotlib.pyplot as plt

# Load the scraped data CSV
file_path = '../data/Scraped_data_output/scraped_data_1000_more_advanced.csv'
scraped_data = pd.read_csv(file_path)

# Inspect the data structure
# print(f"Dataset contains {len(scraped_data)} rows and {scraped_data.shape[1]} columns.")
# print(scraped_data.head())


# 1. **Extract Most Commonly Targeted Regions**
def analyze_geolocation(data):
    region_counts = data['region'].value_counts()
    total = region_counts.sum()
    print("\n### Most Commonly Targeted Regions ###")
    for region, count in region_counts.head(10).items():
        percentage = (count / total) * 100
        print(f"- {region}: {count} times ({percentage:.2f}%)")
    # region_counts.plot(kind='bar', figsize=(10, 6), title='Most Commonly Targeted Regions')
    # plt.xlabel('Region')
    # plt.ylabel('Frequency')
    # plt.show()


# 2. **Analyze Form Fields**
def analyze_form_fields(data):
    all_forms = data['forms'].dropna()
    forms_combined = []

    for form_list in all_forms:
        try:
            forms_combined.extend(json.loads(form_list.replace("'", '"')))
        except Exception:
            pass

    field_types = [field['type'] for form in forms_combined for field in form.get('inputs', []) if 'type' in field]
    field_counts = Counter(field_types)
    total_fields = sum(field_counts.values())

    print("\n### Most Common Input Field Types ###")
    for field, count in field_counts.most_common():
        proportion = (count / total_fields) * 100
        print(f"- {field}: {count} times ({proportion:.2f}%)")

    # pd.Series(field_counts).plot(kind='bar', figsize=(10, 6), title='Input Field Types')
    # plt.xlabel('Field Type')
    # plt.ylabel('Frequency')
    # plt.show()


# 3. **Analyze Meta Tags**
def analyze_meta_tags(data):
    meta_data = data['meta_tags'].dropna()
    meta_combined = Counter()

    for meta in meta_data:
        try:
            meta_combined.update(json.loads(meta.replace("'", '"')))
        except Exception:
            pass

    print("\n### Most Common Meta Tags ###")
    for tag, content in meta_combined.most_common(5):
        print(f"- {tag}: Example content - {content[:50]}...")


# 4. **Extract Suspicious Links**
def analyze_suspicious_links(data):
    suspicious_links = data['suspicious_links'].dropna()
    suspicious_combined = []

    for links in suspicious_links:
        try:
            suspicious_combined.extend(json.loads(links.replace("'", '"')))
        except Exception:
            pass

    categorized_links = Counter(
        'shortened' if 'bit.ly' in link or 'rebrandly' in link else 'full'
        for link in suspicious_combined
    )

    print("\n### Suspicious Links Breakdown ###")
    print(f"- Shortened Links: {categorized_links['shortened']}")
    print(f"- Full Links: {categorized_links['full']}")
    print("\nSample Suspicious Links:")
    for link in suspicious_combined[:5]:
        print(f"- {link}")


# 5. **Generate Summary Statistics**
def generate_summary_statistics(data):
    print("\nSummary Statistics:")
    print(f"Total URLs Scraped: {len(data)}")
    print(f"Average Page Size: {data['page_size'].mean():.2f} bytes")
    print(f"Average Response Time: {data['response_time'].mean():.2f} seconds")
    print(f"Total Forms Found: {data['num_forms'].sum()}")
    https_count = sum(1 for url in data['url'] if url.startswith('https'))
    http_count = len(data) - https_count
    print("\n### URL Characteristics ###")
    print(f"- HTTPS URLs: {https_count}")
    print(f"- HTTP URLs: {http_count}")


# 6. **Most Common Countries Hosting Phishing Sites**
def analyze_countries(data):
    country_counts = data['country'].value_counts()
    print("\n### Most Common Countries Hosting Phishing Sites ###")
    for country, count in country_counts.head().items():
        print(f"- {country}: {count} times")


# 7. **Text Content: Phishing Keywords**
def analyze_text_keywords(data):
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')
    keywords = ['login', 'verify', 'password', 'account', 'urgent']
    keyword_counts = {kw: text_data.str.contains(kw, case=False).sum() for kw in keywords}

    print("\n### Phishing Keywords in Text Content ###")
    for keyword, count in keyword_counts.items():
        print(f"- {keyword.capitalize()}: {count} occurrences")


# 8. **Forms with Sensitive Input Fields**
def analyze_sensitive_fields(data):
    all_forms = data['forms'].dropna()
    sensitive_fields = ['password', 'ssn', 'creditcard']
    sensitive_count = 0

    for form_list in all_forms:
        try:
            forms = json.loads(form_list.replace("'", '"'))
            sensitive_count += sum(
                1 for form in forms for field in form.get('inputs', [])
                if field.get('type') in sensitive_fields
            )
        except Exception:
            pass

    print("\n### Sensitive Fields in Forms ###")
    print(f"- Total forms with sensitive fields: {sensitive_count}")


def analyze_response_time_by_country(data):
    response_times = data.groupby('country')['response_time'].mean().sort_values(ascending=False)
    print("\n### Average Response Time by Country ###")
    for country, avg_time in response_times.items():
        print(f"- {country}: {avg_time:.2f} seconds")

def analyze_external_links(data):
    external_link_counts = data['external_links'].dropna().apply(lambda x: len(eval(x)))
    print("\n### External Link Distribution ###")
    print(f"- Average External Links Per Page: {external_link_counts.mean():.2f}")
    print(f"- Max External Links on a Page: {external_link_counts.max()}")


def analyze_button_texts(data):
    all_buttons = data['buttons'].dropna()
    words_combined = []

    for button_list in all_buttons:
        try:
            words = eval(button_list)
            filtered_words = [word.strip() for word in words if word.strip()]  # Remove blank/whitespace-only texts
            words_combined.extend(filtered_words)
        except Exception:
            pass

    word_counts = Counter(words_combined)
    print("\n### Most Common Words in Button Texts ###")
    for word, count in word_counts.most_common(10):
        print(f"- {word}: {count} occurrences")


# 9. **Phishing Risk Scoring System**
def compute_risk_score(row):
    """
    Compute a phishing risk score for each URL.
    """
    score = 0

    # Suspicious links
    if pd.notna(row['suspicious_links']):
        try:
            suspicious_links = json.loads(row['suspicious_links'].replace("'", '"'))
            score += len(suspicious_links) * 2
        except json.JSONDecodeError:
            pass

    # Keywords in meta tags
    if pd.notna(row['meta_tags']):
        try:
            meta = json.loads(row['meta_tags'].replace("'", '"'))
            if any(kw in meta.get('description', '').lower() for kw in ['login', 'verify', 'account','secure']):
                score += 5
        except json.JSONDecodeError:
            pass

    # 4. Form Fields
    if pd.notna(row['forms']):
        try:
            forms = json.loads(row['forms'].replace("'", '"'))
            sensitive_fields = ['password', 'creditcard', 'ssn']
            for form in forms:
                if any(field.get('type') in sensitive_fields for field in form.get('inputs', [])):
                    score += 4
        except json.JSONDecodeError:
            pass

    # 5. Page Title
    if pd.notna(row['title']):
        if any(kw in row['title'].lower() for kw in ['login', 'verify', 'secure']):
            score += 3  # Moderate weight for phishing-related titles

    # Button texts
    if pd.notna(row['buttons']):
        try:
            buttons = json.loads(row['buttons'].replace("'", '"'))
            if any(btn.lower() in ['login', 'verify', 'submit'] for btn in buttons):
                score += 3
        except json.JSONDecodeError:
            pass

    # 6. Inline Styles or Hidden Content
    if pd.notna(row['inline_styles']):
        try:
            hidden_content = json.loads(row['inline_styles'].replace("'", '"'))
            if len(hidden_content) > 0:
                score += 2  # Indication of obfuscation
        except json.JSONDecodeError:
            pass

    # Geolocation anomalies
    if row['country'] not in ['US', 'UK', 'CA']:
        score += 2

    return score


def classify_risk_level(score):
    """
    Classify phishing risk into Low, Medium, or High based on the score.
    """
    if score >= 5:
        return "High"
    elif score >= 2:
        return "Medium"
    else:
        return "Low"

# 10. **Cluster Phishing Websites**
def cluster_websites(data, num_clusters=5):
    """
    Cluster phishing websites based on textual content (title and meta tags).
    """
    # Combine 'title' and 'meta_tags' for clustering
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')

    # Vectorize text data
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(text_data)

    # Perform clustering
    kmeans = KMeans(n_clusters=num_clusters, random_state=42)
    data['cluster'] = kmeans.fit_predict(X)

    # Extract top keywords for each cluster
    cluster_keywords = {}
    feature_names = vectorizer.get_feature_names_out()
    for cluster_num in range(num_clusters):
        cluster_center = kmeans.cluster_centers_[cluster_num]
        top_keywords = [feature_names[i] for i in cluster_center.argsort()[-10:]]
        cluster_keywords[cluster_num] = top_keywords

    # Display cluster distribution
    print("\n### Cluster Distribution ###")
    cluster_counts = data['cluster'].value_counts().sort_index()
    for cluster, count in cluster_counts.items():
        print(f"- Cluster {cluster}: {count} websites")
        print(f"Representative Keywords: {', '.join(cluster_keywords[cluster])}")
    return data


# 11. **Text NLP Analysis**
def analyze_text_content(data):
    """
       Perform NLP analysis to identify common words in text content.
       """
    # Combine 'title' and 'meta_tags' for text analysis
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')

    # Split text into individual words and count occurrences
    words = text_data.str.split().explode()
    filtered_words = [word.lower() for word in words if len(word) > 2]  # Ignore short words
    common_words = Counter(filtered_words).most_common(20)

    # Display most common words
    print("\n### Most Common Words Across Text Content ###")
    for word, count in common_words:
        print(f"- {word}: {count} occurrences")


# Run analysis functions
analyze_geolocation(scraped_data)
analyze_form_fields(scraped_data)
analyze_meta_tags(scraped_data)
analyze_suspicious_links(scraped_data)
generate_summary_statistics(scraped_data)
analyze_countries(scraped_data)
analyze_text_keywords(scraped_data)
analyze_sensitive_fields(scraped_data)
analyze_response_time_by_country(scraped_data)
analyze_external_links(scraped_data)
analyze_button_texts(scraped_data)

# Compute risk scores
scraped_data['risk_score'] = scraped_data.apply(compute_risk_score, axis=1)
scraped_data['risk_level'] = scraped_data['risk_score'].apply(classify_risk_level)

print("\nPhishing Risk Scores:")
print(scraped_data[['url', 'risk_score','risk_level']].sort_values(by='risk_score', ascending=False).head(10))

# Cluster websites
cluster_websites(scraped_data)

# Text content analysis
analyze_text_content(scraped_data)

# Save the dataset with the computed risk scores, risk levels, and cluster column to a new CSV file
output_file_path = '../data/Scraped_data_output/Updated_scraped_data_with_risk_score.csv'
scraped_data.to_csv(output_file_path, index=False)

print(f"\nData with risk scores, risk levels, and clusters saved to {output_file_path}")
