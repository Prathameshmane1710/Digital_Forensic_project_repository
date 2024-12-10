import json
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer

# Load the dataset
file_path = '../data/Scraped_data_output/Cleaned_data.csv'
scraped_data = pd.read_csv(file_path)

# Ensure any necessary columns exist
required_columns = ['risk_level', 'country', 'suspicious_links', 'title', 'meta_tags', 'cluster']
missing_columns = [col for col in required_columns if col not in scraped_data.columns]
if missing_columns:
    print(f"Missing columns: {missing_columns}")
else:
    print("All required columns are present.")


def visualize_risk_distribution(data):
    """
    Bar chart showing the distribution of phishing websites by risk level.
    """
    plt.figure(figsize=(8, 6))
    sns.countplot(x='risk_level', data=data, palette='Set2', order=['Low', 'Medium', 'High'])
    plt.title('Risk Level Distribution')
    plt.xlabel('Risk Level')
    plt.ylabel('Number of Websites')
    plt.show()

    risk_counts = data['risk_level'].value_counts()
    plt.figure(figsize=(8, 5))
    risk_counts.plot(kind='pie', autopct='%1.1f%%', colors=['green', 'orange', 'red'], labels=risk_counts.index)
    plt.title('Risk Level Distribution')
    plt.ylabel('')
    plt.tight_layout()
    plt.show()


def visualize_geolocation(data):
    """
    Visualize the most commonly targeted regions.
    """
    region_counts = data['region'].value_counts().head(10)
    total = region_counts.sum()

    plt.figure(figsize=(12, 6))
    sns.barplot(x=region_counts.values, y=region_counts.index, palette='viridis')
    plt.title('Most Commonly Targeted Regions')
    plt.xlabel('Number of Websites')
    plt.ylabel('Region')

    # Annotate percentages
    for i, (count, region) in enumerate(zip(region_counts.values, region_counts.index)):
        percentage = (count / total) * 100
        plt.text(count, i, f"{percentage:.2f}%", va='center')

    plt.show()

    region_counts = data['region'].value_counts()
    region_counts.plot(kind='bar', figsize=(10, 6), title='Most Commonly Targeted Regions')
    plt.xlabel('Region')
    plt.ylabel('Frequency')
    plt.show()


def visualize_form_fields(data):
    """
    Visualize the most common input field types in forms.
    """
    all_forms = data['forms'].dropna()
    forms_combined = []

    for form_list in all_forms:
        try:
            forms_combined.extend(json.loads(form_list.replace("'", '"')))
        except Exception:
            pass

    field_types = [field['type'] for form in forms_combined for field in form.get('inputs', []) if 'type' in field]
    field_counts = Counter(field_types)

    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(field_counts.keys()), y=list(field_counts.values()), palette='coolwarm')
    plt.title('Most Common Input Field Types')
    plt.xlabel('Field Type')
    plt.ylabel('Frequency')
    plt.xticks(rotation=45)
    plt.show()


def visualize_summary_statistics(data):
    """
    Visualize summary statistics as a bar chart.
    """
    summary_stats = {
        "HTTPS URLs": sum(1 for url in data['url'] if url.startswith('https')),
        "HTTP URLs": len(data) - sum(1 for url in data['url'] if url.startswith('https')),
    }

    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(summary_stats.keys()), y=list(summary_stats.values()), palette='cubehelix')
    plt.title('Summary Statistics')
    plt.ylabel('Values')
    plt.xticks(rotation=45)
    plt.show()


def visualize_top_cities(data):
    """
    Bar chart showing the top 10 cities hosting phishing websites.
    """
    city_counts = data['city'].value_counts().head(10)
    plt.figure(figsize=(10, 6))
    sns.barplot(x=city_counts.values, y=city_counts.index, palette='coolwarm')
    plt.title('Top 10 Cities Hosting Phishing Websites')
    plt.xlabel('Number of Websites')
    plt.ylabel('City')
    plt.show()

    city_counts2 = data['city'].value_counts().head(30)
    plt.figure(figsize=(10, 60))
    sns.barplot(x=city_counts2.values, y=city_counts2.index, palette='coolwarm')
    plt.title('Top 30 Cities Hosting Phishing Websites')
    plt.xlabel('Number of Websites')
    plt.ylabel('City')
    plt.show()


def visualize_wordcloud(data):
    """
    Generate a word cloud from phishing-related keywords.
    """
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')
    wordcloud = WordCloud(width=800, height=400, background_color='white').generate(' '.join(text_data))

    plt.figure(figsize=(10, 6))
    plt.imshow(wordcloud, interpolation='bilinear')
    plt.axis('off')
    plt.title('Phishing Keywords Word Cloud')
    plt.show()


def visualize_clusters(data, num_keywords=5):
    """
       Display cluster sizes as a bar chart and include representative keywords for each cluster.
       """
    # Cluster Counts
    cluster_counts = data['cluster'].value_counts().sort_index()

    # Extract representative keywords for each cluster
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')
    vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
    X = vectorizer.fit_transform(text_data)
    feature_names = vectorizer.get_feature_names_out()

    cluster_keywords = {}
    for cluster in cluster_counts.index:
        cluster_data = data[data['cluster'] == cluster]
        cluster_vectorized = vectorizer.transform(
            cluster_data['title'].fillna('') + ' ' + cluster_data['meta_tags'].fillna(''))
        avg_vector = cluster_vectorized.mean(axis=0).A1  # Compute average vector for the cluster
        top_indices = avg_vector.argsort()[-num_keywords:][::-1]
        cluster_keywords[cluster] = [feature_names[i] for i in top_indices]

    # Visualization
    plt.figure(figsize=(10, 6))
    sns.barplot(x=cluster_counts.index, y=cluster_counts.values, palette='viridis')
    plt.title('Phishing Website Clusters with Representative Keywords')
    plt.xlabel('Cluster')
    plt.ylabel('Number of Websites')

    # Add keywords as annotations
    for i, (cluster, count) in enumerate(zip(cluster_counts.index, cluster_counts.values)):
        keywords = ', '.join(cluster_keywords[cluster])
        plt.text(i, count + 0.5, keywords, ha='center', fontsize=9, rotation=45)

    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.show()

    # Print cluster keywords
    print("\n### Cluster Keywords ###")
    for cluster, keywords in cluster_keywords.items():
        print(f"- Cluster {cluster}: {', '.join(keywords)}")

def visualize_phishing_keywords(data):
    """
    Visualize phishing-related keywords in text content.
    """
    text_data = data['title'].fillna('') + ' ' + data['meta_tags'].fillna('')
    keywords = ['login', 'verify', 'password', 'account', 'urgent']
    keyword_counts = {kw: text_data.str.contains(kw, case=False).sum() for kw in keywords}

    plt.figure(figsize=(8, 6))
    sns.barplot(x=list(keyword_counts.keys()), y=list(keyword_counts.values()), palette='rocket')
    plt.title('Phishing Keywords in Text Content')
    plt.xlabel('Keyword')
    plt.ylabel('Occurrences')
    plt.show()


def visualize_suspicious_links(data):
    """
    Histogram of the number of suspicious links per website with enhanced annotations and insights.
    """
    suspicious_link_counts = data['suspicious_links'].dropna().apply(lambda x: len(eval(x)))

    plt.figure(figsize=(10, 6))
    sns.histplot(suspicious_link_counts, bins=10, kde=True, color='purple')

    # Set plot title and labels
    plt.title('Distribution of Suspicious Links per Website', fontsize=16)
    plt.xlabel('Number of Suspicious Links', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)

    # Calculate percentage of websites with zero suspicious links
    zero_links_percentage = (suspicious_link_counts == 0).mean() * 100
    one_link_percentage = (suspicious_link_counts == 1).mean() * 100

    # Add annotation for zero suspicious links
    plt.annotate(f'~{zero_links_percentage:.2f}% websites with 0 links',
                 xy=(0, suspicious_link_counts.value_counts().max() * 0.9),
                 xytext=(1, suspicious_link_counts.value_counts().max() * 1.1),
                 arrowprops=dict(facecolor='black', shrink=0.05),
                 fontsize=11, color='black')

    # Add annotation for one suspicious link
    plt.annotate(f'~{one_link_percentage:.2f}% websites with 1 link',
                 xy=(1, suspicious_link_counts.value_counts().max() * 0.75),
                 xytext=(2, suspicious_link_counts.value_counts().max() * 0.85),
                 arrowprops=dict(facecolor='black', shrink=0.05),
                 fontsize=11, color='black')

    # Use log scale for y-axis if the data is highly skewed
    plt.yscale('log')
    plt.tight_layout()

    # Display the plot
    plt.show()


if __name__ == "__main__":
    visualize_risk_distribution(scraped_data)
    visualize_geolocation(scraped_data)
    visualize_form_fields(scraped_data)
    visualize_summary_statistics(scraped_data)
    visualize_top_cities(scraped_data)
    visualize_phishing_keywords(scraped_data)
    visualize_wordcloud(scraped_data)
    visualize_clusters(scraped_data)
    visualize_suspicious_links(scraped_data)

