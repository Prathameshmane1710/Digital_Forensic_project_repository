import json
from collections import Counter
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Dash, dcc, html, Input, Output
from wordcloud import WordCloud
import matplotlib.pyplot as plt
import base64

# Load dataset
file_path = '../data/Scraped_data_output/Cleaned_data.csv'
scraped_data = pd.read_csv(file_path)

# Initialize Dash app
app = Dash(__name__)
app.title = "Phishing Dashboard"

# Layout
app.layout = html.Div([
    html.H1("Phishing Data Dashboard", style={'text-align': 'center'}),

    # Dropdown for selecting visualization
    html.Div([
        html.Label("Select Visualization:"),
        dcc.Dropdown(
            id='visualization-dropdown',
            options=[
                {'label': 'Risk Level Distribution', 'value': 'risk'},
                {'label': 'Geographical Hotspots', 'value': 'geo'},
                {'label': 'Form Fields Distribution', 'value': 'form'},
                {'label': 'HTTPS VS HTTP URLS', 'value': 'summary'},
                {'label': 'Top Cities Hosting Phishing Sites', 'value': 'cities'},
                {'label': 'Suspicious Links Distribution', 'value': 'links'},
                {'label': 'Word Cloud', 'value': 'wordcloud'},
                {'label': 'Clusters', 'value': 'clusters'},
            ],
            value='risk',
            clearable=False,
            style={'width': '50%'}
        ),
    ], style={'margin': '20px'}),

    # Graph output
    dcc.Graph(id='visualization-graph'),

    # Word cloud output (conditionally shown)
    html.Div(id='wordcloud-output', style={'text-align': 'center'})
])

# Callbacks
@app.callback(
    [Output('visualization-graph', 'figure'),
     Output('wordcloud-output', 'children')],
    [Input('visualization-dropdown', 'value')]
)
def update_visualization(selected_visualization):
    # Handle Word Cloud separately
    if selected_visualization == 'wordcloud':
        text_data = scraped_data['title'].fillna('') + ' ' + scraped_data['meta_tags'].fillna('')
        wordcloud = WordCloud(width=800, height=400, background_color='white').generate(' '.join(text_data))

        # Save word cloud image temporarily
        wordcloud_path = "wordcloud.png"
        wordcloud.to_file(wordcloud_path)
        encoded_image = base64.b64encode(open(wordcloud_path, 'rb').read()).decode('ascii')

        return {}, html.Img(src='data:image/png;base64,{}'.format(encoded_image), style={'width': '80%'})

    # Reset wordcloud output for non-wordcloud visualizations
    wordcloud_output = None

    # Risk Level Distribution
    if selected_visualization == 'risk':
        risk_counts = scraped_data['risk_level'].value_counts()
        fig = px.bar(risk_counts, x=risk_counts.index, y=risk_counts.values,
                     labels={'x': 'Risk Level', 'y': 'Number of Websites'},
                     title="Risk Level Distribution", color=risk_counts.index)
        return fig, wordcloud_output

    # Geographical Hotspots
    elif selected_visualization == 'geo':
        region_counts = scraped_data['region'].value_counts().head(10)
        fig = px.bar(region_counts, x=region_counts.values, y=region_counts.index,
                     orientation='h', labels={'x': 'Number of Websites', 'y': 'Region'},
                     title="Geographical Hotspots")
        return fig, wordcloud_output

    # Form Fields Distribution
    elif selected_visualization == 'form':
        all_forms = scraped_data['forms'].dropna()
        forms_combined = []

        for form_list in all_forms:
            try:
                forms_combined.extend(json.loads(form_list.replace("'", '"')))
            except Exception:
                pass

        field_types = [field['type'] for form in forms_combined for field in form.get('inputs', []) if 'type' in field]
        field_counts = Counter(field_types)
        fig = px.bar(x=list(field_counts.keys()), y=list(field_counts.values()),
                     labels={'x': 'Field Type', 'y': 'Frequency'},
                     title="Form Fields Distribution")
        return fig, wordcloud_output

    # Summary Statistics
    elif selected_visualization == 'summary':
        summary_stats = {
            "HTTPS URLs": sum(1 for url in scraped_data['url'] if url.startswith('https')),
            "HTTP URLs": len(scraped_data) - sum(1 for url in scraped_data['url'] if url.startswith('https')),
        }
        fig = px.bar(x=list(summary_stats.keys()), y=list(summary_stats.values()),
                     labels={'x': 'URL Type', 'y': 'Count'},
                     title="Summary Statistics")
        return fig, wordcloud_output

    # Top Cities Hosting Phishing Sites
    elif selected_visualization == 'cities':
        city_counts = scraped_data['city'].value_counts().head(10)
        fig = px.bar(city_counts, x=city_counts.values, y=city_counts.index, orientation='h',
                     labels={'x': 'Number of Websites', 'y': 'City'},
                     title="Top Cities Hosting Phishing Sites")
        return fig, wordcloud_output

    # Suspicious Links Distribution
    elif selected_visualization == 'links':
        suspicious_links = scraped_data['suspicious_links'].dropna().apply(lambda x: len(eval(x)))
        fig = px.histogram(suspicious_links, nbins=10,
                           labels={'value': 'Number of Suspicious Links', 'count': 'Frequency'},
                           title="Suspicious Links Distribution")
        return fig, wordcloud_output

    # Clusters
    elif selected_visualization == 'clusters':
        cluster_counts = scraped_data['cluster'].value_counts()
        fig = px.bar(cluster_counts, x=cluster_counts.index, y=cluster_counts.values,
                     labels={'x': 'Cluster', 'y': 'Number of Websites'},
                     title="Phishing Website Clusters")
        return fig, wordcloud_output

    # Default empty graph
    return {}, wordcloud_output


# Run the app
if __name__ == '__main__':
    app.run_server(debug=True)
