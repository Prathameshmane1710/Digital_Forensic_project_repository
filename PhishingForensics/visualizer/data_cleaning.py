import pandas as pd

# Load the dataset
file_path = '../data/Scraped_data_output/Updated_scraped_data_with_risk_score.csv'
data = pd.read_csv(file_path)

# Filter rows where the 'url' starts with "http" or "https"
data = data[data['url'].str.startswith(('http', 'https'), na=False)]

# Drop the 'inline_styles' column
data.drop(columns=['inline_styles'], inplace=True)

# Drop the 'status_code' column
data.drop(columns=['status_code'], inplace=True)

# Replace None or missing values in 'title' with 'Unknown'
if data['title'].isnull().all():
    data['title'] = 'Unknown'
else:
    # Replace NaN/None with 'Unknown' in non-empty columns
    data['title'] = data['title'].apply(lambda x: 'Unknown' if pd.isna(x) else x)

# Save the filtered dataset to a new CSV file
filtered_file_path = '../data/Scraped_data_output/Cleaned_data.csv'
data.to_csv(filtered_file_path, index=False)

print(f"Filtered data saved to {filtered_file_path}")
