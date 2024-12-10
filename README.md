Installation and Usage Guide
System Requirements

1. Operating System:
o Windows, macOS, or Linux with support for Python 3.8+.

2. Software Requirements:
o Python 3.8+ installed on your system.
o PyCharm IDE (recommended for editing and running Python files).

3. Dependencies:
o Python libraries: pandas, matplotlib, seaborn, dash, sqlite3, fpdf, plotly, BeautifulSoup4, requests,json,Counter and other libraries.
o Ensure internet access for API requests and external resource downloads.

Installation Steps

1. Clone the Repository:
o Clone the repository from GitHub or Simply download the zip and extract it from the link:
git clone <repository-link>
cd <repository-folder>
o Link -: https://github.com/Prathameshmane1710/Digital_Forensic_project_repository

2. Set Up Python Environment:

o Create and activate a virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate       # For macOS/Linux
venv\Scripts\activate          # For Windows

3. Install Required Libraries:
o Install the dependencies listed in the requirements.txt file:
pip install -r requirements.txt

4. Set Up Environment Variables:
o For geolocation API integration, ensure valid API keys are set in your environment variables or directly in the script configuration files.

5. Open the Project in PyCharm:
o Open PyCharm and load the project directory. Ensure the Python interpreter is configured to use your virtual environment.

Usage Instructions
1. Data Collection
* Script: API_data.py
* Directory: scraper and extractor
* Purpose: Fetch phishing website URLs from the PhishTank API.
* Command: (Run the commands or simply run from IDE)
       python scraper and extractor/API_data.py

2. Scraping Metadata
* Script: scraper_extractor.py
* Directory: scraper and extractor
* Purpose: Extract metadata (IP addresses, geolocation, links, forms, etc.) from phishing websites.
* Command:
       python scraper and extractor/scraper_extractor.py

3. Analyze Data
* Script: pattern_analyzer.py
* Directory: analyzer
* Purpose: Perform data analysis to extract insights (e.g., most targeted regions, suspicious links).
* Command:
       python analyzer/pattern_analyzer.py

4. Data Visualization
* Scripts:
o data_cleaning.py
o visualizer.py
o dashboard.py
* Directory: visualizer
* Purpose: Generate visualizations and interactive dashboards for data exploration.
* Command:
python visualizer/data_cleaning.py
python visualizer/visualizer.py
python visualizer/dashboard.py

5. Repository Setup
* Script: repository.py
* Directory: repository
* Purpose: Set up and manage an SQLite database for forensic queries.
* Command:
       python repository/repository.py

6. Generate Comprehensive Report
* Script: Forensic_Report.py
* Directory: reports
* Purpose: Generate a PDF report summarizing the project's findings and insights.
* Command:
       python reports/Forensic_Report.py

Troubleshooting
1. Missing Dependencies:
o Run the following to install any missing library:
       pip install <library-name>
2. API Configuration Issues:
o Ensure that valid API keys (e.g., ipinfo.io) are properly configured in the scripts.
3. Internet Access:
o Verify your internet connection for data scraping and API requests.
4. PyCharm Issues:
o Ensure the Python interpreter is set to the correct virtual environment under File > Settings > Project: <Project-Name> > Python Interpreter.
5. Database Issues:
o Ensure SQLite is properly installed, and no permission errors occur when accessing database files.
6. Invalid URLs:
o If URLs fail during scraping, the script is designed to skip invalid entries. Check Output logs for detailed errors.
