from fpdf import FPDF
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import json


def generate_forensic_report(data, output_path):
    """
    Generate a comprehensive forensic analysis report with all insights, visualizations, and explanations.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Add Title Page
    pdf.add_page()
    pdf.set_font('Arial', 'B', 20)
    pdf.cell(0, 10, 'Forensic Analysis Report', ln=True, align='C')
    pdf.ln(20)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10,
        "This report provides an analysis of phishing websites, including geographical hotspots, "
        "risk levels, suspicious patterns, sensitive fields, and actionable recommendations. "
        "The dataset was collected from PhishTank, which provided 66,661 phishing websites,1,000 websites were successfully scraped and analyzed for suspicious links, metadata, and sensitive forms."
        "Each section includes insights, visualizations, and explanations to assist investigators."
    )
    pdf.ln(10)
    pdf.cell(0, 10, 'This report is intended to provide a comprehensive overview', ln=True, align='C')
    pdf.cell(0, 10, 'of the findings and analysis conducted on the collected data.', ln=True, align='C')
    pdf.add_page()

    # Section 1: Geographical Analysis
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '1. Geographical Hotspots', ln=True)
    pdf.ln(5)
    region_counts = data['region'].value_counts().head(10)
    pdf.set_font('Arial', '', 12)
    for region, count in region_counts.items():
        pdf.cell(0, 10, f"- {region}: {count} occurrences", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "The chart below highlights the top 10 regions hosting phishing websites. "
        "These regions are hotspots for hosting malicious sites, with California and Texas showing the highest occurrences."
    )
    pdf.ln(10)

    # Add Geographical Chart
    plt.figure(figsize=(8, 5))
    region_counts.plot(kind='bar', color='skyblue', edgecolor='black')
    plt.title('Top Regions Hosting Phishing Websites', fontsize=14)
    plt.ylabel('Frequency', fontsize=12)
    plt.xlabel('Regions', fontsize=12)
    plt.tight_layout()
    chart_path = "geolocation_chart.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    pdf.image(chart_path, x=20, y=pdf.get_y(), w=170)
    pdf.add_page()

    # Section 2: Risk Levels
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '2. Risk Levels Distribution', ln=True)
    pdf.ln(5)
    risk_counts = data['risk_level'].value_counts()
    pdf.set_font('Arial', '', 12)
    for risk, count in risk_counts.items():
        pdf.cell(0, 10, f"- {risk}: {count} websites", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "The pie chart below categorizes phishing websites into risk levels: Low, Medium, and High. "
        "High-risk websites are flagged for immediate attention as they exhibit strong phishing indicators, such as suspicious links and sensitive input fields."
    )
    pdf.ln(10)

    # Add Risk Level Chart
    plt.figure(figsize=(8, 5))
    risk_counts.plot(kind='pie', autopct='%1.1f%%', colors=['green', 'orange', 'red'], labels=risk_counts.index)
    plt.title('Risk Level Distribution', fontsize=14)
    plt.ylabel('')
    plt.tight_layout()
    chart_path = "risk_level_chart.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    pdf.image(chart_path, x=20, y=pdf.get_y(), w=170)
    pdf.add_page()

    # Section 3: Suspicious Links
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '3. Suspicious Links Breakdown', ln=True)
    pdf.ln(5)
    suspicious_links = data['suspicious_links'].dropna().apply(lambda x: len(eval(x)))
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f"- Total Suspicious Links: {suspicious_links.sum()}", ln=True)
    pdf.cell(0, 10, f"- Average Suspicious Links Per Website: {suspicious_links.mean():.2f}", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "The histogram below shows the distribution of suspicious links across websites. "
        "Websites with high numbers of suspicious links should be prioritized for investigation."
    )
    pdf.ln(10)

    # Add Suspicious Links Chart
    plt.figure(figsize=(8, 5))
    sns.histplot(suspicious_links, bins=10, kde=True, color='purple')
    plt.title('Distribution of Suspicious Links Per Website', fontsize=14)
    plt.xlabel('Number of Suspicious Links', fontsize=12)
    plt.ylabel('Frequency', fontsize=12)
    plt.tight_layout()
    chart_path = "suspicious_links_chart.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    pdf.image(chart_path, x=20, y=pdf.get_y(), w=170)
    pdf.add_page()

    # Section 4: Sensitive Fields
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '4. Forms with Sensitive Input Fields', ln=True)
    pdf.ln(5)
    sensitive_fields = ['password', 'creditcard', 'ssn']
    sensitive_count = 0

    for forms in data['forms'].dropna():
        try:
            forms = json.loads(forms.replace("'", '"'))
            for form in forms:
                if any(field.get('type') in sensitive_fields for field in form.get('inputs', [])):
                    sensitive_count += 1
        except Exception:
            pass

    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f"- Total Forms with Sensitive Fields: {sensitive_count}", ln=True)
    pdf.ln(5)
    pdf.multi_cell(0, 10,
        "Sensitive fields such as passwords, credit card numbers, and SSNs are often targeted by phishing websites. "
        "Investigators should focus on websites containing such forms as they are likely designed to steal user credentials."
    )
    pdf.ln(10)

    # Section 5: Recommendations
    pdf.set_font('Arial', 'B', 14)
    pdf.cell(0, 10, '5. Recommendations for Investigators', ln=True)
    pdf.ln(5)
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10,
        "1. Focus on geographical hotspots like California and Texas for targeted analysis.\n"
        "2. Investigate websites with high-risk levels (e.g., classified as 'High Risk').\n"
        "3. Pay attention to forms targeting sensitive fields such as passwords and credit card details.\n"
        "4. Use the suspicious link distribution to identify potential outliers or patterns."
    )
    pdf.ln(10)

    # Save the PDF
    pdf.output(output_path)
    print(f"Forensic report generated: {output_path}")

# Load the scraped data
file_path = '../data/Scraped_data_output/Cleaned_data.csv'
scraped_data = pd.read_csv(file_path)

# Generate the report
generate_forensic_report(scraped_data, output_path='Comprehensive_Forensic_Analysis_Report.pdf')
