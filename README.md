# Sysdig Posture Report Analytics

Web-based tool for analyzing Sysdig posture reports and generating executive and security dashboards.

## Features

- Upload CSV or gzipped CSV posture reports
- Executive Dashboard: identify top contributors to compliance failures
- Security Drill-Down: treemap, heatmap, and severity breakdowns
- Downloadable CSV reports

## Setup

### Prerequisites

- Python 3.9+

### Installation

```bash
git clone https://github.com/sysdig/sysdig-coding.git
cd sysdig-coding
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the Web App

```bash
streamlit run app.py
```

The browser will open automatically to `http://localhost:8501`.

## Usage

1. Export your posture report from Sysdig as CSV
2. Open the web app and upload the file via the sidebar
3. View dashboards in the Executive and Security tabs
4. Download summary reports from the Download Reports tab

## Command Line (Alternative)

You can also run the analysis directly from the command line:

```bash
# Place your CSV file in the data/ directory
python analyze_posture.py [data_dir] [output_dir]
```

Output files will be saved to the `output/` directory.
