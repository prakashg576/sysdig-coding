# Sysdig Security Analytics

A web-based tool for analyzing Sysdig security data, including posture compliance reports and container registry vulnerability scans.

## Features

### Posture Analytics
- Upload CSV or gzipped CSV posture compliance reports
- Executive Dashboard: identify top contributors to compliance failures
- Security Drill-Down: interactive treemap, heatmap, and severity breakdowns
- Trend Analysis: compare multiple reports over time
- Downloadable CSV reports for offline analysis

### Vulnerability Analytics
- Fetch container image vulnerability data from Sysdig Registry Scanner API
- Executive Dashboard: top vulnerable images, severity distribution, vendor analysis
- Customizable widget layout with drag-and-drop reordering
- Trend Analysis: track vulnerability changes across snapshots
- Data Explorer: search and filter scanned images
- Export to CSV and JSON formats

## Prerequisites

- Python 3.9+
- Sysdig account with API access (for Vulnerability Analytics)

## Installation

```bash
git clone https://github.com/prakashg576/sysdig-coding.git
cd sysdig-coding
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

### Environment Variables

Set these environment variables before running the application:

| Variable | Required | Description |
|----------|----------|-------------|
| `SYSDIG_API_TOKEN` | For Vulnerability Analytics | Your Sysdig API bearer token |
| `SYSDIG_API_BASE` | Optional | Sysdig API base URL (defaults to US region) |

### Setting Up the Sysdig API Token

1. Log in to your Sysdig console
2. Navigate to **Settings** > **User Profile** > **Sysdig API Token**
3. Copy your API token
4. Set the environment variable:

```bash
# Option 1: Export in terminal (temporary)
export SYSDIG_API_TOKEN="your-api-token-here"

# Option 2: Add to shell profile (persistent)
echo 'export SYSDIG_API_TOKEN="your-api-token-here"' >> ~/.bashrc
source ~/.bashrc

# Option 3: Create a .env file (recommended for development)
echo 'SYSDIG_API_TOKEN=your-api-token-here' > .env
```

**Note:** Never commit your API token to version control. The `.env` file is already in `.gitignore`.

### Regional API Endpoints

Set `SYSDIG_API_BASE` based on your Sysdig region:

| Region | API Base URL |
|--------|--------------|
| US (default) | `https://api.sysdig.com` |
| EU | `https://eu1.app.sysdig.com/api` |
| US West | `https://us2.app.sysdig.com/api` |
| AU | `https://api.au1.sysdig.com` |

Example:
```bash
export SYSDIG_API_BASE="https://eu1.app.sysdig.com/api"
```

## Usage

### Web Application (Recommended)

```bash
streamlit run app.py
```

The browser will open automatically to `http://localhost:8501`.

#### Posture Analytics
1. Select **Posture Analytics** from the sidebar
2. Export your posture report from Sysdig as CSV
3. Upload the file via the sidebar
4. View dashboards in the Executive, Security Drill-Down, and Trend tabs
5. Download summary reports from the Download Reports tab

#### Vulnerability Analytics
1. Select **Vulnerability Analytics** from the sidebar
2. Ensure `SYSDIG_API_TOKEN` is set
3. Click **Fetch Latest Data** to query the Sysdig API
4. Explore the interactive dashboard with customizable widgets
5. Upload multiple JSON snapshots to view trends over time

### Command Line (Alternative)

For posture report analysis without the web interface:

```bash
# Place your CSV file in the data/ directory
python analyze_posture.py [data_dir] [output_dir]

# Example
python analyze_posture.py ./data ./output
```

Output HTML dashboards and CSV reports will be saved to the specified output directory.

## Output Files

The following files are generated (stored locally, not committed to git):

| File | Description |
|------|-------------|
| `executive_dashboard.html` | Overview of top contributors to failures |
| `security_drilldown.html` | Interactive treemap for hierarchical analysis |
| `owner_control_matrix.html` | Heatmap of owner vs. control failures |
| `owner_severity_breakdown.html` | Stacked bar chart by severity |
| `owner_summary.csv` | Summary statistics per owner |
| `actionable_report.csv` | Detailed breakdown for remediation |
| `owner_accounts.csv` | Owner to account mapping |

## Project Structure

```
sysdig-coding/
├── app.py                 # Streamlit web application
├── analyze_posture.py     # Command-line analysis tool
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── data/                 # Input CSV files (gitignored)
└── output/               # Generated reports (gitignored)
```

## Security Notes

- API tokens are loaded from environment variables, never hardcoded
- Output files containing sensitive data are excluded from version control
- The `output/` and `data/` directories are gitignored by default
- Vulnerability snapshots are stored locally in `~/sysdig-vuln-data/`

## License

MIT
