# Snyk Vulnerability Dashboard — Prototype

A multi-organization vulnerability analysis tool built in two stages: a Jupyter Notebook for data exploration, and a browser-based interactive dashboard that brings those same visualizations to life.

---

## Table of Contents

1. [Dataset](#dataset)
2. [Jupyter Notebook](#jupyter-notebook)
   - [Setup and Dependencies](#setup-and-dependencies)
   - [Data Loading and Parsing](#data-loading-and-parsing)
   - [The Ten Analysis Sections](#the-ten-analysis-sections)
3. [Web Application](#web-application)
   - [Architecture](#architecture)
   - [How Data Loads](#how-data-loads)
   - [Filters](#filters)
   - [KPI Cards](#kpi-cards)
   - [Charts](#charts)
   - [Chart-Specific Data Logic](#chart-specific-data-logic)
4. [Running the Web App](#running-the-web-app)
5. [Using Real Snyk Data](#using-real-snyk-data)
6. [Project Structure](#project-structure)

---

## Dataset

`snyk_vulnerability_dataset.csv` is a synthetic dataset that mirrors the column structure of a Snyk Reporting API export. It contains **~445 issues** across **5 organizations** and **20 projects**.

| Column | Description |
|---|---|
| `issue_id` | Unique identifier for the issue |
| `snyk_id` | Snyk vulnerability ID |
| `issue_type` | `vuln`, `license` |
| `scan_type` | `sca`, `sast`, `iac` |
| `title` | Human-readable vulnerability name |
| `severity` | `critical`, `high`, `medium`, `low` |
| `cvss_score` | CVSS v3 numeric score (0–10) |
| `priority_score` | Snyk priority score (0–1000) |
| `cve_id` | CVE identifier, if applicable |
| `cwe_id` | CWE weakness category |
| `exploit_maturity` | `no-known-exploit`, `proof-of-concept`, `mature` |
| `status` | `open`, `fixed`, `ignored` |
| `is_fixable` | Whether a fix version exists (`True`/`False`) |
| `package_name` | Affected package |
| `current_version` / `fix_version` | Installed and patched versions |
| `package_manager` / `language` | Ecosystem (e.g. `pip`, `Python`) |
| `project_name` / `project_origin` | Project name and source (e.g. `github`) |
| `org_id` / `org_name` / `org_slug` | Organization identifiers |
| `introduced_date` / `discovered_date` | When the issue was introduced and found |
| `resolved_date` / `resolution_days` | When and how long it took to fix |

---

## Jupyter Notebook

`snyk_vulnerability_analysis.ipynb` is the analytical foundation of this prototype. It explores the dataset through ten themed sections, each producing one or two matplotlib/seaborn charts.

### Setup and Dependencies

The notebook installs and imports the following Python libraries:

```python
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
```

It then applies a shared visual style at the top — a seaborn `whitegrid` theme with Snyk's brand severity colors defined as constants:

```python
SEVERITY_COLORS = {'critical': '#AB1A1A', 'high': '#CE5019', 'medium': '#D68000', 'low': '#88879E'}
SEVERITY_ORDER  = ['critical', 'high', 'medium', 'low']
STATUS_COLORS   = {'open': '#CE5019', 'fixed': '#28A745', 'ignored': '#88879E'}
```

These same color constants are carried over into the web application to keep visuals consistent between both tools.

### Data Loading and Parsing

```python
df = pd.read_csv('snyk_vulnerability_dataset.csv')
df['introduced_date'] = pd.to_datetime(df['introduced_date'])
df['discovered_date'] = pd.to_datetime(df['discovered_date'])
df['resolved_date']   = pd.to_datetime(df['resolved_date'], errors='coerce')
df['severity']        = pd.Categorical(df['severity'], categories=SEVERITY_ORDER, ordered=True)
```

Three key transformations happen here:

- Date columns are parsed from ISO strings into proper `datetime` objects so they can be grouped by month or sorted chronologically.
- `resolved_date` uses `errors='coerce'` so that open issues (which have no resolution date) become `NaT` instead of raising an error.
- `severity` is cast to an **ordered Categorical** type. This means pandas knows that `critical > high > medium > low`, which ensures charts always render severity in the correct order without manual sorting.

### The Ten Analysis Sections

**Section 1 — Executive Summary**
Filters for `status == 'open'` and cross-tabulates `org_name` against `severity` using `.groupby().size().unstack()`. Rendered as a `seaborn.heatmap` (left) and a horizontal bar chart of total open issues per org (right). Bars above the median are colored orange-red to draw attention.

**Section 2 — Severity Distribution**
Uses the full dataset (all statuses). Stacks severity counts per organization as a grouped bar chart, and shows the global severity proportion as a pie chart. Together they answer: "where are the most issues, and how severe are they?"

**Section 3 — Vulnerability Discovery Trends**
Groups issues by `discovered_date` rounded to month (`dt.to_period('M')`), then stacks severity bands into a filled area chart over time. The x-axis spans the full date range of the dataset.

**Section 4 — Scan Type Breakdown**
Compares `sca` (Software Composition Analysis), `sast` (Static Application Security Testing), and `iac` (Infrastructure as Code) issue counts per organization. A second chart shows each scan type's severity mix as a 100% stacked horizontal bar, normalizing for volume differences between scan types.

**Section 5 — Technology Stack Risk Profile**
Groups issues by `language` for a stacked horizontal bar ranked by total volume. A companion box plot shows the spread of `cvss_score` values per language for `issue_type == 'vuln'` rows only, with dashed reference lines at CVSS 7.0 (High) and 9.0 (Critical).

**Section 6 — Mean Time to Remediate (MTTR)**
Filters to `status == 'fixed'` and uses the pre-computed `resolution_days` column. Calculates the mean days per org per severity and plots them as a grouped bar chart overlaid with SLA reference lines (15 days for critical, 30 days for high). A violin plot shows the full distribution of remediation times, revealing skew and outliers that a simple mean hides.

**Section 7 — Fixability & Exploit Maturity**
Shows what percentage of each organization's issues have a known fix version (`is_fixable == True`) as a 100% stacked horizontal bar. A second chart cross-tabs `exploit_maturity` against `severity` for vulnerability-type issues only, highlighting how many high/critical vulnerabilities have known working exploits.

**Section 8 — CWE Analysis**
Filters to `issue_type == 'vuln'` with a non-empty `cwe_id`, finds the 10 most frequent weakness categories, and plots them as a horizontal stacked bar broken down by severity. CWE IDs are displayed with their human-readable title (e.g. `CWE-79 — Cross-site Scripting`).

**Section 9 — Project Risk Scatter**
Aggregates open issues per project to produce four metrics: `total_open`, `avg_cvss`, `critical_count`, and `high_count`. These are plotted as a bubble chart where x = total open issues, y = average CVSS score, bubble size = critical count, and bubble color = high count. Projects in the top-right corner with large bubbles are the highest-priority remediation candidates.

**Section 10 — Next Steps**
Documents how to connect the notebook to real Snyk data (via the Reporting API, `snyk-issues-to-csv`, or a UI export) and how to normalize data from other scanners (Trivy, OWASP Dependency-Check, SonarQube) into the same schema.

---

## Web Application

The web app is a direct translation of the notebook into an interactive browser dashboard. No server-side code is required — all data processing runs in the browser.

### Architecture

```
index.html      — Page structure and chart containers
dashboard.css   — Layout, KPI cards, filter chips, responsive grid
dashboard.js    — Data loading, filtering, and all 15 Plotly chart renders
```

Two external libraries are loaded from CDN:

- **[Plotly.js 2.35](https://plotly.com/javascript/)** — renders every chart. Plotly was chosen because it supports every chart type used in the notebook (heatmap, box, violin, stacked area, scatter) and adds interactivity (hover, zoom, pan, PNG export) for free.
- **[PapaParse 5.4](https://www.papaparse.com/)** — parses the CSV file in the browser. It handles header detection, type inference, and empty-row filtering.

### How Data Loads

When the page opens, `init()` runs and attempts to `fetch('snyk_vulnerability_dataset.csv')` from the same directory as `index.html`. If the fetch succeeds, PapaParse parses the raw text into an array of row objects and `parseRow()` coerces each field into the correct type:

```js
cvss_score:      parseFloat(d.cvss_score) || 0
resolution_days: d.resolution_days ? parseFloat(d.resolution_days) : null
is_fixable:      d.is_fixable === 'True'         // string → boolean
discovered_date: new Date(d.discovered_date)     // string → Date
```

If the fetch fails — which happens when the HTML file is opened directly as a `file://` URL due to browser security restrictions — the app falls back to a file upload prompt so the user can select the CSV manually.

Once data is ready, `onDataReady()` stores it in the module-level `allData` array, builds the filter chips from the unique values in the dataset, and calls `renderAll()`.

### Filters

Two filter groups sit in the sticky filter bar: **Organization** and **Scan Type**. Each is rendered as a row of toggle chips built dynamically from the unique values in the loaded dataset.

Clicking a chip calls `handleChipClick()`, which updates either `activeOrgs` or `activeScanTypes` (both are JavaScript `Set` objects). The logic is:

- Clicking **All** clears all individual selections and marks only "All" as active.
- Clicking an individual value deactivates "All" and toggles that value in the set.
- Deselecting the last individual value automatically reactivates "All".

After any chip change, `applyFilters()` runs — it filters `allData` down to `filteredData` by checking each row against both active sets, then calls `renderAll()` to redraw every chart with the new data. Because the dataset is small (~445 rows), this is instant.

The **Reset** button restores both sets to `{ '__all__' }` and re-renders.

### KPI Cards

Five summary numbers update on every filter change:

| Card | Logic |
|---|---|
| Total Issues | `filteredData.length` |
| Critical Open | rows where `status === 'open'` and `severity === 'critical'` |
| High Open | rows where `status === 'open'` and `severity === 'high'` |
| Fixed | rows where `status === 'fixed'` and `resolution_days` is not null |
| Avg MTTR | mean of `resolution_days` across all fixed issues in the selection |

### Charts

All 15 chart render functions follow the same pattern: receive the current `filteredData` array, apply any chart-specific sub-filter internally, build a Plotly traces array, and call `Plotly.react()`. Using `react()` instead of `newPlot()` allows Plotly to diff the previous state and update efficiently rather than destroying and recreating the DOM element.

Every chart shares a `BASE_LAYOUT` object that sets transparent backgrounds, a consistent font stack, light grid lines, and dark tooltip styling. Individual chart functions merge their own margin and axis settings on top of this using the `layout()` helper.

### Chart-Specific Data Logic

Some charts scope their data differently from the global `filteredData`:

| Chart | Internal filter applied |
|---|---|
| Heatmap, Org Totals, Project Scatter | `status === 'open'` only |
| CVSS Box Plot | `issue_type === 'vuln'` and `cvss_score > 0` |
| MTTR Bar, MTTR Violin | `status === 'fixed'` and `resolution_days !== null` |
| Exploit Maturity | `issue_type === 'vuln'` and `exploit_maturity` is non-empty |
| CWE Analysis | `issue_type === 'vuln'` and `cwe_id` is non-empty |
| Severity Distribution, Trends, Scan Type, Language, Fixability | Full `filteredData` (all statuses) |

Each chart also renders an empty-state placeholder if its internal filter returns zero rows — for example, if the user filters to a scan type that has no fixed issues, the MTTR charts show a "No fixed issues in current selection" message instead of a broken chart.

---

## Running the Web App

The dashboard requires a local HTTP server because the browser's `fetch()` API cannot read local files under a `file://` URL. The quickest options:

**Python (no install needed):**
```bash
cd /path/to/snyk_visualization_prototype
python -m http.server 8000
```
Then open `http://localhost:8000` in your browser.

**Node.js (if installed):**
```bash
npx serve .
```

**VS Code:**
Install the [Live Server](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer) extension, right-click `index.html`, and choose "Open with Live Server".

If you cannot run a server, open `index.html` directly in the browser. The app will detect the failed fetch and show a file picker — click "Choose CSV file" and select `snyk_vulnerability_dataset.csv` from the project folder.

---

## Using Real Snyk Data

Replace `snyk_vulnerability_dataset.csv` with an export from any of these sources. The column names in the CSV must match those listed in the [Dataset](#dataset) section above.

**Option 1 — Snyk Reporting API v1**
```
GET https://api.snyk.io/v1/reporting/issues/latest?groupBy=issue
```
Map the response fields to the CSV schema and export as CSV.

**Option 2 — snyk-issues-to-csv CLI**
```bash
npm install -g snyk-issues-to-csv
snyk-issues-to-csv --orgId <your-org-id>
```
This tool outputs a CSV that closely matches the column structure used here.

**Option 3 — Snyk UI Export**
Navigate to **Reports → Issues Detail → Download CSV** in the Snyk web interface.

For the notebook, update the `read_csv` path and confirm the column names match. For the web app, drop the new CSV into the project directory (keeping the filename `snyk_vulnerability_dataset.csv`) and refresh the page.

---

## Project Structure

```
snyk_visualization_prototype/
├── snyk_vulnerability_analysis.ipynb   # Jupyter Notebook (exploration)
├── snyk_vulnerability_dataset.csv      # Synthetic dataset (~445 rows)
├── index.html                          # Web app — page structure
├── dashboard.css                       # Web app — styles
└── dashboard.js                        # Web app — data logic and charts
```
