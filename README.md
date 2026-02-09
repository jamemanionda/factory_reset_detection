# Factory Reset Artifact Analyzer

A GUI-based forensic tool for analyzing Factory Reset artifacts on Android devices.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Artifacts](#supported-artifacts)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

Factory Reset Artifact Analyzer is a comprehensive forensic analysis tool designed to extract and analyze factory reset-related artifacts from Android devices. It supports multiple data sources including ZIP files (from tools like UFED), local folders, and direct ADB connections.

The tool automatically extracts timestamps, converts timezones (UTC ↔ KST), and provides a deep search functionality to find related files across the entire file system.

## Features

### Artifact Analysis
- Automatic extraction and analysis of factory reset artifacts
- Support for multiple data sources:
  - ZIP files (e.g., from UFED extraction)
  - Local folders
  - Direct ADB device connection
- Timezone conversion (UTC ↔ KST)
- Multiple artifact types support

### Deep Search
- File system-wide search based on extracted timestamps
- Multiple search methods:
  - HEX pattern matching
  - File modification time search
  - Text pattern matching
- Configurable time tolerance (default: 5 minutes)

### Result Management
- Automatic result saving (JSON format)
- Load and compare saved results
- Export/Import functionality
- Saved results stored in `saved_results/` folder

### User Interface
- Intuitive GUI built with PyQt5
- Tab-based organization by artifact type
- Time-based sorting and highlighting
- Raw/HEX viewer with search functionality
- Item-level show/hide controls
- Summary results view


<img width="2000" height="1029" alt="image" src="https://github.com/user-attachments/assets/aaaa650f-588e-422e-b39a-c60fbf6949b5" />



## Requirements

### System Requirements
- **Python**: 3.7 or higher
- **Operating System**: Windows, Linux, or macOS
- **Android Debug Bridge (ADB)**: Required for direct device connection (optional)

### Python Dependencies
```
PyQt5 >= 5.15.0
pandas >= 1.3.0
pyaxmlparser >= 0.3.0
```

## Installation

### 1. Clone the Repository
```bash
git clone [<repository-url>](https://github.com/jamemanionda/factory_reset_detection)
cd factory_reset_setting
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install PyQt5 pandas pyaxmlparser
```

### 4. ADB Setup (Optional)
If you plan to use ADB for direct device connection:
- Add ADB to your system PATH, or
- Modify the ADB path in `resetfactory.py`

## Usage

### Basic Execution
```bash
python factory4.py
```

### Workflow

#### 1. Select Analysis Source
Choose your data source:
- **ZIP File**: Select a ZIP file extracted from forensic tools (e.g., UFED)
- **Folder**: Select a local folder path
- **ADB Connection**: Connect directly to an Android device

#### 2. Select Artifacts
Choose which artifacts to analyze:
- Check **"All"** to select/deselect all artifacts
- Or select individual artifacts using checkboxes

#### 3. Run Analysis
1. Click the **"Run Analysis"** button
2. Monitor progress in the log window
3. View results in artifact-specific tabs

#### 4. Deep Search (Optional)
1. After analysis completes, the **"Deep Search"** button becomes active
2. Click to search the file system using extracted timestamps
3. Results appear in the **"Deep Search Results"** tab

#### 5. View Results
- **Summary Results**: Consolidated view of all timestamps from all artifacts
- **Artifact Tabs**: Detailed results for each artifact type
- **Deep Search Results**: Additional files found during deep search

#### 6. View Details
- Click any row in the result tables to open the Raw/HEX viewer
- Matching portions are highlighted
- View binary data in HEX format
- Search functionality within the viewer

### Timezone Settings
- Toggle between KST (Korea Standard Time) and UTC display
- Original timestamps are preserved
- Automatic conversion between timezones

### Filtering
- Filter artifacts by type using checkboxes
- Show/hide individual items
- Right-click context menu for quick actions

## Supported Artifacts

| ID | Artifact Name | Description |
|----|--------------|-------------|
| 1 | bootstat | Boot statistics file |
| 21 | recovery.log | Recovery log file |
| 22 | last_log | Last log file |
| 3 | suggestions.xml | Suggestions configuration file |
| 4 | persistent_properties | Persistent properties file |
| 5 | appops | App permissions settings |
| 6 | wellbing | Wellbeing-related data |
| 7 | internal | Internal settings file |
| 8 | eRR.p | Error log file |
| 9 | ULR_PERSISTENT_PREFS.xml | ULR persistent preferences file |

## Project Structure

```
factory_reset_setting/
├── main.py              # Main GUI application
├── resetfactory.py          # ADB utility functions
├── saved_results/           # Saved analysis results (JSON)
├── README.md                 # This file
└── requirements.txt         # Python package dependencies
```




