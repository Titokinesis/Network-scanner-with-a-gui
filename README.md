# Network-scanner-gui

A multi-threaded desktop application that automates Nmap network reconnaissance, parses the host and service data, and exports structured datasets for security analysis as well.

## Overview
Reading raw Nmap output in a terminal is standard, but organizing that data for client reports or security dashboards requires structuring. This tool solves that by providing a user-friendly CustomTkinter interface to execute local port and service scans against authorized targets, parse the output, and export it as a clean `.xlsx` database file.

## Requirements
* Nmap (should be installed on the host system)
* Python 3
* `python-nmap`, `customtkinter`, `pandas`, `openpyxl`

## Usage
1. Install system dependencies:
```bash
sudo dnf install nmap python3-tkinter
