## What's this about?
Sublert-http is a maintained fork of [sublert](https://github.com/yassineaboukir/sublert). Sublert-http is security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs HTTP requests to determine working subdomains.

## Requirements
- Virtual Private Server (VPS) running on Unix. 
- Python 2.x or 3.x.
- Free Slack workspace.

## Installation & Configuration
Please refer to below article for a detailed technical explanation:
- https://medium.com/@yassineaboukir/automated-monitoring-of-subdomains-for-fun-and-profit-release-of-sublert-634cfc5d7708

## Usage

1. python3 -m venv runtime && source runtime/bin/activate && pip install -r requirements.txt
2. Add hostnames to domains.txt in the output/ directory.
3. Run the script with python3 sublert.py -r 1.1.1.1