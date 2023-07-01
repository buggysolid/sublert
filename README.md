## What's this about?
Sublert-http is a maintained fork of [sublert](https://github.com/yassineaboukir/sublert). Sublert-http is security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs HTTP requests to determine working subdomains.

## Requirements
- Virtual Private Server (VPS) running on Unix. 
- Python 3.
- Free Slack workspace.

## Usage

1. git clone https://github.com/buggysolid/sublert-http
1. cd sublert-http
1. python3 -m venv runtime && source runtime/bin/activate && pip install -r requirements.txt
1. python3 sublert.py -u tiktokv.com
1. Edit config.py to include your slack incoming webhook. https://api.slack.com/messaging/webhooks
1. python3 sublert.py
1. python3 sublert.py

**You have to run it twice because the first pass pulls initial domains and stores them. Then on the next run they will be detected as "new"**