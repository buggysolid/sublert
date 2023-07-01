## What's this about?
Sublert-http is a maintained fork of [sublert](https://github.com/yassineaboukir/sublert). Sublert-http is security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs HTTP requests to determine working subdomains.

## Requirements
- Virtual Private Server (VPS) running on Unix. 
- Python 3.
- Free Slack workspace.

## Setup

### Install git

Copy and paste the below into your terminal.  

```
cat<<EOF | sudo /usr/bin/env bash
if [[ -f "/usr/bin/apt" ]]; then
  apt update
  apt install -y git
elif [[ -f "/usr/bin/yum" ]]; then
  yum makecache
  yum install -y git
else
  echo "Could not determine which package manager is installed."
  exit
fi
EOF
```

### Clone the repo

Make sure to update your config/settings.toml file with the webhooks from slack so you get notifications.  

https://api.slack.com/apps/  

```
git clone https://github.com/buggysolid/sublert-http
cd sublert-http
vi config/settings.toml
```

### Run setup.sh

```
sudo ./setup.sh
```

### Add a domain to monitor.

```
source runtime/bin/activate
python sublert.py -u just-eat.io
```

Everything should be in place now for the script to run every hour using the provided cron job.
