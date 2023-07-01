# What is this?
Sublert-http is a maintained fork of [sublert](https://github.com/yassineaboukir/sublert). 

## What does this do?

You put a list of domains in domains.txt. The tool monitor certificate transparency logs for newly issued certificates.
Any certificate issued that has a CN or SAN that is a child of any of the domains in the domains.txt file will be selected. The tool then issues 
a DNS query to the hostname, then it visits the IP over HTTP or HTTPs recording certain information.

The tool will notify you over slack when it detects new assets.

### Example of output.

```
status_code, content_length, content_type, url_ip, found_form, page_title, hostname_url 
200,9090,text/html,http://127.0.0.1,1,"Admin Login",http://supersecret.bugbountyonhackerone.com
```

## What do you use this tool for?

I use it to monitor for new assets/infrastructure being brought up by bug bounty targets on [Hackerone](https://hackerone.com/directory/programs), [Bugcrowd](https://bugcrowd.com/programs) and [Intigriti](https://www.intigriti.com/programs).

## Requirements
- Python 3.
- Free Slack workspace.

## Setup

The tool defaults to running once every hour via Cron.

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

### Setup Python runtime and install crontab.

```
python3 -m venv runtime && source runtime/bin/activate && pip install -r requirements.txt
cp run.sh /tmp/
crontab config/sublert.cron
```

### Add a domain to monitor.

```
python sublert.py -u just-eat.io
```

Everything should be in place now for the script to run every hour using the provided cron job.
