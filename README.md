## What is this?
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

## Usage

The tool default to running once every hour.

1. git clone https://github.com/buggysolid/sublert-http
1. cd sublert-http
1. python3 -m venv runtime && source runtime/bin/activate && pip install -r requirements.txt
1. Edit config/settings.toml to include your slack incoming webhook. https://api.slack.com/messaging/webhooks
1. python3 sublert.py -u tiktokv.com
1. python3 sublert.py

**You have to run it twice because the first pass pulls initial domains and stores them. Then on the next run they will be detected as "new"**