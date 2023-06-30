import json
import logging
import random
import time

import requests

from lib.config import get_config


def error_log(error):  # log errors and post them to slack channel
    logger = logging.getLogger(f"sublert-http")
    logger.error("\n[!] We encountered a small issue, please check error logging slack channel.")
    config = get_config()
    webhook_url = config.get('errorlogging_webhook')
    slack_data = {'text': '```' + error + '```'}
    response = requests.post(
        webhook_url,
        data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if response.status_code != 200:
        error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code,
                                                                                     response.text)
        error_log(error)


def slack(data):  # posting to Slack
    config = get_config()
    webhook_url = config.get('posting_webhook')
    slack_data = {'text': data}
    response = requests.post(
        webhook_url,
        data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if not response.ok:
        error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code,
                                                                                     response.text)
        error_log(error)
        # should really go through the whole retry, backoff, timeout dance but this will do. Maybe add a jitter to the
        # random range selection.
        time.sleep(random.choice(range(1, 3)))
