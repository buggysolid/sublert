#!/usr/bin/env python
# coding: utf-8
# Announced and released during OWASP Seasides 2019 & NullCon.
# Huge shout out to the Indian bug bounty community for their hospitality.

import argparse
import asyncio
import difflib
import json
import os
import random
import re
import sqlite3
import sys
import threading

import aiohttp
import psycopg2
import requests
from aiohttp import InvalidURL, ServerDisconnectedError, ClientConnectorError
from dns import asyncresolver
from dns.resolver import NXDOMAIN, NoAnswer
from requests import ReadTimeout
from termcolor import colored
from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound

is_py2 = sys.version[
             0] == "2"  # checks if python version used == 2 in order to properly handle import of Queue module depending on the version used.
if is_py2:
    import Queue as queue
else:
    import queue as queue
from config import *
import time

version = "1.4.8"
requests.packages.urllib3.disable_warnings()


def banner():
    print('''
                   _____       __    __          __
                  / ___/__  __/ /_  / /__  _____/ /_
                  \__ \/ / / / __ \/ / _ \/ ___/ __/
                 ___/ / /_/ / /_/ / /  __/ /  / /_
                /____/\__,_/_.___/_/\___/_/   \__/
    ''')
    print(colored("             Author: Yassine Aboukir (@yassineaboukir)", "red"))
    print(colored("                           Version: {}", "red").format(version))


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-u', '--url',
                        dest="target",
                        help="Domain to monitor. E.g: yahoo.com",
                        required=False)
    parser.add_argument('-t', '--threads',
                        dest="threads",
                        help="Number of concurrent threads to use. Default: 10",
                        type=int,
                        default=10)
    parser.add_argument('-r', '--resolve',
                        dest="resolve",
                        help="Perform DNS resolution.",
                        required=False,
                        nargs='?',
                        const="True")
    parser.add_argument('-l', '--logging',
                        dest="logging",
                        help="Enable Slack-based error logging.",
                        required=False,
                        nargs='?',
                        const="True")
    return parser.parse_args()


def domain_sanity_check(domain):  # Verify the domain name sanity
    try:
        domain_ = get_fld(domain, fix_protocol=True)
        return domain_
    except (TldBadUrl, TldDomainNotFound):
        print(colored(
            "[!] Incorrect domain format. Please follow this format: example.com, http(s)://example.com, www.example.com",
            "red"))


def slack(data):  # posting to Slack
    webhook_url = posting_webhook
    slack_data = {'text': data}
    response = requests.post(
        webhook_url,
        data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )
    if not response.ok:
        error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code,
                                                                                     response.text)
        error_log(error, enable_logging)
    if slack_sleep_enabled:
        time.sleep(1)


def send_healthcheck_to_slack():
    HEALTHCHECK_MESSAGE = 'Sublert is running.'
    slack(HEALTHCHECK_MESSAGE)


def error_log(error, enable_logging):  # log errors and post them to slack channel
    if enable_logging:
        print(colored("\n[!] We encountered a small issue, please check error logging slack channel.", "red"))
        webhook_url = errorlogging_webhook
        slack_data = {'text': '```' + error + '```'}
        response = requests.post(
            webhook_url,
            data=json.dumps(slack_data),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            error = "Request to slack returned an error {}, the response is:\n{}".format(response.status_code,
                                                                                         response.text)
            error_log(error, enable_logging)
    else:
        pass


class cert_database(object):  # Connecting to crt.sh public API to retrieve subdomains
    global enable_logging

    def lookup(self, domain, wildcard=True):
        try:
            # connecting to crt.sh postgres database to retrieve subdomains.
            unique_domains = set()
            domain = domain.replace('%25.', '')
            conn = psycopg2.connect("dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
            conn.autocommit = True
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(
                    domain))
            for result in cursor.fetchall():
                matches = re.findall(r"\'(.+?)\'", str(result))
                for subdomain in matches:
                    try:
                        if get_fld("https://" + subdomain) == domain:
                            unique_domains.add(subdomain.lower())
                    except:
                        pass
            return sorted(unique_domains)
        except:
            base_url = "https://crt.sh/?q={}&output=json"
            if wildcard:
                domain = "%25.{}".format(domain)
                url = base_url.format(domain)
            subdomains = set()
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0'
            retries = 3
            timeout = 30
            backoff = 2
            success = False
            while retries != 0 and success is not True:
                try:
                    req = requests.get(url, headers={'User-Agent': user_agent}, timeout=timeout,
                                       verify=False)
                    if req.status_code == 200:
                        success = True
                        content = req.content.decode('utf-8')
                        data = json.loads(content)
                        for subdomain in data:
                            subdomains.add(subdomain["name_value"].lower())
                        return sorted(subdomains)
                except (TimeoutError, ReadTimeout):
                    success = False
                    retries -= 1
                    timeout *= backoff
                    print('Request to https://crt.sh timed out.')


def queuing():  # using the queue for multithreading purposes
    global domain_to_monitor
    global q1
    global q2
    q1 = queue.Queue(maxsize=0)
    q2 = queue.Queue(maxsize=0)
    if domain_to_monitor:
        pass
    elif os.path.getsize("domains.txt") == 0:
        print(colored("[!] Please consider adding a list of domains to monitor first.", "red"))
        sys.exit(1)
    else:
        with open("domains.txt", "r") as targets:
            for line in targets:
                if line != "":
                    q1.put(line.replace('\n', ''))
                    q2.put(line.replace('\n', ''))
                else:
                    pass


def adding_new_domain(q1):  # adds a new domain to the monitoring list
    unique_list = []
    global domain_to_monitor
    global input
    if domain_to_monitor:
        if not os.path.isfile('./domains.txt'):  # check if domains.txt exist, if not create a new one
            os.system("touch domains.txt")
        else:
            pass
        with open("domains.txt", "r+") as domains:  # checking domain name isn't already monitored
            for line in domains:
                if domain_to_monitor == line.replace('\n', ''):
                    print(
                        colored("[!] The domain name {} is already being monitored.".format(domain_to_monitor), "red"))
                    sys.exit(1)
            response = cert_database().lookup(domain_to_monitor)
            if response:
                with open("./output/" + domain_to_monitor.lower() + ".txt",
                          "a") as subdomains:  # saving a copy of current subdomains
                    for subdomain in response:
                        subdomains.write(subdomain + "\n")
                with open("domains.txt", "a") as domains:  # fetching subdomains if not monitored
                    domains.write(domain_to_monitor.lower() + '\n')
                    print(colored("\n[+] Adding {} to the monitored list of domains.\n".format(domain_to_monitor),
                                  "yellow"))
            else:
                print(colored(
                    "\n[!] Added but unfortunately, we couldn't find any subdomain for {}".format(domain_to_monitor),
                    "red"))
                sys.exit(1)
    else:  # checks if a domain is monitored but has no text file saved in ./output
        try:
            line = q1.get(timeout=10)
            if not os.path.isfile("./output/" + line.lower() + ".txt"):
                response = cert_database().lookup(line)
                if response:
                    with open("./output/" + line.lower() + ".txt", "a") as subdomains:
                        for subdomain in response:
                            subdomains.write(subdomain + "\n")
                else:
                    pass
            else:
                pass
        except queue.Empty:
            pass


def check_new_subdomains(
        q2):  # retrieves new list of subdomains and stores a temporary text file for comparaison purposes
    global domain_to_monitor
    if domain_to_monitor is None:
        try:
            line = q2.get(timeout=10)
            print("[*] Checking {}".format(line))
            with open("./output/" + line.lower() + "_tmp.txt", "a") as subs:
                response = cert_database().lookup(line)
                if response:
                    for subdomain in response:
                        subs.write(subdomain + "\n")
        except queue.Empty:
            pass
    else:
        pass


def compare_files_diff(
        domain_to_monitor):  # compares the temporary text file with previously stored copy to check if there are new subdomains
    global enable_logging
    if domain_to_monitor is None:
        result = []
        with open("domains.txt", "r") as targets:
            for line in targets:
                domain_to_monitor = line.replace('\n', '')
                try:
                    file1 = open("./output/" + domain_to_monitor.lower() + '.txt', 'r')
                    file2 = open("./output/" + domain_to_monitor.lower() + '_tmp.txt', 'r')
                    diff = difflib.ndiff(file1.readlines(), file2.readlines())
                    changes = [l for l in diff if l.startswith('+ ')]  # check if there are new items/subdomains
                    newdiff = []
                    for c in changes:
                        c = c \
                            .replace('+ ', '') \
                            .replace('*.', '') \
                            .replace('\n', '')
                        result.append(c)
                        result = list(set(result))  # remove duplicates
                except:
                    error = "There was an error opening one of the files: {} or {}".format(
                        domain_to_monitor + '.txt', domain_to_monitor + '_tmp.txt')
                    error_log(error, enable_logging)
                    os.system("rm -f ./output/{}".format(line.replace('\n', '') + "_tmp.txt"))
            return (result)


async def get_request(url):
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            async with session.get(url, ssl=False) as response:
                return url
        except InvalidURL:
            print(f'Malformed URL {url}')
        except ClientConnectorError as client_error:
            print(f'Can not connect to {url}')
            print(client_error)
        except ServerDisconnectedError:
            print(f'Server disconnected when trying {url}')
        except AssertionError:
            print(f'Something went wrong when trying to resolve {url}')
        except asyncio.exceptions.TimeoutError:
            print(f'Timed out while waiting for response from {url}')
        except aiohttp.client_exceptions.ClientOSError:
            print(f'Connection reset by peer when requesting {url}')


async def resolve_name_to_ip(url):
    resolver = asyncresolver.Resolver()
    try:
        rdata = await resolver.resolve(url)
        if rdata.rrset:
            if len(rdata.rrset) > 1:
                return random.choice(rdata.rrset.to_rdataset()).address
            elif len(rdata.rrset) == 1:
                return rdata.rrset.to_rdataset()[0].address
    except NXDOMAIN:
        print(f'{url} does not exist.')
    except NoAnswer:
        print(f'There was no answer from the remote nameservers for {url}')


async def http_get_request(url):
    ip = await resolve_name_to_ip(url)
    if ip is None:
        return
    ip = 'http://' + ip
    http_url = await get_request(ip)
    if http_url:
        return 'http://' + url


async def https_get_request(url):
    ip = await resolve_name_to_ip(url)
    if ip is None:
        return
    ip = 'https://' + ip
    http_url = await get_request(ip)
    if http_url:
        return 'https://' + url


async def dns_resolution(new_subdomains):  # Perform DNS resolution on retrieved subdomains
    dns_results = set()
    subdomains_to_resolve = new_subdomains
    print(colored("\n[!] Performing DNS resolution. Please do not interrupt!", "red"))
    for domain in subdomains_to_resolve:
        domain = domain \
            .replace('+ ', '') \
            .replace('*.', '')
        http_url = await http_get_request(domain)
        https_url = await https_get_request(domain)
        if http_url is not None:
            dns_results.add(http_url)
        elif https_url is not None:
            dns_results.add(https_url)
        print(dns_results)

    if dns_results:
        return posting_to_slack(None, True, dns_results)  # Slack new subdomains with DNS ouput


def at_channel():  # control slack @channel
    return ("<!channel> " if at_channel_enabled else "")


def check_and_insert_url(url):
    db_path = 'output/urls.db'
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                url TEXT PRIMARY KEY
            );
        ''')

        c.execute('SELECT url FROM urls WHERE url = ?;', (url,))
        result = c.fetchone()

        if result is None:
            print(f'New URL found. {url}')
            slack(url)
            c.execute('INSERT INTO urls (url) VALUES (?);', (url,))
        else:
            print(f'{url} already exists in the database.')

        conn.commit()


def posting_to_slack(result, dns_resolve, dns_output):  # sending result to slack workplace
    global domain_to_monitor
    global new_subdomains
    if dns_resolve:
        for domain in dns_output:
            check_and_insert_url(domain)
    elif result:
        for domain in result:
            check_and_insert_url(domain)


def multithreading(threads):
    global domain_to_monitor
    threads_list = []
    if not domain_to_monitor:
        num = sum(1 for line in open("domains.txt"))  # minimum threads executed equals the number of monitored domains
        for i in range(max(threads, num)):
            if not (q1.empty() and q2.empty()):
                t1 = threading.Thread(target=adding_new_domain, args=(q1,))
                t2 = threading.Thread(target=check_new_subdomains, args=(q2,))
                t1.start()
                t2.start()
                threads_list.append(t1)
                threads_list.append(t2)
    else:
        adding_new_domain(domain_to_monitor)

    for t in threads_list:
        t.join()


def string_to_bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


if __name__ == '__main__':

    # parse arguments
    dns_resolve = parse_args().resolve
    enable_logging = parse_args().logging
    domain_to_monitor = None
    if parse_args().target:
        domain_to_monitor = domain_sanity_check(parse_args().target)

    # execute the various functions
    banner()
    queuing()
    multithreading(parse_args().threads)
    new_subdomains = compare_files_diff(domain_to_monitor)

    # Check if DNS resolution is checked
    if not domain_to_monitor:
        if dns_resolve and new_subdomains:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(dns_resolution(new_subdomains))
        else:
            posting_to_slack(new_subdomains, False, None)
    else:
        pass
