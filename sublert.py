#!/usr/bin/env python

import argparse
import asyncio
import difflib
import json
import os
import queue as queue
import random
import re
import sqlite3
import sys
import threading
import time
import pathlib
from operator import itemgetter

import aiohttp
import psycopg2
import requests
from aiohttp import InvalidURL, ServerDisconnectedError, ClientConnectorError
from dns import asyncresolver
from dns.resolver import NXDOMAIN, NoAnswer, LifetimeTimeout, NoNameservers, YXDOMAIN
from requests import ReadTimeout
from termcolor import colored
from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound

from config import *

version = "1.0.1"
requests.packages.urllib3.disable_warnings()


def cpu_core_count():
    return os.cpu_count()


class URLValidationAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if domain_sanity_check(values):
            setattr(namespace, self.dest, values)
        else:
            exit(-1)


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-u', '--url',
                        dest="target",
                        action=URLValidationAction,
                        help="Domain to monitor. E.g: yahoo.com",
                        required=False)
    parser.add_argument('-t', '--threads',
                        dest="threads",
                        help="Number of concurrent threads to use. Default: 10",
                        type=int,
                        default=cpu_core_count())
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


class cert_database(object):  # Connecting to crt.sh public API to retrieve subdomains
    print('Attempting to gather information via crt.sh')
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
    # Move this to a CLI check, there is no point in getting this far and then checking.
    elif not pathlib.Path('domains.txt').exists():
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
                    domain_to_monitor_ = f'{domain_to_monitor.lower()}\n'
                    domains.write(domain_to_monitor_)
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
                if response.content_length is None:
                    # The database will not be happy if we try to store Nones a integers.
                    return [response.status, 0, response.content_type, url]
                return [response.status, response.content_length, response.content_type, url]
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
    except LifetimeTimeout:
        print(f'DNS query for {url} timed out.')
    except NoNameservers:
        print(f'DNS query for {url} SERVFAIL.')
    except YXDOMAIN:
        print(f'DNS query for {url} is too long.')


async def http_get_request(url):
    ip = await resolve_name_to_ip(url)
    if ip is None:
        return
    ip = 'http://' + ip
    http_response = await get_request(ip)
    if http_response:
        http_response.append('http://' + url)
        return http_response


async def https_get_request(url):
    ip = await resolve_name_to_ip(url)
    if ip is None:
        return
    ip = 'https://' + ip
    https_response = await get_request(ip)
    if https_response:
        https_response.append('https://' + url)
        return https_response


async def check_hostnames_over_http_and_https(new_subdomains):
    dns_results = list()
    subdomains_to_resolve = new_subdomains
    print(colored("\n[!] Performing HTTP and HTTPs GET requests. Please do not interrupt!", "red"))
    for domain in subdomains_to_resolve:
        domain = domain \
            .replace('+ ', '') \
            .replace('*.', '')
        http_url = await http_get_request(domain)
        https_url = await https_get_request(domain)
        if http_url is not None:
            dns_results.append(http_url)
        elif https_url is not None:
            dns_results.append(https_url)
        print(dns_results)

    if dns_results:
        return posting_to_slack(None, True, dns_results)  # Slack new subdomains with DNS ouput


def at_channel():  # control slack @channel
    return ("<!channel> " if at_channel_enabled else "")


def check_and_insert_url(http_responses):
    db_path = 'output/urls.db'
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                status_code INTEGER,
                content_length INTEGER,
                content_type TEXT,
                ip_url TEXT,
                dns_url TEXT PRIMARY KEY
            )
        ''')

        '''
        Sort by several fields.
        
        I want a list of URLs sorted by status code, content-length, mime type and then the url itself.
        
        The goal being to have URLs with 403 Forbidden, application/json and the letter 'a' as in api.x.com to be shown most 
        recently in the slack channel.
        '''
        # status_code
        http_responses.sort(key=itemgetter(0), reverse=True)

        def custom_url_sort(item_):
            # the hostname based url
            item = item_[4]
            # compare the fqdn and not the URI
            return item.split('://')[-1]

        # URL with hostname
        http_responses.sort(key=custom_url_sort)

        '''
        May need to add a another edge case for this sort to handle
        things like application/octet-stream
        
        maybe consider sorting content type header by the first letter after the split?
        '''
        def custom_content_type_sort(item_):
            # the content type header
            item = item_[2]
            # consider the right most half of the content-type header
            # .e.g. application/json will be 'json'
            return item.split('/')[-1]
        # content_type
        http_responses.sort(key=custom_content_type_sort)
        # content_length
        http_responses.sort(key=itemgetter(1), reverse=True)

        for http_response in http_responses:
            status_code, content_length, content_type, ip_url, dns_url = http_response
            c.execute('SELECT dns_url FROM urls WHERE dns_url = ?;', (dns_url,))
            result = c.fetchone()

            if result is None:
                print(f'New URL found. {dns_url}')
                http_response_formatted_for_slack = f'{status_code},{content_length},{content_type},{ip_url},{dns_url}'
                slack(http_response_formatted_for_slack)
                c.execute('''
                            INSERT INTO urls (status_code, content_length, content_type, ip_url, dns_url) 
                            VALUES (?, ?, ?, ?, ?)
                        ''', http_response)
            else:
                print(f'{dns_url} already exists in the database.')

            conn.commit()


def posting_to_slack(result, dns_resolve, dns_output):  # sending result to slack workplace
    global domain_to_monitor
    global new_subdomains
    if dns_resolve:
        check_and_insert_url(dns_output)
    elif result:
        check_and_insert_url(result)


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


if __name__ == '__main__':

    domain_to_monitor = parse_args().target

    queuing()
    multithreading(parse_args().threads)
    new_subdomains = compare_files_diff(domain_to_monitor)

    if not domain_to_monitor and new_subdomains:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(check_hostnames_over_http_and_https(new_subdomains))
    else:
        posting_to_slack(new_subdomains, False, None)
