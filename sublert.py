#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import random
import re
import sqlite3
import time
from ipaddress import ip_address
from operator import itemgetter

import aiohttp
import psycopg2
import requests
from aiohttp import InvalidURL, ServerDisconnectedError, ClientConnectorError, client_exceptions, http_exceptions
from dns import asyncresolver
from dns.resolver import NXDOMAIN, NoAnswer, LifetimeTimeout, NoNameservers, YXDOMAIN
from requests import ReadTimeout
from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound

from lib.config import get_config


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
    return parser.parse_args()


def domain_sanity_check(domain):  # Verify the domain name sanity
    logger = logging.getLogger(f"sublert-http")
    try:
        domain_ = get_fld(domain, fix_protocol=True)
        return domain_
    except (TldBadUrl, TldDomainNotFound):
        logger.error('Badly formatted domain provided.', domain)


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


def send_healthcheck_to_slack():
    HEALTHCHECK_MESSAGE = 'Sublert is running.'
    slack(HEALTHCHECK_MESSAGE)


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


def crt_sh_query_via_sql(domain):
    # note: globals into config.toml and print() -> logging.info()
    logger = logging.getLogger(f"sublert-http")
    logger.info('Querying crt.sh for %s via SQL.', domain)
    # connecting to crt.sh postgres database to retrieve subdomains.
    unique_domains = set()
    config = get_config()
    try:
        db_name = config.get('DB_NAME')
        db_host = config.get('DB_HOST')
        db_user = config.get('DB_USER')
        conn = psycopg2.connect("dbname={0} user={1} host={2}".format(db_name, db_user, db_host))
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse("
            "lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'));".format(
                domain))
        for result in cursor.fetchall():
            if len(result) == 1:
                # First entry in tuple
                domain = result[0]
                unique_domains.update([domain])
    except psycopg2.DatabaseError as db_error:
        logger.error('Error interacting with database. {} {}' % db_error.pgcode, db_error.pgerror)
    except psycopg2.InterfaceError as db_interface_error:
        logger.error('Database interface error. {} {}' % db_interface_error.pgcode, db_interface_error.pgerror)

    return unique_domains


def crt_sh_query_over_http(domain, wildcard=True):
    logger = logging.getLogger(f"sublert-http")
    logger.info('Querying crt.sh via HTTP.')
    crt_sh_url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0'
    retries = 3
    timeout = 30
    backoff = 2
    success = False
    while retries != 0 and success is not True:
        try:
            req = requests.get(crt_sh_url, headers={'User-Agent': user_agent}, timeout=timeout,
                               verify=False)
            if req.status_code == 200:
                success = True
                content = req.content.decode('utf-8')
                data = json.loads(content)
                for subdomain in data:
                    subdomains.add(subdomain["name_value"].lower())
                return subdomains
        except (TimeoutError, ReadTimeout):
            success = False
            retries -= 1
            timeout *= backoff
            logger.error('Request to https://crt.sh timed out.')


def lookup(domain, wildcard=True):
    lookup_data = crt_sh_query_via_sql(domain)
    if lookup_data:
        return lookup_data
    lookup_data = crt_sh_query_over_http(domain, wildcard)
    if lookup_data:
        return lookup_data


async def get_request(url_with_scheme_using_ip, url_with_scheme_using_hostname, hostname):
    timeout = aiohttp.ClientTimeout(total=5)
    headers = {
        'Host': hostname,
        'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
        'Referer': 'https://www.google.com/'
    }
    # If these regular expression expand any further switch to using lxml or bs4 to actually parse HTML correctly.
    title_regex_pattern = re.compile(r'\<title\>(.*?)\<\/title\>')
    page_title = ''
    form_pattern = re.compile(r"<form[\s\S]*?</form>")
    # SQLite DB has no native boolean type so I am just using 0 and 1.
    has_form = 0
    logger = logging.getLogger(f"sublert-http")
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        try:
            async with session.get(url_with_scheme_using_ip, ssl=False) as response:
                if response.content_length is None:
                    # The database will not be happy if we try to store Nones as an integer.
                    return [response.status, 0, response.content_type, url_with_scheme_using_ip, has_form, page_title,
                            url_with_scheme_using_hostname]
                page_body = await response.content.read()
                page_body_decoded = page_body.decode('UTF-8')
                title_match = title_regex_pattern.search(page_body_decoded)
                if title_match:
                    page_title = title_match.group(1)
                form_match = form_pattern.search(page_body_decoded)
                if form_match:
                    has_form = 1
                return [response.status, response.content_length, response.content_type, url_with_scheme_using_ip,
                        has_form, page_title,
                        url_with_scheme_using_hostname]
        except InvalidURL:
            logger.error('Malformed URL: %s', url_with_scheme_using_ip)
        except ClientConnectorError as client_error:
            logger.error('Cannot connect to: %s', url_with_scheme_using_ip)
        except ServerDisconnectedError:
            logger.error('Server disconnected when trying: %s', url_with_scheme_using_ip)
        except AssertionError:
            logger.error('Something went wrong when trying to resolve: %s', url_with_scheme_using_ip)
        except TimeoutError:
            logger.error('Timed out while waiting for response from %s', url_with_scheme_using_ip)
        except aiohttp.client_exceptions.ClientOSError:
            logger.error('Connection reset by peer when requesting %s', url_with_scheme_using_ip)
        except aiohttp.client_exceptions.TooManyRedirects:
            logger.error('Request for %s resulting in too many redirects.', url_with_scheme_using_ip)
        except aiohttp.http_exceptions.LineTooLong:
            logger.error('Request for %s returned too many lines.', url_with_scheme_using_ip)
        except aiohttp.client_exceptions.ClientResponseError:
            logger.error('Something went wrong on the client side when processing request for %s',
                         url_with_scheme_using_ip)


async def resolve_name_to_ip(url):
    resolver = asyncresolver.Resolver()
    logger = logging.getLogger(f"sublert-http")
    try:
        rdata = await resolver.resolve(url)
        if rdata.rrset:
            if len(rdata.rrset) > 1:
                return random.choice(rdata.rrset.to_rdataset()).address
            elif len(rdata.rrset) == 1:
                return rdata.rrset.to_rdataset()[0].address
    except NXDOMAIN:
        logger.error('%s does not exist.', url)
    except NoAnswer:
        logger.error('There was no answer from the remote nameservers for %s', url)
    except LifetimeTimeout:
        logger.error('DNS query for %s timed out.', url)
    except NoNameservers:
        logger.error('DNS query for %s SERVFAIL.', url)
    except YXDOMAIN:
        logger.error('DNS query for %s is too long.', url)


async def http_get_request(host):
    ip = await resolve_name_to_ip(host)
    if ip is None or ip_address(ip).is_private:
        return
    url_with_scheme_using_ip = 'http://' + ip
    url_with_scheme_using_hostname = 'http://' + host
    http_response = await get_request(url_with_scheme_using_ip, url_with_scheme_using_hostname, host)
    return http_response


async def https_get_request(host):
    ip = await resolve_name_to_ip(host)
    if ip is None or ip_address(ip).is_private:
        return
    url_with_scheme_using_ip = 'https://' + ip
    url_with_scheme_using_hostname = 'https://' + host
    https_response = await get_request(url_with_scheme_using_ip, url_with_scheme_using_hostname, host)
    return https_response


async def check_hostnames_over_http_and_https(domains):
    logger = logging.getLogger(f"sublert-http")
    logger.info("\n[!] Performing HTTP and HTTPs GET requests. Please do not interrupt!")
    dns_results = []
    for domain in domains:
        domain = domain.replace('*.', '')
        http_url = await http_get_request(domain)
        https_url = await https_get_request(domain)
        if http_url:
            dns_results.append(http_url)
        elif https_url:
            dns_results.append(https_url)
    return dns_results


def check_and_insert_url(http_responses):
    db_path = 'output/urls.db'
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()

        # [response.status, response.content_length, response.content_type, ip, has_form, page_title, response.url]
        c.execute('''
            CREATE TABLE IF NOT EXISTS urls (
                status_code INTEGER,
                content_length INTEGER,
                content_type TEXT,
                ip_url TEXT,
                has_form INTEGER,
                page_title TEXT,
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
            item = item_[-1]
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

        logger = logging.getLogger(f"sublert-http")

        for http_response in http_responses:
            status_code, content_length, content_type, ip_url, has_form, page_title, dns_url = http_response
            c.execute('SELECT dns_url FROM urls WHERE dns_url = ?;', (dns_url,))
            result = c.fetchone()

            if result is None:
                logger.info('New URL found. %s', dns_url)
                http_response_formatted_for_slack = f'{status_code},{content_length},{content_type},{ip_url},{has_form},{page_title},{dns_url}'
                slack(http_response_formatted_for_slack)
                c.execute('''
                            INSERT INTO urls (status_code, content_length, content_type, ip_url, has_form, page_title, dns_url) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', http_response)
            else:
                logger.info('%s already exists in the database.', dns_url)

            conn.commit()


def check_for_new_domains(domains):
    db_path = 'output/urls.db'
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS crt_sh_domains (domain_name text PRIMARY KEY)')

    new_domains = []
    logger = logging.getLogger(f"sublert-http")
    for domain in domains:
        # Check if the domain is already in the database
        c.execute('SELECT domain_name FROM crt_sh_domains WHERE domain_name=?', (domain,))
        data = c.fetchone()

        # If the domain is not in the database, insert it
        if data:
            logger.info('Domain %s already exists in the database.', domain)
        else:
            c.execute('INSERT INTO crt_sh_domains (domain_name) VALUES (?)', (domain,))
            new_domains.append(domain)
            logger.info('New domain %s added to database.', domain)

    conn.commit()
    conn.close()

    return new_domains


def main():
    domain_to_monitor = parse_args().target

    # this will go into its own logging module
    logger = logging.getLogger(f"sublert-http")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler('service.log')
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    new_domains = []
    if domain_to_monitor is not None:
        number_of_domains_in_file = 0
        with open('domains.txt') as count_lines_domains_file:
            for line in count_lines_domains_file:
                number_of_domains_in_file += 1
        logger.info(number_of_domains_in_file)
        # I am aware this means there could be dups in the domains.txt file. I am find with that for now.
        with open('domains.txt', 'a') as domains_file:
            if number_of_domains_in_file >= 1:
                domains_file.write(f'\n{domain_to_monitor}')
            elif number_of_domains_in_file < 1:
                domains_file.write(f'{domain_to_monitor}')
        domains_from_cert_lookup = lookup(domain_to_monitor)
        new_domains = check_for_new_domains(domains_from_cert_lookup)
    else:
        with open('domains.txt') as domains_file:
            sld_from_domains_file = [domain.strip('\n') for domain in domains_file.readlines()]
            domains_from_cert_lookup = set()
            for domain in sld_from_domains_file:
                domains_from_cert_lookup.update(lookup(domain))
            new_domains = check_for_new_domains(domains_from_cert_lookup)

    loop = asyncio.get_event_loop()
    if new_domains:
        dns_results = loop.run_until_complete(check_hostnames_over_http_and_https(new_domains))
        check_and_insert_url(dns_results)


if __name__ == '__main__':
    main()
