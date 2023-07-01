#!/usr/bin/env python

import argparse
import asyncio
import logging

from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound

from lib.certificate import lookup
from lib.database import check_and_insert_url, check_for_new_domains
from lib.http import https_get_request, http_get_request
from lib.slack import slack


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


def send_healthcheck_to_slack():
    HEALTHCHECK_MESSAGE = 'Sublert is running.'
    slack(HEALTHCHECK_MESSAGE)


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
            if len(sld_from_domains_file) == 0:
                logger.info('The domains.txt file is empty. Add some domains to monitor with python sublert.py -u')
                exit(-1)
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
