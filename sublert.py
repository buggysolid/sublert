#!/usr/bin/env python

import argparse
import asyncio
import logging

from lib.certificate import lookup
from lib.database import check_and_insert_url, check_for_new_domains
from lib.domain import domain_sanity_check
from lib.http import check_hostnames_over_http_and_https


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


def main():
    domain_from_cli_argument = parse_args().target

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
    if domain_from_cli_argument:
        with open('domains.txt', 'a') as domains_file:
            domains_file.write(f'{domain_from_cli_argument}\n')

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
