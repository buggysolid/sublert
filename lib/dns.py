import logging
import random

from dns import asyncresolver
from dns.resolver import NXDOMAIN, NoAnswer, LifetimeTimeout, NoNameservers, YXDOMAIN


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
