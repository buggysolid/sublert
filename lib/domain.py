import logging

from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound


def domain_sanity_check(domain):  # Verify the domain name sanity
    logger = logging.getLogger(f"sublert-http")
    try:
        domain_ = get_fld(domain, fix_protocol=True)
        return domain_
    except (TldBadUrl, TldDomainNotFound):
        logger.error('Badly formatted domain provided.', domain)
