import json
import logging

import psycopg2
import requests
from requests import ReadTimeout

from lib.config import get_config


def lookup(domain):
    lookup_data = _crt_sh_query_via_sql(domain)
    return lookup_data


def _crt_sh_query_via_sql(domain):
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
