import logging
import random
import time

import psycopg2

from lib.config import get_config


def lookup(domain):
    db_connection = _connect_to_db()
    db_query_result_set = _crt_sh_query_via_sql(domain, db_connection)
    results = _gather_db_query_results(db_query_result_set)
    return results


def _connect_to_db():
    logger = logging.getLogger(f"sublert-http")
    config = get_config()
    logger.info('Connecting to crt.sh database.')
    try:
        db_name = config.get('DB_NAME')
        db_host = config.get('DB_HOST')
        db_user = config.get('DB_USER')
        conn = psycopg2.connect("dbname={0} user={1} host={2}".format(db_name, db_user, db_host))
        conn.autocommit = True
        return conn
    except psycopg2.DatabaseError as db_error:
        logger.error('Error interacting with database. {} {}' % db_error.pgcode, db_error.pgerror)
    except psycopg2.InterfaceError as db_interface_error:
        logger.error('Database interface error. {} {}' % db_interface_error.pgcode, db_interface_error.pgerror)


def _gather_db_query_results(db_query_result_set_):
    unique_domains = set()
    for result in db_query_result_set_:
        # First entry in tuple
        domain = result[0]
        unique_domains.update([domain])
    return unique_domains


def _crt_sh_query_via_sql(domain, db_connection_):
    # note: globals into config.toml and print() -> logging.info()
    logger = logging.getLogger(f"sublert-http")
    logger.info('Querying crt.sh for %s via SQL.', domain)
    # connecting to crt.sh postgres database to retrieve subdomains.
    config = get_config()
    try:
        # Currently the number of lines in domains.txt defines the number of times this function will be called. So
        # we are O(n) where n is the number of lines in domains.txt meaning this is linear. Ignoring how the DB calls
        # work and network.
        #
        # Let's be kind to the DBMS and sleep between queries.
        time.sleep(random.choice(range(1, 4)))
        with db_connection_.cursor() as cursor:
            cursor.execute(
                "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse("
                "lower(ci.NAME_VALUE)) LIKE reverse(lower('%.{}'));".format(
                    domain))
            db_query_result_set = cursor.fetchall()
            if len(db_query_result_set):
                return db_query_result_set
            else:
                logger.info('No results found for %s', domain)
    except psycopg2.DatabaseError as db_error:
        logger.error('Error interacting with database. {} {}' % db_error.pgcode, db_error.pgerror)
    except psycopg2.InterfaceError as db_interface_error:
        logger.error('Database interface error. {} {}' % db_interface_error.pgcode, db_interface_error.pgerror)
