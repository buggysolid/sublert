import logging
import sqlite3
from _operator import itemgetter

from lib.slack import slack


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
