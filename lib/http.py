import logging
import re
from ipaddress import ip_address

import aiohttp
from aiohttp import InvalidURL, ClientConnectorError, ServerDisconnectedError

from lib.dns import resolve_name_to_ip


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


async def https_get_request(host):
    ip = await resolve_name_to_ip(host)
    if ip is None or ip_address(ip).is_private:
        return
    url_with_scheme_using_ip = 'https://' + ip
    url_with_scheme_using_hostname = 'https://' + host
    https_response = await get_request(url_with_scheme_using_ip, url_with_scheme_using_hostname, host)
    return https_response


async def http_get_request(host):
    ip = await resolve_name_to_ip(host)
    if ip is None or ip_address(ip).is_private:
        return
    url_with_scheme_using_ip = 'http://' + ip
    url_with_scheme_using_hostname = 'http://' + host
    http_response = await get_request(url_with_scheme_using_ip, url_with_scheme_using_hostname, host)
    return http_response
