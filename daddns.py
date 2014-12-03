#!/bin/python

import argparse
import getpass
import logging
import re
import requests
import sys
import urllib

try:
    import configparser
except ImportError:
    # Python 2
    import ConfigParser as configparser


def get_wan_ip(wan_ip_url):
    return requests.get(wan_ip_url).content.rstrip()


class Client(object):
    PROTECTED_HOSTNAMES = ['ftp', 'headers', 'localhost', 'mail', 'pop',
                           'smtp', 'www', 'www.headers']

    def __init__(self, host, wan_ip_url=None, verify_ssl=True, verbose=False):
        self.host = re.sub('/$', '', host)
        self.log = logging.getLogger()
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.timeout = 2

        self.session = requests.session()
        self.authenticated = False

        if self.verbose:
            try:
                import http.client as http_client
            except ImportError:
                # Python 2
                import httplib as http_client
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def __request(self, request_type, command, data={}, args={}):
        url = self.__make_cmd_url(command, args)
        request = getattr(self.session, request_type)
        response = request(url, data=data, timeout=self.timeout,
                           verify=self.verify_ssl, allow_redirects=False)
        return response

    def __post(self, command, data={}, args={}):
        return self.__request('post', command, data, args)

    def __get(self, command, data={}, args={}):
        return self.__request('get', command, data, args)

    def __make_cmd_url(self, command, args=None):
        if args:
            return '{}/{}?{}'.format(self.host, command,
                                     urllib.urlencode(args))
        return '{}/{}'.format(self.host, command)

    def authenticate(self, username, password):
        login_data = {'referer': '/',
                      'username': username,
                      'password': password}
        response = self.__post('CMD_LOGIN', data=login_data)

        if ('X-DirectAdmin' in response.headers
                and response.headers['X-DirectAdmin'] == 'unauthorized'):
            raise RuntimeError('Invalid credentials (authentication failed).')
        self.authenticated = True

    def get_current_ip(self, domain, name):
        assert self.authenticated, 'Not authenticated'
        record = self.get_current_record(domain, name) or [None]
        return record[-1]

    def get_current_record(self, domain, name):
        assert self.authenticated, 'Not authenticated'
        response = self.__get('CMD_API_DNS_CONTROL', args={'domain': domain})
        assert response.status_code == 200, \
            'Invalid HTTP status code {}'.response.status_code

        current_records = re.findall('^{}.*$'.format(name),
                                     response.content,
                                     re.MULTILINE)
        if not len(current_records):
            return None

        current_record = re.sub('[\s]+', ' ', current_records[0]).split(' ')
        return current_record

    def delete_record(self, domain, name, addr):
        assert self.authenticated, 'Not authenticated'
        assert name not in self.PROTECTED_HOSTNAMES, \
            'Cannot change protected host name {}'.format(name)
        response = self.__get('CMD_API_DNS_CONTROL',
                              args={'domain': domain,
                                    'action': 'select',
                                    'arecs0': ('name={}&value={}'
                                               .format(name, addr))})
        response = self.session.get(delete_record_url,
                                    allow_redirects=False)
        assert response.status_code == 200, \
            'Invalid HTTP status code {}'.response.status_code

    def add_record(self, domain, name, addr):
        assert self.authenticated, 'Not authenticated'
        assert name not in self.PROTECTED_HOSTNAMES, \
            'Cannot change protected host name {}'.format(name)
        old_addr = self.get_current_ip(domain, name)
        if old_addr:
            self.delete_record(domain, name, old_addr)
        add_record_url = ('{}/CMD_API_DNS_CONTROL?domain={}&'
                          'action=add&type=A&name={}&value={}'
                          .format(self.host, domain, name, addr))
        response = self.session.get(add_record_url,
                                    allow_redirects=False)
        assert response.status_code == 200, \
            'Invalid HTTP status code {}'.response.status_code
        self.log.info('Record updated ({}.{} now points to {}'
                      .format(domain, name, addr))


def __parser():
    parser = argparse.ArgumentParser(
        prog='dadns', add_help=False,
        description=('Update a DDNS record on a DirectAdmin hosted domain'))
    parser.add_argument('--help',
                        action='help', default=argparse.SUPPRESS,
                        help='show this help message and exit')
    group1 = parser.add_argument_group(title='File-based configuration')
    group1.add_argument('--config', '-c',
                        help='Read configuration from file')

    group2 = parser.add_argument_group(title='Command line configuration')
    group2.add_argument('--host', '-h',
                        help='DirectAdmin host address')
    group2.add_argument('--domain', '-d',
                        help='Domain name to manage')
    group2.add_argument('--name', '-n',
                        help='Host name to change')
    group2.add_argument('--addr', '-a',
                        help=('IP address for the host name to add/update'))
    group2.add_argument('--username', '-u',
                        help='DirectAdmin username')
    group2.add_argument('--password', '-p',
                        help=('DirectAdmin password or login key '
                              '(omit for prompt)'))
    group2.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    group2.add_argument('--ignore-ssl', '-i', action='store_true',
                        help='Ignore SSL certificate issues')
    group2.add_argument('--wan-ip-url', '-w', default='http://icanhazip.com/',
                        help=('Service to use for resolving WAN IP '
                              '(default: http://icanhazip.com/)'))
    return parser


def __get_options_from_config(config_file):
    config = configparser.RawConfigParser(allow_no_value=True)
    config.add_section('daddns')
    config.set('daddns', 'host', None)
    config.set('daddns', 'domain', None)
    config.set('daddns', 'name', None)
    config.set('daddns', 'addr', None)
    config.set('daddns', 'username', None)
    config.set('daddns', 'password', None)
    config.set('daddns', 'ignore-ssl', 'false')
    config.set('daddns', 'verbose', 'false')
    config.readfp(open(config_file))
    return config


def __main(options):

    client = Client(options.host)
    client.authenticate(options.username, options.password)
    old_ip = client.get_current_ip(options.domain, options.name)
    if options.addr == old_ip:
        print('The record is up to date ({}.{} is bound to IP address {}). '
              'No update is needed.'
              .format(options.name, options.domain, options.addr))
        exit(0)

    print('The record needs update ({} != {})'.format(old_ip, options.addr))

    client.add_record(options.domain, options.name, options.addr)
    print('The record was updated ({}.{} is bound to IP address {}).'
          .format(options.name, options.domain, options.addr))
    exit(0)

if __name__ == '__main__':
    try:
        parser = __parser()
        options = parser.parse_args(sys.argv[1:])

        if options.config:
            config_options = __get_options_from_config(options.config)
            for key, value in config_options.items('daddns'):
                setattr(options, key, value)
        else:
            for required_option in ('host', 'domain', 'name', 'username'):
                if (not hasattr(options, required_option)
                        or not getattr(options, required_option)):
                    argument = [arg for arg in parser._actions
                                if arg.dest == required_option][0]
                    raise argparse.ArgumentError(argument, 'is required')

        if not options.addr:
            options.addr = get_wan_ip(options.wan_ip_url)

        if not options.config and not options.password:
            options.password = getpass.getpass('Enter password for {}: '
                                               .format(options.username))
        __main(options)
    except Exception as e:
        print('An error occurred: {}'.format(e))
