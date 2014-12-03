daddns
======

DADDNS enables DNS record updates on a DirectAdmin controlled domain.

### Version
1.0.0

### Requirements
* Python 2.7+ or 3.3+
* requests 2.5.0+

### Usage
```
usage: dadns [--help] [--config CONFIG] [--host HOST] [--domain DOMAIN]
             [--name NAME] [--addr ADDR] [--username USERNAME]
             [--password PASSWORD] [--verbose] [--ignore-ssl]
             [--wan-ip-url WAN_IP_URL]

Update a DDNS record on a DirectAdmin hosted domain

optional arguments:
  --help                show this help message and exit

File-based configuration:
  --config CONFIG, -c CONFIG
                        Read configuration from file

Command line configuration:
  --host HOST, -h HOST  DirectAdmin host address
  --domain DOMAIN, -d DOMAIN
                        Domain name to manage
  --name NAME, -n NAME  Host name to change
  --addr ADDR, -a ADDR  IP address for the host name to add/update
  --username USERNAME, -u USERNAME
                        DirectAdmin username
  --password PASSWORD, -p PASSWORD
                        DirectAdmin password or login key (omit for prompt)
  --verbose, -v         Verbose output
  --ignore-ssl, -i      Ignore SSL certificate issues
  --wan-ip-url WAN_IP_URL, -w WAN_IP_URL
                        Service to use for resolving WAN IP (default:
                        http://icanhazip.com/)
```

### Example dadns.conf
```
[daddns]
host = https://myprovider.com:2222/
domain = mydomain.com
username = directadmin_user
password = directadmin_login_key_with_dns_privilege
name = home
ignore-ssl = False
verbose = False
```
