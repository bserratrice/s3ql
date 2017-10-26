'''
oauth_client.py - this file is part of S3QL.

Copyright © 2008 Nikolaus Rath <Nikolaus@rath.org>

This work can be distributed under the terms of the GNU GPLv3.
'''

from .logging import logging, setup_logging, QuietError
from .parse_args import ArgumentParser
import sys
import textwrap
import requests
import time
import re
from urllib import parse
from requests.auth import HTTPBasicAuth
import getpass

log = logging.getLogger(__name__)

# S3QL client id and client secret for Google APIs.
# Don't get your hopes up, this isn't truly secret.
CLIENT_ID = '381875429714-6pch5vnnmqab454c68pkt8ugm86ef95v.apps.googleusercontent.com'
CLIENT_SECRET = 'HGl8fJeVML-gZ-1HSZRNZPz_'

hubic_token_url = 'https://api.hubic.com/oauth/token'
hubic_auth_url = 'https://api.hubic.com/oauth/auth'

def parse_args(args):
    '''Parse command line'''

    parser = ArgumentParser(
        description=textwrap.dedent('''\
        Obtain OAuth2 refresh token for Google Storage or Hubic
        '''))

    parser.add_debug()
    parser.add_quiet()
    parser.add_version()
    
    parser.add_argument("--gs", action="store_true", default=False,
                          help="Google OAuth")
    parser.add_argument("--hubic", action="store_true", default=False,
                          help="Hubic OAuth")
    parser.add_argument("--clientid", help="Client ID (Hubic only)")
    parser.add_argument("--clientsecret", help="Client secret (Hubic only)")

    return parser.parse_args(args)

def _log_response(r):
    '''Log server response'''

    if not log.isEnabledFor(logging.DEBUG):
        return

    s = [ 'Server response:',
          '%03d %s' % (r.status_code, r.reason) ]
    for tup in r.headers.items():
        s.append('%s: %s' % tup)

    s.append('')
    s.append(r.text)

    log.debug('\n'.join(s))

def _parse_response(r):

    _log_response(r)
    if r.status_code != requests.codes.ok:
        raise QuietError('Connection failed with: %d %s'
                         % (r.status_code, r.reason))

    return r.json()

def main(args=None):

    if args is None:
        args = sys.argv[1:]

    options = parse_args(args)
    setup_logging(options)

    cli = requests.Session()

    if options.gs:
        # We need full control in order to be able to update metadata
        # cf. https://stackoverflow.com/questions/24718787
        r = cli.post('https://accounts.google.com/o/oauth2/device/code',
                    data={ 'client_id': CLIENT_ID,
                            'scope': 'https://www.googleapis.com/auth/devstorage.full_control' },
                    verify=True, allow_redirects=False, timeout=20)
        req_json = _parse_response(r)

        print(textwrap.fill('Please open %s in your browser and enter the following '
                                'user code: %s' % (req_json['verification_url'],
                                                req_json['user_code'])))

        while True:
            log.debug('polling..')
            time.sleep(req_json['interval'])

            r = cli.post('https://accounts.google.com/o/oauth2/token',
                        data={ 'client_id': CLIENT_ID,
                                'client_secret': CLIENT_SECRET,
                                'code': req_json['device_code'],
                                'grant_type': 'http://oauth.net/grant_type/device/1.0' },
                        verify=True, allow_redirects=False, timeout=20)
            resp_json = _parse_response(r)
            r.close()

            if 'error' in resp_json:
                if resp_json['error'] == 'authorization_pending':
                    continue
                else:
                    raise QuietError('Authentication failed: ' + resp_json['error'])
            else:
                break

            
    elif options.hubic:
        if options.clientid is None or options.clientsecret is None:
            print("Please enter the client ID and secret on the command line")
            return
        # Authorization request
        client_id = options.clientid
        client_secret = options.clientsecret
        redirect_uri = 'http://localhost/'
        
        data = {'client_id': client_id,
                'redirect_uri': redirect_uri,
                'scope': 'credentials.r',
                'response_type': 'code',
                'state': 'none'}

        log.debug('Request authorization code')
        
        try:
            r = cli.get(hubic_auth_url, params=data)
            oauth_str = re.search('<input type="hidden" name="oauth" value="(\d+)">', r.text).groups()[0]
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            r = cli.post(hubic_auth_url, data = {'credentials':'r','oauth': oauth_str,
                                'action':'accepted','login':username,'user_pwd':password}, allow_redirects=False)
            if not r.is_redirect:
                raise QuietError('Username or password incorrect?')
            oauth_code = parse.parse_qs(parse.urlparse(r.headers['Location']).query)['code']
        except:
            print('Failed. Instead, please open %s?%s in your browser' % (hubic_auth_url, parse.urlencode(data)))
            oauth_code = input('OAuth2 Code (from URL bar after login): ')
        
        data = {'code': oauth_code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'}

        log.debug('Request access token')

        r = cli.post(hubic_token_url, data,
                          auth=HTTPBasicAuth(client_id, client_secret),
                          allow_redirects=False)

        resp_json = _parse_response(r)
    else:
        print("Select Google or hubic")
        return
    
    cli.close()
    print('Success. Your refresh token is:\n',
          resp_json['refresh_token'])
