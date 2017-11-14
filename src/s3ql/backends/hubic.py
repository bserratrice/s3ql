from ..logging import logging, QuietError  # Ensure use of custom logger class
from . import swift
from dugong import HTTPConnection, CaseInsensitiveDict
from .common import AuthorizationError, retry
from ..inherit_docstrings import copy_ancestor_docstring
from urllib.parse import urlsplit, urlencode
import re
import urllib.parse
import sys
import threading
import requests
import pprint
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


class Backend(swift.Backend):
    """A backend to store data in Hubic"""

    needs_login = True

    # Hubic endpoints
    token_url = 'https://api.hubic.com/oauth/token'
    auth_url = 'https://api.hubic.com/oauth/auth'
    cred_url = 'https://api.hubic.com/1.0/account/credentials'

    # We don't want to request an access token for each instance,
    # because there is a limit on the total number of valid tokens.
    # This class variable holds the mapping from refresh tokens to
    # access tokens.
    os_token = None
    os_token_expiry = None
    _refresh_lock = threading.Lock()

    def __init__(self, storage_url, login=None, password=None,
                 options=None):

        # Client app creds
        self.client_id, self.client_secret = login.split(':')
        self.refresh_token = password
        self.redirect_uri = 'http://localhost/'

        super().__init__(storage_url, login, password, options)

    @copy_ancestor_docstring
    def _parse_storage_url(self, storage_url, ssl_context):

        # hubic://<containername>/<prefix>
        hit = re.match(r'^[a-zA-Z0-9]+://'  # Backend
                       r'([^/]+)'  # Containername
                       r'(?:/(.*))?$',  # Prefix
                       storage_url)
        if not hit:
            raise QuietError('Invalid storage URL', exitcode=2)

        container_name = hit.group(1)
        prefix = hit.group(2) or ''

        self.container_name = container_name
        self.prefix = prefix

    def __str__(self):
        return 'Hubic container %s, prefix %s' % (self.container_name, self.prefix)

    def _get_os_token(self):

        log.info('Requesting new hubic token')

        payload = {'refresh_token': self.refresh_token,
                   'grant_type': 'refresh_token'}

        log.debug('Refresh access token')

        r = requests.post(self.token_url, payload,
                          auth=HTTPBasicAuth(self.client_id,
                                             self.client_secret),
                          allow_redirects=False)

        log.debug('HTTP Status Code: ' + str(r.status_code))

        if r.status_code != 200:
            log.debug('HTTP Response: ' + pprint.pformat(r))
            raise AuthorizationError(r.json()['error'])

        log.info('Requesting new openstack swift token')

        headers = {'Authorization': 'Bearer ' + r.json()['access_token']}

        # Retrieve storage url and token
        r = requests.get(self.cred_url, headers=headers)

        if r.status_code != 200:
            log.debug('HTTP Response: ' + pprint.pformat(r))
            raise AuthorizationError(r.json()['error'])

        Backend.os_token = r.json()
        Backend.os_token_expiry = (datetime.strptime(r.json()['expires'][:-6],'%Y-%m-%dT%H:%M:%S')
                                   - timedelta(hours=int(r.json()['expires'][-6:-3]),
                                               minutes=int(r.json()['expires'][-2:])))
        log.debug('OS token %s expires at %s' % (Backend.os_token, Backend.os_token_expiry.isoformat()))

    @retry
    def _get_conn(self):
        """Obtain connection to server and authentication token"""
        
        try:
            if not Backend.os_token or Backend.os_token_expiry < datetime.utcnow() + timedelta(minutes=1):
                # check access_token expired
                log.debug('Access token has expired, try to renew it')

                # If we reach this point, then the access token must have
                # expired, so we try to get a new one. We use a lock to prevent
                # multiple threads from refreshing the token simultaneously.
                with Backend._refresh_lock:
                    # Don't refresh if another thread has already done so while
                    # we waited for the lock.
                    self._get_os_token()

            log.debug('started')

            self.auth_token = Backend.os_token['token']
            o = urlsplit(Backend.os_token['endpoint'])
            self.auth_prefix = urllib.parse.unquote(o.path)
            if o.scheme == 'https':
                ssl_context = self.ssl_context
            elif o.scheme == 'http':
                ssl_context = None
            else:
                # fall through to scheme used for authentication
                pass

            log.debug('Connecting to %s:%s' % (o.hostname, o.port))
            conn = HTTPConnection(o.hostname, o.port, proxy=self.proxy,
                                  ssl_context=ssl_context)
            conn.timeout = int(self.options.get('tcp-timeout', 30))
            return conn
        except:
            #If we're having problems, reset the token
            log.debug('Resetting hubic token')
            Backend.os_token = None
            raise