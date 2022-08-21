"""
base.py -- client for the base Rinnai API
"""

import datetime, json, logging, time

import requests
from rinnaicontrolr.aws_srp import AWSSRP

LOGGER = logging.getLogger('rinnaicontrolr')

from rinnaicontrolr.const import (
    POOL_ID,
    CLIENT_ID,
    POOL_REGION,
    GRAPHQL_ENDPOINT,
    SHADOW_ENDPOINT,
    GET_DEVICES_PAYLOAD
)

class RinnaiWaterHeater(object):
    # Represents a Rinnai Water Heater, with methods for status and issuing commands

    def __init__(self, username, password, timeout=30):
        """
        timeout is the number of seconds to timeout any HTTPS request after authentication.
        Authentication timeouts are handled by the boto3 client config, which can be
        controled by an environment variable. Also, keep in mind that some functions
        in this API perform multiple HTTPS requests.
        """
        self.username = username
        self.password = password
        self.timeout = timeout
        self.token = {}

    def validate_token(self):
        """Fetch or refresh the access token as needed"""

        now = time.time()
        if now >= self.token.get('expires_at', 0):
            if self.token.get('RefreshToken'):
                self._refresh_token()
            else:
                self._get_initial_token()
        assert now < self.token.get('expires_at', 0), self.token

    def _get_initial_token(self):
        """Authenticate and store the initial access token"""

        aws = AWSSRP(username=self.username, password=self.password, pool_id=POOL_ID,
                     client_id=CLIENT_ID, pool_region=POOL_REGION)
        self._store_token(aws.authenticate_user())

    def _store_token(self, js):
        self.token = js['AuthenticationResult']
        assert 'AccessToken' in self.token, self.token
        assert 'IdToken' in self.token, self.token
        assert 'RefreshToken' in self.token, self.token
        self.token['expires_at'] = time.time() + self.token['ExpiresIn']
        LOGGER.debug(f'received token, expires {self.token["expires_at"]}')

    def _refresh_token(self):
        # Since we've stored the password there's no reason to actually use the
        # refresh token. If we wanted to do so, we could look at renew_access_token()
        # in https://github.com/capless/warrant/blob/master/warrant/__init__.py
        # We don't do that now to avoid unnecessary code paths (and their bugs).
        # NOTE: If Rinnai ever supports 2FA, that would be a reason to use
        # the refresh token instead of re-running the password verifier, but
        # that would also require other changes to this file.
        self._get_initial_token()

    def _set_shadow(self, dev, value: dict):
        """Use the (authenticated) shadow API to set attribute to value
        on device dev."""

        # Call to validate the token now
        self.validate_token()

        data = json.dumps(value)
        headers = {
            'User-Agent': 'okhttp/3.12.1',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip',
            'Accept': 'application/json, text/plain, */*',
            'Authorization': "Bearer {}".format(self.token.get('IdToken')),
        }
        r = requests.patch(SHADOW_ENDPOINT % (dev['thing_name']), data=data, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r

    def get_devices(self):
        """Returns a list of devices, one for each water heater associated
        with self.username. A device is just a dictionary of data for that
        device. If you want to refresh the data for the device,
        call this method again."""

        # We need to call validate_token() here as Rinnai has removed
        # the unauthenticated URL
        self.validate_token()

        payload = GET_DEVICES_PAYLOAD % (self.username)
        headers = {
          'x-amz-user-agent': 'aws-amplify/3.4.3 react-native',
          'x-api-key': 'da2-dm2g4rqvjbaoxcpo4eccs3k5he',
          'Content-Type': 'application/json'
        }

        r = requests.post(GRAPHQL_ENDPOINT, data=payload, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        result = r.json()
        for items in result["data"]['getUserByEmail']['items']:
            for k,v in items['devices'].items():
                return v

    def start_recirculation(self, dev, duration: int):
        """Start recirculation on the specified device. dev is one of the devices
        returned by get_devices()."""
        return self._set_shadow(dev, {"recirculation_duration": str(duration), "set_recirculation_enabled": True})

    def is_recirculating(self, dev):
        return dev['shadow']['recirculation_enabled']

    def set_temperature_setpoint(self, dev, temp: int):
        return self._set_shadow(dev, {'set_priority_status': True, 'set_domestic_temperature': temp})

    def get_temperature_setpoint(self, dev):
        return dev['info']['domestic_temperature']

    def is_heating(self, dev):
        return dev['info']['domestic_combustion'] == 'true'

    @property
    def is_connected(self):
        """Connection status of client with Rinnai Cloud service"""
        return time.time() < self.token.get('expires_at', 0)
