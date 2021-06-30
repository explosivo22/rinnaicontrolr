import secrets, hashlib, hmac, base64
import datetime, json, logging, re, six, time

import requests

LOGGER = logging.getLogger('rinnaicontrolr')

from rinnaicontrolr.const import (
    INIT_AUTH_HEADERS,
    RESPOND_TO_AUTH_CHALLENGE_HEADERS,
    BASE_AUTH_URL,
    N_HEX,
    G_HEX,
    INFO_BITS,
    POOL_ID,
    CLIENT_ID,
    GET_DEVICES_PAYLOAD
)

def hash_sha256(buf):
    a = hashlib.sha256(buf).hexdigest()
    return (64 - len(a)) * '0' + a

def hex_hash(hex_string):
    return hash_sha256(bytearray.fromhex(hex_string))

def hex_to_bytes(hex_string):
    x = bytes.fromhex(hex_string[0][2:])
    return x

def hex_to_long(hex_string):
    return int(hex_string,16)

def long_to_hex(long_num):
    return '%x' % long_num

def get_random(bytes):
    random = secrets.token_hex(bytes)
    return hex_to_long(random)

def pad_hex(long_int):
    """
    Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
    :param {Long integer|String} long_int Number or string to pad.
    :return {String} Padded hex string.
    """
    if not isinstance(long_int, six.string_types):
        hash_str = long_to_hex(long_int)
    else:
        hash_str = long_int
    if len(hash_str) % 2 == 1:
        hash_str = '0%s' % hash_str
    elif hash_str[0] in '89ABCDEFabcdef':
        hash_str = '00%s' % hash_str
    return hash_str

def compute_hkdf(ikm, salt):
    """
    Standard hkdf algorithm
    :param {Buffer} ikm Input key material.
    :param {Buffer} salt Salt value.
    :return {Buffer} Strong key material.
    @private
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info_bits_update = INFO_BITS + bytearray(chr(1), 'utf-8')
    hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
    return hmac_hash[:16]

def calculate_u(big_a, big_b):
    u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
    return hex_to_long(u_hex_hash)

class RinnaiWaterHeater(object):
    # Represents a Rinnai Water Heater, with methods for status and issuing commands

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.pool_id = POOL_ID
        self.client_id = CLIENT_ID
        self.big_n = hex_to_long(N_HEX)
        self.g = hex_to_long(G_HEX)
        self.k = hex_to_long(hex_hash('00' + N_HEX + '0' + G_HEX))
        self.small_a_value = self.generate_random_small_a()
        self.large_a_value = self.calculate_a()
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

        payload = ("{\"AuthFlow\":\"USER_SRP_AUTH\",\"ClientId\":\"%s\",\"AuthParameters\":"
        "{\"USERNAME\":\"%s\",\"SRP_A\":\"%s\"},\"ClientMetadata\":{}}" 
        % (self.client_id,self.username,format(self.large_a_value,'x')))

        r = requests.post(
            BASE_AUTH_URL,
            data=payload,
            headers=INIT_AUTH_HEADERS,
        )
        r.raise_for_status()

        LOGGER.debug("Successfully sent initAuth")
        result = r.json()
        assert result['ChallengeName'] == 'PASSWORD_VERIFIER', result
        payload = self.process_challenge(result['ChallengeParameters'])

        r = requests.post(
            BASE_AUTH_URL,
            data=payload,
            headers=RESPOND_TO_AUTH_CHALLENGE_HEADERS,
        )
        r.raise_for_status()
        self._store_token(r.json())

    def _store_token(self, js):
        self.token = js['AuthenticationResult']
        assert 'AccessToken' in self.token, self.token
        assert 'IdToken' in self.token, self.token
        assert 'RefreshToken' in self.token, self.token
        self.token['expires_at'] = time.time() + self.token['ExpiresIn']
        LOGGER.debug(f'received token, expires {self.token["expires_at"]}')

    def _refresh_token(self):
        payload = ("{\"ClientId\":\"%s\",\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"AuthParameters\":"
                   "\"REFRESH_TOKEN\":\"%s\"}}" % (self.client_id, self.token['RefreshToken']))

        r = requests.post(
            BASE_AUTH_URL,
            data=payload,
            headers=INIT_AUTH_HEADERS,
        )
        r.raise_for_status()
        self._store_token(r.json())

    def getDevices(self):
        self.validate_token()

        payload = GET_DEVICES_PAYLOAD % (self.username)
        headers = {
          'x-amz-user-agent': 'aws-amplify/3.4.3 react-native',
          'x-api-key': 'da2-dm2g4rqvjbaoxcpo4eccs3k5he',
          'Content-Type': 'application/json'
        }

        r = requests.post(
            'https://s34ox7kri5dsvdr43bfgp6qh6i.appsync-api.us-east-1.amazonaws.com/graphql',
            data=payload,
            headers=headers,
        )
        r.raise_for_status()

        result = r.json()
        for items in result["data"]['getUserByEmail']['items']:
            for k,v in items['devices'].items():
                return v

    @property
    def is_connected(self):
        """Connection status of client with Rinnai Cloud service"""
        return time.time() < self.token.get('expires_at', 0)

    def generate_random_small_a(self):
        random_long_int = get_random(128)
        return random_long_int % self.big_n

    def calculate_a(self):
        big_a = pow(self.g, self.small_a_value, self.big_n)
        return big_a

    def get_password_authentication_key(self, username, password, server_b_value, salt):
        u_value = calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError('U cannot be zero.')
        username_password = '%s%s:%s' % (self.pool_id.split('_')[1], username, password)
        username_password_hash = hash_sha256(username_password.encode('utf-8'))

        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self.g, x_value, self.big_n)
        int_value2 = server_b_value - self.k * g_mod_pow_xn
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.big_n)
        hkdf = compute_hkdf(bytearray.fromhex(pad_hex(s_value)), bytearray.fromhex(pad_hex(long_to_hex(u_value))))
        return hkdf

    def process_challenge(self, challenge_parameters):
        user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
        salt_hex = challenge_parameters['SALT']
        srp_b_hex = challenge_parameters['SRP_B']
        secret_block_b64 = challenge_parameters['SECRET_BLOCK']

        timestamp = re.sub(r" 0(\d) ", r" \1 ",
                               datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

        hkdf = self.get_password_authentication_key(user_id_for_srp, self.password, hex_to_long(srp_b_hex), salt_hex)
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = bytearray(self.pool_id.split('_')[1], 'utf-8') + bytearray(user_id_for_srp, 'utf-8') + \
                  bytearray(secret_block_bytes) + bytearray(timestamp, 'utf-8')
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())

        return ("{\"ChallengeName\":\"PASSWORD_VERIFIER\",\"ClientId\":\"%s\",\"ChallengeResponses\":"
                "{\"USERNAME\":\"%s\",\"PASSWORD_CLAIM_SECRET_BLOCK\":\"%s\",\"TIMESTAMP\":\"%s\","
                "\"PASSWORD_CLAIM_SIGNATURE\":\"%s\"},\"ClientMetadata\":{}}" 
                % (self.client_id,user_id_for_srp,secret_block_b64,timestamp,signature_string.decode('utf-8')))

    def start_recirculation(self, thing_name: str, user_uuid: str, duration: int, additional_params={}):
        """start recirculation on the specified device"""
        url = "https://d1coipyopavzuf.cloudfront.net/api/device_shadow/input"

        headers = {
          'User-Agent': 'okhttp/3.12.1',
          'Content-Type': 'application/x-www-form-urlencoded'
        }
        payload = "user=%s&thing=%s&attribute=set_priority_status&value=true" % (user_uuid, thing_name)

        r = requests.post(
            url,
            data=payload,
            headers=headers
        )
        r.raise_for_status()

        payload = "user=%s&thing=%s&attribute=recirculation_duration&value=%s" % (user_uuid, thing_name, duration)
        r = requests.post(
            url,
            data=payload,
            headers=headers
        )
        r.raise_for_status()

        payload = "user=%s&thing=%s&attribute=set_recirculation_enabled&value=true" % (user_uuid, thing_name)
        r = requests.post(
            url,
            data=payload,
            headers=headers
        )
        r.raise_for_status()

        return r
