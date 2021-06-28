import secrets, hashlib, hmac, base64
import datetime, json, logging, re, six, time
from typing import Optional

import requests
from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError

from .errors import RequestError

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
        self._username = username
        self._password = password
        self._pool_id = POOL_ID
        self._client_id = CLIENT_ID
        self._big_n = hex_to_long(N_HEX)
        self._g = hex_to_long(G_HEX)
        self._k = hex_to_long(hex_hash('00' + N_HEX + '0' + G_HEX))
        self._small_a_value = self.generate_random_small_a()
        self._large_a_value = self.calculate_a()
        self._access_token = None
        self._expires_in = None
        self._id_token = None
        self._refresh_token = None
        self._expiry_date = None

    async def auth(self):
        """
        Authenticate and store the tokens
        """

        payload = ("{\"AuthFlow\":\"USER_SRP_AUTH\",\"ClientId\":\"%s\",\"AuthParameters\":"
        "{\"USERNAME\":\"%s\",\"SRP_A\":\"%s\"},\"ClientMetadata\":{}}" 
        % (self._client_id,self._username,format(self._large_a_value,'x')))

        session = ClientSession(timeout=ClientTimeout(total=10))

        try:
            async with session.post(BASE_AUTH_URL,data=payload,headers=INIT_AUTH_HEADERS) as init_auth_resp:
                init_auth_data: dict = await init_auth_resp.json(content_type = None)
                init_auth_resp.raise_for_status()

                logging.info("Successfully sent initAuth")
                payload = self.process_challenge(init_auth_data['ChallengeParameters'])

                try:
                    async with session.post(BASE_AUTH_URL, data=payload, headers=RESPOND_TO_AUTH_CHALLENGE_HEADERS) as respond_auth_challenge_response:
                        respond_data: dict = await respond_auth_challenge_response.json(content_type = None)
                        respond_auth_challenge_response.raise_for_status()

                        logging.info("Successfully responded to Authentication Challenge")
                        self._access_token = respond_data['AuthenticationResult']['AccessToken']
                        self._expires_in = respond_data['AuthenticationResult']['ExpiresIn']
                        self._id_token = respond_data['AuthenticationResult']['IdToken']
                        self._refresh_token = respond_data['AuthenticationResult']['RefreshToken']
                        self._expiry_date = time.time() + respond_data['AuthenticationResult']['ExpiresIn']
                except ClientError as err:
                    raise RequestError(f"There was an error in respond_auth while requesting {BASE_AUTH_URL}") from err
        except ClientError as err:
            raise RequestError(f"There was an error in init_auth while requesting {BASE_AUTH_URL}") from err
        finally:
            await session.close()
        return True

    async def refreshToken(self, accessToken):
        payload = ("{\"ClientId\":\"%s\",\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"AuthParameters\":"
                   "\"REFRESH_TOKEN\":\"%s\"}}" % (self._client_id, accessToken['refresh_token']))

        session = ClientSession(timeout=ClientTimeout(total=10))

        try:
            async with session.post(BASE_AUTH_URL, data=payload, headers=INIT_AUTH_HEADERS) as refresh_response:
                refresh_data: dict = await refresh_refresh_response.json(content_type=None)
                refresh_response.raise_for_status()

                self._access_token = refresh_data['AuthenticationResult']['AccessToken']
                self._expires_in = refresh_data['AuthenticationResult']['ExpiresIn']
                self._id_token = refresh_data['AuthenticationResult']['IdToken']
                self._refresh_token = refresh_data['AuthenticationResult']['RefreshToken']
                self._expiry_date = time.time() + refresh_data['AuthenticationResult']['ExpiresIn']
        except ClientError as err:
            raise RequestError(f"There was an error refreshing the tokens {BASE_AUTH_URL}") from err
        finally:
            await session.close()
        

    async def __acquireToken(self):
        # Fetch and refresh tokens as needed
        data = dict()
        data["refresh_token"] = self._refresh_token

        self._refresh_token = data['refresh_token']
        if self._expiry_date:
            if time.time() >= self._expiry_date:
                logging.info('No token, or has expired, requesting new token')
                await self.refreshToken(data)
        if self._access_token == None:
            #No existing token exists so refreshing library
            await self.auth()
        else:
            logging.info('Token is valid, continuing')
            pass

    async def getDevices(self):
        await self.__acquireToken()

        payload = GET_DEVICES_PAYLOAD % (self._username)
        headers = {
          'x-amz-user-agent': 'aws-amplify/3.4.3 react-native',
          'x-api-key': 'da2-dm2g4rqvjbaoxcpo4eccs3k5he',
          'Content-Type': 'application/json'
        }

        session = ClientSession(timeout=ClientTimeout(total=10))

        try:
            async with session.post('https://s34ox7kri5dsvdr43bfgp6qh6i.appsync-api.us-east-1.amazonaws.com/graphql',data=payload,headers=headers) as resp:
                data: dict = await resp.json(content_type=None)
                resp.raise_for_status()
                for items in data["data"]['getUserByEmail']['items']:
                    for k,v in items['devices'].items():
                        return v
        except ClientError as err:
            raise RequestError(f"There was an error getting the device information") from err
        finally:
            await session.close()

    @property
    def is_connected(self):
        """Connection status of client with Rinnai Cloud service"""
        return bool(self._access_token) and time.time() < self._expiry_date

    def generate_random_small_a(self):
        random_long_int = get_random(128)
        return random_long_int % self._big_n

    def calculate_a(self):
        big_a = pow(self._g, self._small_a_value, self._big_n)
        return big_a

    def get_password_authentication_key(self, username, password, server_b_value, salt):
        u_value = calculate_u(self._large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError('U cannot be zero.')
        username_password = '%s%s:%s' % (self._pool_id.split('_')[1], username, password)
        username_password_hash = hash_sha256(username_password.encode('utf-8'))

        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self._g, x_value, self._big_n)
        int_value2 = server_b_value - self._k * g_mod_pow_xn
        s_value = pow(int_value2, self._small_a_value + u_value * x_value, self._big_n)
        hkdf = compute_hkdf(bytearray.fromhex(pad_hex(s_value)), bytearray.fromhex(pad_hex(long_to_hex(u_value))))
        return hkdf

    def process_challenge(self, challenge_parameters):
        user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
        salt_hex = challenge_parameters['SALT']
        srp_b_hex = challenge_parameters['SRP_B']
        secret_block_b64 = challenge_parameters['SECRET_BLOCK']

        timestamp = re.sub(r" 0(\d) ", r" \1 ",
                               datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

        hkdf = self.get_password_authentication_key(user_id_for_srp, self._password, hex_to_long(srp_b_hex), salt_hex)
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = bytearray(self._pool_id.split('_')[1], 'utf-8') + bytearray(user_id_for_srp, 'utf-8') + \
                  bytearray(secret_block_bytes) + bytearray(timestamp, 'utf-8')
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())

        return ("{\"ChallengeName\":\"PASSWORD_VERIFIER\",\"ClientId\":\"%s\",\"ChallengeResponses\":"
                "{\"USERNAME\":\"%s\",\"PASSWORD_CLAIM_SECRET_BLOCK\":\"%s\",\"TIMESTAMP\":\"%s\","
                "\"PASSWORD_CLAIM_SIGNATURE\":\"%s\"},\"ClientMetadata\":{}}" 
                % (self._client_id,user_id_for_srp,secret_block_b64,timestamp,signature_string.decode('utf-8')))

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

async def async_get_wh(
    username: str, password: str, *, session: Optional[ClientSession] = None
) -> RinnaiWaterHeater:
    wh = RinnaiWaterHeater(username,password)
    await wh.auth()
    return wh