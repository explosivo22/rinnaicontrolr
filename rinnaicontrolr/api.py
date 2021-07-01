import secrets, hashlib, hmac, base64
import json, logging, re, six
from datetime import datetime, timedelta, time
from typing import Optional

from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientError

from .errors import RequestError
from .device import Device
from .user import User

from rinnaicontrolr.const import (
    INIT_AUTH_HEADERS,
    RESPOND_TO_AUTH_CHALLENGE_HEADERS,
    BASE_AUTH_URL,
    N_HEX,
    G_HEX,
    INFO_BITS,
    POOL_ID,
    CLIENT_ID,
    GET_USER_PAYLOAD
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

class API(object):
    # Represents a Rinnai Water Heater, with methods for status and issuing commands

    def __init__(self, username: str, password: str, *, session: Optional[ClientSession] = None
    ) -> None:
        self._username: str = username
        self._password: str = password
        self._session: ClientSession = session
        self._pool_id: str = POOL_ID
        self._client_id: str = CLIENT_ID
        self._big_n: int = hex_to_long(N_HEX)
        self._g: int = hex_to_long(G_HEX)
        self._k: int = hex_to_long(hex_hash('00' + N_HEX + '0' + G_HEX))
        self._small_a_value: int = self.generate_random_small_a()
        self._large_a_value: int = self.calculate_a()
        self._access_token: Optional[str] = None
        self._expires_in: Optional[time] = None
        self._id_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._expiry_date: Optional[datetime] = None

        self.device: Device = Device(self._request)

         # These endpoints will get instantiated post-authentication:
        self.user: Optional[User] = None

    async def _request(self, method: str, url: str, **kwargs) -> dict:
        """Make a request against the API."""

        if self._expiry_date and datetime.now() >= self._expiry_date:
            logging.info("Requesting new access token to replace expired one")

            # Nullify the token so that the authentication request doesn't use it:
            self._access_token = None

            # Nullify the expiration so the authentication request doesn't get caught
            # here:
            self._expiry_date = None

            await self.refreshToken()

        use_running_session = self._session and not self._session.closed

        if use_running_session:
            session = self._session
        else:
            session = ClientSession(timeout=ClientTimeout(total=120))

        try:
            async with session.request(method, url, **kwargs) as resp:
                data: dict = await resp.json(content_type=None)
                resp.raise_for_status()
                return data
        except ClientError as err:
            raise RequestError(f"There was an error while requesting {url}") from err
        finally:
            if not use_running_session:
                await session.close()

    async def async_authenticate(self) -> None:
        """
        Authenticate and store the tokens
        """

        payload = ("{\"AuthFlow\":\"USER_SRP_AUTH\",\"ClientId\":\"%s\",\"AuthParameters\":"
        "{\"USERNAME\":\"%s\",\"SRP_A\":\"%s\"},\"ClientMetadata\":{}}" 
        % (self._client_id,self._username,format(self._large_a_value,'x')))

        init_auth_response: dict = await self._request(
            "post",
            BASE_AUTH_URL,
            data=payload,
            headers=INIT_AUTH_HEADERS
        )

        logging.info("Successfully sent initAuth")
        payload = self.process_challenge(init_auth_response['ChallengeParameters'])

        respond_auth_response: dict = await self._request(
            "post",
            BASE_AUTH_URL,
            data=payload,
            headers=RESPOND_TO_AUTH_CHALLENGE_HEADERS
        )

        logging.info("Successfully responded to Authentication Challenge")
        self._access_token = respond_auth_response['AuthenticationResult']['AccessToken']
        self._expires_in = respond_auth_response['AuthenticationResult']['ExpiresIn']
        self._id_token = respond_auth_response['AuthenticationResult']['IdToken']
        self._refresh_token = respond_auth_response['AuthenticationResult']['RefreshToken']
        self._expiry_date = datetime.now() + timedelta(seconds=respond_auth_response['AuthenticationResult']['ExpiresIn'])

        if not self.user:
            self.user = User(self._request, self._username)

    async def refreshToken(self):
        payload = ("{\"ClientId\":\"%s\",\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"AuthParameters\":"
                    "\"REFRESH_TOKEN\":\"%s\"}}" % (self._client_id, self._refresh_token))

        refresh_response: dict = await self._request(
            "post",
            BASE_AUTH_URL,
            data=payload,
            headers=INIT_AUTH_HEADERS
        )

        self._access_token = refresh_response['AuthenticationResult']['AccessToken']
        self._expires_in = refresh_response['AuthenticationResult']['ExpiresIn']
        self._id_token = refresh_response['AuthenticationResult']['IdToken']
        self._refresh_token = refresh_response['AuthenticationResult']['RefreshToken']
        self._expiry_date = datetime.now() + timedelta(seconds=refresh_response['AuthenticationResult']['ExpiresIn'])

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
                               datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

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

async def async_get_api(
    username: str, password: str, *, session: Optional[ClientSession] = None
) -> API:
    wh = API(username,password)
    await wh.async_authenticate()
    return wh