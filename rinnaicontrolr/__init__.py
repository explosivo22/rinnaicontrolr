import secrets
import hashlib
import hmac
import base64
import datetime
import json
import logging
import re
import six
import time

import requests

defaultAuthHeaders = {
	"x-amz-user-agent" : "aws-amplify/0.1.x react-native",
	"Content-Type" : "application/x-amz-json-1.1",
}

initAuthHeaders = {
	**defaultAuthHeaders,
	"x-amz-target" : "AWSCognitoIdentityProviderService.InitiateAuth",
}

respondToAuthChallengeHeaders = {
	**defaultAuthHeaders,
	"x-amz-target" : "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
}

baseAuthUrl = "https://cognito-idp.us-east-1.amazonaws.com"

n_hex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' + \
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' + \
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' + \
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' + \
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' + \
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' + \
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' + \
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'

g_hex = '2'

info_bits = bytearray('Caldera Derived Key', 'utf-8')

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
    info_bits_update = info_bits + bytearray(chr(1), 'utf-8')
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
        self.pool_id = 'cognitor-idp.us-east-1.amazonaws.com/us-east-1_OcwpRQbMM'
        self.client_id = '5ghq3i6k4p9s7dfu34ckmec91'
        self.big_n = hex_to_long(n_hex)
        self.g = hex_to_long(g_hex)
        self.k = hex_to_long(hex_hash('00' + n_hex + '0' + g_hex))
        self.small_a_value = self.generate_random_small_a()
        self.large_a_value = self.calculate_a()
        self.access_token = None
        self.expires_in = None
        self.id_token = None
        self.refresh_token = None
        self.expiry_date = None

        self.__acquireToken()

    def auth(self):
        """
        Authenticate and store the tokens
        """

        payload = ("{\"AuthFlow\":\"USER_SRP_AUTH\",\"ClientId\":\"%s\",\"AuthParameters\":"
        "{\"USERNAME\":\"%s\",\"SRP_A\":\"%s\"},\"ClientMetadata\":{}}" 
        % (self.client_id,self.username,format(self.large_a_value,'x')))

        r = requests.post(
            baseAuthUrl,
            data=payload,
            headers=initAuthHeaders,
        )

        if r.status_code == 200:
            logging.info("Successfully sent initAuth")
            result = r.json()
            payload = self.process_challenge(result['ChallengeParameters'])

            r = requests.post(
                baseAuthUrl,
                data=payload,
                headers=respondToAuthChallengeHeaders,
            )

            if r.status_code == 200:
                result = r.json()
                self.access_token = result['AuthenticationResult']['AccessToken']
                self.expires_in = result['AuthenticationResult']['ExpiresIn']
                self.id_token = result['AuthenticationResult']['IdToken']
                self.refresh_token = result['AuthenticationResult']['RefreshToken']
                self.expiry_date = time.time() + result['AuthenticationResult']['ExpiresIn']
                return True
        else:
            r.raise_for_status()

    def refreshToken(self, accessToken):
        payload = ("{\"ClientId\":\"%s\",\"AuthFlow\":\"REFRESH_TOKEN_AUTH\",\"AuthParameters\":"
                   "\"REFRESH_TOKEN\":\"%s\"}}" % (self.client_id, token['refresh_token']))

        r = requests.post(
            baseAuthUrl,
            data=payload,
            headers=initAuthHeaders,
        )

        if r.status_code == 200:
            result = r.json()
            self.access_token = result['AuthenticationResult']['AccessToken']
            self.expires_in = result['AuthenticationResult']['ExpiresIn']
            self.id_token = result['AuthenticationResult']['IdToken']
            self.refresh_token = result['AuthenticationResult']['RefreshToken']
            self.expiry_date = time.time() + result['AuthenticationResult']['ExpiresIn'] 

    def __acquireToken(self):
        # Fetch and refresh tokens as needed
        data = dict()
        data["refresh_token"] = self.refresh_token

        self.refresh_token = data['refresh_token']
        if self.expiry_date:
            if time.time() >= self.expiry_date:
                logging.info('No token, or has expired, requesting new token')
                self.refreshToken(data)
        if self.access_token == None:
            #No existing token exists so refreshing library
            self.auth()
        else:
            logging.info('Token is valid, continuing')
            pass
        
    def getDevices(self):
        self.__acquireToken()

        payload = ("{\r\n    \"query\": \"query GetUserByEmail($email: String, $sortDirection: ModelSortDirection, $filter: ModelRinnaiUserFilterInput, $limit: Int, $nextToken: String) "
                   "{\\n  getUserByEmail(email: $email, sortDirection: $sortDirection, filter: $filter, limit: $limit, nextToken: $nextToken) {\\n    items {devices {\\n        "
                   "items {\\n          id\\n          thing_name\\n          device_name\\n          dealer_uuid\\n          "
                   "city\\n          state\\n          street\\n          zip\\n          country\\n          firmware\\n          model\\n          dsn\\n          user_uuid\\n          connected_at\\n          "
                   "key\\n          lat\\n          lng\\n          address\\n          vacation\\n          createdAt\\n          updatedAt\\n          activity {\\n            clientId\\n            "
                   "serial_id\\n            timestamp\\n            eventType\\n          }\\n          shadow {\\n            heater_serial_number\\n            ayla_dsn\\n            "
                   "rinnai_registered\\n            do_maintenance_retrieval\\n            model\\n            module_log_level\\n            set_priority_status\\n            "
                   "set_recirculation_enable\\n            set_recirculation_enabled\\n            set_domestic_temperature\\n            set_operation_enabled\\n            schedule\\n            "
                   "schedule_holiday\\n            schedule_enabled\\n            do_zigbee\\n            timezone\\n            timezone_encoded\\n            priority_status\\n            "
                   "recirculation_enabled\\n            recirculation_duration\\n            lock_enabled\\n            operation_enabled\\n            module_firmware_version\\n            "
                   "recirculation_not_configured\\n            maximum_domestic_temperature\\n            minimum_domestic_temperature\\n            createdAt\\n            updatedAt\\n          }"
                   "\\n          monitoring {\\n            serial_id\\n            dealer_uuid\\n            user_uuid\\n            request_state\\n            createdAt\\n            updatedAt\\n            "
                   "dealer {\\n              id\\n              name\\n              email\\n              admin\\n              approved\\n              confirmed\\n              aws_confirm\\n              "
                   "imported\\n              country\\n              city\\n              state\\n              street\\n              zip\\n              company\\n              username\\n              "
                   "firstname\\n              lastname\\n              st_accesstoken\\n              st_refreshtoken\\n              phone_country_code\\n              phone\\n              "
                   "primary_contact\\n              terms_accepted\\n              terms_accepted_at\\n              terms_email_sent_at\\n              terms_token\\n              roles\\n              "
                   "createdAt\\n              updatedAt\\n            }\\n          }\\n          schedule {\\n            items {\\n              id\\n              serial_id\\n              name\\n              "
                   "schedule\\n              days\\n              times\\n              schedule_date\\n              active\\n              createdAt\\n              updatedAt\\n            }\\n            "
                   "nextToken\\n          }\\n          info {\\n            serial_id\\n            ayla_dsn\\n            name\\n            domestic_combustion\\n            domestic_temperature\\n            "
                   "wifi_ssid\\n            wifi_signal_strength\\n            wifi_channel_frequency\\n            local_ip\\n            public_ip\\n            ap_mac_addr\\n            "
                   "recirculation_temperature\\n            recirculation_duration\\n            zigbee_inventory\\n            zigbee_status\\n            lime_scale_error\\n            "
                   "mc__total_calories\\n            type\\n            unix_time\\n            m01_water_flow_rate_raw\\n            do_maintenance_retrieval\\n            aft_tml\\n            "
                   "tot_cli\\n            unt_mmp\\n            aft_tmh\\n            bod_tmp\\n            m09_fan_current\\n            m02_outlet_temperature\\n            firmware_version\\n            "
                   "bur_thm\\n            tot_clm\\n            exh_tmp\\n            m05_fan_frequency\\n            thermal_fuse_temperature\\n            m04_combustion_cycles\\n            "
                   "hardware_version\\n            m11_heat_exchanger_outlet_temperature\\n            bur_tmp\\n            tot_wrl\\n            m12_bypass_servo_position\\n            "
                   "m08_inlet_temperature\\n            m20_pump_cycles\\n            module_firmware_version\\n            error_code\\n            warning_code\\n            internal_temperature\\n            "
                   "tot_wrm\\n            unknown_b\\n            rem_idn\\n            m07_water_flow_control_position\\n            operation_hours\\n            thermocouple\\n            tot_wrh\\n            "
                   "recirculation_capable\\n            maintenance_list\\n            tot_clh\\n            temperature_table\\n            m19_pump_hours\\n            oem_host_version\\n            "
                   "schedule_a_name\\n            zigbee_pairing_count\\n            schedule_c_name\\n            schedule_b_name\\n            model\\n            schedule_d_name\\n            "
                   "total_bath_fill_volume\\n            dt\\n            createdAt\\n            updatedAt\\n          }\\n          errorLogs {\\n            items {\\n              id\\n              "
                   "serial_id\\n              ayla_dsn\\n              name\\n              lime_scale_error\\n              m01_water_flow_rate_raw\\n              m02_outlet_temperature\\n              "
                   "m04_combustion_cycles\\n              m08_inlet_temperature\\n              error_code\\n              warning_code\\n              operation_hours\\n              active\\n              "
                   "createdAt\\n              updatedAt\\n            }\\n            nextToken\\n          }\\n          registration {\\n            items {\\n              serial\\n              "
                   "dealer_id\\n              device_id\\n              user_uuid\\n              model\\n              gateway_dsn\\n              application_type\\n              recirculation_type\\n              "
                   "install_datetime\\n              registration_type\\n              dealer_user_email\\n              active\\n              createdAt\\n              updatedAt\\n            }\\n            "
                   "nextToken\\n          }\\n        }\\n        nextToken\\n      }\\n    }\\n    nextToken\\n  }\\n}\\n\",\r\n    \"variables\": {\r\n        \"email\": \"%s\"\r\n    }\r\n}" % (self.username))
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

        if r.status_code == 200:
            result = r.json()
            for items in result["data"]['getUserByEmail']['items']:
                for k,v in items['devices'].items():
                    return v
        else:
            r.raise_for_status()

    @property
    def is_connected(self):
        """Connection status of client with Rinnai Cloud service"""
        return bool(self.access_token) and time.time() < self.expiry_date

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
