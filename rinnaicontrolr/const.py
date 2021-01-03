"""Constants used by RinnaiWaterHeater"""

DEFAULT_AUTH_HEADERS = {
	"x-amz-user-agent" : "aws-amplify/0.1.x react-native",
	"Content-Type" : "application/x-amz-json-1.1",
}

INIT_AUTH_HEADERS = {
	**DEFAULT_AUTH_HEADERS,
	"x-amz-target" : "AWSCognitoIdentityProviderService.InitiateAuth",
}

RESPOND_TO_AUTH_CHALLENGE_HEADERS = {
	**DEFAULT_AUTH_HEADERS,
	"x-amz-target" : "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
}

BASE_AUTH_URL = "https://cognito-idp.us-east-1.amazonaws.com"

N_HEX = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' + \
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' + \
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' + \
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' + \
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' + \
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' + \
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' + \
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'

G_HEX = '2'

INFO_BITS = bytearray('Caldera Derived Key', 'utf-8')

POOL_ID = 'cognitor-idp.us-east-1.amazonaws.com/us-east-1_OcwpRQbMM'

CLIENT_ID = '5ghq3i6k4p9s7dfu34ckmec91'

GET_DEVICES_PAYLOAD = ("{\r\n    \"query\": \"query GetUserByEmail($email: String, $sortDirection: ModelSortDirection, $filter: ModelRinnaiUserFilterInput, $limit: Int, $nextToken: String) "
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
                   "nextToken\\n          }\\n        }\\n        nextToken\\n      }\\n    }\\n    nextToken\\n  }\\n}\\n\",\r\n    \"variables\": {\r\n        \"email\": \"%s\"\r\n    }\r\n}")
