"""Constants used by RinnaiWaterHeater"""

POOL_ID = 'cognitor-idp.us-east-1.amazonaws.com/us-east-1_OcwpRQbMM'
CLIENT_ID = '5ghq3i6k4p9s7dfu34ckmec91'
POOL_REGION = 'us-east-1'

GRAPHQL_ENDPOINT = 'https://s34ox7kri5dsvdr43bfgp6qh6i.appsync-api.us-east-1.amazonaws.com/graphql'
SHADOW_ENDPOINT = 'https://d1coipyopavzuf.cloudfront.net/api/device_shadow/input'

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
