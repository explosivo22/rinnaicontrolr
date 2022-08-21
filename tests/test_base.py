"""
test for rinnaicontrolr.base

"Because any test is better than no test."

Create a file in this directory called
   test_credentials.json
that contains a dictionary with a "user" key
and a "password" key.

TODO: test more things
TODO: create unittests that have no dependency on external servers
"""

# make it easy to run the test from various places in the tree
import sys
sys.path = ['.', '..'] + sys.path

def path_open(fname, *args, **kwargs):
    """open fname, wherever it may be, and return the file object"""
    for prefix in ['', './tests/', '../tests/']:
        try:
            return open(prefix + fname, *args, **kwargs)
        except FileNotFoundError:
            pass

import json, requests
from botocore.exceptions import ClientError
from rinnaicontrolr.base import RinnaiWaterHeater

wh = RinnaiWaterHeater('not_a_valid_user@gmail.com', 'wrong_password')
try:
    wh.validate_token()
    assert False # shouldn't get here
except ClientError:
    pass

def test_rinnai_water_heater(wh):
    for device in wh.get_devices():
        s = device['info']['domestic_combustion']
        # Yes, their API returns a string, not a bool.
        # We check to make sure the string is valid.
        assert s == 'true' or s == 'false', s

with path_open('test_credentials.json') as jfile:
    js = json.load(jfile)
    wh = RinnaiWaterHeater(js['user'], js['password'])
    wh.validate_token()
    test_rinnai_water_heater(wh)
