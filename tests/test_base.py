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
from rinnaicontrolr.base import RinnaiWaterHeater

try:
    wh = RinnaiWaterHeater('not_a_valid_user@gmail.com', 'wrong_password')
    assert False # shouldn't get here
except requests.exceptions.HTTPError as e:
    code = e.response.status_code
    assert code == 400, code

with path_open('test_credentials.json') as jfile:
    js = json.load(jfile)
    wh = RinnaiWaterHeater(js['user'], js['password'])
    for device in wh.getDevices():
        s = device['info']['domestic_combustion']
        # Yes, their API returns a string.
        # We check to make sure the string is valid.
        assert s == 'true' or s == 'false', s
