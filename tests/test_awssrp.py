"""
test the SRP flow that we copied from "warrant"
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

import json
from botocore.exceptions import ClientError
from rinnaicontrolr.aws_srp import AWSSRP
from rinnaicontrolr.const import POOL_ID, CLIENT_ID

bad = AWSSRP(username='not_a_valid_user@gmail.com', password='wrong_password', pool_id=POOL_ID,
             client_id=CLIENT_ID, pool_region='us-east-1')
try:
    tokens = bad.authenticate_user()
    assert False, tokens # should not get here
except ClientError:
    pass

with path_open('test_credentials.json') as jfile:
    js = json.load(jfile)
    aws = AWSSRP(username=js['user'], password=js['password'], pool_id=POOL_ID,
                 client_id=CLIENT_ID, pool_region='us-east-1')
    tokens = aws.authenticate_user()
    # if we didn't raise an exception above, the test passes
