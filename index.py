"""
Extend the standard S3 presigned URL mechanism to support presigned URLs that
last longer than one hour. This is accomplished by using API Gateway and AWS
Lambda to return HTTP redirect status codes to a freshly generated S3 presigned
URL as long as the outer envelope presigned URL is valid.

The outer presigned URL is cryptographically secured by providing a secret
salt (256 bits) that is used when hashing the request parameters and generating
the request URL.

See: https://kennbrodhagen.net/2016/04/02/how-to-return-302-using-api-gateway-lambda/
See: https://benlog.com/2008/06/19/dont-hash-secrets/
"""

import hmac
import json
import time
from base64 import b64encode, b64decode
import hashlib

import boto3
s3 = boto3.client('s3')

NONCE_TIMEOUT = 10


def assert_common_form(event):
    """
    Ensure that the event contains the appropriate structure and parameters.
    """
    # Every request must contain the salt information provided by API Gateway
    if 'Salt' not in event:
        return False
    else:
        # The salt, if specified, should be at least 256 bits (32 characters)
        if not isinstance(event['Salt'], str) and \
            not isinstance(event['Salt'], unicode):
            return False
        assert len(event['Salt']) > 32


def fetch_object(event):
    """
    Given a request, return the S3 presigned URL for the object.
    """
    s3.generate_presigned_url
    return None


def generate_url(event):
    """
    Generate a URL given request parameters.
    """
    nonce = event['Nonce']
    nonce_ts = event['NoneTimestamp']
    nonce_ts_hmac = event['NonceHMAC']

    cur_ts = time.time()
    if cur_ts - NONCE_TIMEOUT < float(nonce_ts) < cur_ts + NONCE_TIMEOUT:
        return {
            'Error': 'Nonce timestamp is invalid, should be in (%f,%f)' %
            (cur_ts - NONCE_TIMEOUT, cur_ts + NONCE_TIMEOUT)
        }

    # Confirm that the HMAC with the salt of the nonce and timestamp
    ss_nonce_ts_hmac = hmac.new(event['Salt'], nonce + nonce_ts).hexdigest()
    if nonce_ts_hmac != ss_nonce_ts_hmac:
        return {'Error': "Nonce HMAC does not match computed HMAC."}

    object_path = event['ObjectPath']
    start_time = event['StartTime']
    end_time = event['EndTime']
    source_address_list = event['SourceAddresses']

    request = {
        'ObjectPath': object_path,
        'StartTime': start_time,
        'EndTime': end_time,
        'SourceAddresses': source_address_list
    }

    sig = hmac.new(str(event['Salt']),
                   json.dumps(
                       request, sort_keys=True),
                   hashlib.sha256).digest()

    return {
        'URL': "/".join(
            (event['APIDomain'], "object", event['FriendlyName'], b64encode(
                json.dumps(
                    request, sort_keys=True), "-_"), b64encode(sig, "-_")))
    }


def handler(event, context):
    """
    Lambda insertion point.
    """
    assert_common_form(event)
    if 'Method' not in event:
        return None
    if event['Method'] == 'Generate':
        return generate_url(event)
    elif event['Method'] == 'Fetch':
        return fetch_object(event)
    else:
        return None


if __name__ == "__main__":
    import sys
    if not sys.stdin.isatty():
        print handler(json.loads(sys.stdin.read()), None)