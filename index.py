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
# Get a Boto3 client in the default region of US Standard
# Additional clients in regions matching the buckets will be required later.
# The 'None' region is US Standard.
S3_CLIENTS = {None: boto3.client('s3')}

B64_ALTCHARS = "-_"
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
    try:
        friendly_name = event["FriendlyName"]
        request = json.loads(b64decode(str(event["Request"]), B64_ALTCHARS))
        client_sig = b64decode(str(event["Signature"]), B64_ALTCHARS)
    except:
        return "BADREQUEST: Malformed parameters"

    # Validate the signature of the request.
    server_sig = hmac.new(str(event['Salt']),
                          json.dumps(
                              request, sort_keys=True),
                          hashlib.sha256).digest()

    if server_sig != client_sig:
        return "UNAUTHORIZED: Signature mismatch"

    # Confirm that the validity interval is valid.
    cur_ts = time.time()
    if cur_ts < request['StartTime'] or cur_ts > request['EndTime']:
        return "FORBIDDEN: Timestamp mismatch"

    s3_client = S3_CLIENTS[event['BucketRegion']]
    url = s3_client.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': event['S3Bucket'],
            'Key': (event['S3Prefix'] + "/"
                    if event['S3Prefix'] != "" else "") + request['ObjectPath']
        })
    return {'Location': url}


def generate_url(event):
    """
    Generate a URL given request parameters.
    """
    # nonce = event['Nonce']
    # nonce_ts = event['NoneTimestamp']
    # nonce_ts_hmac = event['NonceHMAC']

    # cur_ts = time.time()
    # if cur_ts - NONCE_TIMEOUT < float(nonce_ts) < cur_ts + NONCE_TIMEOUT:
    #     return {
    #         'Error': 'Nonce timestamp is invalid, should be in (%f,%f)' %
    #         (cur_ts - NONCE_TIMEOUT, cur_ts + NONCE_TIMEOUT)
    #     }

    # # Confirm that the HMAC with the salt of the nonce and timestamp
    # ss_nonce_ts_hmac = hmac.new(event['Salt'], nonce + nonce_ts).hexdigest()
    # if nonce_ts_hmac != ss_nonce_ts_hmac:
    #     return {'Error': "Nonce HMAC does not match computed HMAC."}

    object_path = event['ObjectPath']
    start_time = event['StartTime']
    end_time = event['EndTime']
    source_address_list = event.get('SourceAddresses', None)

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
                    request, sort_keys=True), B64_ALTCHARS),
             b64encode(sig, B64_ALTCHARS)))
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
        bucket = event.get('S3Bucket', None)
        if bucket is None:
            return None
        else:
            s3 = S3_CLIENTS[None]
            bucket_location = s3.get_bucket_location(Bucket=bucket)
            # The US Standard region has a LocationConstraint of None.
            bucket_region = bucket_location.get('LocationConstraint', None)
            if bucket_region is not None and bucket_region not in S3_CLIENTS:
                S3_CLIENTS[bucket_region] = boto3.client('s3', bucket_region)
            event['BucketRegion'] = bucket_region
        return fetch_object(event)
    else:
        return None


if __name__ == "__main__":
    import sys
    if not sys.stdin.isatty():
        print handler(json.loads(sys.stdin.read()), None)
