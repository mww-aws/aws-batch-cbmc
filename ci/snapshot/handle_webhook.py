import os
import hashlib
import hmac
import json
import traceback
from pprint import pprint
import clog_writert
from clog_writert import CLogWriter

import boto3


def get_github_secret():
    """Get plaintext for key used by GitHub to compute HMAC"""
    sm = boto3.client('secretsmanager')
    s = sm.get_secret_value(SecretId='GitHubSecret')
    return str(json.loads(s['SecretString'])[0]['Secret'])


def check_hmac(github_signature, payload):
    """
    Check HMAC as suggested here:
    https://developer.github.com/webhooks/securing/
    """
    h = hmac.new(get_github_secret().encode(), payload.encode(), hashlib.sha1)
    signature = 'sha1=' + h.hexdigest()
    return hmac.compare_digest(signature, github_signature)


def lambda_handler(event, context):
    logger = CLogWriter.init_lambda("HandleWebhookLambda", event, context)
    logger.started()

    print("event = ")
    print(json.dumps(event))
    print("context = ")
    pprint(context)

    running = os.environ.get('CBMC_CI_OPERATIONAL')
    if not (running and running.strip().lower() == 'true'):
        print("Ignoring GitHub event: CBMC CI is not running")
        return {'statusCode': 200}

    response = {}
    try:
        event['headers'] = {k.lower(): v
                            for k, v in event['headers'].items()}
        if not check_hmac(
                str(event['headers']['x-hub-signature']),
                str(event['body'])):
            response['statusCode'] = 403
        elif event['headers']['x-github-event'] == 'ping':
            response['body'] = 'pong'
            response['statusCode'] = 200
        else:
            lc = boto3.client('lambda')
            event['correlation_list'] = logger.create_child_correlation_list()
            logger.launch_child("cbmc_ci_start:lambda_handler", None, event['correlation_list'])
            result = lc.invoke(
                FunctionName='${InvokeBatchLambda}',
                Payload=json.dumps(event))
            response['statusCode'] = result['StatusCode']
    except Exception as e:
        response['statusCode'] = 500
        traceback.print_exc()
        print('Error: ' + str(e))
        # raise e

    print("response = ")
    print(json.dumps(response))
    status = clog_writert.SUCCEEDED if (response['statusCode'] >= 200 and response['statusCode'] <= 299) else clog_writert.FAILED
    logger.summary(status, event, response)
    return response