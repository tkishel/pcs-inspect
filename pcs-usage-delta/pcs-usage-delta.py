#!/usr/bin/env python3

import argparse
from base64 import b64decode
import boto3
import csv
from datetime import datetime, timedelta
import json
import math
import os
from urllib.parse import urlparse, urlencode
import urllib3
import sys

##########################################################################################
# Notification.
##########################################################################################

# Customize this function to meet your notification requirements.

def notify(percentage_change, current_usage_count, resource_count_mean, resource_count_count, percent_change_trigger):
    if percentage_change > 0:
        spike_or_drop = 'Spike'
        increase_or_decrease = 'greater'
    else:
        spike_or_drop = 'Drop'
        increase_or_decrease = 'less'
    output()
    output('NOTIFY: %s !!!' % spike_or_drop) 
    output('NOTIFY: Current resource count (%s) is %s percent %s than the mean resource count (%s).' % (current_usage_count, percentage_change, increase_or_decrease, resource_count_mean))
    output('NOTIFY: This notification is triggered by a delta greater than %s percent, measured over %s samples.' % (percent_change_trigger, resource_count_count))
    output()

##########################################################################################
# Configuration. See also terraform/main.tf for defaults.
##########################################################################################

def configure_defaults():
    result = {}
    result['HISTORICAL_DATA_FILE']        = '~/pcs-usage-history.csv'
    result['HISTORICAL_DATA_TO_RETAIN']   = 30
    result['PERCENT_CHANGE_TRIGGER']      = 10
    result['TIME_RANGE_AMOUNT']           = 1
    result['TIME_RANGE_UNIT']             = 'month'
    result['LAMBDA_HISTORICAL_DATA_FILE'] = '/tmp/pcs-usage-history.csv'
    result['LAMBDA_S3_BUCKET']            = 'pcs-usage-delta'
    result['LAMBDA_S3_OBJECT']            = 'pcs-usage-history.csv'
    result['LAMBDA_KMS_KEY_ID']           = 'alias/pcs_usage_delta_kms_key'
    return result

def command_line_configure():
    defaults = configure_defaults()
    result = {}
    pc_parser = argparse.ArgumentParser(description='This script samples (licensable) resource (and workload) counts.', prog=os.path.basename(__file__))
    pc_parser.add_argument('-u', '--url',
        type=str, required=True,
        help='*Required* Prisma Cloud API URL')
    pc_parser.add_argument('-a', '--access_key',
        type=str, required=True,
        help='*Required* API Access Key')
    pc_parser.add_argument('-s', '--secret_key',
        type=str, required=True,
        help='*Required* API Secret Key')
    pc_parser.add_argument('-d', '--debug',
        action='store_true',
        help='(Optional) Enable debugging')
    pc_parser.add_argument('-ca', '--cloud_account',
        type=str,
        help='(Optional) Cloud Account ID to limit the usage query')
    pc_parser.add_argument('-o', '--output_file',
        type=str, default=defaults['HISTORICAL_DATA_FILE'],
        help="(Optional) Output file to save samples. Default: '%s'" % defaults['HISTORICAL_DATA_FILE'])
    pc_parser.add_argument('-r', '--retain_samples',
        type=int, default=defaults['HISTORICAL_DATA_TO_RETAIN'],
        help='(Optional) Number of samples to retain. Default: %s' % defaults['HISTORICAL_DATA_TO_RETAIN'])
    pc_parser.add_argument('-p', '--percent_trigger',
        type=int, default=defaults['PERCENT_CHANGE_TRIGGER'],
        help='(Optional) Percentage to trigger a notification. Default: %s' % defaults['PERCENT_CHANGE_TRIGGER'])
    pc_parser.add_argument('-ta', '--time_range_amount',
        type=int, default=defaults['TIME_RANGE_AMOUNT'], choices=[1, 2, 3],
        help='(Optional) Time Range Amount to limit the usage query. Default: %s' % defaults['TIME_RANGE_AMOUNT'])
    pc_parser.add_argument('-tu', '--time_range_unit',
        type=str, default=defaults['TIME_RANGE_UNIT'], choices=['day', 'week', 'month', 'year'],
        help="(Optional) Time Range Unit to limit the usage query. Default: '%s'" % defaults['TIME_RANGE_UNIT'])
    pc_parser.add_argument('-c', '--customer_name',
        type=str,
        help='(Optional) Customer Name')
    pc_parser.add_argument('-sa', '--support_api',
        action='store_true',
        help='(Optional) Use the Support API to collect data')
    args = pc_parser.parse_args()
    result['PRISMA_API_ENDPOINT'] = args.url
    result['PRISMA_ACCESS_KEY']   = args.access_key
    result['PRISMA_SECRET_KEY']   = args.secret_key
    result['PRISMA_API_HEADERS']  = {
        'accept': 'application/json; charset=UTF-8',
        'content-type': 'application/json'
    }
    result['DEBUG_MODE']                  = args.debug
    result['PRISMA_API_REQUEST_TIMEOUTS'] = (30, 300) # (CONNECT, READ)
    result['CLOUD_ACCOUNT_ID']            = args.cloud_account
    result['HISTORICAL_DATA_FILE']        = os.path.expanduser(args.output_file)
    result['HISTORICAL_DATA_TO_RETAIN']   = args.retain_samples
    result['PERCENT_CHANGE_TRIGGER']      = args.percent_trigger
    result['TIME_RANGE_AMOUNT']           = args.time_range_amount
    result['TIME_RANGE_UNIT']             = args.time_range_unit
    result['CUSTOMER_NAME']               = args.customer_name
    result['SUPPORT_API_MODE']            = args.support_api
    return result

####

def lambda_configure():
    defaults = configure_defaults()
    result = {}
    result['PRISMA_API_ENDPOINT'] = env_var_or_none('PRISMA_API_ENDPOINT')
    prisma_api_key = env_var_or_none('PRISMA_API_KEY')
    if prisma_api_key:
        try:
            decrypted_prisma_api_key = boto3.client('kms').decrypt(
                CiphertextBlob = b64decode(prisma_api_key),
                KeyId = defaults['LAMBDA_KMS_KEY_ID']
            )['Plaintext']
            if decrypted_prisma_api_key:
                prisma_api_key = json.loads(decrypted_prisma_api_key)
                result['PRISMA_ACCESS_KEY'] = prisma_api_key['PRISMA_ACCESS_KEY']
                result['PRISMA_SECRET_KEY'] = prisma_api_key['PRISMA_SECRET_KEY']
        except Exception as e:
            output('Error with KMS: %s' % e)
    result['PRISMA_API_HEADERS']  = {
        'accept': 'application/json; charset=UTF-8',
        'content-type': 'application/json'
    }
    result['DEBUG_MODE']                  = (env_var_or_none('DEBUG_MODE') == 'true')
    result['PRISMA_API_REQUEST_TIMEOUTS'] = (30, 300) # (CONNECT, READ)
    result['CLOUD_ACCOUNT_ID']            = env_var_or_none('CLOUD_ACCOUNT_ID')
    result['HISTORICAL_DATA_FILE']        = env_var_or_none('HISTORICAL_DATA_FILE')            or defaults['LAMBDA_HISTORICAL_DATA_FILE']
    result['HISTORICAL_DATA_TO_RETAIN']   = env_var_or_none('HISTORICAL_DATA_TO_RETAIN', True) or defaults['HISTORICAL_DATA_TO_RETAIN']
    result['LAMBDA_S3_BUCKET']            = env_var_or_none('LAMBDA_S3_BUCKET')                or defaults['LAMBDA_S3_BUCKET']
    result['LAMBDA_S3_OBJECT']            = env_var_or_none('LAMBDA_S3_OBJECT')                or defaults['LAMBDA_S3_OBJECT']
    result['PERCENT_CHANGE_TRIGGER']      = env_var_or_none('PERCENT_CHANGE_TRIGGER', True)    or defaults['PERCENT_CHANGE_TRIGGER']
    result['TIME_RANGE_AMOUNT']           = env_var_or_none('TIME_RANGE_AMOUNT', True)         or defaults['TIME_RANGE_AMOUNT']
    result['TIME_RANGE_UNIT']             = env_var_or_none('TIME_RANGE_UNIT')                 or defaults['TIME_RANGE_UNIT']
    result['CUSTOMER_NAME']               = ''
    result['SUPPORT_API_MODE']            = False
    if not result['PRISMA_API_ENDPOINT']:
        output('Error: PRISMA_API_ENDPOINT Undefined')
        sys.exit()
    if not result['PRISMA_ACCESS_KEY']:
        output('Error: PRISMA_ACCESS_KEY in PRISMA_API_KEY Undefined')
        sys.exit()
    if not result['PRISMA_SECRET_KEY']:
        output('Error: PRISMA_SECRET_KEY in PRISMA_API_KEY Undefined')
        sys.exit()
    return result

####

def env_var_or_none(var_name, to_int=False):
    var_value = os.environ.get(var_name)
    if var_value == None:
        return None
    var_value_stripped = var_value.strip(' ')
    if var_value_stripped:
        if to_int:
            return int(var_value_stripped)
        else:
            return var_value_stripped
    else:
        return None

##########################################################################################
# Utilities.
##########################################################################################

def make_api_call(config, method, api_url, body_data=None):
    # GlobalProtect generates 'ignore self signed certificate in certificate chain' errors.
    # Set 'SSL_CERT_FILE' to a valid CA bundle including the 'Palo Alto Networks Inc Root CA' used by GlobalProtect.
    # Hint: Copy the bundle provided by the certifi module (locate via 'python -m certifi') and append the 'Palo Alto Networks Inc Root CA' 
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED')
    try:
        resp = http.request(method, api_url, body=body_data, headers=config['PRISMA_API_HEADERS'])
    except urllib3.exceptions.RequestError as e:
        output()
        output('Error with API: URL: %s: Error: %s' % (api_url, str(e)))
        output()
        output('For CERTIFICATE_VERIFY_FAILED errors with GlobalProtect, try setting SSL_CERT_FILE to a bundle with the Palo Alto Networks Inc Root CA.')
        sys.exit()
    if resp.status == 200:
        return resp.data
    else:
        return {}

####

def get_prisma_login(config):
    api_url = '%s/login' % config['PRISMA_API_ENDPOINT']
    body_data = json.dumps({
        "username": config['PRISMA_ACCESS_KEY'],
        "password": config['PRISMA_SECRET_KEY']
    })
    api_response = make_api_call(config, 'POST', api_url, body_data)
    resp_data = json.loads(api_response)
    token = resp_data.get('token')
    if not token:
        output('Error with API Login: %s' % resp_data)
        sys.exit()
    return token

####

def get_cloud_accounts(config):
    account_list = []
    if config['SUPPORT_API_MODE']:
        body_params = {'customerName': '%s' % config['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call(config, 'POST', '%s/_support/cloud' % config['PRISMA_API_ENDPOINT'], request_data)
        api_response_json = json.loads(api_response)
        for account in api_response_json:
            if account['numberOfChildAccounts'] > 0:
                api_response_children = make_api_call(config, 'POST', '%s/_support/cloud/%s/%s/project' % (config['PRISMA_API_ENDPOINT'], account['cloudType'], account['accountId']), request_data)
                account_list.extend(parse_account_children(account, api_response_children))
            else:
                account_list.append(account)
    else:
        api_response = make_api_call(config, 'GET', '%s/cloud' % config['PRISMA_API_ENDPOINT'])
        api_response_json = json.loads(api_response)
        for account in api_response_json:
            if account['accountType'] == 'organization':
                api_response_children = make_api_call(config, 'GET', '%s/cloud/%s/%s/project' % (config['PRISMA_API_ENDPOINT'], account['cloudType'], account['accountId']))
                account_list.extend(parse_account_children(account, api_response_children))
            else:
                account_list.append(account)
    return account_list

def parse_account_children(account, api_response_children):
    children = []
    api_response_children_json = json.loads(api_response_children)
    for child_account in api_response_children_json:
        # Children of an organization include the parent, but numberOfChildAccounts is always reported as zero by the endpoint.
        if account['accountId'] == child_account['accountId']:
            child_account['numberOfChildAccounts'] = account['numberOfChildAccounts']
        children.append(child_account)
    return children

####

def get_cloud_account_usage(config, cloud_account):
    body_params = {
        'accountIds': [cloud_account['accountId']],
        'cloudType': cloud_account['cloudType'],
        'timeRange': {"value": {"unit": "%s" % config['TIME_RANGE_UNIT'], "amount": config['TIME_RANGE_AMOUNT']}, "type": "relative"}
    }
    encoded_query_params = urlencode({'cloud_type': cloud_account['cloudType']})
    if config['SUPPORT_API_MODE']:
        body_params['customerName'] = '%s' % config['CUSTOMER_NAME']
        api_url = '%s/_support/license/api/v1/usage/?%s' % (config['PRISMA_API_ENDPOINT'], encoded_query_params)
    else:
        api_url = '%s/license/api/v1/usage/?%s' % (config['PRISMA_API_ENDPOINT'], encoded_query_params)
    body_data = json.dumps(body_params)
    api_response = make_api_call(config, 'POST', api_url, body_data)
    cloud_account_usage = json.loads(api_response)
    return cloud_account_usage

####

def lambda_download_s3(config):
    bucket_name = config['LAMBDA_S3_BUCKET']
    object_name = config['LAMBDA_S3_OBJECT']
    s3_resource = boto3.resource('s3')
    try:
        pc_delta_bucket = s3_resource.Bucket(bucket_name)
        pc_delta_object = pc_delta_bucket.objects.filter(Prefix=object_name)
        for item in pc_delta_object:
            pc_delta_bucket.download_file(object_name, config['HISTORICAL_DATA_FILE'])
            return True
        else:
            return False
    except Exception as e:
        output('Error with S3 Resource: %s' % e)
        return False

####

def lambda_upload_s3(config):
    bucket_name = config['LAMBDA_S3_BUCKET']
    object_name = config['LAMBDA_S3_OBJECT']
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(config['HISTORICAL_DATA_FILE'], bucket_name, object_name)
        return True
    except Exception as e:
        output('Error with S3 Client: %s' % e)
        return False

####

def output(data=''):
    print(data)

####

# The following allows for differentiating between CSPM resources and CWP workloads.
# Alternatives: data['total'] or data['stats']['stats']['total'] or data['items'][n]['resourceTypeCount']['total']

def count_licensable_usage(usage_data):
    pcs_usage = 0
    pcs_resources = 0
    pcc_workloads = 0
    pcc_workload_keys = ['host', 'container', 'serverless', 'waas']
    if not 'stats' in usage_data:
        return pcs_usage
    if not 'stats' in usage_data['stats']:
        return pcs_usage
    for k in usage_data['stats']['stats'].keys():
        if k == 'total':
            continue
        if k in pcc_workload_keys:
            pcc_workloads += usage_data['stats']['stats'][k]
        else:
            pcs_resources += usage_data['stats']['stats'][k]
    pcs_usage = pcs_resources + pcc_workloads
    return pcs_usage

####

def mean_of_list(usage_data):
    return (sum(usage_data) / float(len(usage_data)))

##########################################################################################
# Main Handler.
##########################################################################################

def common_handler(config):
    current_usage_count = 0
    field_names = ['Date', 'Resources']
    historical_data = []
    today_yyyy_mm_dd = datetime.today().strftime('%Y-%m-%d-%H:%M:%S')
    yesterday_yyyy_mm_dd = (datetime.today() - timedelta(days = 1)).strftime('%Y-%m-%d-%H:%M:%S')

    output('Generating Prisma Cloud API Token')
    token = get_prisma_login(config)
    if config['DEBUG_MODE']:
        output()
        output(token)
        output()
    config['PRISMA_API_HEADERS']['x-redlock-auth'] = token

    output('Querying Cloud Accounts')
    cloud_accounts = get_cloud_accounts(config)
    cloud_accounts = [{'accountId': '%s' % a['accountId'], 'name': '%s' % a['name'], 'cloudType': '%s' % a['cloudType']} for a in cloud_accounts if a['enabled'] == True]

    output('Querying Usage for %s Cloud Accounts' % len(cloud_accounts))
    for cloud_account in cloud_accounts:
        if config['CLOUD_ACCOUNT_ID'] and (cloud_account['accountId'] != config['CLOUD_ACCOUNT_ID']):
            continue
        if config['DEBUG_MODE']:
            output('    Cloud Account ID: %s, Name: %s' % (cloud_account['accountId'], cloud_account['name']))
        else:
            sys.stdout.write('.')
            sys.stdout.flush()
        cloud_account_usage = get_cloud_account_usage(config, cloud_account)
        current_usage_count += count_licensable_usage(cloud_account_usage)

    output()
    output('Current (Licensable) Resource Count: %s' % current_usage_count)
    output()

    # Read historical data; or create historical data with one resource to avoid a divide by zero error.

    if os.path.isfile(config['HISTORICAL_DATA_FILE']) and os.stat(config['HISTORICAL_DATA_FILE']).st_size > 0:
        with open(config['HISTORICAL_DATA_FILE'], 'r') as f:
            csv_reader = csv.DictReader(f, fieldnames=field_names, delimiter = '\t')
            for sample in csv_reader:
                historical_data.append(sample)
    else:
        historical_data = [{"Date": yesterday_yyyy_mm_dd, 'Resources': 1}]

    # Limit historical data to (n) samples.

    historical_data = historical_data[-config['HISTORICAL_DATA_TO_RETAIN']:]

    # Write historical data.

    output('Historical (Licensable) Resource Count:')
    output()

    with open(config['HISTORICAL_DATA_FILE'], 'w') as f:
        csv_writer = csv.DictWriter(f, fieldnames=field_names, delimiter = '\t')
        for sample in historical_data:
            csv_writer.writerow(sample)
            output(sample)
        csv_writer.writerow({'Date': today_yyyy_mm_dd, 'Resources': current_usage_count})

    # Calculon, Compute!

    resource_count_list = []
    for sample in historical_data:
        resource_count_list.append(int(sample['Resources'])) 

    resource_count_count = len(resource_count_list)
    resource_count_mean = math.trunc(mean_of_list(resource_count_list))
    percentage_change = math.trunc((current_usage_count - resource_count_mean) / resource_count_mean * 100)

    if config['DEBUG_MODE']:
        output()
        output('Mean: %s, Percent Change: %s' % (resource_count_mean, percentage_change))
        output()
        output('Current: %s' % current_usage_count)
        output()

    # Notify, if the percentage of change exceeds the trigger.

    if abs(percentage_change) > config['PERCENT_CHANGE_TRIGGER']:
        notify(percentage_change, current_usage_count, resource_count_mean, resource_count_count, config['PERCENT_CHANGE_TRIGGER'])

##########################################################################################
# Main: via AWS Lambda or Command Line
##########################################################################################

def lambda_handler(event, context): 
    config = lambda_configure()
    lambda_download_s3(config)
    common_handler(config)
    result = lambda_upload_s3(config)
    if result:
        return {
            'statusCode': 200,
            'body': 'Success'
       }
    else:
        return {
            'statusCode': 400,
            'body': 'Error'
       }

if __name__ == "__main__":
    config = command_line_configure()
    common_handler(config)
