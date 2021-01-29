#!/usr/bin/env python3

import argparse
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
    print()
    print('NOTIFY: %s !!!' % spike_or_drop) 
    print('NOTIFY: Current resource count (%s) is %s percent %s than the mean resource count (%s).' % (current_usage_count, percentage_change, increase_or_decrease, resource_count_mean))
    print('NOTIFY: This notification is triggered by a delta greater than %s percent, measured over %s samples.' % (percent_change_trigger, resource_count_count))
    print()

##########################################################################################
# Configuration.
##########################################################################################

def configure_defaults():
    result = {}
    result['HISTORICAL_DATA_FILE'] = '~/pcs-usage-history.csv'
    result['HISTORICAL_DATA_TO_RETAIN'] = 30
    result['PERCENT_CHANGE_TRIGGER'] = 10
    result['TIME_RANGE_AMOUNT'] = 1
    result['TIME_RANGE_UNIT'] = 'month'
    result['LAMBDA_HISTORICAL_DATA_FILE'] = '/tmp/pcs-usage-history.csv'
    result['LAMBDA_S3_BUCKET'] = 'pcs-usage-delta'
    result['LAMBDA_S3_OBJECT'] = 'pcs-usage-history.csv'
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
    pc_parser.add_argument('-ca', '--cloud_account',
        type=str,
        help='(Optional) Cloud Account ID to limit the usage query')
    pc_parser.add_argument('-ta', '--time_range_amount',
        type=int, default=defaults['TIME_RANGE_AMOUNT'], choices=[1, 2, 3],
        help='(Optional) Time Range Amount to limit the usage query. Default: %s' % defaults['TIME_RANGE_AMOUNT'])
    pc_parser.add_argument('-tu', '--time_range_unit',
        type=str, default=defaults['TIME_RANGE_UNIT'], choices=['day', 'week', 'month', 'year'],
        help="(Optional) Time Range Unit to limit the usage query. Default: '%s'" % defaults['TIME_RANGE_UNIT'])
    pc_parser.add_argument('-p', '--percent_trigger',
        type=int, default=defaults['PERCENT_CHANGE_TRIGGER'],
        help='(Optional) Percentage to trigger a notification. Default: %s' % defaults['PERCENT_CHANGE_TRIGGER'])
    pc_parser.add_argument('-r', '--retain_samples',
        type=int, default=defaults['HISTORICAL_DATA_TO_RETAIN'],
        help='(Optional) Number of samples to retain. Default: %s' % defaults['HISTORICAL_DATA_TO_RETAIN'])
    pc_parser.add_argument('-o', '--output_file',
        type=str, default=defaults['HISTORICAL_DATA_FILE'],
        help="(Optional) Output file to save samples. Default: '%s'" % defaults['HISTORICAL_DATA_FILE'])
    pc_parser.add_argument('-d', '--debug',
        action='store_true',
        help='(Optional) Enable debugging.')
    args = pc_parser.parse_args()

    result['DEBUG_MODE'] = args.debug
    result['PRISMA_API_ENDPOINT'] = args.url
    result['PRISMA_ACCESS_KEY'] = args.access_key
    result['PRISMA_SECRET_KEY'] = args.secret_key
    result['PRISMA_API_HEADERS'] = {
        'accept': 'application/json; charset=UTF-8',
        'content-type': 'application/json'
    }
    result['PRISMA_API_REQUEST_TIMEOUTS'] = (30, 300) # (CONNECT, READ)
    result['CLOUD_ACCOUNT_ID'] = args.cloud_account
    result['HISTORICAL_DATA_FILE'] = os.path.expanduser(args.output_file)
    result['HISTORICAL_DATA_TO_RETAIN'] = args.retain_samples
    result['PERCENT_CHANGE_TRIGGER'] = args.percent_trigger
    result['TIME_RANGE_AMOUNT'] = args.time_range_amount
    result['TIME_RANGE_UNIT'] = args.time_range_unit
    return result

####

def lambda_configure():
    defaults = configure_defaults()
    result = {}
    result['DEBUG_MODE'] = (env_var_or_none('DEBUG_MODE') == 'true')
    result['PRISMA_API_ENDPOINT'] = env_var_or_none('PRISMA_API_ENDPOINT')
    print('TJK %s' % result['PRISMA_API_ENDPOINT'])
    result['PRISMA_ACCESS_KEY']   = env_var_or_none('PRISMA_ACCESS_KEY')
    result['PRISMA_SECRET_KEY']   = env_var_or_none('PRISMA_SECRET_KEY')
    result['PRISMA_API_HEADERS'] = {
        'accept': 'application/json; charset=UTF-8',
        'content-type': 'application/json'
    }
    result['PRISMA_API_REQUEST_TIMEOUTS'] = (30, 300) # (CONNECT, READ)
    result['CLOUD_ACCOUNT_ID'] = env_var_or_none('CLOUD_ACCOUNT_ID')
    result['HISTORICAL_DATA_FILE'] = defaults['LAMBDA_HISTORICAL_DATA_FILE']
    result['HISTORICAL_DATA_TO_RETAIN'] = env_var_or_none('HISTORICAL_DATA_TO_RETAIN') or defaults['HISTORICAL_DATA_TO_RETAIN']
    result['LAMBDA_S3_BUCKET'] = defaults['LAMBDA_S3_BUCKET']
    result['LAMBDA_S3_OBJECT'] = defaults['LAMBDA_S3_OBJECT']
    result['PERCENT_CHANGE_TRIGGER'] = env_var_or_none('PERCENT_CHANGE_TRIGGER') or defaults['PERCENT_CHANGE_TRIGGER']
    result['TIME_RANGE_AMOUNT'] = env_var_or_none('TIME_RANGE_AMOUNT') or defaults['TIME_RANGE_AMOUNT']
    result['TIME_RANGE_UNIT'] = env_var_or_none('TIME_RANGE_UNIT') or defaults['TIME_RANGE_UNIT']
    if not result['PRISMA_API_ENDPOINT']:
        print('Error: specify PRISMA_API_ENDPOINT')
        sys.exit()
    if not result['PRISMA_ACCESS_KEY']:
        print('Error: specify PRISMA_ACCESS_KEY')
        sys.exit()
    if not result['PRISMA_SECRET_KEY']:
        print('Error: specify PRISMA_SECRET_KEY')
        sys.exit()
    if not result['PRISMA_API_ENDPOINT']:
        print('Error: specify PRISMA_API_ENDPOINT')
        sys.exit()
    return result

def env_var_or_none(var_name):
    return os.environ.get(var_name)

##########################################################################################
# Utilities.
##########################################################################################

def make_api_call(config, method, api_url, body_data=None):
    # GlobalProtect generates 'ignore self signed certificate in certificate chain' errors:
    urllib3.disable_warnings()
    http = urllib3.PoolManager(cert_reqs='CERT_NONE')
    resp = http.request(method, api_url, body=body_data, headers=config['PRISMA_API_HEADERS'])
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
        print('Error with API Login: %s' % resp_data)
        sys.exit()
    return token

####

def get_cloud_accounts(config):
    encoded_query_params = urlencode({'excludeAccountGroupDetails': "true"})
    api_url = '%s/cloud?%s' % (config['PRISMA_API_ENDPOINT'], encoded_query_params)
    api_response = make_api_call(config, 'GET', api_url)
    cloud_accounts = json.loads(api_response)
    return cloud_accounts

####

def get_cloud_account_usage(config, cloud_account):
    encoded_query_params = urlencode({'cloud_type': cloud_account['cloudType']})
    api_url = '%s/license/api/v1/usage/?%s' % (config['PRISMA_API_ENDPOINT'], encoded_query_params)
    body_data = json.dumps({
        "accountIds": [cloud_account['accountId']],
        "cloudType": cloud_account['cloudType'],
        "timeRange": {"value": {"unit":"%s" % config['TIME_RANGE_UNIT'], "amount":config['TIME_RANGE_AMOUNT']}, "type":"relative"}
    })
    api_response = make_api_call(config, 'POST', api_url, body_data)
    cloud_account_usage = json.loads(api_response)
    return cloud_account_usage

####

def lambda_download_s3(config):
    bucket_name = config['LAMBDA_S3_BUCKET']
    object_name = config['LAMBDA_S3_OBJECT']
    s3_resource = boto3.resource('s3')
    try:
        s3_resource.Object(bucket_name, object_name).load()
    except:
        return False
    s3_client = boto3.client('s3')
    results = s3_client.download_file(bucket_name, object_name, config['HISTORICAL_DATA_FILE'], )
    print(results['ResponseMetadata'])
    return results['ResponseMetadata']['HTTPStatusCode'] == 200

####

def lambda_upload_s3(config):
    bucket_name = config['LAMBDA_S3_BUCKET']
    object_name = config['LAMBDA_S3_OBJECT']
    s3_client = boto3.client('s3')
    results = s3_client.upload_file(config['HISTORICAL_DATA_FILE'], bucket_name, object_name)
    print(results['ResponseMetadata'])
    return results['ResponseMetadata']['HTTPStatusCode'] == 200

####

# The following allows for differentiating between CSPM resources and CWP workloads.
# Alternatives: data['total'] or data['stats']['stats']['total'] or data['items'][n]['resourceTypeCount']['total']

def count_licensable_usage(usage_data):
    pc_usage = 0
    pcs_resources = 0
    pcc_workloads = 0
    pcc_workload_keys = ['host', 'container', 'serverless', 'waas']
    if not 'stats' in usage_data:
        return pc_usage
    if not 'stats' in usage_data['stats']:
        return pc_usage
    for k in usage_data['stats']['stats'].keys():
        if k == 'total':
            continue
        if k in pcc_workload_keys:
            pcc_workloads += usage_data['stats']['stats'][k]
        else:
            pcs_resources += usage_data['stats']['stats'][k]
    pc_usage = pcs_resources + pcc_workloads
    return pc_usage

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
    today_yyyy_mm_dd = datetime.today().strftime('%Y-%m-%d')
    yesterday_yyyy_mm_dd = (datetime.today() - timedelta(days = 1)).strftime('%Y-%m-%d')

    print('Generating Prisma Cloud API Token')
    token = get_prisma_login(config)
    if config['DEBUG_MODE']:
        print()
        print(token)
        print()
    config['PRISMA_API_HEADERS']['x-redlock-auth'] = token

    print('Querying Cloud Accounts')
    cloud_accounts = get_cloud_accounts(config)
    cloud_accounts = [{'accountId': '%s' % a['accountId'], 'name': '%s' % a['name'], 'cloudType': '%s' % a['cloudType']} for a in cloud_accounts if a['enabled'] == True]

    print('Querying Usage for %s Cloud Accounts' % len(cloud_accounts))
    for cloud_account in cloud_accounts:
        if config['CLOUD_ACCOUNT_ID'] and (cloud_account['accountId'] != config['CLOUD_ACCOUNT_ID']):
            continue
        if config['DEBUG_MODE']:
            print('    Cloud Account ID: %s, Name: %s' % (cloud_account['accountId'], cloud_account['name']))
        else:
            sys.stdout.write('.')
            sys.stdout.flush()
        cloud_account_usage = get_cloud_account_usage(config, cloud_account)
        current_usage_count += count_licensable_usage(cloud_account_usage)

    print()
    print('Current (Licensable) Resource Count: %s' % current_usage_count)
    print()

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

    print('Historical (Licensable) Resource Count:')
    print()

    with open(config['HISTORICAL_DATA_FILE'], 'w') as f:
        csv_writer = csv.DictWriter(f, fieldnames=field_names, delimiter = '\t')
        for sample in historical_data:
            csv_writer.writerow(sample)
            print(sample)
        csv_writer.writerow({'Date': today_yyyy_mm_dd, 'Resources': current_usage_count})

    # Calculon, Compute!

    resource_count_list = []
    for sample in historical_data:
        resource_count_list.append(int(sample['Resources'])) 

    resource_count_count = len(resource_count_list)
    resource_count_mean = math.trunc(mean_of_list(resource_count_list))
    percentage_change = math.trunc((current_usage_count - resource_count_mean) / resource_count_mean * 100)

    if config['DEBUG_MODE']:
        print()
        print('Mean: %s, Percent Change: %s' % (resource_count_mean, percentage_change))
        print()
        print('Current: %s' % current_usage_count)
        print()

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
