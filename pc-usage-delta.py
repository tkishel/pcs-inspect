#!/usr/bin/env python

import argparse
import csv
from datetime import datetime, timedelta
import json
import math
import os
import requests
from requests.exceptions import RequestException
import sys

##########################################################################################
# Configuration.
##########################################################################################

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
    type=int, default=1, choices=[1, 2, 3],
    help="(Optional) Time Range Amount to limit the usage query. Default: 1")

pc_parser.add_argument('-tu', '--time_range_unit',
    type=str, default='month', choices=['day', 'week', 'month', 'year'],
    help="(Optional) Time Range Unit to limit the usage query. Default: 'month'")

pc_parser.add_argument('-p', '--percent_trigger',
    type=int, default=10,
    help="(Optional) Percentage to trigger a notification. Default: 10")

pc_parser.add_argument('-r', '--retain_samples',
    type=int, default=30,
    help="(Optional) Number of samples to retain. Default: 30")

pc_parser.add_argument('-o', '--output_file',
    type=str, default='~/pcs-usage-history.csv',
    help="(Optional) Output file to save samples. Default: '~/pcs-usage-history.csv'")

pc_parser.add_argument('-d', '--debug',
    action='store_true',
    help='(Optional) Enable debugging.')

args = pc_parser.parse_args()

####

DEBUG_MODE = args.debug

PRISMA_API_ENDPOINT = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
PRISMA_ACCESS_KEY   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
PRISMA_SECRET_KEY   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
PRISMA_API_HEADERS = {
    'accept': 'application/json; charset=UTF-8',
    'content-type': 'application/json'
}
PRISMA_API_REQUEST_TIMEOUTS = (30, 300) # (CONNECT, READ)
CLOUD_ACCOUNT_ID = args.cloud_account
HISTORICAL_DATA_FILE = os.path.expanduser(args.output_file)
HISTORICAL_DATA_TO_RETAIN = args.retain_samples
PERCENT_CHANGE_TRIGGER = args.percent_trigger
TIME_RANGE_AMOUNT = args.time_range_amount
TIME_RANGE_UNIT = args.time_range_unit

##########################################################################################
# Notification.
##########################################################################################

# Customize this function to meet your notification requirements.

def notify(percentage_change, current_usage_count, resource_count_mean, resource_count_count, PERCENT_CHANGE_TRIGGER):
    if percentage_change > 0:
        spike_or_drop = 'Spike'
        increase_or_decrease = 'greater'
    else:
        spike_or_drop = 'Drop'
        increase_or_decrease = 'less'
    print
    print('NOTIFY: %s !!!' % spike_or_drop) 
    print('NOTIFY: Current resource count (%s) is %s percent %s than the mean resource count (%s).' % (current_usage_count, percentage_change, increase_or_decrease, resource_count_mean))
    print('NOTIFY: This notification is triggered by a delta greater than %s percent, measured over %s samples.' % (PERCENT_CHANGE_TRIGGER, resource_count_count))
    print

##########################################################################################
# Utilities.
##########################################################################################

def make_api_call(method, url, requ_data = None):
    try:
        requ = requests.Request(method, url, data = requ_data, headers = PRISMA_API_HEADERS)
        prep = requ.prepare()
        sess = requests.Session()
        resp = sess.send(prep, timeout=(PRISMA_API_REQUEST_TIMEOUTS))
        if resp.status_code == 200:
            return resp.content
        else:
            return {}
    except RequestException as e:
        print('Error with API: %s: %s' % (url, str(e)))
        sys.exit()

####

def get_prisma_login():
    request_data = json.dumps({
        "username": PRISMA_ACCESS_KEY,
        "password": PRISMA_SECRET_KEY
    })
    api_response = make_api_call('POST', '%s/login' % PRISMA_API_ENDPOINT, request_data)
    resp_data = json.loads(api_response)
    token = resp_data.get('token')
    if not token:
        print('Error with API Login: %s' % resp_data)
        sys.exit()
    return token

####

def get_cloud_accounts():
    api_response = make_api_call('GET', '%s/cloud?excludeAccountGroupDetails=true' % PRISMA_API_ENDPOINT)
    cloud_accounts = json.loads(api_response)
    return cloud_accounts

####

def get_cloud_account_usage(cloud_account):
    request_data = json.dumps({
        "accountIds": [cloud_account['accountId']],
        "cloudType": cloud_account['cloudType'],
        "timeRange": {"value": {"unit":"%s" % TIME_RANGE_UNIT, "amount":TIME_RANGE_AMOUNT}, "type":"relative"}
    })
    api_response = make_api_call('POST', '%s/license/api/v1/usage/?cloud_type=%s' % (PRISMA_API_ENDPOINT, cloud_account['cloudType']), request_data)
    cloud_account_usage = json.loads(api_response)
    return cloud_account_usage

# The following allows for differentiating between CSPM resources and CWP workloads.
# Alternatives: data['total'] or data['stats']['stats']['total'] or data['items'][n]['resourceTypeCount']['total']

def count_licensable_usage(usage_data):
    pc_usage = 0
    pcs_resources = 0
    pcc_workloads = 0
    pcc_workload_keys = ['host', 'container', 'serverless', 'waas']
    if not usage_data.has_key('stats'):
        return pc_usage
    if not usage_data['stats'].has_key('stats'):
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

def mean_of_list(usage_data):
    return (sum(usage_data) / float(len(usage_data)))

##########################################################################################
# Main.
##########################################################################################

current_usage_count = 0
field_names = ['Date', 'Resources']
historical_data = []
today_yyyy_mm_dd = datetime.today().strftime('%Y-%m-%d')
yesterday_yyyy_mm_dd = (datetime.today() - timedelta(days = 1)).strftime('%Y-%m-%d')

print('Generating Prisma Cloud API Token')
token = get_prisma_login()
if DEBUG_MODE:
    print
    print(token)
    print
PRISMA_API_HEADERS['x-redlock-auth'] = token

print('Querying Cloud Accounts')
cloud_accounts = get_cloud_accounts()
cloud_accounts = [{'accountId': '%s' % a['accountId'], 'name': '%s' % a['name'], 'cloudType': '%s' % a['cloudType']} for a in cloud_accounts if a['enabled'] == True]

print('Querying Usage for %s Cloud Accounts' % len(cloud_accounts))
for cloud_account in cloud_accounts:
    if CLOUD_ACCOUNT_ID and (cloud_account['accountId'] != CLOUD_ACCOUNT_ID):
        continue
    if DEBUG_MODE:
        print('    Cloud Account ID: %s, Name: %s' % (cloud_account['accountId'], cloud_account['name']))
    else:
        sys.stdout.write('.')
        sys.stdout.flush()
    cloud_account_usage = get_cloud_account_usage(cloud_account)
    current_usage_count += count_licensable_usage(cloud_account_usage)

print
print('Current (Licensable) Resource Count: %s' % current_usage_count)
print

# Read historical data; or create historical data with one resource to avoid a divide by zero error.

if os.path.isfile(HISTORICAL_DATA_FILE) and os.stat(HISTORICAL_DATA_FILE).st_size > 0:
    with open(HISTORICAL_DATA_FILE, 'r') as f:
        csv_reader = csv.DictReader(f, fieldnames=field_names, delimiter = '\t')
        for sample in csv_reader:
            historical_data.append(sample)
else:
    historical_data = [{"Date": yesterday_yyyy_mm_dd, 'Resources': 1}]

# Limit historical data to (HISTORICAL_DATA_TO_RETAIN) samples.

historical_data = historical_data[-HISTORICAL_DATA_TO_RETAIN:]

# Write historical data.

print('Historical (Licensable) Resource Count:')
print

with open(HISTORICAL_DATA_FILE, 'w') as f:
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

if DEBUG_MODE:
    print
    print('Mean: %s, Percent Change: %s' % (resource_count_mean, percentage_change))
    print
    print('Current: %s' % current_usage_count)
    print

# Notify, if the percentage of change exceeds the trigger.

if abs(percentage_change) > PERCENT_CHANGE_TRIGGER:
    notify(percentage_change, current_usage_count, resource_count_mean, resource_count_count, PERCENT_CHANGE_TRIGGER)
