#!/usr/bin/env python3

import argparse
import json
import os
import requests
import sys

from datetime import datetime

##########################################################################################
# Process arguments / parameters.
##########################################################################################

pc_parser = argparse.ArgumentParser(description='Where is this Tenant?', prog=os.path.basename(__file__))

pc_parser.add_argument(
    'customer_name',
    type=str,
    help='*Required* Customer Name')
pc_parser.add_argument(
    '--ca_bundle',
    default=os.environ.get('CA_BUNDLE', None),
    type=str,
    help='(Optional) - Custom CA (bundle) file')
pc_parser.add_argument('-d', '--debug',
    action='store_true',
    help='(Optional) Enable debugging.')

args = pc_parser.parse_args()

DEBUG_MODE = args.debug

##########################################################################################
# Helpers.
##########################################################################################

def output(output_data=''):
    print(output_data)

##########################################################################################
# Helpers.
##########################################################################################

def login(url, access_key, secret_key, ca_bundle):
    endpoint = '%s/login' % url
    headers = {'Content-Type': 'application/json'}
    data = json.dumps({'username': access_key, 'password': secret_key})
    api_response = requests.request('POST', endpoint, headers=headers, data=data, verify=ca_bundle)
    if api_response.ok:
        api_response = json.loads(api_response.content)
        token = api_response.get('token')
    else:
        output('API (%s) responded with an error\n%s' % (endpoint, api_response.text))
        sys.exit(1)
    if DEBUG_MODE:
        output(endpoint)
        output(token)
    return token

def execute(action, url, token, ca_bundle=None, requ_data=None):
    headers = {'Content-Type': 'application/json'}
    headers['x-redlock-auth'] = token
    api_response = requests.request(action, url, headers=headers, verify=ca_bundle, data=requ_data)
    result = None
    if api_response.status_code in [401, 429, 500, 502, 503, 504]:
        for _ in range(1, 3):
            time.sleep(16)
            api_response = requests.request(action, url, headers=headers, verify=ca_bundle, data=requ_data)
            if api_response.ok:
                break # retry loop
    if api_response.ok:
        try:
            result = json.loads(api_response.content)
        except ValueError:
            output('API (%s) responded with an error\n%s' % (endpoint, api_response.content))
            sys.exit(1)
    else:
        if DEBUG_MODE:
            output(api_response.content)
    return result

def find_customer(stack, tenants, customer_name, url, ca_bundle, token):
    count = 0
    if not tenants:
        return count

    customer_name_lower = customer_name.lower()
    for customer in tenants:
        customer_lower = customer['customerName'].lower()
        if customer_name_lower in customer_lower:
            output('%s found on %s as %s' % (customer_name, stack, customer['customerName']))
            if DEBUG_MODE:
                output(json.dumps(customer, indent=4))
            output('\tCustomer ID:   %s' % customer['customerId'])
            if 'marketplaceData' in customer['licenseDetails'] and customer['licenseDetails']['marketplaceData']:
                if 'serialNumber' in customer['licenseDetails']['marketplaceData']:
                    output('\tSerial Number: %s' % customer['licenseDetails']['marketplaceData']['serialNumber'])
                if 'tenantId' in customer['licenseDetails']['marketplaceData']:
                    output('\tTenant ID:     %s' % customer['licenseDetails']['marketplaceData']['tenantId'])
                if 'endTs' in customer['licenseDetails'] and customer['licenseDetails']['endTs']:
                    endDt = datetime.fromtimestamp(customer['licenseDetails']['endTs']/1000.0)
                    output('\tRenewal Date:  %s' % endDt)
            output('\tPrisma ID:     %s' % customer['prismaId'])
            output('\tEval:          %s' % customer['eval'])
            output('\tActive:        %s' % customer['active'])
            output('\tCredits:       %s' % customer['workloads'])

            usage_query = json.dumps({'customerName': customer['customerName'], 'timeRange': {'type':'relative','value': {'amount': 1,'unit': 'month'}}})
            usage = execute('POST', '%s/_support/license/api/v1/usage/time_series' % url, token, ca_bundle, usage_query)
            if DEBUG_MODE:
                output(json.dumps(usage, indent=4))
            if usage and 'dataPoints' in usage and len(usage['dataPoints']) > 0:
                current_usage = usage['dataPoints'][-1]
                if 'counts' in current_usage and len(current_usage['counts']) > 0:
                    current_usage_count = sum(sum(c.values()) for c in current_usage['counts'].values())
                    output('\tUsed Credits:  %s' % current_usage_count)

            output()

            count += 1
    return count

##########################################################################################
## Main.
##########################################################################################

CONFIG = {}
try:
    from config import *
except ImportError:
    output('Error reading config')
    exit(1)

configured = False
for stack in CONFIG['STACKS']:
    if CONFIG['STACKS'][stack]['access_key'] != None:
        configured = True
if (not configured):
    output("It appears you haven't configured credentials to access the Prisma Cloud stacks. Copy config.py.org to config.py and put them into your config.py file")
    exit(1)

if args.ca_bundle:
    CONFIG['CA_BUNDLE'] = args.ca_bundle

CONFIG['CUSTOMER_NAME'] = args.customer_name

found = 0

for stack in CONFIG['STACKS']:
    if CONFIG['STACKS'][stack]['access_key']:
        token     = login(CONFIG['STACKS'][stack]['url'], CONFIG['STACKS'][stack]['access_key'], CONFIG['STACKS'][stack]['secret_key'], CONFIG['CA_BUNDLE'])
        tenants = execute('GET', '%s/_support/customer' % CONFIG['STACKS'][stack]['url'], token, CONFIG['CA_BUNDLE'])
        found    += find_customer(stack, tenants, CONFIG['CUSTOMER_NAME'], CONFIG['STACKS'][stack]['url'], CONFIG['CA_BUNDLE'], token)

if found == 0:
    output('%s not found on any configured stack' % CONFIG['CUSTOMER_NAME'])
