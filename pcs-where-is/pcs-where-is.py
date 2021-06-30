#!/usr/bin/env python3

import argparse
import json
import os
import requests
import sys

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
# Configure.
##########################################################################################

def configure(args):
    config = {}
    config['CA_BUNDLE'] = args.ca_bundle
    config['CUSTOMER_NAME'] = args.customer_name
    config['API'] = {
        'url':        'https://api.prismacloud.io',
        'access_key': os.environ.get('API_ACCESS_KEY', None),
        'secret_key': os.environ.get('API_SECRET_KEY', None)
    }
    config['API2'] = {
        'url':        'https://api2.prismacloud.io',
        'access_key': os.environ.get('API2_ACCESS_KEY', None),
        'secret_key': os.environ.get('API2_SECRET_KEY', None)
    }
    config['API3'] = {
        'url':        'https://api3.prismacloud.io',
        'access_key': os.environ.get('API3_ACCESS_KEY', None),
        'secret_key': os.environ.get('API3_SECRET_KEY', None)
    }
    return config

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
        output('API (%s) responded with an error\n%s' % (requ_url, api_response.text))
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
            output('API (%s) responded with an error\n%s' % (requ_url, api_response.content))
            sys.exit(1)
    else:
        if DEBUG_MODE:
            output(api_response.content)
    return result

def find_customer(stack, customers, customer_name):
    count = 0
    if not customers:
        return count
    customer_name_lower = customer_name.lower()
    for customer in customers:
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
            output('\tPrisma ID:     %s' % customer['prismaId'])
            output('\tWorkloads:     %s' % customer['workloads'])
            output('\tEval:          %s' % customer['eval'])
            output('\tActive:        %s' % customer['active'])
            output()
            count += 1
    return count

##########################################################################################
## Main.
##########################################################################################

CONFIG = configure(args)

found = 0

token     = login(CONFIG['API']['url'], CONFIG['API']['access_key'], CONFIG['API']['secret_key'], CONFIG['CA_BUNDLE'])
customers = execute('GET', '%s/_support/customer' % CONFIG['API']['url'], token, CONFIG['CA_BUNDLE'])
found    += find_customer('APP', customers, CONFIG['CUSTOMER_NAME'])

token     = login(CONFIG['API2']['url'], CONFIG['API2']['access_key'], CONFIG['API2']['secret_key'], CONFIG['CA_BUNDLE'])
customers = execute('GET', '%s/_support/customer' % CONFIG['API2']['url'], token, CONFIG['CA_BUNDLE'])
found    += find_customer('APP2', customers, CONFIG['CUSTOMER_NAME'])

token     = login(CONFIG['API3']['url'], CONFIG['API3']['access_key'], CONFIG['API3']['secret_key'], CONFIG['CA_BUNDLE'])
customers = execute('GET', '%s/_support/customer' % CONFIG['API3']['url'], token, CONFIG['CA_BUNDLE'])
found    += find_customer('APP3', customers, CONFIG['CUSTOMER_NAME'])

if found == 0:
    output('%s not found on APP, APP2 or APP3' % CONFIG['CUSTOMER_NAME'])

##########################################################################################
# TODO:
##########################################################################################

# usage_query = json.dumps({'customerName': customer, 'timeRange': {'type':'relative','value': {'amount': 1,'unit': 'month'}}})
# result = execute('POST', '%s/_support/license/api/v1/usage/time_series' % url, token, CONFIG['CA_BUNDLE'], usage_query)
# print(json.dumps(result, indent=4))

