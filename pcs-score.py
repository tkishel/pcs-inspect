#!/usr/bin/env python3

import argparse
import json
import math
import os
import re
import requests
from requests.exceptions import RequestException
from shutil import which
import sys

##########################################################################################
# Process arguments / parameters.
##########################################################################################

pc_parser = argparse.ArgumentParser(description='This script collects or processes Policies and Alerts.', prog=os.path.basename(__file__))

pc_parser.add_argument('-u', '--url',
    type=str,
    help="(Required with '--mode collect') Prisma Cloud API URL")

pc_parser.add_argument('-a', '--access_key',
    type=str,
    help="(Required with '--mode collect') API Access Key")

pc_parser.add_argument('-s', '--secret_key',
    type=str,
    help="(Required with '--mode collect') API Secret Key")

pc_parser.add_argument('-ta', '--time_range_amount',
    type=int, default=1, choices=[1, 2, 3],
    help="(Optional) Time Range Amount to limit the Alert query. Default: 1")

pc_parser.add_argument('-tu', '--time_range_unit',
    type=str, default='month', choices=['day', 'week', 'month', 'year'],
    help="(Optional) Time Range Unit to limit the Alert query. Default: 'month'")

pc_parser.add_argument('-m', '--mode',
    type=str, default='auto', choices=['collect', 'process'],
    help="(Optional) Mode: just collect data, or just process collected data. Default: 'auto'")

pc_parser.add_argument('-d', '--debug',
    action='store_true',
    help='(Optional) Enable debugging.')

args = pc_parser.parse_args()

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
    config['DEBUG_MODE']          = args.debug
    config['RUN_MODE']            = args.mode
    config['SUPPORT_API_MODE']    = True
    config['PRISMA_API_ENDPOINT'] = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
    config['PRISMA_ACCESS_KEY']   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
    config['PRISMA_SECRET_KEY']   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
    config['PRISMA_API_HEADERS']  = {
        'Accept': 'application/json; charset=UTF-8, text/plain, */*',
        'Content-Type': 'application/json'
    }
    config['API_TIMEOUTS']      = (60, 600) # (CONNECT, READ)
    config['TIME_RANGE_AMOUNT'] = args.time_range_amount
    config['TIME_RANGE_UNIT']   = args.time_range_unit
    config['TIME_RANGE_LABEL']  = 'Past %s %s' % (config['TIME_RANGE_AMOUNT'], config['TIME_RANGE_UNIT'].capitalize())
    config['RESULTS_FILE'] = {
        'CUSTOMERS':    '%s-customers.json' % re.sub(r'\W+', '', config['PRISMA_API_ENDPOINT']).lower(),
        'POLICIES':     'policies.json',
        'ALERTS':       'alerts.json'
    }
    if config['RUN_MODE'] in ['auto', 'collect'] :
        if not config['PRISMA_API_ENDPOINT']:
            output("Error: '--url' is required")
            sys.exit(1)
        if not config['PRISMA_ACCESS_KEY']:
            output("Error: '--access_key' is required")
            sys.exit(1)
        if not config['PRISMA_SECRET_KEY']:
            output("Error: '--secret_key' is required")
            sys.exit(1)
    config['MINIMUM_ALERTS'] = 100
    config['MINIMUM_RATIO']  = 20
    return config

##########################################################################################
# File Helpers.
##########################################################################################

def delete_file_if_exists(file_name):
    if os.path.exists(file_name):
        os.remove(file_name)

##########################################################################################
# API Helpers.
##########################################################################################

def make_api_call(method, url, requ_data=None):
    if CONFIG['DEBUG_MODE']:
        output('URL: %s' % url)
        output('METHOD: %s' % method)
        output('REQUEST DATA: %s' % requ_data)
    try:
        requ = requests.Request(method, url, data=requ_data, headers=CONFIG['PRISMA_API_HEADERS'])
        prep = requ.prepare()
        sess = requests.Session()
        # GlobalProtect generates 'ignore self signed certificate in certificate chain' errors.
        # Set 'REQUESTS_CA_BUNDLE' to a valid CA bundle including the 'Palo Alto Networks Inc Root CA' used by GlobalProtect.
        # Hint: Copy the bundle provided by the certifi module (locate via 'python -m certifi') and append the 'Palo Alto Networks Inc Root CA'
        if 'REQUESTS_CA_BUNDLE' in os.environ:
            resp = sess.send(prep, timeout=(CONFIG['API_TIMEOUTS']), verify="%s" % os.environ['REQUESTS_CA_BUNDLE'])
        else:
            resp = sess.send(prep, timeout=(CONFIG['API_TIMEOUTS']))
        if CONFIG['DEBUG_MODE']:
            output(resp.text)
        if resp.ok:
            return resp.content
        else:
            # TJK
            output('Error with API: Status Code: %s Details: %s' % (resp.status_code, resp.text))
            # sys.exit(1)
    except RequestException as e:
        output()
        output('Error with API: URL: %s: Error: %s' % (url, str(e)))
        output()
        output('For CERTIFICATE_VERIFY_FAILED errors with GlobalProtect, try setting REQUESTS_CA_BUNDLE to a bundle with the Palo Alto Networks Inc Root CA.')
        sys.exit(1)

####

def get_prisma_login():
    request_data = json.dumps({
        "username": CONFIG['PRISMA_ACCESS_KEY'],
        "password": CONFIG['PRISMA_SECRET_KEY']
    })
    api_response = make_api_call('POST', '%s/login' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    resp_data = json.loads(api_response)
    token = resp_data.get('token')
    if not token:
        output('Error with API Login: %s' % resp_data)
        sys.exit(1)
    return token

# SUPPORT_API_MODE:

def get_customers(output_file_name):
    if os.path.exists(output_file_name):
        output('Using cached customers file')
        return
    delete_file_if_exists(output_file_name)
    api_response = make_api_call('GET', '%s/_support/customer' % CONFIG['PRISMA_API_ENDPOINT'])
    if api_response:
        result_file = open(output_file_name, 'wb')
        result_file.write(api_response)
        result_file.close()

# SUPPORT_API_MODE:
# This script depends upon Open Alert counts for all Policies (as provided by '/policy'), but '/_support/policy' doesn't return open Alert counts.
# And '/_support/alert/policy' does return alertCount, but I cannot tell if that is all (Open or Closed) or just Open Alerts, and returns fewer Policies than '_support/policy' ... given the same parameters.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_policies(customer_name, output_file_name):
    if os.path.exists(output_file_name):
        output('Using cached Policies file for %s' % customer_name)
        return
    output('Querying Policies for %s' % customer_name)
    delete_file_if_exists(output_file_name)
    body_params = {"customerName": "%s" % customer_name}
    request_data = json.dumps(body_params)
    api_response = make_api_call('POST', '%s/_support/policy' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    if api_response:
        result_file = open(output_file_name, 'wb')
        result_file.write(api_response)
        result_file.close()

# SUPPORT_API_MODE:
# This script depends upon the not implemented '/_support/alert/jobs' endpoint.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_alerts(customer_name, output_file_name):
    if os.path.exists(output_file_name):
        output('Using cached Alerts file for %s' % customer_name)
        return
    output('Querying Alerts for %s' % customer_name)
    delete_file_if_exists(output_file_name)
    api_response = {}
    api_response['by_policy']          = get_alerts_aggregate(customer_name, 'policy.name')     # [{"policyName":"AWS VPC subnets should not allow automatic public IP assignment","alerts":105},{"policyName":"AWS Security Group overly permissive to all traffic","alerts":91}, ...
    api_response['by_policy_type']     = get_alerts_aggregate(customer_name, 'policy.type')     # [{"alerts":422,"policyType":"config"},{"alerts":15,"policyType":"network"},{"alerts":2,"policyType":"anomaly"},{"alerts":0,"policyType":"iam"},{"alerts":0,"policyType":"data"},{"alerts":0,"policyType":"audit_event"}]
    api_response['by_policy_severity'] = get_alerts_aggregate(customer_name, 'policy.severity') # [{"severity":"medium","alerts":225},{"severity":"high","alerts":214},{"severity":"low","alerts":0}]
    api_response['by_alert.status']    = get_alerts_aggregate(customer_name, 'alert.status')    # [{"alerts":439,"status":"open"},{"alerts":88,"status":"resolved"},{"alerts":0,"status":"dismissed"},{"alerts":0,"status":"snoozed"}]'
    if all(api_response.values()):
        api_response_json = json.dumps(api_response, indent=2, separators=(', ', ': '))
        result_file = open(output_file_name, 'w')
        result_file.write(api_response_json)
        result_file.close()

## Valid filter options: policy.name, policy.type, policy.severity, or alert.status.

def get_alerts_aggregate(customer_name, group_by_field):
    body_params = {}
    body_params = {"customerName": "%s" % customer_name}
    body_params['timeRange'] = {"value": {"unit": "%s" % CONFIG['TIME_RANGE_UNIT'], "amount": CONFIG['TIME_RANGE_AMOUNT']}, "type": "relative"}
    body_params['groupBy'] = group_by_field
    body_params['limit'] = 9999
    request_data = json.dumps(body_params)
    api_response = make_api_call('POST', '%s/_support/alert/aggregate' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    if api_response:
        return json.loads(api_response)
    else:
        return []

##########################################################################################
# Collect mode: Query the API and write the results to files.
##########################################################################################

def collect_data():
    output('Generating Prisma Cloud API Token')
    token = get_prisma_login()
    if CONFIG['DEBUG_MODE']:
        output()
        output(token)
        output()
    CONFIG['PRISMA_API_HEADERS']['x-redlock-auth'] = token
    output()
    output('Querying Customers')
    get_customers(CONFIG['RESULTS_FILE']['CUSTOMERS'])
    format_collected_data(CONFIG['RESULTS_FILE']['CUSTOMERS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['CUSTOMERS'])
    output()
    with open(CONFIG['RESULTS_FILE']['CUSTOMERS'], 'r', encoding='utf8') as f:
        customers = json.load(f)
    sorted_customers = sorted(customers, key=lambda customer: customer['customerName']) 
    for customer in sorted_customers:
        customer_prefix = re.sub(r'\W+', '', customer['customerName']).lower()
        get_policies(customer['customerName'], '%s-%s' % (customer_prefix, CONFIG['RESULTS_FILE']['POLICIES']))
        get_alerts(customer['customerName'], '%s-%s' % (customer_prefix, CONFIG['RESULTS_FILE']['ALERTS']))
        token = get_prisma_login()
        CONFIG['PRISMA_API_HEADERS']['x-redlock-auth'] = token
        output()

##########################################################################################
# Collect mode: Pretty the input files ... using jq to avoid encoding errors.
##########################################################################################

def format_collected_data(this_file):
    if which('jq') is None:
        return
    temp_file = '%s.temp' % this_file
    if not os.path.isfile(this_file):
        return
    os.system('cat %s | jq > %s' % (this_file, temp_file))
    os.system('mv %s %s' % (temp_file, this_file))
    output('Formatting: %s' % this_file)
    output()

##########################################################################################
# Process mode: Read the input files.
##########################################################################################

def read_collected_data():
    if not os.path.isfile(CONFIG['RESULTS_FILE']['CUSTOMERS']):
        output('Error: Query result file does not exist: %s' % CONFIG['RESULTS_FILE']['CUSTOMERS'])
        sys.exit(1)
    with open(CONFIG['RESULTS_FILE']['CUSTOMERS'], 'r', encoding='utf8') as f:
        customers = json.load(f)
    sorted_customers = sorted(customers, key=lambda customer: customer['customerName']) 
    for customer in sorted_customers:
        customer_prefix = re.sub(r'\W+', '', customer['customerName']).lower()
        ##
        this_file = '%s-%s' % (customer_prefix, CONFIG['RESULTS_FILE']['POLICIES'])
        if not os.path.isfile(this_file):
          # output('Error: Query result file does not exist: %s' % this_file)
          # output()
          continue
        with open(this_file, 'r', encoding='utf8') as f:
          DATA['POLICIES'] = json.load(f)
        ##
        this_file = '%s-%s' % (customer_prefix, CONFIG['RESULTS_FILE']['ALERTS'])
        if not os.path.isfile(this_file):
          # output('Error: Query result file does not exist: %s' % this_file)
          # output()
          continue
        with open(this_file, 'r', encoding='utf8') as f:
          DATA['ALERTS'] = json.load(f)
        ##
        process_collected_data()
        output_alerts_summary(customer['customerName'])

##########################################################################################
# Process mode: Process the data.
##########################################################################################

# cloud_type      = {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0}
# policy_mode     = {'custom': 0, 'default': 0}
# policy_feature  = {'remediable': 0, 'shiftable': 0, 'remediable_and_shiftable': 0}
# policy_severity = {'high': 0, 'medium': 0, 'low': 0}
# policy_type     = {'anomaly': 0, 'audit_event': 0, 'config': 0, 'iam': 0, 'network': 0}
# alert_status    = {'open': 0, 'dismissed': 0, 'snoozed': 0, 'resolved': 0}

def process_collected_data():
    # SUPPORT_API_MODE saves a dictionary (of Open) Alerts instead of a list.
    if type(DATA['ALERTS']) is dict:
        CONFIG['SUPPORT_API_MODE'] = True
        RESULTS['alerts_aggregated_by'] = process_aggregated_alerts(DATA['ALERTS'])
    # POLICIES
    RESULTS['compliance_standards_from_policies'] = {}
    RESULTS['policies_by_name'] = {}
    RESULTS['policies'] = {}
    RESULTS['alert_counts_from_policies'] = {
        'cloud_type': {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0},
        'feature':    {'remediable': 0, 'shiftable': 0, 'remediable_and_shiftable': 0},
        'mode':       {'custom': 0, 'default': 0},
        'severity':   {'high': 0, 'medium': 0, 'low': 0},
        'status':     {'open': 0, 'dismissed': 0, 'snoozed': 0, 'resolved': 0},
        'type':       {'anomaly': 0, 'audit_event': 0, 'config': 0, 'data': 0, 'iam': 0, 'network': 0},
    }
    process_policies(DATA['POLICIES'])
    # ALERTS
    RESULTS['compliance_standards_from_alerts'] = {}
    RESULTS['policies_from_alerts'] = {}
    RESULTS['policy_counts_from_alerts'] = {
        'cloud_type': {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0},
        'severity': {'high': 0, 'medium': 0, 'low': 0},
        'type':     {'anomaly': 0, 'audit_event': 0, 'config': 0, 'data': 0, 'iam': 0, 'network': 0},
    }
    RESULTS['alert_counts_from_alerts'] = {
        'cloud_type':           {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0},
        'feature':              {'remediable': 0, 'shiftable': 0, 'remediable_and_shiftable': 0},
        'mode':                 {'custom': 0, 'default': 0},
        'policy':               {'disabled': 0, 'deleted': 0},
        'status_by_feature': {
            'remediable':       {'open': 0, 'dismissed': 0, 'snoozed': 0, 'resolved': 0},
        },
        'severity':             {'high': 0, 'medium': 0, 'low': 0},
        'status':               {'open': 0, 'dismissed': 0, 'snoozed': 0, 'resolved': 0},
        'severity_by_status': {
            'open':             {'high': 0, 'medium': 0, 'low': 0},
            'dismissed':        {'high': 0, 'medium': 0, 'low': 0},
            'snoozed':          {'high': 0, 'medium': 0, 'low': 0},
            'resolved':         {'high': 0, 'medium': 0, 'low': 0},
        },
        'type':                 {'anomaly': 0, 'audit_event': 0, 'config': 0, 'data': 0, 'iam': 0, 'network': 0},
        'resolved_by_policy':   {'disabled': 0, 'deleted': 0},
        'resolved_by_resource': {'deleted': 0, 'updated': 0},
    }
    RESULTS['deleted_policies_from_alerts']  = {}
    RESULTS['disabled_policies_from_alerts'] = {}
    RESULTS['resources_from_alerts'] = {}
    process_alerts(DATA['ALERTS'])
    # SUMMARY
    RESULTS['summary'] = {}
    RESULTS['summary']['count_of_assets'] = 0
    RESULTS['summary']['count_of_aggregated_open_alerts'] = 0
    RESULTS['summary']['count_of_resources_with_alerts_from_alerts'] = 0
    RESULTS['summary']['count_of_compliance_standards_with_alerts_from_policies'] = 0
    RESULTS['summary']['count_of_compliance_standards_with_alerts_from_alerts']   = 0
    RESULTS['summary']['count_of_policies_with_alerts_from_policies']             = 0
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']    = {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0}
    RESULTS['summary']['count_of_policies_with_alerts_from_alerts']               = 0
    process_summary()

##########################################################################################
# SUPPORT_API_MODE: Loop through '/_support/alert/aggregate' results and collect the details.
# Alert counts from that endpoint include Open Alerts and are scoped to a time range.
# Valid filter options: policy.name, policy.type, policy.severity, or alert.status.
##########################################################################################

def process_aggregated_alerts(alerts):
    alerts_by = {
        'policy':   {},
        'type':     {'anomaly': 0, 'audit_event': 0, 'config': 0, 'data': 0, 'iam': 0,'network': 0},
        'severity': {'high': 0, 'medium': 0, 'low': 0},
        'status':   {'open': 0, 'resolved': 0}
    }
    for item in alerts['by_policy']:
        alerts_by['policy'][item['policyName']] = item['alerts']
    for item in alerts['by_policy_type']:
        alerts_by['type'][item['policyType']]   = item['alerts']
    for item in alerts['by_policy_severity']:
        alerts_by['severity'][item['severity']] = item['alerts']
    for item in alerts['by_alert.status']:
        alerts_by['status'][item['status']]     = item['alerts']
    return alerts_by

##########################################################################################
# Loop through all Policies and collect the details.
# Alert counts from this endpoint include Open Alerts and are not scoped to a time range.
# SUPPORT_API_MODE: Substitute aggregated Alerts (as '/_support/policy' does not return openAlertsCount).
##########################################################################################

def process_policies(policies):
    for this_policy in policies:
        this_policy_id = this_policy['policyId']
        RESULTS['policies_by_name'][this_policy['name']] = {'policyId': this_policy_id}
        RESULTS['policies'][this_policy_id] = {'policyName': this_policy['name']}
        RESULTS['policies'][this_policy_id]['policyEnabled']       = this_policy['enabled']
        RESULTS['policies'][this_policy_id]['policySeverity']      = this_policy['severity']
        RESULTS['policies'][this_policy_id]['policyType']          = this_policy['policyType']
        RESULTS['policies'][this_policy_id]['policySubTypes']      = this_policy['policySubTypes']
        RESULTS['policies'][this_policy_id]['policyCategory']      = this_policy['policyCategory']
        RESULTS['policies'][this_policy_id]['policyClass']         = this_policy['policyClass']
        RESULTS['policies'][this_policy_id]['policyCloudType']     = this_policy['cloudType'].lower()
        RESULTS['policies'][this_policy_id]['policyShiftable']     = 'build' in this_policy['policySubTypes']
        RESULTS['policies'][this_policy_id]['policyRemediable']    = this_policy['remediable']
        #
        RESULTS['policies'][this_policy_id]['policyShiftableRemediable'] = 'build' in this_policy['policySubTypes'] and this_policy['remediable']
        #
        RESULTS['policies'][this_policy_id]['policySystemDefault'] = this_policy['systemDefault']
        RESULTS['policies'][this_policy_id]['policyLabels']        = this_policy['labels']
        if 'policyUpi' in this_policy:
            RESULTS['policies'][this_policy_id]['policyUpi'] = this_policy['policyUpi']
        else:
            RESULTS['policies'][this_policy_id]['policyUpi'] = 'UNKNOWN'
        # Alerts
        if CONFIG['SUPPORT_API_MODE']:
            if this_policy['name'] in RESULTS['alerts_aggregated_by']['policy']:
                RESULTS['policies'][this_policy_id]['alertCount'] = RESULTS['alerts_aggregated_by']['policy'][this_policy['name']]
            else:
                RESULTS['policies'][this_policy_id]['alertCount'] = 0
        else:
            RESULTS['policies'][this_policy_id]['alertCount']     = this_policy['openAlertsCount']
        RESULTS['alert_counts_from_policies']['status']['open']                               += RESULTS['policies'][this_policy_id]['alertCount']
        RESULTS['alert_counts_from_policies']['severity'][this_policy['severity']]            += RESULTS['policies'][this_policy_id]['alertCount']
        RESULTS['alert_counts_from_policies']['type'][this_policy['policyType']]              += RESULTS['policies'][this_policy_id]['alertCount']
        RESULTS['alert_counts_from_policies']['cloud_type'][this_policy['cloudType'].lower()] += RESULTS['policies'][this_policy_id]['alertCount']
        if RESULTS['policies'][this_policy_id]['policyRemediable']:
            RESULTS['alert_counts_from_policies']['feature']['remediable']         += RESULTS['policies'][this_policy_id]['alertCount']
        if RESULTS['policies'][this_policy_id]['policyShiftable']:
            RESULTS['alert_counts_from_policies']['feature']['shiftable']          += RESULTS['policies'][this_policy_id]['alertCount']
        if RESULTS['policies'][this_policy_id]['policyShiftableRemediable']:
            RESULTS['alert_counts_from_policies']['feature']['remediable_and_shiftable'] += RESULTS['policies'][this_policy_id]['alertCount']
        if RESULTS['policies'][this_policy_id]['policySystemDefault'] == True:
            RESULTS['alert_counts_from_policies']['mode']['default']               += RESULTS['policies'][this_policy_id]['alertCount']
        else:
            RESULTS['alert_counts_from_policies']['mode']['custom']                += RESULTS['policies'][this_policy_id]['alertCount']
        # Create sets and lists of Compliance Standards to create a sorted, unique list of counters for each Compliance Standard.
        RESULTS['policies'][this_policy_id]['complianceStandards'] = list()
        if 'complianceMetadata' in this_policy:
            compliance_standards_set = set()
            for standard in this_policy['complianceMetadata']:
                compliance_standards_set.add(standard['standardName'])
            compliance_standards_list = list(compliance_standards_set)
            compliance_standards_list.sort()
            RESULTS['policies'][this_policy_id]['complianceStandards'] = compliance_standards_list
            for compliance_standard_name in compliance_standards_list:
                RESULTS['compliance_standards_from_policies'].setdefault(compliance_standard_name, {'high': 0, 'medium': 0, 'low': 0})
                RESULTS['compliance_standards_from_policies'][compliance_standard_name][this_policy['severity']] += RESULTS['policies'][this_policy_id]['alertCount']

##########################################################################################
# Loop through all Alerts and collect the details of each Alert.
# Alert data includes Open and Closed Alerts.
# Some details come from the Alert, some from the related Policy and Compliance Standards.
# Alerts can contain a reference to a Policy that has been deleted.
# SUPPORT_API_MODE: Substitute aggregated Alerts (as '/_support/policy' does not return openAlertsCount).
##########################################################################################

def process_alerts(alerts):
    if CONFIG['SUPPORT_API_MODE']:
        RESULTS['policy_counts_from_alerts']['severity']['high']    = RESULTS['alerts_aggregated_by']['severity']['high']
        RESULTS['policy_counts_from_alerts']['severity']['medium']  = RESULTS['alerts_aggregated_by']['severity']['medium']
        RESULTS['policy_counts_from_alerts']['severity']['low']     = RESULTS['alerts_aggregated_by']['severity']['low']
        RESULTS['policy_counts_from_alerts']['type']['anomaly']     = RESULTS['alerts_aggregated_by']['type']['anomaly']
        RESULTS['policy_counts_from_alerts']['type']['audit_event'] = RESULTS['alerts_aggregated_by']['type']['audit_event']
        RESULTS['policy_counts_from_alerts']['type']['config']      = RESULTS['alerts_aggregated_by']['type']['config']
        RESULTS['policy_counts_from_alerts']['type']['data']        = RESULTS['alerts_aggregated_by']['type']['data']
        RESULTS['policy_counts_from_alerts']['type']['iam']         = RESULTS['alerts_aggregated_by']['type']['iam']
        RESULTS['policy_counts_from_alerts']['type']['network']     = RESULTS['alerts_aggregated_by']['type']['network']
        RESULTS['alert_counts_from_alerts']['status']['open']       = RESULTS['alerts_aggregated_by']['status']['open']
        RESULTS['alert_counts_from_alerts']['status']['resolved']   = RESULTS['alerts_aggregated_by']['status']['resolved']
    else:
        for this_alert in alerts:
            this_policy_id = this_alert['policy']['policyId']
            if this_alert['policy']['systemDefault'] == True:
                RESULTS['alert_counts_from_alerts']['mode']['default'] += 1
            else:
                RESULTS['alert_counts_from_alerts']['mode']['custom']  += 1
            RESULTS['alert_counts_from_alerts']['type'][this_alert['policy']['policyType']] += 1
            if this_alert['policy']['remediable']:
                RESULTS['alert_counts_from_alerts']['feature']['remediable'] += 1
                RESULTS['alert_counts_from_alerts']['status_by_feature']['remediable'][this_alert['status']] += 1
            RESULTS['alert_counts_from_alerts']['status'][this_alert['status']] += 1
            if 'reason' in this_alert:
                if this_alert['reason'] == 'RESOURCE_DELETED':
                    RESULTS['alert_counts_from_alerts']['resolved_by_resource']['deleted'] += 1
                if this_alert['reason'] == 'RESOURCE_UPDATED':
                    RESULTS['alert_counts_from_alerts']['resolved_by_resource']['updated'] += 1
            if 'resource' in this_alert:
                if 'rrn' in this_alert['resource']:
                    RESULTS['resources_from_alerts'][this_alert['resource']['rrn']] = this_alert['resource']['rrn']
            #
            # This is all of the data we can collect without a reference to a Policy.
            #
            if not this_policy_id in RESULTS['policies']:
                if 'reason' in this_alert:
                    if this_alert['reason'] == 'POLICY_DELETED':
                        RESULTS['deleted_policies_from_alerts'].setdefault(this_policy_id, 0)
                        RESULTS['deleted_policies_from_alerts'][this_policy_id] += 1
                        RESULTS['alert_counts_from_alerts']['resolved_by_policy']['deleted'] += 1
                if CONFIG['DEBUG_MODE']:
                    output('Skipping Alert: Related Policy Not Found: Policy ID: %s' % this_policy_id)
                continue
            # Policy data from the related Policy.
            policy_name = RESULTS['policies'][this_policy_id]['policyName']
            RESULTS['policies_from_alerts'].setdefault(policy_name, {'policyId': this_policy_id, 'alertCount': 0})
            RESULTS['policies_from_alerts'][policy_name]['alertCount'] += 1
            RESULTS['policy_counts_from_alerts']['severity'][RESULTS['policies'][this_policy_id]['policySeverity']] += 1
            RESULTS['policy_counts_from_alerts']['type'][RESULTS['policies'][this_policy_id]['policyType']] += 1
            if RESULTS['policies'][this_policy_id]['policyEnabled'] == False:
                RESULTS['disabled_policies_from_alerts'].setdefault(policy_name, 0)
                RESULTS['disabled_policies_from_alerts'][policy_name] += 1
                RESULTS['alert_counts_from_alerts']['policy']['disabled'] += 1
            # Compliance Standard data from the related Policy.
            for compliance_standard_name in RESULTS['policies'][this_policy_id]['complianceStandards']:
                RESULTS['compliance_standards_from_alerts'].setdefault(compliance_standard_name, {'high': 0, 'medium': 0, 'low': 0})
                RESULTS['compliance_standards_from_alerts'][compliance_standard_name][RESULTS['policies'][this_policy_id]['policySeverity']] += 1
            # Alert data from the related Policy.
            RESULTS['alert_counts_from_alerts']['cloud_type'][RESULTS['policies'][this_policy_id]['policyCloudType']] += 1
            if RESULTS['policies'][this_policy_id]['policyShiftable']:
                RESULTS['alert_counts_from_alerts']['feature']['shiftable'] += 1
            if RESULTS['policies'][this_policy_id]['policyRemediable']:
                RESULTS['alert_counts_from_alerts']['feature']['remediable'] += 1
            if RESULTS['policies'][this_policy_id]['policyShiftableRemediable']:
                RESULTS['alert_counts_from_alerts']['feature']['remediable_and_shiftable'] += 1
            RESULTS['alert_counts_from_alerts']['severity_by_status'][this_alert['status']][RESULTS['policies'][this_policy_id]['policySeverity']] += 1

##########################################################################################
# Process mode: Summarize the data.
##########################################################################################

def process_summary():
    if CONFIG['SUPPORT_API_MODE']:
        RESULTS['summary']['count_of_policies_with_alerts_from_policies']         = len(RESULTS['alerts_aggregated_by']['policy'])
        RESULTS['summary']['count_of_aggregated_open_alerts']                     = RESULTS['alerts_aggregated_by']['status']['open']
    else:
        RESULTS['summary']['count_of_resources_with_alerts_from_alerts']          = len(RESULTS['resources_from_alerts'].keys())
        RESULTS['summary']['count_of_policies_with_alerts_from_policies']         = sum(v['alertCount'] != 0 for k,v in RESULTS['policies'].items())
        RESULTS['summary']['count_of_open_closed_alerts']                         = len(DATA['ALERTS'])
    RESULTS['summary']['count_of_compliance_standards_with_alerts_from_policies'] = sum(v != {'high': 0, 'medium': 0, 'low': 0} for k,v in RESULTS['compliance_standards_from_policies'].items())
    RESULTS['summary']['count_of_compliance_standards_with_alerts_from_alerts']   = len(RESULTS['compliance_standards_from_alerts'])
    RESULTS['summary']['count_of_policies_with_alerts_from_alerts']               = len(RESULTS['policies_from_alerts'])
    #
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['aws']           = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'aws'     for k,v in RESULTS['policies'].items())
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['azure']         = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'azure'   for k,v in RESULTS['policies'].items())
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['gcp']           = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'gcp'     for k,v in RESULTS['policies'].items())
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['alibaba_cloud'] = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'alibaba_cloud' for k,v in RESULTS['policies'].items())
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['oci']           = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'oci'     for k,v in RESULTS['policies'].items())
    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['all']           = sum(v['alertCount'] != 0 and v['policyCloudType'].lower() == 'all'     for k,v in RESULTS['policies'].items())

##########################################################################################
# Process mode: Output the data.
##########################################################################################

def output_alerts_summary(customer_name):
    if RESULTS['alert_counts_from_policies']['type']['config'] > 0:
        ratio = round((RESULTS['alert_counts_from_policies']['feature']['shiftable'] / RESULTS['alert_counts_from_policies']['type']['config']) * 100)
        if (RESULTS['alert_counts_from_policies']['status']['open'] > CONFIG['MINIMUM_ALERTS'] and ratio > CONFIG['MINIMUM_RATIO']):
            output()
            output('Customer: %s' % customer_name)
            output('  Open Alerts: %s' %                 RESULTS['alert_counts_from_policies']['status']['open'])
            output('  Open Config Alerts: %s' %          RESULTS['alert_counts_from_policies']['type']['config'])
            output('  Open Config Alerts with IaC: %s' % RESULTS['alert_counts_from_policies']['feature']['shiftable'])
            # RESULTS['alert_counts_from_policies']['feature']['remediable']
            # RESULTS['alert_counts_from_policies']['feature']['remediable_and_shiftable']
            output('  Open Config Alert/IaC Ratio: %s %s' % (ratio, '%'))

##########################################################################################
##########################################################################################
## Main
##########################################################################################
##########################################################################################

# This is something of a constant after it has been initially populated by configure(),
# except CONFIG['PRISMA_API_HEADERS']['x-redlock-auth'] and CONFIG['SUPPORT_API_MODE'] are added/updated later.
CONFIG = configure(args)

# This is a constant after it has been initially populated by read_collected_data().
DATA = {}

# This is not a constant, just capitalized for visibility.
RESULTS = {}

if CONFIG['RUN_MODE'] in ['collect', 'auto']:
    output('Collecting Data')
    output()
    collect_data()
    output()

if CONFIG['RUN_MODE'] in ['process', 'auto']:
    output('Processing Data')
    output()
    read_collected_data()
