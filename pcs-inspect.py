#!/usr/bin/env python3

import argparse
import json
import math
import os
import pandas as pd
import re
import requests
from requests.exceptions import RequestException
import sys

##########################################################################################
# Process arguments / parameters.
##########################################################################################

pc_parser = argparse.ArgumentParser(description='This script collects or processes Policies and Alerts.', prog=os.path.basename(__file__))

pc_parser.add_argument(
    '-c', '--customer_name',
    type=str, required=True,
    help='*Required* Customer Name')

pc_parser.add_argument('-u', '--url',
    type=str,
    help="(Required with '--mode collect') Prisma Cloud API URL")

pc_parser.add_argument('-a', '--access_key',
    type=str,
    help="(Required with '--mode collect') API Access Key")

pc_parser.add_argument('-s', '--secret_key',
    type=str,
    help="(Required with '--mode collect') API Secret Key")

pc_parser.add_argument('-ca', '--cloud_account',
    type=str,
    help='(Optional) Cloud Account ID to limit the Alert query')

pc_parser.add_argument('-ta', '--time_range_amount',
    type=int, default=1, choices=[1, 2, 3],
    help="(Optional) Time Range Amount to limit the Alert query. Default: 1")

pc_parser.add_argument('-tu', '--time_range_unit',
    type=str, default='month', choices=['day', 'week', 'month', 'year'],
    help="(Optional) Time Range Unit to limit the Alert query. Default: 'month'")

pc_parser.add_argument('-m', '--mode',
    type=str, default='auto', choices=['collect', 'process'],
    help="(Optional) Mode: just collect Policies and Alerts, or just process collected data")

pc_parser.add_argument('-sa', '--support_api',
    action='store_true',
    help='(Optional) Use the Support API to collect data without needing a Tenant API Key')

pc_parser.add_argument('-d', '--debug',
    action='store_true',
    help='(Optional) Enable debugging.')

args = pc_parser.parse_args()

##########################################################################################
# Configure.
##########################################################################################

DEBUG_MODE          = args.debug
RUN_MODE            = args.mode
SUPPORT_API_MODE    = args.support_api
PRISMA_API_ENDPOINT = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
PRISMA_ACCESS_KEY   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
PRISMA_SECRET_KEY   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
PRISMA_API_HEADERS  = {
    'Accept': 'application/json; charset=UTF-8, text/plain, */*',
    'Content-Type': 'application/json'
}
API_TIMEOUTS      = (60, 600) # (CONNECT, READ)
CUSTOMER_NAME     = args.customer_name
CLOUD_ACCOUNT_ID  = args.cloud_account
TIME_RANGE_AMOUNT = args.time_range_amount
TIME_RANGE_UNIT   = args.time_range_unit
TIME_RANGE_LABEL  = 'Past %s %s' % (TIME_RANGE_AMOUNT, TIME_RANGE_UNIT.capitalize())
CUSTOMER_PREFIX   = re.sub(r'\W+', '', CUSTOMER_NAME).lower()
RESULT_FILES = {
    'ASSETS':       '%s-assets.txt'        % CUSTOMER_PREFIX,
    'POLICIES':     '%s-policies.txt'      % CUSTOMER_PREFIX,
    'ALERTS':       '%s-alerts.txt'        % CUSTOMER_PREFIX,
    'USERS':        '%s-users.txt'         % CUSTOMER_PREFIX,
    'ACCOUNTS':     '%s-accounts.txt'      % CUSTOMER_PREFIX,
    'GROUPS':       '%s-groups.txt'        % CUSTOMER_PREFIX,
    'RULES':        '%s-rules.txt'         % CUSTOMER_PREFIX,
    'INTEGRATIONS': '%s-integrations.txt'  % CUSTOMER_PREFIX
}
OUTPUT_FILE_XLS = '%s.xls' % CUSTOMER_PREFIX

##########################################################################################
# Helpers.
##########################################################################################

def output(output_data=''):
    print(output_data)

####

def open_sheet(file_name):
    return pd.ExcelWriter(file_name, engine='xlsxwriter')

####

def write_sheet(panda_writer, this_sheet_name, rows):
    dataframe = pd.DataFrame.from_records(rows)
    dataframe.to_excel(panda_writer, sheet_name=this_sheet_name, header=False, index=False)
    if DEBUG_MODE:
        print(this_sheet_name)
        print()
        pd.set_option('display.max_rows', None)
        print(dataframe)
        print()

####

def save_sheet(panda_writer):
    panda_writer.save()

####

def make_api_call(method, url, requ_data=None):
    try:
        requ = requests.Request(method, url, data = requ_data, headers = PRISMA_API_HEADERS)
        prep = requ.prepare()
        sess = requests.Session()
        # GlobalProtect generates 'ignore self signed certificate in certificate chain' errors:
        requests.packages.urllib3.disable_warnings()
        resp = sess.send(prep, timeout=(API_TIMEOUTS), verify=False)
        if resp.status_code == 200:
            return resp.content
        else:
            return bytes('[]', 'utf-8')
    except RequestException as e:
        output('Error with API: %s: %s' % (url, str(e)))
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
        output('Error with API Login: %s' % resp_data)
        sys.exit()
    return token

#### Valid options: policy.name, policy.type, policy.severity, or alert.status.

def get_alerts_aggregate(group_by_field):
    body_params = {}
    body_params = {"customerName": "%s" % CUSTOMER_NAME}
    if CLOUD_ACCOUNT_ID:
        body_params["accountIds"] = ["%s" % CLOUD_ACCOUNT_ID]
    body_params['timeRange'] = {"value": {"unit": "%s" % TIME_RANGE_UNIT, "amount": TIME_RANGE_AMOUNT}, "type": "relative"}
    body_params['groupBy'] = group_by_field 
    body_params['limit'] = 9999
    request_data = json.dumps(body_params)
    api_response = make_api_call('POST', '%s/_support/alert/aggregate' % PRISMA_API_ENDPOINT, request_data)
    return api_response

# SUPPORT_API_MODE:
# Use '/_support/timeline/resource' instead of the not implemented '_support/v2/inventory' endpoint.
    
def get_assets():
    if SUPPORT_API_MODE:
        body_params = {}
        body_params["customerName"] = "%s" % CUSTOMER_NAME
        if CLOUD_ACCOUNT_ID:
            body_params["accountIds"] = ["%s" % CLOUD_ACCOUNT_ID]
        body_params['timeRange'] = {"value": {"unit": "%s" % TIME_RANGE_UNIT, "amount": TIME_RANGE_AMOUNT}, "type": "relative"}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/timeline/resource' % PRISMA_API_ENDPOINT, request_data)
        api_response_json = json.loads(api_response)
        if api_response_json and 'resources' in api_response_json[0]:
            api_response = bytes('{"summary": {"totalResources": %s}}' % api_response_json[0]['resources'], 'utf-8')
        else:
            api_response = bytes('{"summary": {"totalResources": 0}}', 'utf-8')
    else:
        if CLOUD_ACCOUNT_ID:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s&cloud.account=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT, CLOUD_ACCOUNT_ID)
        else:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT)
        api_response = make_api_call('GET', '%s/v2/inventory?%s' % (PRISMA_API_ENDPOINT, query_params))
    result_file = open(RESULT_FILES['ASSETS'], 'wb')
    result_file.write(api_response)
    result_file.close()
    # This returns a dictionary instead of a list.

# SUPPORT_API_MODE:
# This script depends upon Open Alert counts for all Policies (as provided by '/policy'), but '/_support/policy' doesn't return open Alert counts.
# And '/_support/alert/policy' does return alertCount, but I cannot tell if that is all (Open or Closed) or just Open Alerts, and returns fewer Policies than '_support/policy' ... given the same parameters.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_policies():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/policy?policy.enabled=true' % PRISMA_API_ENDPOINT, request_data)
        result_file = open(RESULT_FILES['POLICIES'], 'wb')
        result_file.write(api_response)
        result_file.close()
    else:
        api_response = make_api_call('GET', '%s/policy?policy.enabled=true' % PRISMA_API_ENDPOINT)
        result_file = open(RESULT_FILES['POLICIES'], 'wb')
        result_file.write(api_response)
        result_file.close()

# SUPPORT_API_MODE:
# This script depends upon the not implemented '/_support/v2/alert(s)' endpoint.
# And the '/_support/alert' endpoint returns 'getAlert()' instead of 'getAlerts()' on the backend.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_alerts():
    if SUPPORT_API_MODE:
        api_response = {}
        api_response['by_policy']          = json.loads(get_alerts_aggregate('policy.name'))     # [{"policyName":"AWS VPC subnets should not allow automatic public IP assignment","alerts":105},{"policyName":"AWS Security Group overly permissive to all traffic","alerts":91}, ...
        api_response['by_policy_type']     = json.loads(get_alerts_aggregate('policy.type'))     # [{"alerts":422,"policyType":"config"},{"alerts":15,"policyType":"network"},{"alerts":2,"policyType":"anomaly"},{"alerts":0,"policyType":"iam"},{"alerts":0,"policyType":"data"},{"alerts":0,"policyType":"audit_event"}]
        api_response['by_policy_severity'] = json.loads(get_alerts_aggregate('policy.severity')) # [{"severity":"medium","alerts":225},{"severity":"high","alerts":214},{"severity":"low","alerts":0}]
        api_response['by_alert.status']    = json.loads(get_alerts_aggregate('alert.status'))    # [{"alerts":439,"status":"open"},{"alerts":88,"status":"resolved"},{"alerts":0,"status":"dismissed"},{"alerts":0,"status":"snoozed"}]'
        api_response_json = json.dumps(api_response, indent=2, separators=(', ', ': '))
        result_file = open(RESULT_FILES['ALERTS'], 'w')
        result_file.write(api_response_json)
        result_file.close()
        # This returns a dictionary (of Open Alerts) instead of a list.
    else:
        body_params = {}
        body_params['timeRange'] = {"value": {"unit": "%s" % TIME_RANGE_UNIT, "amount": TIME_RANGE_AMOUNT}, "type": "relative"}
        if CLOUD_ACCOUNT_ID:
            body_params["filters"] = [{"name": "cloud.accountId","value": "%s" % CLOUD_ACCOUNT_ID, "operator": "="}]
        body_params['limit'] = 100
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/v2/alert' % PRISMA_API_ENDPOINT, request_data)
        api_response_json = json.loads(api_response)
        api_response_array = api_response_json['items']
        result_file = open(RESULT_FILES['ALERTS'], 'w')
        while 'nextPageToken' in api_response_json:
            sys.stdout.write('.')
            sys.stdout.flush()
            body_params = {}
            body_params['limit'] = 100
            body_params['pageToken'] = api_response_json['nextPageToken']
            request_data = json.dumps(body_params)
            api_response = make_api_call('POST', '%s/v2/alert' % PRISMA_API_ENDPOINT, request_data)
            api_response_json = json.loads(api_response)
            if 'items' in api_response_json:
                api_response_array_page = api_response_json['items']
                api_response_array.extend(api_response_array_page)
        api_response_array_json = json.dumps(api_response_array, indent=2, separators=(', ', ': '))
        result_file.write(api_response_array_json)
        result_file.close()
        # This returns a list (of Open and Closed Alerts).

def get_users():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/v2/_support/user' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/user' % PRISMA_API_ENDPOINT)
    result_file = open(RESULT_FILES['USERS'], 'wb')
    result_file.write(api_response)
    result_file.close()

# TODO: Query for any accounts that are children of an organization via https://api.prismacloud.io/cloud/cloud_type/id/project
#   "accountType": "organization",
#   "cloudType": 
#   "numberOfChildAccounts":

def get_accounts():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/cloud' % PRISMA_API_ENDPOINT)
    result_file = open(RESULT_FILES['ACCOUNTS'], 'wb')
    result_file.write(api_response)
    result_file.close()

def get_account_groups():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud/group' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/cloud/group' % PRISMA_API_ENDPOINT)
    result_file = open(RESULT_FILES['GROUPS'], 'wb')
    result_file.write(api_response)
    result_file.close()

def get_alert_rules():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/alert/rule' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/alert/rule' % PRISMA_API_ENDPOINT)
    result_file = open(RESULT_FILES['RULES'], 'wb')
    result_file.write(api_response)
    result_file.close()

def get_integrations():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/integration' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/integration' % PRISMA_API_ENDPOINT)
    result_file = open(RESULT_FILES['INTEGRATIONS'], 'wb')
    result_file.write(api_response)
    result_file.close()

##########################################################################################
# Collect mode: Query the API and write the results to files.
##########################################################################################

if RUN_MODE in ['collect', 'auto'] :
    if not PRISMA_API_ENDPOINT:
        output("Error: '--url' is required")
        sys.exit(0)
    if not PRISMA_ACCESS_KEY:
        output("Error: '--access_key' is required")
        sys.exit(0)
    if not PRISMA_SECRET_KEY:
        output("Error: '--secret_key' is required")
        sys.exit(0)
    output('Generating Prisma Cloud API Token')
    token = get_prisma_login()
    if DEBUG_MODE:
        output()
        output(token)
        output()
    PRISMA_API_HEADERS['x-redlock-auth'] = token
    output()
    output('Querying Assets')
    get_assets()
    output('Results saved as: %s' % RESULT_FILES['ASSETS'])
    output()
    output('Querying Policies')
    get_policies()
    output('Results saved as: %s' % RESULT_FILES['POLICIES'])
    output()
    output('Querying Alerts (please wait)')
    get_alerts()
    output()
    output('Results saved as: %s' % RESULT_FILES['ALERTS'])
    output()
    output('Querying Users')
    get_users()
    output('Results saved as: %s' % RESULT_FILES['USERS'])
    output()
    output('Querying Accounts')
    get_accounts()
    output('Results saved as: %s' % RESULT_FILES['ACCOUNTS'])
    output()
    output('Querying Account Groups')
    get_account_groups()
    output('Results saved as: %s' % RESULT_FILES['GROUPS'])
    output()
    output('Querying Alert Rules')
    get_alert_rules()
    output('Results saved as: %s' % RESULT_FILES['RULES'])
    output()
    output('Querying Integrations')
    get_integrations()
    output('Results saved as: %s' % RESULT_FILES['INTEGRATIONS'])
    output()
    if RUN_MODE == 'collect':
        output("Run '%s --customer_name %s --mode process' to process the collected data and save to a spreadsheet." % (os.path.basename(__file__), CUSTOMER_NAME))
        sys.exit(0)

##########################################################################################
# Inspect mode: Read the result files and write output files.
##########################################################################################

DATA = {}

# Read input files.

for this_result_file in RESULT_FILES:
    if not os.path.isfile(RESULT_FILES[this_result_file]):
      output('Error: Query result file does not exist: %s' % RESULT_FILES[this_result_file])
      sys.exit(1)
    with open(RESULT_FILES[this_result_file], 'r') as f:
      DATA[this_result_file] = json.load(f)

# SUPPORT_API_MODE returns a dictionary (of Open Alerts) instead of a list.

if type(DATA['ALERTS']) is dict:
    SUPPORT_API_MODE = True

##########################################################################################
# SUPPORT_API_MODE: Loop through aggregated Alerts and collect the details.
# Alert counts from this endpoint include Open Alerts and are scoped to a time range.
##########################################################################################

if SUPPORT_API_MODE:
    aggregate_alerts_by = {'policy': {}, 'type': {}, 'severity': {}, 'status': {}}
    for item in DATA['ALERTS']['by_policy']:
        aggregate_alerts_by['policy'][item['policyName']] = item['alerts']
    for item in DATA['ALERTS']['by_policy_type']:
        aggregate_alerts_by['type'][item['policyType']]   = item['alerts']
    for item in DATA['ALERTS']['by_policy_severity']:
        aggregate_alerts_by['severity'][item['severity']] = item['alerts'] 
    for item in DATA['ALERTS']['by_alert.status']:
        aggregate_alerts_by['status'][item['status']]     = item['alerts']

##########################################################################################
# Loop through all Policies and collect the details.
# Alert counts from this endpoint include Open Alerts and are not scoped to a time range.
# SUPPORT_API_MODE: Substitute aggregated Alerts (as _support/policy does not return openAlertsCount).
##########################################################################################
  
# Collect Compliance Standard totals from Policy data.

compliance_standards_counts_from_policies = {}

# Collect Policy totals from Policy data.

policies = {}
policies_by_name = {}

# Collect (open) Alert totals from Policy data, in case we are unable to retrieve alert data from the /alerts endpoint.

alert_totals_by_policy = {
    'open':        0,
    'open_high':   0,
    'open_medium': 0,
    'open_low':    0,
    'anomaly':     0,
    'audit_event': 0,
    'config':      0,
    'data':        0,
    'iam':         0,
    'network':     0,
    'remediable':  0,
    'shiftable':   0,
    'custom':      0,
    'default':     0
}

for this_policy in DATA['POLICIES']:
    this_policy_id = this_policy['policyId']
    policies[this_policy_id] = {}
    if SUPPORT_API_MODE:
        if this_policy['name'] in aggregate_alerts_by['policy']:
            policies[this_policy_id]['alertCount']  = aggregate_alerts_by['policy'][this_policy['name']]
        else:
            policies[this_policy_id]['alertCount']  = 0
    else:
        policies[this_policy_id]['alertCount']      = this_policy['openAlertsCount']    
    policies[this_policy_id]['policyName']          = this_policy['name']
    policies[this_policy_id]['policySeverity']      = this_policy['severity']
    policies[this_policy_id]['policyType']          = this_policy['policyType']
    policies[this_policy_id]['policyShiftable']     = 'build' in this_policy['policySubTypes']
    policies[this_policy_id]['policyRemediable']    = this_policy['remediable']
    policies[this_policy_id]['policySystemDefault'] = this_policy['systemDefault']
    # Create sets and lists of Compliance Standards to create a sorted, unique list of counters for each Compliance Standard.
    policies[this_policy_id]['complianceStandards'] = list()
    if 'complianceMetadata' in this_policy:
        compliance_standards_set = set()
        for standard in this_policy['complianceMetadata']:
            compliance_standards_set.add(standard['standardName'])
        compliance_standards_list = list(compliance_standards_set)
        compliance_standards_list.sort()
        policies[this_policy_id]['complianceStandards'] = compliance_standards_list
        for compliance_standard_name in compliance_standards_list:
            compliance_standards_counts_from_policies.setdefault(compliance_standard_name, {'high': 0, 'medium': 0, 'low': 0})
            compliance_standards_counts_from_policies[compliance_standard_name][this_policy['severity']] += policies[this_policy_id]['alertCount']
    policies_by_name[this_policy['name']] = {'policyId': this_policy_id}
    # Alerts
    alert_totals_by_policy['open']                              += policies[this_policy_id]['alertCount']
    alert_totals_by_policy['open_%s' % this_policy['severity']] += policies[this_policy_id]['alertCount']
    alert_totals_by_policy[this_policy['policyType']]           += policies[this_policy_id]['alertCount']
    if policies[this_policy_id]['policyRemediable']:
        alert_totals_by_policy['remediable']                    += policies[this_policy_id]['alertCount']
    if policies[this_policy_id]['policyShiftable']:
        alert_totals_by_policy['shiftable']                     += policies[this_policy_id]['alertCount']
    if policies[this_policy_id]['policySystemDefault'] == True:
        alert_totals_by_policy['default']                       += policies[this_policy_id]['alertCount']
    else:
        alert_totals_by_policy['custom']                        += policies[this_policy_id]['alertCount']        

##########################################################################################
# Loop through all Alerts and collect the details of each Alert.
# Some details come from the Alert, some from the associated Policy.
##########################################################################################

# Collect Compliance Standard totals from Alert data, as Alert data includes open and closed Alerts.

compliance_standards_counts_from_alerts = {}

# Collect Policy totals from Alert data, as Alert data includes open and closed Alerts.

policy_counts_from_alerts = {}

policy_totals_by_alert = {
    'high':        0,
    'medium':      0,
    'low':         0,
    'anomaly':     0,
    'audit_event': 0,
    'config':      0,
    'data':        0,
    'iam':         0,
    'network':     0,
    'custom':      0,
    'default':     0,
}

# Collect Alert totals from Alert data.

alert_totals_by_alert = {
    'open':                0,
    'open_high':           0,
    'open_medium':         0,
    'open_low':            0,
    'resolved':            0,
    'resolved_deleted':    0,
    'resolved_updated':    0,
    'resolved_high':       0,
    'resolved_medium':     0,
    'resolved_low':        0,
    'dismissed':           0,
    'snoosed':             0,
    'remediable':          0,
    'remediable_open':     0,
    'remediable_resolved': 0,
    'shiftable':           0,
    'custom':              0,
    'default':             0
}

# With , as Alert data includes open and closed Alerts.

if SUPPORT_API_MODE:
    policy_totals_by_alert['high']        = aggregate_alerts_by['severity']['high']
    policy_totals_by_alert['medium']      = aggregate_alerts_by['severity']['medium']
    policy_totals_by_alert['low']         = aggregate_alerts_by['severity']['low']
    policy_totals_by_alert['anomaly']     = aggregate_alerts_by['type']['anomaly']
    policy_totals_by_alert['audit_event'] = aggregate_alerts_by['type']['audit_event']
    policy_totals_by_alert['config']      = aggregate_alerts_by['type']['config']
    policy_totals_by_alert['data']        = aggregate_alerts_by['type']['data']
    policy_totals_by_alert['iam']         = aggregate_alerts_by['type']['iam']
    policy_totals_by_alert['network']     = aggregate_alerts_by['type']['network']
    alert_totals_by_alert['open']         = aggregate_alerts_by['status']['open']
    alert_totals_by_alert['resolved']     = aggregate_alerts_by['status']['resolved']
else:
    for this_alert in DATA['ALERTS']:
        this_policy_id = this_alert['policy']['policyId']
        if not this_policy_id in policies:
            if DEBUG_MODE:
                output('Skipping Alert: Policy Deleted or Disabled: Policy ID: %s' % this_policy_id)
            continue
        policy_name = policies[this_policy_id]['policyName']
        # Compliance Standards
        for compliance_standard_name in policies[this_policy_id]['complianceStandards']:
            compliance_standards_counts_from_alerts.setdefault(compliance_standard_name, {'high': 0, 'medium': 0, 'low': 0})
            compliance_standards_counts_from_alerts[compliance_standard_name][policies[this_policy_id]['policySeverity']] += 1
        # Policies
        policy_counts_from_alerts.setdefault(policy_name, {'policyId': this_policy_id, 'alertCount': 0})
        policy_counts_from_alerts[policy_name]['alertCount']          += 1
        policy_totals_by_alert[policies[this_policy_id]['policySeverity']] += 1
        policy_totals_by_alert[policies[this_policy_id]['policyType']]     += 1
        # Alerts
        alert_totals_by_alert[this_alert['status']] += 1
        if 'reason' in this_alert:
            if this_alert['reason'] == 'RESOURCE_DELETED':
                alert_totals_by_alert['resolved_deleted'] += 1
            if this_alert['reason'] == 'RESOURCE_UPDATED':
                alert_totals_by_alert['resolved_updated'] += 1
        alert_totals_by_alert['%s_%s' % (this_alert['status'], policies[this_policy_id]['policySeverity'])] += 1
        if this_alert['policy']['remediable']:
            alert_totals_by_alert['remediable'] += 1
            alert_totals_by_alert['remediable_%s' % this_alert['status']] += 1
        if policies[this_policy_id]['policyShiftable']:
            alert_totals_by_alert['shiftable']  += 1
        if policies[this_policy_id]['policySystemDefault'] == True:
            alert_totals_by_alert['default']    += 1
        else:
            alert_totals_by_alert['custom']     += 1
    
##########################################################################################
# Variable output variables.
##########################################################################################

asset_count = DATA['ASSETS']['summary']['totalResources']

count_of_compliance_standards_with_alerts_from_policies = sum(v != {'high': 0, 'medium': 0, 'low': 0} for k,v in compliance_standards_counts_from_policies.items())

if SUPPORT_API_MODE:
    VAR_TIME_RANGE = ' %s' % TIME_RANGE_LABEL
    alert_count                                             = aggregate_alerts_by['status']['open']
    count_of_policies_with_alerts_from_policies             = len(aggregate_alerts_by['policy'])
else:
    VAR_TIME_RANGE = ''
    alert_count                                             = len(DATA['ALERTS'])
    count_of_policies_with_alerts_from_policies             = sum(v['alertCount'] != 0 for k,v in policies.items())
    count_of_compliance_standards_with_alerts_from_alerts   = len(compliance_standards_counts_from_alerts)
    count_of_policies_with_alerts_from_alerts               = len(policy_counts_from_alerts)

##########################################################################################
# Output totals.
##########################################################################################

panda_writer = open_sheet(OUTPUT_FILE_XLS)

output()
output('Saving Utilization Worksheet')
output()
rows = [
    ('Number of Assets',               asset_count),
    ('',''),
    ('Number of Cloud Accounts',       len(DATA['ACCOUNTS'])), # (Not Including Child Accounts)
    ('Cloud Accounts Disabled',        sum(x.get('enabled') == False for x in DATA['ACCOUNTS'])),
    ('Cloud Accounts Enabled',         sum(x.get('enabled') == True for x in DATA['ACCOUNTS'])),
    ('',''),
    ('Number of Cloud Account Groups', len(DATA['GROUPS'])),
    ('',''),
    ('Number of Alert Rules',          len(DATA['RULES'])),
    ('Alert Rules Disabled',           sum(x.get('enabled') == False for x in DATA['RULES'])),
    ('Alert Rules Enabled',            sum(x.get('enabled') == True for x in DATA['RULES'])),
    ('',''),
    ('Number of Integrations',         len(DATA['INTEGRATIONS'])),
    ('Integrations Disabled',          sum(x.get('enabled') == False for x in DATA['INTEGRATIONS'])),
    ('Integrations Enabled',           sum(x.get('enabled') == True for x in DATA['INTEGRATIONS'])),
    ('',''),
    ('Number of Policies',             len(DATA['POLICIES'])),
    ('Policies Custom',                sum(x.get('systemDefault') == False for x in DATA['POLICIES'])),
    ('Policies Default',               sum(x.get('systemDefault') == True for x in DATA['POLICIES'])),
    ('',''),
    ('Number of Users',                len(DATA['USERS'])),
    ('Users Disabled',                 sum(x.get('enabled') == False for x in DATA['USERS'])),
    ('Users Enabled',                  sum(x.get('enabled') == True for x in DATA['USERS'])),    
]
write_sheet(panda_writer, 'Utilization', rows)

output('Saving Alerts by Compliance Standard Worksheet(s)')
output()
rows = []
rows.append(('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low') )
for compliance_standard_name in sorted(compliance_standards_counts_from_policies):
    alert_count_high   = compliance_standards_counts_from_policies[compliance_standard_name]['high']
    alert_count_medium = compliance_standards_counts_from_policies[compliance_standard_name]['medium']
    alert_count_low    = compliance_standards_counts_from_policies[compliance_standard_name]['low']
    rows.append((compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low) )
rows.append((''))
rows.append((''))
rows.append(('Time Range: %s' % VAR_TIME_RANGE, ''))
write_sheet(panda_writer, 'Open Alerts by Standard', rows)

if not SUPPORT_API_MODE:
    rows = []
    rows.append(('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low'))
    for compliance_standard_name in sorted(compliance_standards_counts_from_alerts):
        alert_count_high   = compliance_standards_counts_from_alerts[compliance_standard_name]['high']
        alert_count_medium = compliance_standards_counts_from_alerts[compliance_standard_name]['medium']
        alert_count_low    = compliance_standards_counts_from_alerts[compliance_standard_name]['low']
        rows.append((compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low))
    rows.append((''))
    rows.append((''))
    rows.append(('Time Range: %s' % TIME_RANGE_LABEL, ''))
    write_sheet(panda_writer, 'Open and Closed Alerts by Standard', rows)

output('Saving Alerts by Policy Worksheet(s)')
output()
rows = []
rows.append(('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Compliance Standards'))
for policy_name in sorted(policies_by_name):
    this_policy_id        = policies_by_name[policy_name]['policyId']
    policy_severity       = policies[this_policy_id]['policySeverity']
    policy_type           = policies[this_policy_id]['policyType']
    policy_is_shiftable   = policies[this_policy_id]['policyShiftable']
    policy_is_remediable  = policies[this_policy_id]['policyRemediable']
    policy_alert_count    = policies[this_policy_id]['alertCount']
    policy_standards_list = ','.join(map(str, policies[this_policy_id]['complianceStandards']))
    rows.append((policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_standards_list))
rows.append((''))
rows.append((''))
rows.append(('Time Range: %s' % VAR_TIME_RANGE, ''))
write_sheet(panda_writer, 'Open Alerts by Policy', rows)

if not SUPPORT_API_MODE:
    rows = []
    rows.append(('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Compliance Standards'))
    for policy_name in sorted(policy_counts_from_alerts):
        this_policy_id        = policy_counts_from_alerts[policy_name]['policyId']
        policy_severity       = policies[this_policy_id]['policySeverity']
        policy_type           = policies[this_policy_id]['policyType']
        policy_is_shiftable   = policies[this_policy_id]['policyShiftable']
        policy_is_remediable  = policies[this_policy_id]['policyRemediable']
        policy_alert_count    = policy_counts_from_alerts[policy_name]['alertCount']
        policy_standards_list = ','.join(map(str, policies[this_policy_id]['complianceStandards']))
        rows.append((policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_standards_list))
    rows.append((''))
    rows.append((''))
    rows.append(('Time Range: %s' % TIME_RANGE_LABEL, ''))
    write_sheet(panda_writer, 'Open and Closed Alerts by Policy', rows)

output('Saving Alerts Summary Worksheet(s)')
output()
rows = [
    ('Number of Compliance Standards with Open Alerts',  count_of_compliance_standards_with_alerts_from_policies),
    ('',''),
    ('Number of Policies with Open Alerts',              count_of_policies_with_alerts_from_policies),
    ('',''),
    ('Open Alerts',                                      alert_totals_by_policy['open']),
    ('',''),
    ('Open Alerts High-Severity',                        alert_totals_by_policy['open_high']),
    ('Open Alerts Medium-Severity',                      alert_totals_by_policy['open_medium']),
    ('Open Alerts Low-Severity',                         alert_totals_by_policy['open_low']),
    ('',''),
    ('Open Anomaly Alerts',                              alert_totals_by_policy['anomaly']),
    ('Open Config Alerts',                               alert_totals_by_policy['config']),
    ('Open Network Alerts',                              alert_totals_by_policy['network']),
    ('',''),
    ('Open Alerts with IaC',                             alert_totals_by_policy['shiftable']),
    ('',''),
    ('Open Alerts with Remediation',                     alert_totals_by_policy['remediable']),
    ('',''),
    ('Open Alerts Generated by Custom Policies',         alert_totals_by_policy['custom']),
    ('Open Alerts Generated by Default Policies',        alert_totals_by_policy['default']),
    ('',''),
    ('',''),
    ('Time Range: %s' %VAR_TIME_RANGE, ''),
]
write_sheet(panda_writer, 'Open Alerts Summary', rows)
    
if not SUPPORT_API_MODE:
    rows = [
        ('Number of Compliance Standards with Alerts',  count_of_compliance_standards_with_alerts_from_alerts),
        ('',''),
        ('Number of Policies with Alerts',              count_of_policies_with_alerts_from_alerts),
        ('',''),
        ('Number of Alerts',                            alert_count),
        ('',''),
        ('Open Alerts',                                 alert_totals_by_alert['open']),
        ('',''),
        ('Open Alerts High-Severity',                   alert_totals_by_alert['open_high']),
        ('Open Alerts Medium-Severity',                 alert_totals_by_alert['open_medium']),
        ('Open Alerts Low-Severity',                    alert_totals_by_alert['open_low']),
        ('',''),
        ('Resolved Alerts',                             alert_totals_by_alert['resolved']),
        ('',''),
        ('Resolved By Delete',                          alert_totals_by_alert['resolved_deleted']),
        ('Resolved By Update',                          alert_totals_by_alert['resolved_updated']),
        ('',''),
        ('Resolved Alerts High-Severity',               alert_totals_by_alert['resolved_high']),
        ('Resolved Alerts Medium-Severity',             alert_totals_by_alert['resolved_medium']),
        ('Resolved Alerts Low-Severity',                alert_totals_by_alert['resolved_low']),
        ('',''),
        ('Anomaly Alerts',                              policy_totals_by_alert['anomaly']),
        ('Config Alerts',                               policy_totals_by_alert['config']),
        ('Network Alerts',                              policy_totals_by_alert['network']),
        ('',''),
        ('Alerts with IaC',                             alert_totals_by_alert['shiftable']),
        ('',''),
        ('Alerts with Remediation',                     alert_totals_by_alert['remediable']),
        ('',''),
        ('Alerts Generated by Custom Policies',         alert_totals_by_alert['custom']),
        ('Alerts Generated by Default Policies',        alert_totals_by_alert['default']),
        ('',''),
        ('',''),
        ('Time Range: %s' % TIME_RANGE_LABEL, ''),
    ]
    write_sheet(panda_writer, 'Open and Closed Alerts Summary', rows)

save_sheet(panda_writer)
output('Results saved as: %s' % OUTPUT_FILE_XLS)
