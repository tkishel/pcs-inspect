#!/usr/bin/env python3

import argparse
import json
import math
import os
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

pc_parser.add_argument('-m', '--mode',
    type=str, required=True, choices=['collect', 'process'],
    help="*Required* Mode: collect Policies and Alerts, or process collected data.")

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

pc_parser.add_argument('-sa', '--support_api',
    action='store_true',
    help='(Optional) Use the Support API to collect data without a Tenant API Key.')

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
#   'Accept': 'application/json; charset=UTF-8', 
PRISMA_API_HEADERS  = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json'
}
API_TIMEOUTS      = (60, 600) # (CONNECT, READ)
CUSTOMER_NAME     = args.customer_name
CLOUD_ACCOUNT_ID  = args.cloud_account
TIME_RANGE_AMOUNT = args.time_range_amount
TIME_RANGE_UNIT   = args.time_range_unit
TIME_RANGE_LABEL  = 'Time Range - Past %s %s' % (TIME_RANGE_AMOUNT, TIME_RANGE_UNIT.capitalize())
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
OUTPUT_FILES = {
    'STANDARDS-OPEN-ALERTS': '%s-standards-open-alerts.tab' % CUSTOMER_PREFIX,
    'STANDARDS-ALL-ALERTS':  '%s-standards-all-alerts.tab'  % CUSTOMER_PREFIX,
    'POLICIES-OPEN-ALERTS':  '%s-policies-open-alerts.tab'  % CUSTOMER_PREFIX,
    'POLICIES-ALL-ALERTS':   '%s-policies-all-alerts.tab'   % CUSTOMER_PREFIX,
    'SUMMARY-OPEN-ALERTS':   '%s-summary-open.tab'          % CUSTOMER_PREFIX,
    'SUMMARY-ALL-ALERTS':    '%s-summary-all.tab'           % CUSTOMER_PREFIX,
    'SUMMARY-OTHER':         '%s-summary-all.tab'           % CUSTOMER_PREFIX
}

##########################################################################################
# Helpers.
##########################################################################################

def output(output_data='', file_name=None, to_stdout=True):
    if to_stdout:
        print(output_data)
    if file_name:
        append_file(file_name, output_data)

####

def write_file(file_name, write_data=''):
     this_file = open(file_name, 'w')
     this_file.write(write_data)
     this_file.close()

####

def append_file(file_name, write_data):
     this_file = open(file_name, 'a')
     this_file.write(write_data)
     this_file.write("\n")
     this_file.close()

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
    return
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

if RUN_MODE == 'collect':
    if not PRISMA_API_ENDPOINT:
        output("Error: '--url' is required with '--mode input'")
        sys.exit(0)
    if not PRISMA_ACCESS_KEY:
        output("Error: '--access_key' is required with '--mode input'")
        sys.exit(0)
    if not PRISMA_SECRET_KEY:
        output("Error: '--secret_key' is required with '--mode input'")
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

    output("Run '%s --customer_name %s --mode process' to process the collected data and save to CSV files." % (os.path.basename(__file__), CUSTOMER_NAME))
    sys.exit(0)

##########################################################################################
# Inspect mode: Read the result files and write output files.
##########################################################################################

DATA = {}

for this_result_file in RESULT_FILES:
    if not os.path.isfile(RESULT_FILES[this_result_file]):
      output('Error: Query result file does not exist: %s' % RESULT_FILES[this_result_file])
      sys.exit(1)
    with open(RESULT_FILES[this_result_file], 'r') as f:
      DATA[this_result_file] = json.load(f)

for this_output_file in OUTPUT_FILES:
    write_file(OUTPUT_FILES[this_output_file])

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
        this_policy_name = policies[this_policy_id]['policyName']
        # Compliance Standards
        for compliance_standard_name in policies[this_policy_id]['complianceStandards']:
            compliance_standards_counts_from_alerts.setdefault(compliance_standard_name, {'high': 0, 'medium': 0, 'low': 0})
            compliance_standards_counts_from_alerts[compliance_standard_name][policies[this_policy_id]['policySeverity']] += 1
        # Policies
        policy_counts_from_alerts.setdefault(this_policy_name, {'policyId': this_policy_id, 'alertCount': 0})
        policy_counts_from_alerts[this_policy_name]['alertCount']          += 1
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
# Calculate totals.
##########################################################################################

asset_count = DATA['ASSETS']['summary']['totalResources']

if SUPPORT_API_MODE:
    VAR_TIME_RANGE = ', %s' % TIME_RANGE_LABEL
    count_of_compliance_standards_with_alerts = len(compliance_standards_counts_from_policies)
    count_of_policies_with_alerts             = len(aggregate_alerts_by['policy'])
    alert_count                               = aggregate_alerts_by['status']['open']
else:
    VAR_TIME_RANGE = ''
    count_of_compliance_standards_with_alerts = len(compliance_standards_counts_from_alerts)
    count_of_policies_with_alerts             = len(policy_counts_from_alerts)
    alert_count                               = len(DATA['ALERTS'])

##########################################################################################
# Output totals.
##########################################################################################

# Output Compliance Standards with Alerts.

output()
output('#################################################################################', OUTPUT_FILES['STANDARDS-OPEN-ALERTS'])
output('# SHEET: By Compliance Standard, Open Alerts%s' % VAR_TIME_RANGE,                   OUTPUT_FILES['STANDARDS-OPEN-ALERTS'])
output('#################################################################################', OUTPUT_FILES['STANDARDS-OPEN-ALERTS'])
output('Saved to: %s' % OUTPUT_FILES['STANDARDS-OPEN-ALERTS'])
output('%s\t%s\t%s\t%s' % ('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low'), OUTPUT_FILES['STANDARDS-OPEN-ALERTS'], False)																						
for compliance_standard_name in sorted(compliance_standards_counts_from_policies):
    alert_count_high   = compliance_standards_counts_from_policies[compliance_standard_name]['high']
    alert_count_medium = compliance_standards_counts_from_policies[compliance_standard_name]['medium']
    alert_count_low    = compliance_standards_counts_from_policies[compliance_standard_name]['low']
    output('%s\t%s\t%s\t%s' % (compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low), OUTPUT_FILES['STANDARDS-OPEN-ALERTS'], False)

if not SUPPORT_API_MODE:
    output()
    output('#################################################################################', OUTPUT_FILES['STANDARDS-ALL-ALERTS'])
    output('# SHEET: By Compliance Standard, Open and Closed Alerts, %s' % TIME_RANGE_LABEL,    OUTPUT_FILES['STANDARDS-ALL-ALERTS'])
    output('#################################################################################', OUTPUT_FILES['STANDARDS-ALL-ALERTS'])
    output('Saved to: %s' % OUTPUT_FILES['STANDARDS-ALL-ALERTS'])
    output('%s\t%s\t%s\t%s' % ('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low'), OUTPUT_FILES['STANDARDS-ALL-ALERTS'], False)																						
    for standard_name in sorted(compliance_standards_counts_from_alerts):
        alert_count_high   = compliance_standards_counts_from_alerts[standard_name]['high']
        alert_count_medium = compliance_standards_counts_from_alerts[standard_name]['medium']
        alert_count_low    = compliance_standards_counts_from_alerts[standard_name]['low']
        output('%s\t%s\t%s\t%s' % (standard_name, alert_count_high, alert_count_medium, alert_count_low), OUTPUT_FILES['STANDARDS-ALL-ALERTS'], False)
    
# Output Policies with Alerts.

output()
output('#################################################################################', OUTPUT_FILES['POLICIES-OPEN-ALERTS'])
output('# SHEET: By Policy, Open Alerts%s' % VAR_TIME_RANGE,                                OUTPUT_FILES['POLICIES-OPEN-ALERTS'])
output('#################################################################################', OUTPUT_FILES['POLICIES-OPEN-ALERTS'])
output('Saved to: %s' % OUTPUT_FILES['POLICIES-OPEN-ALERTS'])
output('%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Compliance Standards'), OUTPUT_FILES['POLICIES-OPEN-ALERTS'], False)
for this_policy_name in sorted(policies_by_name):
    this_policy_id        = policies_by_name[this_policy_name]['policyId']
    policy_severity       = policies[this_policy_id]['policySeverity']
    policy_type           = policies[this_policy_id]['policyType']
    policy_is_shiftable   = policies[this_policy_id]['policyShiftable']
    policy_is_remediable  = policies[this_policy_id]['policyRemediable']
    policy_alert_count    = policies[this_policy_id]['alertCount']
    policy_standards_list = ','.join(map(str, policies[this_policy_id]['complianceStandards']))
    output('%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (this_policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_standards_list), OUTPUT_FILES['POLICIES-OPEN-ALERTS'], False)

if not SUPPORT_API_MODE:
    output()
    output('#################################################################################', OUTPUT_FILES['POLICIES-ALL-ALERTS'])
    output('# SHEET: By Policy, Open and Closed Alerts, %s' % TIME_RANGE_LABEL,                 OUTPUT_FILES['POLICIES-ALL-ALERTS'])
    output('#################################################################################', OUTPUT_FILES['POLICIES-ALL-ALERTS'])
    output('Saved to: %s' % OUTPUT_FILES['POLICIES-ALL-ALERTS'])
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Compliance Standards'), OUTPUT_FILES['POLICIES-ALL-ALERTS'], False)
    for this_policy_name in sorted(policy_counts_from_alerts):
        this_policy_id        = policy_counts_from_alerts[this_policy_name]['policyId']
        policy_severity       = policies[this_policy_id]['policySeverity']
        policy_type           = policies[this_policy_id]['policyType']
        policy_is_shiftable   = policies[this_policy_id]['policyShiftable']
        policy_is_remediable  = policies[this_policy_id]['policyRemediable']
        policy_alert_count    = policy_counts_from_alerts[policy_name]['alertCount']
        policy_standards_list = ','.join(map(str, policies[this_policy_id]['complianceStandards']))
        output('%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (this_policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_standards_list), OUTPUT_FILES['POLICIES-ALL-ALERTS'], False)
    
# Output Summary.

output()
output('#################################################################################', OUTPUT_FILES['SUMMARY-OTHER'])
output('# SHEET: Summary, Assets, ..., Users',                                              OUTPUT_FILES['SUMMARY-OTHER'])
output('#################################################################################', OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Assets:\t%s" % asset_count, OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Cloud Accounts:\t%s" % len(DATA['ACCOUNTS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Cloud Accounts Disabled\t%s"   % sum(x.get('enabled') == False for x in DATA['ACCOUNTS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Cloud Accounts Enabled\t%s"    % sum(x.get('enabled') == True for x in DATA['ACCOUNTS']), OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Cloud Account Groups:\t%s" % len(DATA['GROUPS']), OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Alert Rules\t%s" % len(DATA['RULES']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Alert Rules Disabled\t%s"  % sum(x.get('enabled') == False for x in DATA['RULES']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Alert Rules Enabled\t%s"   % sum(x.get('enabled') == True for x in DATA['RULES']), OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Integrations\t%s" % len(DATA['INTEGRATIONS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Integrations Disabled\t%s"  % sum(x.get('enabled') == False for x in DATA['INTEGRATIONS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Integrations Enabled\t%s"   % sum(x.get('enabled') == True for x in DATA['INTEGRATIONS']), OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Policies\t%s" % len(DATA['POLICIES']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Policies Custom\t%s"    % sum(x.get('systemDefault') == False for x in DATA['POLICIES']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Policies Default\t%s"   % sum(x.get('systemDefault') == True for x in DATA['POLICIES']), OUTPUT_FILES['SUMMARY-OTHER'])
output()
output("Number of Users:\t%s" % len(DATA['USERS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Users Disabled\t%s"   % sum(x.get('enabled') == False for x in DATA['USERS']), OUTPUT_FILES['SUMMARY-OTHER'])
output("Users Enabled\t%s"    % sum(x.get('enabled') == True for x in DATA['USERS']), OUTPUT_FILES['SUMMARY-OTHER'])
output()

output('#################################################################################', OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output('# SHEET: Summary, Open Alerts%s' % VAR_TIME_RANGE,                                  OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output('#################################################################################', OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Number of Compliance Standards with Alerts:\t%s" % count_of_compliance_standards_with_alerts, OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Open Alerts\t%s"  % alert_totals_by_policy['open'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Open Alerts High-Severity\t%s"   % alert_totals_by_policy['open_high'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output("Open Alerts Medium-Severity\t%s" % alert_totals_by_policy['open_medium'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output("Open Alerts Low-Severity\t%s"    % alert_totals_by_policy['open_low'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Anomaly Alerts\t%s" % alert_totals_by_policy['anomaly'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS']) # TJK
output("Config Alerts\t%s"  % alert_totals_by_policy['config'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])  # TJK
output("Network Alerts\t%s" % alert_totals_by_policy['network'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS']) # TJK
output()
output("Alerts with IaC\t%s" % alert_totals_by_policy['shiftable'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Alerts with Remediation\t%s" % alert_totals_by_policy['remediable'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
output("Alerts Generated by Custom Policies\t%s"  % alert_totals_by_policy['custom'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output("Alerts Generated by Default Policies\t%s" % alert_totals_by_policy['default'], OUTPUT_FILES['SUMMARY-OPEN-ALERTS'])
output()
    
if not SUPPORT_API_MODE:
    output('#################################################################################', OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output('# SHEET: Summary, Open and Closed Alerts, %s' % TIME_RANGE_LABEL,                   OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output('#################################################################################', OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()    
    output("Number of Compliance Standards with Alerts:\t%s" % count_of_compliance_standards_with_alerts, OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Number of Policies with Alerts: Total\t%s" % count_of_policies_with_alerts, OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Number of Alerts\t%s" % alert_count, OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Open Alerts\t%s" % alert_totals_by_alert['open'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Open Alerts High-Severity\t%s"   % alert_totals_by_alert['open_high'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Open Alerts Medium-Severity\t%s" % alert_totals_by_alert['open_medium'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Open Alerts Low-Severity\t%s"    % alert_totals_by_alert['open_low'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Resolved Alerts\t%s" % alert_totals_by_alert['resolved'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Resolved By Delete\t%s" % alert_totals_by_alert['resolved_deleted'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Resolved By Update\t%s" % alert_totals_by_alert['resolved_updated'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Resolved Alerts High-Severity\t%s"   % alert_totals_by_alert['resolved_high'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Resolved Alerts Medium-Severity\t%s" % alert_totals_by_alert['resolved_medium'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Resolved Alerts Low-Severity\t%s"    % alert_totals_by_alert['resolved_low'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Anomaly Alerts\t%s" % policy_totals_by_alert['anomaly'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Config Alerts\t%s"  % policy_totals_by_alert['config'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Network Alerts\t%s" % policy_totals_by_alert['network'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Alerts with IaC\t%s" % alert_totals_by_alert['shiftable'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Alerts with Remediation\t%s" % alert_totals_by_alert['remediable'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
    output("Alerts Generated by Custom Policies\t%s"  % alert_totals_by_alert['custom'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output("Alerts Generated by Default Policies\t%s" % alert_totals_by_alert['default'], OUTPUT_FILES['SUMMARY-ALL-ALERTS'])
    output()
