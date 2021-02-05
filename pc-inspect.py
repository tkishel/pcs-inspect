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

pc_parser.add_argument('-d', '--debug',
    action='store_true',
    help='(Optional) Enable debugging.')

args = pc_parser.parse_args()

##########################################################################################
# Configure.
##########################################################################################
#     'Accept': 'application/json; charset=UTF-8', 

DEBUG_MODE          = args.debug
RUN_MODE            = args.mode
SUPPORT_API_MODE    = False
PRISMA_API_ENDPOINT = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
PRISMA_ACCESS_KEY   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
PRISMA_SECRET_KEY   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
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
CUSTOMER_FILE     = re.sub(r'\W+', '', CUSTOMER_NAME).lower()
ASSET_FILE        = '%s-assets.txt' % CUSTOMER_FILE
POLICY_FILE       = '%s-policies.txt' % CUSTOMER_FILE
ALERT_FILE        = '%s-alerts.txt' % CUSTOMER_FILE
USER_FILE         = '%s-users.txt' % CUSTOMER_FILE
ACCOUNT_FILE      = '%s-accounts.txt' % CUSTOMER_FILE
ACCOUNTGROUP_FILE = '%s-accountgroups.txt' % CUSTOMER_FILE
ALERTRULE_FILE    = '%s-alertrules.txt' % CUSTOMER_FILE
INTEGRATION_FILE  = '%s-integrations.txt' % CUSTOMER_FILE
DATA_FILES        = [ASSET_FILE, POLICY_FILE, ALERT_FILE, USER_FILE, ACCOUNT_FILE, ACCOUNTGROUP_FILE, ACCOUNTGROUP_FILE, INTEGRATION_FILE]

##########################################################################################
# Helpers.
##########################################################################################

def output(data=''):
    print(data)

####

def make_api_call(method, url, requ_data = None):
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
            return bytes('{}', 'utf-8')
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

# SUPPORT_API_MODE:
# Using '/_support/timeline/resource' in lieu of the required but not implemented '_support/v2/inventory' endpoint.
    
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
        if api_response_json[0] and 'resources' in api_response_json[0]:
            api_response = bytes('{"summary": {"totalResources": %s}}' % api_response_json[0]['resources'], 'utf-8')
        else:
            api_response = bytes('{"summary": {"totalResources": 0}}', 'utf-8')
    else:
        if CLOUD_ACCOUNT_ID:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s&cloud.account=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT, CLOUD_ACCOUNT_ID)
        else:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT)
        api_response = make_api_call('GET', '%s/v2/inventory?%s' % (PRISMA_API_ENDPOINT, query_params))
    alert_file = open(ASSET_FILE, 'wb')
    alert_file.write(api_response)
    alert_file.close()

# SUPPORT_API_MODE:
# Unfortunately, we need to open alert counts for all policies (as provided by '/policy'), but '/_support/policy' doesn't return open alert counts.
# And '/_support/alert/policy' does return an alertCount, but I cannot tell if that is all (open or closed) or just open, and returns fewer policies than '_support/policy' given the same parameters. 

def get_policies():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/policy?policy.enabled=true' % PRISMA_API_ENDPOINT, request_data)
        policy_file = open(POLICY_FILE, 'wb')
        policy_file.write(api_response)
        policy_file.close()
    else:
        api_response = make_api_call('GET', '%s/policy?policy.enabled=true' % PRISMA_API_ENDPOINT)
        policy_file = open(POLICY_FILE, 'wb')
        policy_file.write(api_response)
        policy_file.close()

# SUPPORT_API_MODE for 'get_alerts()' requires a not implemented '/_support/v2/alert(s)' endpoint.
# The '/_support/alert' endpoint returns 'getAlert()' instead of 'getAlerts()'.
# So, the query will error, and not return alert results.

def get_alerts():
    body_params = {}
    body_params['timeRange'] = {"value": {"unit": "%s" % TIME_RANGE_UNIT, "amount": TIME_RANGE_AMOUNT}, "type": "relative"}
    if CLOUD_ACCOUNT_ID:
        body_params["filters"] = [{"name": "cloud.accountId","value": "%s" % CLOUD_ACCOUNT_ID, "operator": "="}]
    if SUPPORT_API_MODE:
        body_params["customerName"] = "%s" % CUSTOMER_NAME
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/v2/alerts_not_implemented' % PRISMA_API_ENDPOINT, request_data)
        alert_file = open(ALERT_FILE, 'wb')
        alert_file.write(api_response)
        alert_file.close()
    else:
        body_params['limit'] = 100
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/v2/alert' % PRISMA_API_ENDPOINT, request_data)
        api_response_json = json.loads(api_response)
        api_response_array = api_response_json['items']
        alert_file = open(ALERT_FILE, 'w')
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
            else:
                print(api_response_json)
        api_response = json.dumps(api_response_array, indent=2, separators=(', ', ': '))
        alert_file.write(api_response)
        alert_file.close()

def get_users():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/v2/_support/user' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/user' % PRISMA_API_ENDPOINT)
    policy_file = open(USER_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

def get_accounts():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/cloud' % PRISMA_API_ENDPOINT)
    policy_file = open(ACCOUNT_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

def get_accountgroups():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud/group' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/cloud/group' % PRISMA_API_ENDPOINT)
    policy_file = open(ACCOUNTGROUP_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

def get_alertrules():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/alert/rule' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/alert/rule' % PRISMA_API_ENDPOINT)
    policy_file = open(ALERTRULE_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

def get_integrations():
    if SUPPORT_API_MODE:
        body_params = {"customerName": "%s" % CUSTOMER_NAME}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/integration' % PRISMA_API_ENDPOINT, request_data)
    else:
        api_response = make_api_call('GET', '%s/integration' % PRISMA_API_ENDPOINT)
    policy_file = open(INTEGRATION_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

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
    output('Results saved as: %s' % ASSET_FILE)
    output()

    output('Querying Policies')
    get_policies()
    output('Results saved as: %s' % POLICY_FILE)
    output()

    output('Querying Alerts (please wait)')
    get_alerts()
    output()
    output('Results saved as: %s' % ALERT_FILE)
    output()

    output('Querying Users')
    get_users()
    output('Results saved as: %s' % USER_FILE)
    output()

    output('Querying Accounts')
    get_accounts()
    output('Results saved as: %s' % ACCOUNT_FILE)
    output()

    output('Querying Account Groups')
    get_accountgroups()
    output('Results saved as: %s' % ACCOUNTGROUP_FILE)
    output()

    output('Querying Alert Rules')
    get_alertrules()
    output('Results saved as: %s' % ALERTRULE_FILE)
    output()

    output('Querying Integrations')
    get_integrations()
    output('Results saved as: %s' % INTEGRATION_FILE)
    output()

    output("Run '%s --customer_name %s --mode process' to process the collected data." % (os.path.basename(__file__), CUSTOMER_NAME))
    output("To save the processed data to a file, redirect the above command by adding ' > {name}-summary.tab'".format(name = CUSTOMER_FILE))
    sys.exit(0)

##########################################################################################
# Inspect mode: Read the result files and output summary results.
##########################################################################################

for data_file in DATA_FILES:
    if not os.path.isfile(data_file):
      output('Error: Data file does not exist: %s' % data_file)
      sys.exit(1)

##########################################################################################
# Initialize counters and structures.
##########################################################################################

policies = {}

# '_from_policy' variables for use when we are unable to retrieve open and closed alerts from the alerts endpoint.

compliance_standard_open_alert_counts_from_policy = {}
policy_open_alert_counts_from_policy              = {}

open_alert_counts_from_policy = {
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
    'default':     0,
}

##

compliance_standard_alert_counts_from_alerts = {}
policy_alert_counts_from_alerts              = {}

policy_detail_counts_from_alerts = {
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

alert_detail_counts_from_alerts = {
    'open':                0,
    'open_high':           0,
    'open_medium':         0,
    'open_low':            0,
    'custom':              0,
    'default':             0,
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
}

##########################################################################################
# Use these results without transformation.
##########################################################################################

with open(ASSET_FILE, 'r') as f:
  asset_list = json.load(f)

with open(USER_FILE, 'r') as f:
  user_list = json.load(f)

with open(ACCOUNT_FILE, 'r') as f:
  account_list = json.load(f)

with open(ACCOUNTGROUP_FILE, 'r') as f:
  accountgroup_list = json.load(f)

with open(ALERTRULE_FILE, 'r') as f:
  alertrule_list = json.load(f)

with open(INTEGRATION_FILE, 'r') as f:
  integration_list = json.load(f)

##########################################################################################
# Loop through all Policies and collect the details of each Policy.
# Alert counts from this endpoint include all open alerts and are not scoped to a time range.
##########################################################################################

# TODO: Track "policyCategory": "incident" and "risk"

with open(POLICY_FILE, 'r') as f:
  policy_list = json.load(f)

for policy in policy_list:
    policyId = policy['policyId']
    if not policyId in policies:
        policies[policyId] = {}
    if not 'openAlertsCount' in policy:
        policy['openAlertsCount'] = 0
    policies[policyId]['policyName'] = policy['name']
    policies[policyId]['policySeverity'] = policy['severity']
    policies[policyId]['policyType'] = policy['policyType']
    policies[policyId]['policyShiftable'] = 'build' in policy['policySubTypes']
    policies[policyId]['policyRemediable'] = policy['remediable']
    policies[policyId]['policyOpenAlertsCount'] = policy['openAlertsCount']
    policies[policyId]['policySystemDefault'] = policy['systemDefault']
    # Create sets and lists of Compliance Standards to create a sorted, unique list of counters for each Compliance Standard.
    policies[policyId]['complianceStandards'] = list()
    if 'complianceMetadata' in policy:
        compliance_standards_set = set()
        for standard in policy['complianceMetadata']:
            compliance_standards_set.add(standard['standardName'])
        compliance_standards_list = list(compliance_standards_set)
        compliance_standards_list.sort()
        policies[policyId]['complianceStandards'] = compliance_standards_list
        for standard in compliance_standards_list:
            if not standard in compliance_standard_alert_counts_from_alerts:
                compliance_standard_open_alert_counts_from_policy[standard] = {'high': 0, 'medium': 0, 'low': 0}
            compliance_standard_open_alert_counts_from_policy[standard][policy['severity']] += policies[policyId]['policyOpenAlertsCount']
            # Initialize `compliance_standard_alert_counts_from_alerts` now, to avoid an error with incrementing when the variable is undefined, when processing `alert_list` later.
            if not standard in compliance_standard_alert_counts_from_alerts:
                compliance_standard_alert_counts_from_alerts[standard] = {'high': 0, 'medium': 0, 'low': 0}
    # Collect policies here, in case we are unable to retrieve open and closed alerts from the alerts endpoint.
    policy_open_alert_counts_from_policy[policy['name']] = {'policyId': policyId, 'openAlertsCount': policies[policyId]['policyOpenAlertsCount']}
    # Collect open alerts here, in case we are unable to retrieve open and closed alerts from the alerts endpoint.
    open_alert_counts_from_policy['open'] += policies[policyId]['policyOpenAlertsCount']
    open_alert_counts_from_policy['open_%s' % policy['severity']] += policies[policyId]['policyOpenAlertsCount']
    open_alert_counts_from_policy[policy['policyType']] += policies[policyId]['policyOpenAlertsCount']
    if policies[policyId]['policyRemediable']:
        open_alert_counts_from_policy['remediable'] += policies[policyId]['policyOpenAlertsCount']
    if policies[policyId]['policyShiftable']:
        open_alert_counts_from_policy['shiftable'] += policies[policyId]['policyOpenAlertsCount']
    if policies[policyId]['policySystemDefault'] == True:
        open_alert_counts_from_policy['default'] += policies[policyId]['policyOpenAlertsCount']
    else:
        open_alert_counts_from_policy['custom'] += policies[policyId]['policyOpenAlertsCount']        

##########################################################################################
# Loop through all Alerts and collect the details of each Alert.
# Some details come from the Alert, some from the associated Policy.
##########################################################################################

with open(ALERT_FILE, 'r') as f:
  alert_list = json.load(f)

for alert in alert_list:
    policyId = alert['policy']['policyId']
    if not policyId in policies:
        if DEBUG_MODE:
            output('Skipping Alert: Policy Deleted or Disabled: Policy ID: %s' % policyId)
        continue
    policyName = policies[policyId]['policyName']
    for standard in policies[policyId]['complianceStandards']:
        compliance_standard_alert_counts_from_alerts[standard][policies[policyId]['policySeverity']] += 1
    if not policyName in policy_alert_counts_from_alerts:
        policy_alert_counts_from_alerts[policyName] = {'policyId': policyId, 'alertCount': 0}
    policy_alert_counts_from_alerts[policyName]['alertCount'] += 1
    policy_detail_counts_from_alerts[policies[policyId]['policySeverity']] += 1
    policy_detail_counts_from_alerts[policies[policyId]['policyType']] += 1
    alert_detail_counts_from_alerts[alert['status']] += 1
    if 'reason' in alert:
        if alert['reason'] == 'RESOURCE_DELETED':
            alert_detail_counts_from_alerts['resolved_deleted'] += 1
        if alert['reason'] == 'RESOURCE_UPDATED':
            alert_detail_counts_from_alerts['resolved_updated'] += 1
    alert_detail_counts_from_alerts['%s_%s' % (alert['status'], policies[policyId]['policySeverity'])] += 1
    if alert['policy']['remediable']:
        alert_detail_counts_from_alerts['remediable'] += 1
        alert_detail_counts_from_alerts['remediable_%s' % alert['status']] += 1
    if policies[policyId]['policyShiftable']:
        alert_detail_counts_from_alerts['shiftable'] += 1
    if policies[policyId]['policySystemDefault'] == True:
        alert_detail_counts_from_alerts['default'] += 1
    else:
        alert_detail_counts_from_alerts['custom'] += 1

##########################################################################################
# Calculate totals.
##########################################################################################

asset_count = asset_list['summary']['totalResources']

compliance_standards_with_alerts_count = len(compliance_standard_alert_counts_from_alerts)
policies_with_alerts_count             = len(policy_alert_counts_from_alerts)

alert_count              = len(alert_list)
policy_count             = len(policy_list)
user_count               = len(user_list)
account_count            = len(account_list)
accountgroup_count       = len(accountgroup_list)
alertrule_count          = len(alertrule_list)
integration_count        = len(integration_list)

# I'm sorry about all of this. Avoid ZeroDivisionError.

if asset_count > 0:
    if alert_count > 0:
        alerts_per_100_assets                          = round((alert_count                                        / asset_count) * 100)
        open_alerts_per_100_assets                     = round((alert_detail_counts_from_alerts['open']            / asset_count) * 100)
        open_alerts_high_severity_per_100_assets       = round((alert_detail_counts_from_alerts['open_high']       / asset_count) * 100)
        open_alerts_medium_severity_per_100_assets     = round((alert_detail_counts_from_alerts['open_medium']     / asset_count) * 100)
        open_alerts_low_severity_per_100_assets        = round((alert_detail_counts_from_alerts['open_low']        / asset_count) * 100)
        resolved_alerts_per_100_assets                 = round((alert_detail_counts_from_alerts['resolved']        / asset_count) * 100)
        resolved_alerts_high_severity_per_100_assets   = round((alert_detail_counts_from_alerts['resolved_high']   / asset_count) * 100)
        resolved_alerts_medium_severity_per_100_assets = round((alert_detail_counts_from_alerts['resolved_medium'] / asset_count) * 100)
        resolved_alerts_low_severity_per_100_assets    = round((alert_detail_counts_from_alerts['resolved_low']    / asset_count) * 100)
        alerts_with_iac_per_100_assets                 = round((alert_detail_counts_from_alerts['shiftable']       / asset_count) * 100)
        alerts_with_remediation_per_100_assets         = round((alert_detail_counts_from_alerts['remediable']      / asset_count) * 100)
    else:
        alerts_per_100_assets                          = 'N/A'
        open_alerts_per_100_assets                     = round((open_alert_counts_from_policy['open']              / asset_count) * 100)
        open_alerts_high_severity_per_100_assets       = round((open_alert_counts_from_policy['open_high']         / asset_count) * 100)
        open_alerts_medium_severity_per_100_assets     = round((open_alert_counts_from_policy['open_medium']       / asset_count) * 100)
        open_alerts_low_severity_per_100_assets        = round((open_alert_counts_from_policy['open_low']          / asset_count) * 100)
        resolved_alerts_per_100_assets                 = 'N/A'
        resolved_alerts_high_severity_per_100_assets   = 'N/A'
        resolved_alerts_medium_severity_per_100_assets = 'N/A'
        resolved_alerts_low_severity_per_100_assets    = 'N/A'
        alerts_with_iac_per_100_assets                 = round((open_alert_counts_from_policy['shiftable']         / asset_count) * 100)
        alerts_with_remediation_per_100_assets         = round((open_alert_counts_from_policy['remediable']        / asset_count) * 100)
else:
    alerts_per_100_assets                          = 'N/A'
    open_alerts_per_100_assets                     = 'N/A'
    open_alerts_high_severity_per_100_assets       = 'N/A'
    open_alerts_medium_severity_per_100_assets     = 'N/A'
    open_alerts_low_severity_per_100_assets        = 'N/A'
    resolved_alerts_per_100_assets                 = 'N/A'
    resolved_alerts_high_severity_per_100_assets   = 'N/A'
    resolved_alerts_medium_severity_per_100_assets = 'N/A'
    resolved_alerts_low_severity_per_100_assets    = 'N/A'
    alerts_with_iac_per_100_assets                 = 'N/A'
    alerts_with_remediation_per_100_assets         = 'N/A'

if alert_count > 0:
    open_alerts_as_percent       = round((alert_detail_counts_from_alerts['open']       / alert_count) * 100)
    resolved_alerts_as_percent   = round((alert_detail_counts_from_alerts['resolved']   / alert_count) * 100)
    shiftable_alerts_as_percent  = round((alert_detail_counts_from_alerts['shiftable']  / alert_count) * 100)
    remediable_alerts_as_percent = round((alert_detail_counts_from_alerts['remediable'] / alert_count) * 100)
else:
    if open_alert_counts_from_policy['open'] > 0:
        open_alerts_as_percent       = round((open_alert_counts_from_policy['open']         / open_alert_counts_from_policy['open']) * 100)
        resolved_alerts_as_percent   = 'N/A'
        shiftable_alerts_as_percent  = round((open_alert_counts_from_policy['shiftable']    / open_alert_counts_from_policy['open']) * 100)
        remediable_alerts_as_percent = round((open_alert_counts_from_policy['remediable']   / open_alert_counts_from_policy['open']) * 100)
    else:
        open_alerts_as_percent       = 'N/A'
        resolved_alerts_as_percent   = 'N/A'
        shiftable_alerts_as_percent  = 'N/A'
        remediable_alerts_as_percent = 'N/A'

##########################################################################################
# Output tables with results and totals.
##########################################################################################

# Output Compliance Standards with Alerts.

output()
output('#################################################################################')
output('# SHEET: By Compliance Standard, All Open Alerts')
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s' % ('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low, Alerts High - Per 100 Assets, Alerts Medium - Per 100 Assets, Alerts Low - Per 100 Assets'))																						
for compliance_standard_name in sorted(compliance_standard_open_alert_counts_from_policy):
    alert_count_high                  = compliance_standard_open_alert_counts_from_policy[compliance_standard_name]['high']
    alert_count_medium                = compliance_standard_open_alert_counts_from_policy[compliance_standard_name]['medium']
    alert_count_low                   = compliance_standard_open_alert_counts_from_policy[compliance_standard_name]['low']
    if asset_count > 0:
        alert_count_high_per_100_assets   = round((alert_count_high   / asset_count) * 100)
        alert_count_medium_per_100_assets = round((alert_count_medium / asset_count) * 100)
        alert_count_low_per_100_assets    = round((alert_count_low    / asset_count) * 100)
    else:
        alert_count_high_per_100_assets   = 'N/A'
        alert_count_medium_per_100_assets = 'N/A'
        alert_count_low_per_100_assets    = 'N/A'
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s' % (compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low, alert_count_high_per_100_assets, alert_count_medium_per_100_assets, alert_count_low_per_100_assets))

output()
output('#################################################################################')
output('# SHEET: By Compliance Standard, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s' % ('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low, Alerts High - Per 100 Assets, Alerts Medium - Per 100 Assets, Alerts Low - Per 100 Assets'))																						
for standard_name in sorted(compliance_standard_alert_counts_from_alerts):
    alert_count_high                  = compliance_standard_alert_counts_from_alerts[standard_name]['high']
    alert_count_medium                = compliance_standard_alert_counts_from_alerts[standard_name]['medium']
    alert_count_low                   = compliance_standard_alert_counts_from_alerts[standard_name]['low']
    if asset_count > 0:
        alert_count_high_per_100_assets   = round((alert_count_high   / asset_count) * 100)
        alert_count_medium_per_100_assets = round((alert_count_medium / asset_count) * 100)
        alert_count_low_per_100_assets    = round((alert_count_low    / asset_count) * 100)
    else:
        alert_count_high_per_100_assets   = 'N/A'
        alert_count_medium_per_100_assets = 'N/A'
        alert_count_low_per_100_assets    = 'N/A'
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s' % (standard_name, alert_count_high, alert_count_medium, alert_count_low, alert_count_high_per_100_assets, alert_count_medium_per_100_assets, alert_count_low_per_100_assets))

# Output Policies with Alerts.

output()
output('#################################################################################')
output('# SHEET: By Policy, All Open Alerts')
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Alert Count - Per 100 Assets', 'Compliance Standards') )
for policy_name in sorted(policy_open_alert_counts_from_policy):
    policyId                          = policy_open_alert_counts_from_policy[policy_name]['policyId']
    policy_severity                   = policies[policyId]['policySeverity']
    policy_type                       = policies[policyId]['policyType']
    policy_is_shiftable               = policies[policyId]['policyShiftable']
    policy_is_remediable              = policies[policyId]['policyRemediable']
    policy_alert_count                = policy_open_alert_counts_from_policy[policy_name]['openAlertsCount']
    if asset_count > 0:
        policy_alert_count_per_100_assets = round((policy_alert_count / asset_count) * 100)
    else:
        policy_alert_count_per_100_assets = 'N/A'
    policy_standards_list             = ','.join(map(str, policies[policyId]['complianceStandards']))
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_alert_count_per_100_assets, policy_standards_list))

output()
output('#################################################################################')
output('# SHEET: By Policy, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Alert Count - Per 100 Assets', 'Compliance Standards') )
for policy_name in sorted(policy_alert_counts_from_alerts):
    policyId                          = policy_alert_counts_from_alerts[policy_name]['policyId']
    policy_severity                   = policies[policyId]['policySeverity']
    policy_type                       = policies[policyId]['policyType']
    policy_is_shiftable               = policies[policyId]['policyShiftable']
    policy_is_remediable              = policies[policyId]['policyRemediable']
    policy_alert_count                = policy_alert_counts_from_alerts[policy_name]['alertCount']
    if asset_count > 0:
        policy_alert_count_per_100_assets = round((policy_alert_count / asset_count) * 100)
    else:
        policy_alert_count_per_100_assets = 'N/A'
    policy_standards_list             = ','.join(map(str, policies[policyId]['complianceStandards']))
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_alert_count_per_100_assets, policy_standards_list))

# Output Summary.

output()
output('#################################################################################')
output('# SHEET: Summary, Assets, Cloud Accounts, Cloud Account Groups, Alert Rules, Integrations, Policies, Users')
output('#################################################################################')
output()
output("Number of Assets:\t%s" % asset_count)
output()
output("Number of Cloud Accounts:\t%s" % account_count)
output("Cloud Accounts Disabled\t%s"   % sum(x.get('enabled') == False for x in account_list))
output("Cloud Accounts Enabled\t%s"    % sum(x.get('enabled') == True for x in account_list))
output()
output("Number of Cloud Account Groups:\t%s" % accountgroup_count)
output()
output("Number of Alert Rules\t%s" % alertrule_count)
output("Alert Rules Disabled\t%s"  % sum(x.get('enabled') == False for x in alertrule_list))
output("Alert Rules Enabled\t%s"   % sum(x.get('enabled') == True for x in alertrule_list))
output()
output("Number of Integrations\t%s" % integration_count)
output("Integrations Disabled\t%s"  % sum(x.get('enabled') == False for x in integration_list))
output("Integrations Enabled\t%s"   % sum(x.get('enabled') == True for x in integration_list))
output()
output("Number of Policies\t%s" % policy_count)
output("Policies Custom\t%s"    % sum(x.get('systemDefault') == False for x in policy_list))
output("Policies Default\t%s"   % sum(x.get('systemDefault') == True for x in policy_list))
output()
output("Number of Users:\t%s" % user_count)
output("Users Disabled\t%s"   % sum(x.get('enabled') == False for x in user_list))
output("Users Enabled\t%s"    % sum(x.get('enabled') == True for x in user_list))
output()

output('#################################################################################')
output('# SHEET: Summary, All Open Alerts')
output('#################################################################################')
output()
output("Number of Compliance Standards with Alerts:\t%s" % compliance_standards_with_alerts_count)
output()
output("Open Alerts\t%s"                % open_alert_counts_from_policy['open'])
output("Open Alerts per 100 Assets\t%s" % open_alerts_per_100_assets)
output()
output("Open Alerts High-Severity\t%s"                  % open_alert_counts_from_policy['open_high'])
output("Open Alerts High-Severity per 100 Assets\t%s"   % open_alerts_high_severity_per_100_assets)
output("Open Alerts Medium-Severity\t%s"                % open_alert_counts_from_policy['open_medium'])
output("Open Alerts Medium-Severity per 100 Assets\t%s" % open_alerts_medium_severity_per_100_assets)
output("Open Alerts Low-Severity\t%s"                   % open_alert_counts_from_policy['open_low'])
output("Open Alerts Low-Severity per 100 Assets\t%s"    % open_alerts_low_severity_per_100_assets)
output()
output("Anomaly Alerts\t%s" % open_alert_counts_from_policy['anomaly']) # TJK
output("Config Alerts\t%s"  % open_alert_counts_from_policy['config'])  # TJK
output("Network Alerts\t%s" % open_alert_counts_from_policy['network']) # TJK
output()
output("Alerts with IaC\t%s"                % open_alert_counts_from_policy['shiftable'])
output("Alerts with IaC per 100 Assets\t%s" % alerts_with_iac_per_100_assets)
output("Alerts with IaC as Percent\t%s%s"   % (shiftable_alerts_as_percent, '%'))
output()
output("Alerts with Remediation\t%s"                % open_alert_counts_from_policy['remediable'])
output("Alerts with Remediation per 100 Assets\t%s" % alerts_with_remediation_per_100_assets)
output("Alerts with Remediation as Percent\t%s%s"   % (remediable_alerts_as_percent, '%'))
output()
output("Alerts Generated by Custom Policies\t%s"  % open_alert_counts_from_policy['custom'])
output("Alerts Generated by Default Policies\t%s" % open_alert_counts_from_policy['default'])
output()
    
output('#################################################################################')
output('# SHEET: Summary, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()

if alert_count < 1:
    output("No alerts returned by the '/alert' endpoint, exiting.")
    sys.exit()
    
output("Number of Compliance Standards with Alerts:\t%s" % compliance_standards_with_alerts_count)
output()
output("Number of Policies with Alerts: Total\t%s" % policies_with_alerts_count)
output()
output("Number of Alerts\t%s" % alert_count)
output("Alerts per 100 Assets\t%s" % alerts_per_100_assets)
output()
output("Open Alerts\t%s"                % alert_detail_counts_from_alerts['open'])
output("Open Alerts per 100 Assets\t%s" % open_alerts_per_100_assets)
output("Open Alerts as Percent\t%s%s"   % (open_alerts_as_percent, '%'))
output()
output("Open Alerts High-Severity\t%s"                  % alert_detail_counts_from_alerts['open_high'])
output("Open Alerts High-Severity per 100 Assets\t%s"   % open_alerts_high_severity_per_100_assets)
output("Open Alerts Medium-Severity\t%s"                % alert_detail_counts_from_alerts['open_medium'])
output("Open Alerts Medium-Severity per 100 Assets\t%s" % open_alerts_medium_severity_per_100_assets)
output("Open Alerts Low-Severity\t%s"                   % alert_detail_counts_from_alerts['open_low'])
output("Open Alerts Low-Severity per 100 Assets\t%s"    % open_alerts_low_severity_per_100_assets)
output()
output("Resolved Alerts\t%s"                % alert_detail_counts_from_alerts['resolved'])
output("Resolved Alerts per 100 Assets\t%s" % resolved_alerts_per_100_assets)
output("Resolved Alerts as Percent\t%s%s"   % (resolved_alerts_as_percent, '%'))
output()
output("Resolved By Delete\t%s" % alert_detail_counts_from_alerts['resolved_deleted'])
output("Resolved By Update\t%s" % alert_detail_counts_from_alerts['resolved_updated'])
output()
output("Resolved Alerts High-Severity\t%s"                  % alert_detail_counts_from_alerts['resolved_high'])
output("Resolved Alerts High-Severity per 100 Assets\t%s"   % resolved_alerts_high_severity_per_100_assets)
output("Resolved Alerts Medium-Severity\t%s"                % alert_detail_counts_from_alerts['resolved_medium'])
output("Resolved Alerts Medium-Severity per 100 Assets\t%s" % resolved_alerts_medium_severity_per_100_assets)
output("Resolved Alerts Low-Severity\t%s"                   % alert_detail_counts_from_alerts['resolved_low'])
output("Resolved Alerts Low-Severity per 100 Assets\t%s"    % resolved_alerts_low_severity_per_100_assets)
output()
output("Anomaly Alerts\t%s" % policy_detail_counts_from_alerts['anomaly'])
output("Config Alerts\t%s"  % policy_detail_counts_from_alerts['config'])
output("Network Alerts\t%s" % policy_detail_counts_from_alerts['network'])
output()
output("Alerts with IaC\t%s"                % alert_detail_counts_from_alerts['shiftable'])
output("Alerts with IaC per 100 Assets\t%s" % alerts_with_iac_per_100_assets)
output("Alerts with IaC as Percent\t%s%s"   % (shiftable_alerts_as_percent, '%'))
output()
output("Alerts with Remediation\t%s"                % alert_detail_counts_from_alerts['remediable'])
output("Alerts with Remediation per 100 Assets\t%s" % alerts_with_remediation_per_100_assets)
output("Alerts with Remediation as Percent\t%s%s"   % (remediable_alerts_as_percent, '%'))
output()
output("Alerts Generated by Custom Policies\t%s"  % alert_detail_counts_from_alerts['custom'])
output("Alerts Generated by Default Policies\t%s" % alert_detail_counts_from_alerts['default'])
output()
