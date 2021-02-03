#!/usr/bin/env python3

import argparse
import json
import math
import os
import requests
from requests.exceptions import RequestException
import sys

##########################################################################################
# Configuration
##########################################################################################

pc_parser = argparse.ArgumentParser(description='This script collects or processes Policies and Alerts.', prog=os.path.basename(__file__))

pc_parser.add_argument(
    '-c', '--customer_name',
    type=str, required=True,
    help='*Required* Customer Name, used for Alert and Policy files')

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

####

DEBUG_MODE          = args.debug
RUN_MODE            = args.mode
PRISMA_API_ENDPOINT = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
PRISMA_ACCESS_KEY   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
PRISMA_SECRET_KEY   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
PRISMA_API_HEADERS  = {
    'Accept': 'application/json; charset=UTF-8',
    'Content-Type': 'application/json'
}
API_TIMEOUTS      = (60, 600) # (CONNECT, READ)
CUSTOMER_NAME     = args.customer_name
CLOUD_ACCOUNT_ID  = args.cloud_account
TIME_RANGE_AMOUNT = args.time_range_amount
TIME_RANGE_UNIT   = args.time_range_unit
TIME_RANGE_LABEL  = 'Time Range - Past %s %s' % (TIME_RANGE_AMOUNT, TIME_RANGE_UNIT.capitalize()) 
ASSET_FILE        = '%s-assets.txt' % CUSTOMER_NAME
POLICY_FILE       = '%s-policies.txt' % CUSTOMER_NAME
ALERT_FILE        = '%s-alerts.txt' % CUSTOMER_NAME
USER_FILE         = '%s-users.txt' % CUSTOMER_NAME
ACCOUNT_FILE      = '%s-accounts.txt' % CUSTOMER_NAME
ACCOUNTGROUP_FILE = '%s-accountgroups.txt' % CUSTOMER_NAME
ALERTRULE_FILE    = '%s-alertrules.txt' % CUSTOMER_NAME
INTEGRATION_FILE  = '%s-integrations.txt' % CUSTOMER_NAME
DATA_FILES        = [ASSET_FILE, POLICY_FILE, ALERT_FILE, USER_FILE, ACCOUNT_FILE, ACCOUNTGROUP_FILE, ACCOUNTGROUP_FILE, INTEGRATION_FILE]

##########################################################################################
# Utilities.
##########################################################################################

def output(data=''):
    print(data)

####

def make_api_call(method, url, requ_data = None):
    try:
        requ = requests.Request(method, url, data = requ_data, headers = PRISMA_API_HEADERS)
        prep = requ.prepare()
        sess = requests.Session()
        resp = sess.send(prep, timeout=(API_TIMEOUTS))
        if resp.status_code == 200:
            return resp.content
        else:
            return {}
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

####
  
def get_assets():
    if CLOUD_ACCOUNT_ID:
        query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s&cloud.account=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT, CLOUD_ACCOUNT_ID)
    else:
        query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s' % ('relative', TIME_RANGE_AMOUNT, TIME_RANGE_UNIT)
    api_response = make_api_call('GET', '%s/v2/inventory?%s' % (PRISMA_API_ENDPOINT, query_params))
    alert_file = open(ASSET_FILE, 'wb') 
    alert_file.write(api_response)
    alert_file.close()

def get_policies():
    api_response = make_api_call('GET', '%s/policy?policy.enabled=true' % PRISMA_API_ENDPOINT)
    policy_file = open(POLICY_FILE, 'wb')
    policy_file.write(api_response)
    policy_file.close()

def get_alerts():
    body_params = {"timeRange": {"value": {"unit":"%s" % TIME_RANGE_UNIT, "amount":TIME_RANGE_AMOUNT}, "type":"relative"}}
    if CLOUD_ACCOUNT_ID:
        body_params["filters"] = [{"name":"cloud.accountId","value":"%s" % CLOUD_ACCOUNT_ID, "operator":"="}]
    request_data = json.dumps(body_params)
    api_response = make_api_call('POST', '%s/alert' % PRISMA_API_ENDPOINT, request_data)
    alert_file = open(ALERT_FILE, 'wb') 
    alert_file.write(api_response)
    alert_file.close()

def get_users():
    api_response = make_api_call('GET', '%s/v2/user' % PRISMA_API_ENDPOINT)
    policy_file = open(USER_FILE, 'wb') 
    policy_file.write(api_response)
    policy_file.close()

def get_accounts():
    api_response = make_api_call('GET', '%s/cloud' % PRISMA_API_ENDPOINT)
    policy_file = open(ACCOUNT_FILE, 'wb') 
    policy_file.write(api_response)
    policy_file.close()

def get_accountgroups():
    api_response = make_api_call('GET', '%s/cloud/group' % PRISMA_API_ENDPOINT)
    policy_file = open(ACCOUNTGROUP_FILE, 'wb') 
    policy_file.write(api_response)
    policy_file.close()

def get_alertrules():
    api_response = make_api_call('GET', '%s/v2/alert/rule' % PRISMA_API_ENDPOINT)
    policy_file = open(ALERTRULE_FILE, 'wb') 
    policy_file.write(api_response)
    policy_file.close()

def get_integrations():
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

    output('Querying Alerts')
    get_alerts()
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
    output("To save the processed data to a file, redirect the above command by adding ' > {name}-summary.tab'".format(name = CUSTOMER_NAME))
    sys.exit(0)


##########################################################################################
# Inspect mode: Read the result files and output summary results.
##########################################################################################

for data_file in DATA_FILES:
    if not os.path.isfile(data_file):
      output('Error: Data file does not exist: %s' % data_file)
      sys.exit(1)

##########################################################################################
# Counters and Structures.
##########################################################################################

policy_counts = {
    'high':        0,
    'medium':      0,
    'low':         0,
    'anomaly':     0,
    'audit_event': 0,
    'config':      0,
    'network':     0,
}

# Duplication between the above and below intended for future error checking.

alert_counts = {
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

policies = {}
alerts_by_standard = {}
alerts_by_policy   = {}

##########################################################################################
# Loop through all Policies and collect the details of each Policy.
# Do not use the alert count from this endpoint, as they are not scoped to a time range.
##########################################################################################

with open(POLICY_FILE, 'r') as f:
  policy_list = json.load(f)

for policy in policy_list:
    policyId = policy['policyId']
    # Transform policies from policy_list into policies.
    if not policyId in policies:
        policies[policyId] = {}
    policies[policyId]['policyName'] = policy['name']
    policies[policyId]['policySeverity'] = policy['severity']
    policies[policyId]['policyType'] = policy['policyType']
    policies[policyId]['policyShiftable'] = 'build' in policy['policySubTypes']
    policies[policyId]['policyRemediable'] = policy['remediable']
    policies[policyId]['policyOpenAlertsCount'] = policy['openAlertsCount']
    policies[policyId]['policySystemDefault'] = policy['systemDefault']
    # Create sets and lists of Compliance Standards to create a sorted, unique list of counters for each Compliance Standard.
    compliance_standards_set = set()
    policies[policyId]['complianceStandards'] = list()
    if 'complianceMetadata' in policy:
        for standard in policy['complianceMetadata']:
            compliance_standards_set.add(standard['standardName'])
        compliance_standards_list = list(compliance_standards_set)
        compliance_standards_list.sort()
        policies[policyId]['complianceStandards'] = compliance_standards_list
        # Initialize Compliance Standard Alert Counts (to avoid an error with += when the variable is undefined).
        for standard in compliance_standards_list:
            if not standard in alerts_by_standard:
                alerts_by_standard[standard] = {'high': 0, 'medium': 0, 'low': 0}

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
    # Transform alerts from alert_list to alerts_by_policy, and initialize Alert Count (to avoid an error with += when the variable is undefined).
    if not policyName in alerts_by_policy:
        alerts_by_policy[policyName] = {'policyId': policyId, 'alertCount': 0}
    # Increment Alert Count for each associated Compliance Standard
    for standard in policies[policyId]['complianceStandards']:
        alerts_by_standard[standard][policies[policyId]['policySeverity']] += 1
    # Increment Alert Count for associated Policy
    alerts_by_policy[policyName]['alertCount'] += 1
    # Increment Policies by Severity
    policy_counts[policies[policyId]['policySeverity']] += 1
    # Increment Policies by Type
    policy_counts[policies[policyId]['policyType']] += 1
    # Increment Alerts by Status
    alert_counts[alert['status']] += 1
    # Increment Alerts Closed by Reason
    if 'reason' in alert:
        if alert['reason'] == 'RESOURCE_DELETED':
            alert_counts['resolved_deleted'] += 1
        if alert['reason'] == 'RESOURCE_UPDATED':
            alert_counts['resolved_updated'] += 1
    # Increment Alerts by Severity
    alert_counts['%s_%s' % (alert['status'], policies[policyId]['policySeverity'])] += 1
    # Increment Alerts with IaC
    if policies[policyId]['policyShiftable']:
        alert_counts['shiftable'] += 1
	# Increment Alerts with Remediation
    if alert['policy']['remediable']:
        alert_counts['remediable'] += 1
        alert_counts['remediable_%s' % alert['status']] += 1
    # Increment Alerts for Custom vs Default Policies
    if policies[policyId]['policySystemDefault'] == True:
        alert_counts['custom'] += 1
    else:
        alert_counts['default'] += 1

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

# Totals

asset_count              = asset_list['summary']['totalResources']

alerts_by_standard_count = len(alerts_by_standard)
alerts_by_policy_count   = len(alerts_by_policy)
alert_count              = len(alert_list)
policy_count             = len(policy_list)
user_count               = len(user_list)
account_count            = len(account_list)
accountgroup_count       = len(accountgroup_list)
alertrule_count          = len(alertrule_list)
integration_count        = len(integration_list)

##########################################################################################
# Output tables and totals.
##########################################################################################

# Output Compliance Standards with Alerts

output()
output('#################################################################################')
output('# SHEET: By Compliance Standard, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s' % ('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low, Alerts High - Per 100 Assets, Alerts Medium - Per 100 Assets, Alerts Low - Per 100 Assets'))																						
for standard_name in sorted(alerts_by_standard):
    alert_count_high                  = alerts_by_standard[standard_name]['high']
    alert_count_medium                = alerts_by_standard[standard_name]['medium']
    alert_count_low                   = alerts_by_standard[standard_name]['low']
    alert_count_high_per_100_assets   = round((alert_count_high / asset_count) * 100)
    alert_count_medium_per_100_assets = round((alert_count_medium / asset_count) * 100)
    alert_count_low_per_100_assets    = round((alert_count_low / asset_count) * 100)
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s' % (standard_name, alert_count_high, alert_count_medium, alert_count_low, alert_count_high_per_100_assets, alert_count_medium_per_100_assets, alert_count_low_per_100_assets))

# Output Policies with Alerts

output()
output('#################################################################################')
output('# SHEET: By Policy, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()
output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('Policy', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Alert Count - Per 100 Assets', 'Compliance Standards') )
for policy_name in sorted(alerts_by_policy):
    policyId                          = alerts_by_policy[policy_name]['policyId']
    policy_severity                   = policies[policyId]['policySeverity']
    policy_type                       = policies[policyId]['policyType']
    policy_is_shiftable               = policies[policyId]['policyShiftable']
    policy_is_remediable              = policies[policyId]['policyRemediable']
    policy_alert_count                = alerts_by_policy[policy_name]['alertCount']
    policy_alert_count_per_100_assets = round((policy_alert_count / asset_count) * 100)
    policy_standards_list             = ','.join(map(str, policies[policyId]['complianceStandards']))
    output('%s\t%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (policy_name, policy_severity, policy_type, policy_is_remediable, policy_is_remediable, policy_alert_count, policy_alert_count_per_100_assets, policy_standards_list))

# Output Summary

output()
output('#################################################################################')
output('# SHEET: Summary')
output('#################################################################################')
output()
output("Number of Assets monitored:\t%s" % asset_count)
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

output("Number of Policies\t%s" % policy_count)
output("Policies Custom\t%s"    % sum(x.get('systemDefault') == False for x in policy_list))
output("Policies Default\t%s"   % sum(x.get('systemDefault') == True for x in policy_list))
output()

output("Number of Users:\t%s" % user_count)
output("Users Disabled\t%s"   % sum(x.get('enabled') == False for x in user_list))
output("Users Enabled\t%s"    % sum(x.get('enabled') == True for x in user_list))
output()

output('#################################################################################')
output('# SHEET: Summary, Open and Closed Alerts, %s' % TIME_RANGE_LABEL)
output('#################################################################################')
output()

output("Number of Compliance Standards with Alerts:\t%s" % alerts_by_standard_count)
output()

output("Number of Policies with Alerts: Total\t%s" % alerts_by_policy_count)
output()

output("Number of Alerts\t%s" % alert_count)
output("Alerts per 100 Assets\t%s" % round((alert_count / asset_count) * 100))
output()
output("Open Alerts\t%s"                % alert_counts['open'])
output("Open Alerts per 100 Assets\t%s" % round((alert_counts['open'] / asset_count) * 100))
output("Open Alerts as Percent\t%s%s"   % (round((alert_counts['open']/alert_count) * 100), '%'))
output()
output("Open Alerts High-Severity\t%s"                  % alert_counts['open_high'])
output("Open Alerts High-Severity per 100 Assets\t%s"   % round((alert_counts['open_high'] / asset_count) * 100))
output("Open Alerts Medium-Severity\t%s"                % alert_counts['open_medium'])
output("Open Alerts Medium-Severity per 100 Assets\t%s" % round((alert_counts['open_medium'] / asset_count) * 100))
output("Open Alerts Low-Severity\t%s"                   % alert_counts['open_low'])
output("Open Alerts Low-Severity per 100 Assets\t%s"    % round((alert_counts['open_low'] / asset_count) * 100))
output()
output("Resolved Alerts\t%s"                % alert_counts['resolved'])
output("Resolved Alerts per 100 Assets\t%s" % round((alert_counts['resolved'] / asset_count) * 100))
output("Resolved Alerts as Percent\t%s%s"   % (round((alert_counts['resolved']/alert_count) * 100), '%'))
output()
output("Resolved By Delete\t%s" % alert_counts['resolved_deleted'])
output("Resolved By Update\t%s" % alert_counts['resolved_updated'])
output()
output("Resolved Alerts High-Severity\t%s"                  % alert_counts['resolved_high'])
output("Resolved Alerts High-Severity per 100 Assets\t%s"   % round((alert_counts['resolved_high'] / asset_count) * 100))
output("Resolved Alerts Medium-Severity\t%s"                % alert_counts['resolved_medium'])
output("Resolved Alerts Medium-Severity per 100 Assets\t%s" % round((alert_counts['resolved_medium'] / asset_count) * 100))
output("Resolved Alerts Low-Severity\t%s"                   % alert_counts['resolved_low'])
output("Resolved Alerts Low-Severity per 100 Assets\t%s"    % round((alert_counts['resolved_low'] / asset_count) * 100))
output()
output("Anomaly Alerts\t%s" % policy_counts['anomaly'])
output("Config Alerts\t%s"  % policy_counts['config'])
output("Network Alerts\t%s" % policy_counts['network'])
output()
output("Alerts with IaC\t%s"                % alert_counts['shiftable'])
output("Alerts with IaC per 100 Assets\t%s" % round((alert_counts['shiftable'] / asset_count) * 100))
output("Alerts with IaC as Percent\t%s%s"   % (round((alert_counts['shiftable']/alert_count) * 100), '%'))
output()
output("Alerts with Remediation\t%s"                % alert_counts['remediable'])
output("Alerts with Remediation per 100 Assets\t%s" % round((alert_counts['remediable'] / asset_count) * 100))
output("Alerts with Remediation as Percent\t%s%s"   % (round((alert_counts['remediable']/alert_count) * 100), '%'))
output()
output("Alerts Generated by Custom Policies\t%s"  % alert_counts['custom'])
output("Alerts Generated by Default Policies\t%s" % alert_counts['default'])
output()
