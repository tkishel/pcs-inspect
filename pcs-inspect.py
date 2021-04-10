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
    config['SUPPORT_API_MODE']    = args.support_api
    config['PRISMA_API_ENDPOINT'] = args.url        # or os.environ.get('PRISMA_API_ENDPOINT')
    config['PRISMA_ACCESS_KEY']   = args.access_key # or os.environ.get('PRISMA_ACCESS_KEY')
    config['PRISMA_SECRET_KEY']   = args.secret_key # or os.environ.get('PRISMA_SECRET_KEY')
    config['PRISMA_API_HEADERS']  = {
        'Accept': 'application/json; charset=UTF-8, text/plain, */*',
        'Content-Type': 'application/json'
    }
    config['API_TIMEOUTS']      = (60, 600) # (CONNECT, READ)
    config['CUSTOMER_NAME']     = args.customer_name
    config['CLOUD_ACCOUNT_ID']  = args.cloud_account
    config['TIME_RANGE_AMOUNT'] = args.time_range_amount
    config['TIME_RANGE_UNIT']   = args.time_range_unit
    config['TIME_RANGE_LABEL']  = 'Past %s %s' % (config['TIME_RANGE_AMOUNT'], config['TIME_RANGE_UNIT'].capitalize())
    config['CUSTOMER_PREFIX']   = re.sub(r'\W+', '', config['CUSTOMER_NAME']).lower()
    config['RESULTS_FILE'] = {
        'ASSETS':       '%s-assets.json'        % config['CUSTOMER_PREFIX'],
        'POLICIES':     '%s-policies.json'      % config['CUSTOMER_PREFIX'],
        'ALERTS':       '%s-alerts.json'        % config['CUSTOMER_PREFIX'],
        'USERS':        '%s-users.json'         % config['CUSTOMER_PREFIX'],
        'ACCOUNTS':     '%s-accounts.json'      % config['CUSTOMER_PREFIX'],
        'GROUPS':       '%s-groups.json'        % config['CUSTOMER_PREFIX'],
        'RULES':        '%s-rules.json'         % config['CUSTOMER_PREFIX'],
        'INTEGRATIONS': '%s-integrations.json'  % config['CUSTOMER_PREFIX']
    }
    config['OUTPUT_FILE_XLS'] = '%s.xls' % config['CUSTOMER_PREFIX']
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
    return config

##########################################################################################
# File Helpers.
##########################################################################################

def delete_file_if_exists(file_name):
    if os.path.exists(file_name):
        os.remove(file_name)

def open_sheet(file_name):
    return pd.ExcelWriter(file_name, engine='xlsxwriter')

def write_sheet(panda_writer, this_sheet_name, rows):
    dataframe = pd.DataFrame.from_records(rows)
    dataframe.to_excel(panda_writer, sheet_name=this_sheet_name, header=False, index=False)
    this_sheet = panda_writer.sheets[this_sheet_name]
    # Approximate autofit column width.
    for idx, column in enumerate(dataframe): # Loop through the columns.
        dataframe_series = dataframe[column]
        column_width = max(
            dataframe_series.astype(str).map(len).max(), # Length of largest cell
            len(str(dataframe_series.name))              # Length of column header / name
            )
        this_sheet.set_column(idx, idx, column_width)
    if CONFIG['DEBUG_MODE']:
        output(this_sheet_name)
        output()
        pd.set_option('display.max_rows', None)
        output(dataframe)
        output()

def save_sheet(panda_writer):
    panda_writer.save()

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
            # return bytes('[]', 'utf-8')
            output('Error with API: Status Code: %s Details: %s' % (resp.status_code, resp.text))
            sys.exit(1)
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
# Using '/_support/timeline/resource' instead of the not-implemented '_support/v2/inventory' endpoint.

def get_assets(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {}
        body_params["customerName"] = "%s" % CONFIG['CUSTOMER_NAME']
        if CONFIG['CLOUD_ACCOUNT_ID']:
            body_params["accountIds"] = ["%s" % CONFIG['CLOUD_ACCOUNT_ID']]
        body_params['timeRange'] = {"value": {"unit": "%s" % CONFIG['TIME_RANGE_UNIT'], "amount": CONFIG['TIME_RANGE_AMOUNT']}, "type": "relative"}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/timeline/resource' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
        api_response_json = json.loads(api_response)
        if api_response_json and 'resources' in api_response_json[0]:
            api_response = bytes('{"summary": {"totalResources": %s}}' % api_response_json[0]['resources'], 'utf-8')
        else:
            api_response = bytes('{"summary": {"totalResources": 0}}', 'utf-8')
    else:
        if CONFIG['CLOUD_ACCOUNT_ID']:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s&cloud.account=%s' % ('relative', CONFIG['TIME_RANGE_AMOUNT'], CONFIG['TIME_RANGE_UNIT'], CONFIG['CLOUD_ACCOUNT_ID'])
        else:
            query_params = 'timeType=%s&timeAmount=%s&timeUnit=%s' % ('relative', CONFIG['TIME_RANGE_AMOUNT'], CONFIG['TIME_RANGE_UNIT'])
        api_response = make_api_call('GET', '%s/v2/inventory?%s' % (CONFIG['PRISMA_API_ENDPOINT'], query_params))
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()
    # This returns a dictionary instead of a list.

# SUPPORT_API_MODE:
# This script depends upon Open Alert counts for all Policies (as provided by '/policy'), but '/_support/policy' doesn't return open Alert counts.
# And '/_support/alert/policy' does return alertCount, but I cannot tell if that is all (Open or Closed) or just Open Alerts, and returns fewer Policies than '_support/policy' ... given the same parameters.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_policies(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/policy' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    else:
        api_response = make_api_call('GET', '%s/policy' % CONFIG['PRISMA_API_ENDPOINT'])
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()

# SUPPORT_API_MODE:
# This script depends upon the not implemented '/_support/alert/jobs' endpoint.
# Instead, this script merges the results of the '/_support/alert/aggregate' endpoint with the results of the '/_support/policy' endpoint.

def get_alerts(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        api_response = {}
        api_response['by_policy']          = json.loads(get_alerts_aggregate('policy.name'))     # [{"policyName":"AWS VPC subnets should not allow automatic public IP assignment","alerts":105},{"policyName":"AWS Security Group overly permissive to all traffic","alerts":91}, ...
        api_response['by_policy_type']     = json.loads(get_alerts_aggregate('policy.type'))     # [{"alerts":422,"policyType":"config"},{"alerts":15,"policyType":"network"},{"alerts":2,"policyType":"anomaly"},{"alerts":0,"policyType":"iam"},{"alerts":0,"policyType":"data"},{"alerts":0,"policyType":"audit_event"}]
        api_response['by_policy_severity'] = json.loads(get_alerts_aggregate('policy.severity')) # [{"severity":"medium","alerts":225},{"severity":"high","alerts":214},{"severity":"low","alerts":0}]
        api_response['by_alert.status']    = json.loads(get_alerts_aggregate('alert.status'))    # [{"alerts":439,"status":"open"},{"alerts":88,"status":"resolved"},{"alerts":0,"status":"dismissed"},{"alerts":0,"status":"snoozed"}]'
        api_response_json = json.dumps(api_response, indent=2, separators=(', ', ': '))
        result_file = open(output_file_name, 'w')
        result_file.write(api_response_json)
        result_file.close()
        # This returns a dictionary (of Open Alerts) instead of a list.
    else:
        body_params = {}
        body_params['timeRange'] = {"value": {"unit": "%s" % CONFIG['TIME_RANGE_UNIT'], "amount": CONFIG['TIME_RANGE_AMOUNT']}, "type": "relative"}
        if CONFIG['CLOUD_ACCOUNT_ID']:
            body_params["filters"] = [{"name": "cloud.accountId","value": "%s" % CONFIG['CLOUD_ACCOUNT_ID'], "operator": "="}]
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/alert/jobs' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
        api_response_json = json.loads(api_response)
        if not 'id' in api_response_json:
            output("Error with '/alert/jobs' API: 'id' missing from response: %s" % api_response_json)
            return
        alert_job_id = api_response_json['id']
        api_response = make_api_call('GET', '%s/alert/jobs/%s/status' % (CONFIG['PRISMA_API_ENDPOINT'], alert_job_id))
        api_response_json = json.loads(api_response)
        if not 'status' in api_response_json:
            output("Error with '/alert/jobs' API: 'status' missing from response: %s" % api_response_json)
            return
        alert_job_status = api_response_json['status']
        while alert_job_status == 'IN_PROGRESS':
            output('Checking: %s' % alert_job_status)
            if CONFIG['DEBUG_MODE']:
                output(api_response_json)
                output()
            api_response = make_api_call('GET', '%s/alert/jobs/%s/status' % (CONFIG['PRISMA_API_ENDPOINT'], alert_job_id))
            api_response_json = json.loads(api_response)
            if not 'status' in api_response_json:
                output("Error with '/alert/jobs' API: 'status' missing from response: %s" % api_response_json)
                return
            alert_job_status = api_response_json['status']
        if alert_job_status == 'READY_TO_DOWNLOAD':
            api_response = make_api_call('GET', '%s/alert/jobs/%s/download' % (CONFIG['PRISMA_API_ENDPOINT'], alert_job_id))
            result_file = open(output_file_name, 'wb')
            result_file.write(api_response)
            result_file.close()
        else:
            output("Error with '/alert/jobs' API: 'status' in response not in ('IN_PROGRESS','READY_TO_DOWNLOAD'): %s" % api_response_json)
        # This returns a list (of Open and Closed Alerts).

## Valid filter options: policy.name, policy.type, policy.severity, or alert.status.

def get_alerts_aggregate(group_by_field):
    body_params = {}
    body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
    if CONFIG['CLOUD_ACCOUNT_ID']:
        body_params["accountIds"] = ["%s" % CONFIG['CLOUD_ACCOUNT_ID']]
    body_params['timeRange'] = {"value": {"unit": "%s" % CONFIG['TIME_RANGE_UNIT'], "amount": CONFIG['TIME_RANGE_AMOUNT']}, "type": "relative"}
    body_params['groupBy'] = group_by_field
    body_params['limit'] = 9999
    request_data = json.dumps(body_params)
    api_response = make_api_call('POST', '%s/_support/alert/aggregate' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    return api_response

####

def get_users(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/v2/_support/user' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/user' % CONFIG['PRISMA_API_ENDPOINT'])
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()

####

def get_accounts(output_file_name):
    delete_file_if_exists(output_file_name)
    account_list = []
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
        api_response_json = json.loads(api_response)
        for account in api_response_json:
            if account['numberOfChildAccounts'] > 0:    # > Or account['accountType'] == 'organization'
                api_response_children = make_api_call('POST', '%s/_support/cloud/%s/%s/project' % (CONFIG['PRISMA_API_ENDPOINT'], account['cloudType'], account['accountId']), request_data)
                account_list.extend(parse_account_children(account, api_response_children))
            else:
                account_list.append(account)
    else:
        api_response = make_api_call('GET', '%s/cloud' % CONFIG['PRISMA_API_ENDPOINT'])
        api_response_json = json.loads(api_response)
        for account in api_response_json:
            if account['accountType'] == 'organization': # ? Or account['numberOfChildAccounts'] > 0
                api_response_children = make_api_call('GET', '%s/cloud/%s/%s/project' % (CONFIG['PRISMA_API_ENDPOINT'], account['cloudType'], account['accountId']))
                account_list.extend(parse_account_children(account, api_response_children))
            else:
                account_list.append(account)
    result_file = open(output_file_name, 'w')
    result_file.write(json.dumps(account_list))
    result_file.close()

##

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

def get_account_groups(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/cloud/group' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    else:
        api_response = make_api_call('GET', '%s/cloud/group' % CONFIG['PRISMA_API_ENDPOINT'])
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()

####

def get_alert_rules(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/alert/rule' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    else:
        api_response = make_api_call('GET', '%s/v2/alert/rule' % CONFIG['PRISMA_API_ENDPOINT'])
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()

####

def get_integrations(output_file_name):
    delete_file_if_exists(output_file_name)
    if CONFIG['SUPPORT_API_MODE']:
        body_params = {"customerName": "%s" % CONFIG['CUSTOMER_NAME']}
        request_data = json.dumps(body_params)
        api_response = make_api_call('POST', '%s/_support/integration' % CONFIG['PRISMA_API_ENDPOINT'], request_data)
    else:
        api_response = make_api_call('GET', '%s/integration' % CONFIG['PRISMA_API_ENDPOINT'])
    result_file = open(output_file_name, 'wb')
    result_file.write(api_response)
    result_file.close()

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
    output('Querying Assets: Time Range: %s' % CONFIG['TIME_RANGE_LABEL'])
    get_assets(CONFIG['RESULTS_FILE']['ASSETS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['ASSETS'])
    output()
    output('Querying Policies')
    get_policies(CONFIG['RESULTS_FILE']['POLICIES'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['POLICIES'])
    output()
    output('Querying Alerts: Time Range: %s (please wait)' % CONFIG['TIME_RANGE_LABEL'])
    get_alerts(CONFIG['RESULTS_FILE']['ALERTS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['ALERTS'])
    output()
    output('Querying Users')
    get_users(CONFIG['RESULTS_FILE']['USERS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['USERS'])
    output()
    output('Querying Accounts')
    get_accounts(CONFIG['RESULTS_FILE']['ACCOUNTS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['ACCOUNTS'])
    output()
    output('Querying Account Groups')
    get_account_groups(CONFIG['RESULTS_FILE']['GROUPS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['GROUPS'])
    output()
    output('Querying Alert Rules')
    get_alert_rules(CONFIG['RESULTS_FILE']['RULES'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['RULES'])
    output()
    output('Querying Integrations')
    get_integrations(CONFIG['RESULTS_FILE']['INTEGRATIONS'])
    output('Results saved as: %s' % CONFIG['RESULTS_FILE']['INTEGRATIONS'])
    output()

##########################################################################################
# Process mode: Read the input files.
##########################################################################################

def read_collected_data():
    for this_result_file in CONFIG['RESULTS_FILE']:
        if not os.path.isfile(CONFIG['RESULTS_FILE'][this_result_file]):
          output('Error: Query result file does not exist: %s' % CONFIG['RESULTS_FILE'][this_result_file])
          sys.exit(1)
        with open(CONFIG['RESULTS_FILE'][this_result_file], 'r', encoding='utf8') as f:
          DATA[this_result_file] = json.load(f)

##########################################################################################
# Process mode: Process the data.
##########################################################################################

# cloud_type      = {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0}
# policy_mode     = {'custom': 0, 'default': 0}
# policy_feature  = {'remediable': 0, 'shiftable': 0}
# policy_severity = {'high': 0, 'medium': 0, 'low': 0}
# policy_type     = {'anomaly': 0, 'audit_event': 0, 'config': 0, 'iam': 0, 'network': 0}
# alert_status    = {'open': 0, 'dismissed': 0, 'snoozed': 0, 'resolved': 0}

def process_collected_data():
    # SUPPORT_API_MODE saves a dictionary (of Open) Alerts instead of a list.
    # Use that to override any '--support_api' argument.
    if type(DATA['ALERTS']) is dict:
        CONFIG['SUPPORT_API_MODE'] = True
        RESULTS['alerts_aggregated_by'] = process_aggregated_alerts(DATA['ALERTS'])
    # POLICIES
    RESULTS['compliance_standards_from_policies'] = {}
    RESULTS['policies_by_name'] = {}
    RESULTS['policies'] = {}
    RESULTS['alert_counts_from_policies'] = {
        'cloud_type': {'all': 0, 'aws': 0, 'azure': 0, 'gcp': 0, 'alibaba_cloud': 0, 'oci': 0},
        'feature':    {'remediable': 0, 'shiftable': 0},
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
        'feature':              {'remediable': 0, 'shiftable': 0},
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
    process_alerts(DATA['ALERTS'])
    # SUMMARY
    RESULTS['summary'] = {}
    RESULTS['summary']['count_of_assets'] = 0
    RESULTS['summary']['count_of_aggregated_open_alerts'] = 0
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
        RESULTS['policies'][this_policy_id]['policyCloudType']     = this_policy['cloudType'].lower()
        RESULTS['policies'][this_policy_id]['policyShiftable']     = 'build' in this_policy['policySubTypes']
        RESULTS['policies'][this_policy_id]['policyRemediable']    = this_policy['remediable']
        RESULTS['policies'][this_policy_id]['policySystemDefault'] = this_policy['systemDefault']
        if 'policyUpi' in this_policy:
            RESULTS['policies'][this_policy_id]['policyUpi'] = this_policy['policyUpi']
        else:
            RESULTS['policies'][this_policy_id]['policyUpi'] = 'CUSTOM'
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
            # This is all of the data we can collect without a reference to a Policy.
            if not this_policy_id in RESULTS['policies']:
                if this_alert['reason'] == 'POLICY_DELETED':
                    RESULTS['deleted_policies_from_alerts'].setdefault(this_policy_id, 0)
                    RESULTS['deleted_policies_from_alerts'][this_policy_id] += 1
                    RESULTS['alert_counts_from_alerts']['resolved_by_policy']['deleted'] += 1
                if CONFIG['DEBUG_MODE']:
                    output('Skipping Alert: Related Policy Deleted: Policy ID: %s' % this_policy_id)
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
                RESULTS['alert_counts_from_alerts']['feature']['shiftable']  += 1
            RESULTS['alert_counts_from_alerts']['severity_by_status'][this_alert['status']][RESULTS['policies'][this_policy_id]['policySeverity']] += 1

##########################################################################################
# Process mode: Summarize the data.
##########################################################################################

def process_summary():
    RESULTS['summary']['count_of_assets']                                         = DATA['ASSETS']['summary']['totalResources']
    if CONFIG['SUPPORT_API_MODE']:
        RESULTS['summary']['count_of_policies_with_alerts_from_policies']         = len(RESULTS['alerts_aggregated_by']['policy'])
        RESULTS['summary']['count_of_aggregated_open_alerts']                     = RESULTS['alerts_aggregated_by']['status']['open']
    else:
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

def output_collected_data():
    panda_writer = open_sheet(CONFIG['OUTPUT_FILE_XLS'])
    output_utilization(panda_writer)
    output_alerts_by_compliance_standard(panda_writer)
    output_alerts_by_policy(panda_writer)
    output_alerts_summary(panda_writer)
    save_sheet(panda_writer)
    output('Results saved as: %s' % CONFIG['OUTPUT_FILE_XLS'])

##

def output_utilization(panda_writer):
    output('Saving Utilization Worksheet')
    output()
    rows = [
        ('Number of Assets',               RESULTS['summary']['count_of_assets']),
        ('',''),
        ('Number of Cloud Accounts',       len(DATA['ACCOUNTS'])),
        ('',''),
        ('Cloud Accounts Disabled',        sum(x.get('enabled') == False for x in DATA['ACCOUNTS'])),
        ('Cloud Accounts Enabled',         sum(x.get('enabled') == True for x in DATA['ACCOUNTS'])),
        ('',''),
        ('Cloud Accounts AWS',             sum(x.get('cloudType').lower() == 'aws' for x in DATA['ACCOUNTS'])),
        ('Cloud Accounts Azure',           sum(x.get('cloudType').lower() == 'azure' for x in DATA['ACCOUNTS'])),
        ('Cloud Accounts Google',          sum(x.get('cloudType').lower() == 'gcp' for x in DATA['ACCOUNTS'])),
        ('Cloud Accounts Alibaba',         sum(x.get('cloudType').lower() == 'alibaba_cloud' for x in DATA['ACCOUNTS'])),
        ('Cloud Accounts Oracle',          sum(x.get('cloudType').lower() == 'oci' for x in DATA['ACCOUNTS'])),
        ('',''),
        ('Number of Cloud Account Groups', len(DATA['GROUPS'])),
        ('',''),
        ('Number of Alert Rules',          len(DATA['RULES'])),
        ('',''),
        ('Alert Rules Disabled',           sum(x.get('enabled') == False for x in DATA['RULES'])),
        ('Alert Rules Enabled',            sum(x.get('enabled') == True for x in DATA['RULES'])),
        ('',''),
        ('Number of Integrations',         len(DATA['INTEGRATIONS'])),
        ('',''),
        ('Integrations Disabled',          sum(x.get('enabled') == False for x in DATA['INTEGRATIONS'])),
        ('Integrations Enabled',           sum(x.get('enabled') == True for x in DATA['INTEGRATIONS'])),
        ('',''),
        ('Number of Policies',             len(DATA['POLICIES'])),
        ('',''),
        ('Policies Disabled',              sum(x.get('enabled') == False for x in DATA['POLICIES'])),
        ('Policies Enabled',               sum(x.get('enabled') == True for x in DATA['POLICIES'])),
        ('',''),
        ('Policies Custom',                sum(x.get('systemDefault') == False for x in DATA['POLICIES'])),
        ('Policies Default',               sum(x.get('systemDefault') == True for x in DATA['POLICIES'])),
        ('',''),
        ('Number of Users',                len(DATA['USERS'])),
        ('',''),
        ('Users Disabled',                 sum(x.get('enabled') == False for x in DATA['USERS'])),
        ('Users Enabled',                  sum(x.get('enabled') == True for x in DATA['USERS'])),
    ]
    write_sheet(panda_writer, 'Utilization', rows)

##

def output_alerts_by_compliance_standard(panda_writer):
    output('Saving Alerts by Compliance Standard Worksheet(s)')
    output()
    rows = []
    rows.append(('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low') )
    for compliance_standard_name in sorted(RESULTS['compliance_standards_from_policies']):
        alert_count_high   = RESULTS['compliance_standards_from_policies'][compliance_standard_name]['high']
        alert_count_medium = RESULTS['compliance_standards_from_policies'][compliance_standard_name]['medium']
        alert_count_low    = RESULTS['compliance_standards_from_policies'][compliance_standard_name]['low']
        rows.append((compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low) )
    write_sheet(panda_writer, 'Open Alerts by Standard', rows)
    if not CONFIG['SUPPORT_API_MODE']:
        rows = []
        rows.append(('Compliance Standard', 'Alerts High', 'Alerts Medium', 'Alerts Low'))
        for compliance_standard_name in sorted(RESULTS['compliance_standards_from_alerts']):
            alert_count_high   = RESULTS['compliance_standards_from_alerts'][compliance_standard_name]['high']
            alert_count_medium = RESULTS['compliance_standards_from_alerts'][compliance_standard_name]['medium']
            alert_count_low    = RESULTS['compliance_standards_from_alerts'][compliance_standard_name]['low']
            rows.append((compliance_standard_name, alert_count_high, alert_count_medium, alert_count_low))
        rows.append((''))
        rows.append((''))
        rows.append(('Time Range: %s' % CONFIG['TIME_RANGE_LABEL'], ''))
        write_sheet(panda_writer, 'Open Closed Alerts by Standard', rows)

##

def output_alerts_by_policy(panda_writer):
    output('Saving Alerts by Policy Worksheet(s)')
    output()
    rows = []
    rows.append(('Policy', 'UPI', 'Alert Count', 'Enabled', 'Severity', 'Type', 'Cloud Type', 'With IAC', 'With Remediation', 'Compliance Standards'))
    # Consider replacing sorted(RESULTS['policies_by_name']) with sorted(RESULTS['policies'], key=lambda x: (RESULTS['policies'][x]['name'])
    for policy_name in sorted(RESULTS['policies_by_name']):
        this_policy_id        = RESULTS['policies_by_name'][policy_name]['policyId']
        policy_upi            = RESULTS['policies'][this_policy_id]['policyUpi']
        policy_alert_count    = RESULTS['policies'][this_policy_id]['alertCount']
        policy_enabled        = RESULTS['policies'][this_policy_id]['policyEnabled']
        policy_severity       = RESULTS['policies'][this_policy_id]['policySeverity']
        policy_type           = RESULTS['policies'][this_policy_id]['policyType']
        policy_cloud_type     = RESULTS['policies'][this_policy_id]['policyCloudType']
        policy_is_shiftable   = RESULTS['policies'][this_policy_id]['policyShiftable']
        policy_is_remediable  = RESULTS['policies'][this_policy_id]['policyRemediable']
        policy_standards_list = ','.join(map(str, RESULTS['policies'][this_policy_id]['complianceStandards']))
        rows.append((policy_name, policy_upi, policy_alert_count, policy_enabled, policy_severity, policy_type, policy_cloud_type, policy_is_remediable, policy_is_remediable, policy_standards_list))
    write_sheet(panda_writer, 'Open Alerts by Policy', rows)
    if not CONFIG['SUPPORT_API_MODE']:
        rows = []
        rows.append(('Policy', 'Enabled', 'UPI', 'Severity', 'Type', 'With IAC', 'With Remediation', 'Alert Count', 'Compliance Standards'))
        for policy_name in sorted(RESULTS['policies_from_alerts']):
            this_policy_id        = RESULTS['policies_from_alerts'][policy_name]['policyId']
            policy_upi            = RESULTS['policies'][this_policy_id]['policyUpi']
            policy_alert_count    = RESULTS['policies_from_alerts'][policy_name]['alertCount'] # Not RESULTS['policies'][this_policy_id]['openAlertsCount'] 
            policy_enabled        = RESULTS['policies'][this_policy_id]['policyEnabled']
            policy_severity       = RESULTS['policies'][this_policy_id]['policySeverity']
            policy_type           = RESULTS['policies'][this_policy_id]['policyType']
            policy_cloud_type     = RESULTS['policies'][this_policy_id]['policyCloudType']
            policy_is_shiftable   = RESULTS['policies'][this_policy_id]['policyShiftable']
            policy_is_remediable  = RESULTS['policies'][this_policy_id]['policyRemediable']
            policy_standards_list = ','.join(map(str, RESULTS['policies'][this_policy_id]['complianceStandards']))
            rows.append((policy_name, policy_upi, policy_alert_count, policy_enabled, policy_severity, policy_type, policy_cloud_type, policy_is_remediable, policy_is_remediable, policy_standards_list))
        rows.append((''))
        rows.append((''))
        rows.append(('Time Range: %s' % CONFIG['TIME_RANGE_LABEL'], ''))
        write_sheet(panda_writer, 'Open Closed Alerts by Policy', rows)

##

def output_alerts_summary(panda_writer):
    output('Saving Alerts Summary Worksheet(s)')
    output()
    rows = [
        ('Number of Compliance Standards with Open Alerts',  RESULTS['summary']['count_of_compliance_standards_with_alerts_from_policies']),
        ('',''),
        ('Number of Policies with Open Alerts',              RESULTS['summary']['count_of_policies_with_alerts_from_policies']),
        ('',''),
        ('AWS Policies with Open Alerts',                    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['aws']),
        ('Azure Policies with Open Alerts',                  RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['azure']),
        ('GCP Policies with Open Alerts',                    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['gcp']),
        ('Alibaba Policies with Open Alerts',                RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['alibaba_cloud']),
        ('OCI Policies with Open Alerts',                    RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['oci']),
        ('Cross-Cloud Policies with Open Alerts',            RESULTS['summary']['count_of_policies_with_alerts_from_policies_by_cloud']['all']),
        ('',''),
        ('Number of Open Alerts',                            RESULTS['alert_counts_from_policies']['status']['open']),
        ('',''),
        ('Open Alerts High-Severity',                        RESULTS['alert_counts_from_policies']['severity']['high']),
        ('Open Alerts Medium-Severity',                      RESULTS['alert_counts_from_policies']['severity']['medium']),
        ('Open Alerts Low-Severity',                         RESULTS['alert_counts_from_policies']['severity']['low']),
        ('',''),
        ('Open Anomaly Alerts',                              RESULTS['alert_counts_from_policies']['type']['anomaly']),
        ('Open Audit Alerts',                                RESULTS['alert_counts_from_policies']['type']['audit_event']),
        ('Open Config Alerts',                               RESULTS['alert_counts_from_policies']['type']['config']),
        ('Open Data Alerts',                                 RESULTS['alert_counts_from_policies']['type']['data']),
        ('Open IAM Alerts',                                  RESULTS['alert_counts_from_policies']['type']['iam']),
        ('Open Network Alerts',                              RESULTS['alert_counts_from_policies']['type']['network']),
        ('',''),
        ('Open Alerts with IaC',                             RESULTS['alert_counts_from_policies']['feature']['shiftable']),
        ('Open Alerts with Remediation',                     RESULTS['alert_counts_from_policies']['feature']['remediable']),
        ('',''),
        ('Open Alerts Generated by Custom Policies',         RESULTS['alert_counts_from_policies']['mode']['custom']),
        ('Open Alerts Generated by Default Policies',        RESULTS['alert_counts_from_policies']['mode']['default']),
        ('',''),
        ('Open Alerts Generated by AWS Policies',            RESULTS['alert_counts_from_policies']['cloud_type']['aws']),
        ('Open Alerts Generated by Azure Policies',          RESULTS['alert_counts_from_policies']['cloud_type']['azure']),
        ('Open Alerts Generated by GCP Policies',            RESULTS['alert_counts_from_policies']['cloud_type']['gcp']),
        ('Open Alerts Generated by Alibaba Policies',        RESULTS['alert_counts_from_policies']['cloud_type']['alibaba_cloud']),
        ('Open Alerts Generated by OCI Policies',            RESULTS['alert_counts_from_policies']['cloud_type']['oci']),
        ('Open Alerts Generated by Cross-Cloud Policies',    RESULTS['alert_counts_from_policies']['cloud_type']['all']),
    ]
    write_sheet(panda_writer, 'Open Alerts Summary', rows)
    if not CONFIG['SUPPORT_API_MODE']:
        rows = [
            ('Number of Compliance Standards with Alerts',  RESULTS['summary']['count_of_compliance_standards_with_alerts_from_alerts']),
            ('',''),
            ('Number of Policies with Alerts',              RESULTS['summary']['count_of_policies_with_alerts_from_alerts']),
            ('',''),
            ('Number of Alerts',                            RESULTS['summary']['count_of_open_closed_alerts']),
            ('',''),
            ('Anomaly Alerts',                              RESULTS['alert_counts_from_alerts']['type']['anomaly']),
            ('Audit Alerts',                                RESULTS['alert_counts_from_alerts']['type']['audit_event']),
            ('Config Alerts',                               RESULTS['alert_counts_from_alerts']['type']['config']),
            ('Data Alerts',                                 RESULTS['alert_counts_from_alerts']['type']['data']),
            ('IAM Alerts',                                  RESULTS['alert_counts_from_alerts']['type']['iam']),
            ('Network Alerts',                              RESULTS['alert_counts_from_alerts']['type']['network']),
            ('',''),
            ('Open Alerts',                                 RESULTS['alert_counts_from_alerts']['status']['open']),
            ('Dismissed Alerts',                            RESULTS['alert_counts_from_alerts']['status']['dismissed']),
            ('Resolved Alerts',                             RESULTS['alert_counts_from_alerts']['status']['resolved']),
            ('Snoozed Alerts',                              RESULTS['alert_counts_from_alerts']['status']['snoozed']),
            ('',''),
            ('Open Alerts High-Severity',                   RESULTS['alert_counts_from_alerts']['severity_by_status']['open']['high']),
            ('Open Alerts Medium-Severity',                 RESULTS['alert_counts_from_alerts']['severity_by_status']['open']['medium']),
            ('Open Alerts Low-Severity',                    RESULTS['alert_counts_from_alerts']['severity_by_status']['open']['low']),
            ('',''),
            ('Dismissed Alerts High-Severity',              RESULTS['alert_counts_from_alerts']['severity_by_status']['dismissed']['high']),
            ('Dismissed Alerts Medium-Severity',            RESULTS['alert_counts_from_alerts']['severity_by_status']['dismissed']['medium']),
            ('Dismissed Alerts Low-Severity',               RESULTS['alert_counts_from_alerts']['severity_by_status']['dismissed']['low']),
            ('',''),
            ('Resolved Alerts High-Severity',               RESULTS['alert_counts_from_alerts']['severity_by_status']['resolved']['high']),
            ('Resolved Alerts Medium-Severity',             RESULTS['alert_counts_from_alerts']['severity_by_status']['resolved']['medium']),
            ('Resolved Alerts Low-Severity',                RESULTS['alert_counts_from_alerts']['severity_by_status']['resolved']['low']),
            ('',''),
            ('Snoozed Alerts High-Severity',                RESULTS['alert_counts_from_alerts']['severity_by_status']['snoozed']['high']),
            ('Snoozed Alerts Medium-Severity',              RESULTS['alert_counts_from_alerts']['severity_by_status']['snoozed']['medium']),
            ('Snoozed Alerts Low-Severity',                 RESULTS['alert_counts_from_alerts']['severity_by_status']['snoozed']['low']),
            ('',''),
            ('Resolved By Delete Policy',                   RESULTS['alert_counts_from_alerts']['resolved_by_policy']['deleted']),
            ('Resolved By Delete Resourse',                 RESULTS['alert_counts_from_alerts']['resolved_by_resource']['deleted']),
            ('Resolved By Update Resourse',                 RESULTS['alert_counts_from_alerts']['resolved_by_resource']['updated']),
            ('',''),
            ('Alerts Generated by Policies with IaC',         RESULTS['alert_counts_from_alerts']['feature']['shiftable']),
            ('Alerts Generated by Policies with Remediation', RESULTS['alert_counts_from_alerts']['feature']['remediable']),
            ('',''),
            ('Alerts Generated by Custom Policies',         RESULTS['alert_counts_from_alerts']['mode']['custom']),
            ('Alerts Generated by Default Policies',        RESULTS['alert_counts_from_alerts']['mode']['default']),
            ('Alerts Generated by Disabled Policies',       RESULTS['alert_counts_from_alerts']['policy']['disabled']),
            ('',''),
            ('Alerts Generated by AWS Policies',            RESULTS['alert_counts_from_alerts']['cloud_type']['aws']),
            ('Alerts Generated by Azure Policies',          RESULTS['alert_counts_from_alerts']['cloud_type']['azure']),
            ('Alerts Generated by GCP Policies',            RESULTS['alert_counts_from_alerts']['cloud_type']['gcp']),
            ('Alerts Generated by Alibaba Policies',        RESULTS['alert_counts_from_alerts']['cloud_type']['alibaba_cloud']),
            ('Alerts Generated by OCI Policies',            RESULTS['alert_counts_from_alerts']['cloud_type']['oci']),
            ('Alerts Generated by Cross-Cloud Policies',    RESULTS['alert_counts_from_alerts']['cloud_type']['all']),
            ('',''),
            ('',''),
            ('Time Range: %s' % CONFIG['TIME_RANGE_LABEL'], ''),
        ]
        write_sheet(panda_writer, 'Open Closed Alerts Summary', rows)
        rows = []
        rows.append(('Deleted Policy', 'Alert Count'))
        for this_policy_id in sorted(RESULTS['deleted_policies_from_alerts']):
            rows.append((this_policy_id, RESULTS['deleted_policies_from_alerts'][this_policy_id]))
        write_sheet(panda_writer, 'Deleted Policies', rows)

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

if CONFIG['RUN_MODE'] == 'collect':
    output("Run '%s --customer_name %s --mode process' to process the collected data and save to a spreadsheet." % (os.path.basename(__file__), CONFIG['CUSTOMER_NAME']))

if CONFIG['RUN_MODE'] in ['process', 'auto']:
    output('Processing Data')
    output()
    read_collected_data()
    process_collected_data()
    output_collected_data()