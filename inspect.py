#!/usr/bin/env python

import argparse
import json
import os
import sys

##########################################################################################
# Configuration
##########################################################################################

pc_parser = argparse.ArgumentParser(prog='pcsinspect')

pc_parser.add_argument(
    '-c',
    '--customer',
    type=str,
    required=True,
    help='*Required* Customer Name, used for input policy and alert file names')

# https://api.docs.prismacloud.io/reference#time-range-model

pc_parser.add_argument(
    '-ta',
    '--time_range_amount',
    type=int,
    default=1,
    choices=[1, 2, 3],
    help="(Optional) Time Range Amount of the data in the alert file. Default: 1")

pc_parser.add_argument(
    '-tu',
    '--time_range_unit',
    type=str,
    default='month',
    choices=['day', 'week', 'month', 'year'],
    help="(Optional) Time Range Unit of the data in the alert file. Default: 'month'")

args = pc_parser.parse_args()

customer = args.customer
policy_file = '%s-policies.txt' % customer
alert_file = '%s-alerts.txt' % customer
time_range_label = 'Time Range - Past %s %s' % (args.time_range_amount, args.time_range_unit.capitalize()) 

# Use inspect.sh or the commented curl commands in this script to create the policy and alert files.

##########################################################################################
# Validation.
##########################################################################################

if not os.path.isfile(policy_file):
    print('Error: Policy file does not exist: %' % policy_file)
    sys.exit(1)

if not os.path.isfile(alert_file):
    print('Error: Alert file does not exist: %' % alert_file)
    sys.exit(1)


##########################################################################################
# Counters and Structures.
##########################################################################################

# Note it appears that `audit_event` alerts are returned from the /policy endpoint, not from the /alert endpoint.
# The `policy_counts` structure counts results from the /alert endpoint. So, included only for reference.

policy_counts = {
    'high':        0,
    'medium':      0,
    'low':         0,
    'anomaly':     0,
    'audit_event': 0,
    'config':      0,
    'network':     0,
}

alert_counts = {
    'open':             0,
    'resolved':         0,
    'resolved_deleted': 0,
    'resolved_updated': 0,
    'resolved_high':    0,
    'resolved_medium':  0,
    'resolved_low':     0,
    'shiftable':        0,
    'remediable':       0,
}

policies = {}
alerts_by_compliance_standard = {}
alerts_by_policy = {}

##########################################################################################
# Loop through all Policies and collect the details of each Policy.
##########################################################################################

# Example API request to generate policies.txt:
#
# curl -s --request GET \
#   --url "${API}/policy?policy.enabled=true" \
#   --header 'Accept: */*' \
#   --header "x-redlock-auth: ${TOKEN}" \
#   | jq > ${CUSTOMER_NAME}-policies.txt

with open(policy_file, 'r') as f:
  policy_list = json.load(f)

for policy in policy_list:
    policyId = policy['policyId']
    # Transform Policies from policy_list to policies.
    if not policies.has_key(policyId):
        policies[policyId] = {}
    policies[policyId]['policyName'] = policy['name']
    policies[policyId]['policySeverity'] = policy['severity']
    policies[policyId]['policyType'] = policy['policyType']
    policies[policyId]['policyShiftable'] = 'build' in policy['policySubTypes']
    policies[policyId]['policyRemediable'] = policy['remediable']
    policies[policyId]['policyOpenAlertsCount'] = policy['openAlertsCount']
    # Create sets and lists of Compliance Standards to create a sorted, unique list of counters for each Compliance Standard.
    compliance_standards_set = set()
    policies[policyId]['complianceStandards'] = list()
    if policy.has_key('complianceMetadata'):
        for standard in policy['complianceMetadata']:
            compliance_standards_set.add(standard['standardName'])
        compliance_standards_list = list(compliance_standards_set)
        compliance_standards_list.sort()
        policies[policyId]['complianceStandards'] = compliance_standards_list
    # Initialize Compliance Standard Alert Counts (to avoid an error with += when the variable is undefined).
    for standard in compliance_standards_list:
        if not alerts_by_compliance_standard.has_key(standard):
            alerts_by_compliance_standard[standard] = {'high': 0, 'medium': 0, 'low': 0}


##########################################################################################
# Loop through all Alerts and collect the details of each Alert.
# Some details come from the Alert, some from the associated Policy.
##########################################################################################

# Example API request to generate alerts.txt:
#
# curl -s --request POST \
#   --url "${API}/alert" \
#   --header 'Accept: */*' \
#   --header 'Content-Type: application/json; charset=UTF-8' \
#   --header "x-redlock-auth: ${TOKEN}" \
#   --data "{\"timeRange\":{\"value\":{\"unit\":\"${TIME_RANGE_UNIT}\",\"amount\":${TIME_RANGE_AMOUNT}},\"type\":\"relative\"}}" \
#   | jq > ${CUSTOMER_NAME}-alerts.txt
  
with open(alert_file, 'r') as f:
  alert_list = json.load(f)

for alert in alert_list:
    policyId = alert['policy']['policyId']
    policyName = policies[policyId]['policyName']
    # Transform alerts from alert_list to alerts_by_policy, and initialize Alert Count (to avoid an error with += when the variable is undefined).
    if not alerts_by_policy.has_key(policyName):
        alerts_by_policy[policyName] = {'policyId': policyId, 'alertCount': 0}
    # Increment Alert Count for each associated Compliance Standard
    for standard in policies[policyId]['complianceStandards']:
        alerts_by_compliance_standard[standard][policies[policyId]['policySeverity']] += 1
    # Increment Alert Count for associated Policy
    alerts_by_policy[policyName]['alertCount'] += 1
    # Increment Policies by Severity
    policy_counts[policies[policyId]['policySeverity']] += 1
    # Increment Policies by Type
    policy_counts[policies[policyId]['policyType']] += 1
    # Increment Alerts by Status
    alert_counts[alert['status']] += 1
    # Increment Alerts Closed by Reason
    if alert.has_key('reason'):
        if alert['reason'] == 'RESOURCE_DELETED':
            alert_counts['resolved_deleted'] += 1
        if alert['reason'] == 'RESOURCE_UPDATED':
            alert_counts['resolved_updated'] += 1
    # Increment Alerts by Severity
    alert_counts['resolved_%s' % policies[policyId]['policySeverity']] += 1
    # Increment Alerts with IaC
    if policies[policyId]['policyShiftable']:
        alert_counts['shiftable'] += 1
	# Increment Alerts with Remediation
    if alert['policy']['remediable']:
        alert_counts['remediable'] += 1

##########################################################################################
# Output tables and totals.
##########################################################################################

# Output Compliance Standards with Alerts

print
print('#################################################################################')
print('# SHEET: By Compliance Standard, Open and Closed Alerts, %s' % time_range_label)
print('#################################################################################')
print
print('%s\t%s\t%s\t%s' % ('Compliance Standard', 'High-Severity Alert Count', 'Medium-Severity Alert Count', 'Low-Severity Alert Count'))																						
for standard in sorted(alerts_by_compliance_standard):
    print('%s\t%s\t%s\t%s' % (standard, alerts_by_compliance_standard[standard]['high'], alerts_by_compliance_standard[standard]['medium'], alerts_by_compliance_standard[standard]['low']))

# Output Policies with Alerts

print
print('#################################################################################')
print('# SHEET: By Policy, Open and Closed Alerts, %s' % time_range_label)
print('#################################################################################')
print
print('%s\t%s\t%s\t%s\t%s\t%s\t%s' % ('policyName', 'policySeverity', 'policyType', 'policyShiftable', 'policyRemediable', 'alertCount', 'policyComplianceStandards') )
for policy in sorted(alerts_by_policy):
    policyId                    = alerts_by_policy[policy]['policyId']
    policyName                  = policies[policyId]['policyName']
    policySeverity              = policies[policyId]['policySeverity']
    policyType                  = policies[policyId]['policyType']
    policyShiftable             = policies[policyId]['policyShiftable']
    policyRemediable            = policies[policyId]['policyRemediable']
    alert_count                 = alerts_by_policy[policy]['alertCount']
    policy_compliance_standards = ','.join(map(str, policies[policyId]['complianceStandards']))
    print('%s\t%s\t%s\t%s\t%s\t%s\t"%s"' % (policyName, policySeverity, policyType, policyShiftable, policyRemediable, alert_count, policy_compliance_standards))

# Output Summary

print
print('#################################################################################')
print('# SHEET: Summary, Open and Closed Alerts, %s' % time_range_label)
print('#################################################################################')
print
print("Compliance Standard with Alerts: Total\t%s" % len(alerts_by_compliance_standard))
print
print("Policies with Alerts: Total\t%s"            % len(alerts_by_policy))
print("Policies with Alerts: High-Severity\t%s"    % policy_counts['high'])
print("Policies with Alerts: Medium-Severity\t%s"  % policy_counts['medium'])
print("Policies with Alerts: Low-Severity\t%s"     % policy_counts['low'])
print("Policies with Alerts: Anomaly\t%s"          % policy_counts['anomaly'])
print("Policies with Alerts: Config\t%s"           % policy_counts['config'])
print("Policies with Alerts: Network\t%s"          % policy_counts['network'])
# print("Policies with Alerts: Audit\t%s"          % policy_counts['audit_event']) # See Note above.
print
print("Alerts: Total\t%s"              % len(alert_list))
print("Alerts: Open\t%s"               % alert_counts['open'])
print("Alerts: Resolved\t%s"           % alert_counts['resolved'])
print("Alerts: Resolved by Delete\t%s" % alert_counts['resolved_deleted'])
print("Alerts: Resolved by Update\t%s" % alert_counts['resolved_updated'])
print("Alerts: High-Severity\t%s"      % alert_counts['resolved_high'])
print("Alerts: Medium-Severity\t%s"    % alert_counts['resolved_medium'])
print("Alerts: Low-Severity\t%s"       % alert_counts['resolved_low'])
print("Alerts: with IaC\t%s"           % alert_counts['shiftable'])
print("Alerts: with Remediation\t%s"   % alert_counts['remediable'])
print
