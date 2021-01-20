#!/usr/bin/env python

import argparse
import json
import sys

##########################################################################################
# Configuration
##########################################################################################

pc_parser = argparse.ArgumentParser(prog='inspect')
pc_parser.add_argument(
    '-o',
    '--organization',
    type=str,
    required=True,
    help='* Required * Prefix of (existing) policy and alert files to inspect.')
args = pc_parser.parse_args()
organization = args.organization

# Use inspect.sh or the commented curl commands in this script to create the policy and alert files.

##########################################################################################
# Counters and Structures.
##########################################################################################

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

policy_alert_counts = {
    'alerts_open_high':        0,
    'alerts_open_medium':      0,
    'alerts_open_low':         0,
    'alerts_open_shiftable':   0,
    'alerts_open_remediable':  0,
}

policies = {}
alerts_by_compliance_standard = {}
alerts_by_policy = {}

##########################################################################################
# Loop through all Policies and collect the details of each Policy.
##########################################################################################

# curl -s --request GET \
#   --url "${API}/policy?policy.enabled=true" \
#   --header 'Accept: */*' \
#   --header "x-redlock-auth: ${TOKEN}" \
#   | jq > ${ORGANIZATION}-policies.txt

with open('%s-policies.txt' % organization, 'r') as f:
  policy_list = json.load(f)

for policy in policy_list:
    policyId = policy['policyId']
    # Transform Policy from policy_list to policies.
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
    # Count Open Alerts by Severity
    policy_alert_counts['alerts_open_%s' % policy['severity']] += policy['openAlertsCount']
    # Count Open Alerts by IaC
    if policies[policyId]['policyShiftable']:
        policy_alert_counts['alerts_open_shiftable'] += policy['openAlertsCount']
    # Count Open Alerts by Remediation
    if policies[policyId]['policyRemediable']:
        policy_alert_counts['alerts_open_remediable'] += policy['openAlertsCount']


##########################################################################################
# Loop through all Alerts and collect the details of each Alert.
# Some details come from the Alert, some from the associated Policy.
##########################################################################################

# curl -s --request POST \
#   --url "${API}/alert" \
#   --header 'Accept: */*' \
#   --header 'Content-Type: application/json; charset=UTF-8' \
#   --header "x-redlock-auth: ${TOKEN}" \
#   --data "{\"timeRange\":{\"value\":{\"unit\":\"month\",\"amount\":1},\"type\":\"relative\"}}" \
#   | jq > ${ORGANIZATION}-alerts.txt
  
with open('%s-alerts.txt' % organization, 'r') as f:
  alert_list = json.load(f)

for alert in alert_list:
    policyId = alert['policy']['policyId']
    policyName = policies[policyId]['policyName']
    # Transform Alert from alert_list to alerts_by_policy, and initialize Alert Count (to avoid an error with += when the variable is undefined).
    if not alerts_by_policy.has_key(policyName):
        alerts_by_policy[policyName] = {'policyId': policyId, 'alertCount': 0}
    # Increment Compliance Standards Alert Count
    for standard in policies[policyId]['complianceStandards']:
        alerts_by_compliance_standard[standard][policies[policyId]['policySeverity']] += 1
    # Increment Policy Alert Count
    alerts_by_policy[policyName]['alertCount'] += 1
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

# Output Policy Totals

print
print('#################################################################################')
print('All Open Alerts: By Policy Severity, IaC, and Remediation')
print('#################################################################################')
print
print('Open Alerts: High-Severity\t%s'    % policy_alert_counts['alerts_open_high'])
print('Open Alerts: Medium-Severity\t%s'  % policy_alert_counts['alerts_open_medium'])
print('Open Alerts: Low-Severity\t%s'     % policy_alert_counts['alerts_open_low'])
print('Open Alerts: With IaC\t%s'         % policy_alert_counts['alerts_open_shiftable'])
print('Open Alerts: With Remediation\t%s' % policy_alert_counts['alerts_open_remediable'])

# Output Compliance Standards with Alerts Totals

print
print('#################################################################################')
print('Last Month: Open and Closed Alerts: By Compliance Standard')
print('#################################################################################')
print
print('%s\t%s\t%s\t%s' % ('Compliance Standard', 'High-Severity Alert Count', 'Medium-Severity Alert Count', 'Low-Severity Alert Count'))																						
for standard in sorted(alerts_by_compliance_standard):
    print('%s\t%s\t%s\t%s' % (standard, alerts_by_compliance_standard[standard]['high'], alerts_by_compliance_standard[standard]['medium'], alerts_by_compliance_standard[standard]['low']))

# Output Policies with Alerts Totals

print
print('#################################################################################')
print('Last Month: Open and Closed Alerts: By Policy')
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

# Output Alert Totals

print
print('#################################################################################')
print('Last Month: Open and Closed Alerts: Totals')
print('#################################################################################')
print
print("Alerts: Total\t%s"              % len(alert_list))
print("Alerts: Open\t%s"               % alert_counts['open'])
print("Alerts: Resolved\t%s"           % alert_counts['resolved'])
print("Alerts: Resolved by Delete\t%s" % alert_counts['resolved_deleted'])
print("Alerts: Resolved by Update\t%s" % alert_counts['resolved_updated'])
print("Alerts: Resolved\t%s"           % alert_counts['resolved'])
print("Alerts: High-Severity\t%s"      % alert_counts['resolved_high'])
print("Alerts: Medium-Severity\t%s"    % alert_counts['resolved_medium'])
print("Alerts: Low-Severity\t%s"       % alert_counts['resolved_low'])
print("Alerts: With IaC\t%s"           % alert_counts['shiftable'])
print("Alerts: With Remediation\t%s"   % alert_counts['remediable'])
print
