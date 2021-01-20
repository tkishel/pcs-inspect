#!/bin/bash

DEBUG=false

#### BEGIN CONFIGURATION

# Prisma Cloud › Access URL: Prisma Cloud API URL
API=https://xxx.prismacloud.io

# Prisma Cloud › Login Credentials: Access Key
USERNAME=yyy

# Prisma Cloud › Login Credentials: Secret Key
PASSWORD=zzz

# Customer Name
ORGANIZATION=example

# Cloud Account
ORGANIZATION_ACCOUNT=

# Logon
PC_API_LOGIN_FILE=/tmp/prisma-api-login.json

#### END CONFIGURATION

#### UTILITY FUNCTIONS

debug() {
  if $DEBUG; then
     echo
     echo "DEBUG: ${1}"
     echo
  fi
}

error_and_exit() {
  echo
  echo "ERROR: ${1}"
  echo
  exit 1
}

#### PREREQUISITES

if ! type "jq" > /dev/null; then
  error_and_exit "jq not installed or not in execution path, jq is required for script execution."
fi

#### MAIN

#### Use the active login, or login.
#
# TODO:
#
# The login token is valid for 10 minutes.
# Refresh instead of replace, if it exists, as per:
# https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin/get-started-with-prisma-cloud/access-the-prisma-cloud-api.html

echo "Logging on and creating an API Token"

ACTIVELOGIN=$(find "${PC_API_LOGIN_FILE}" -mmin -10 2>/dev/null)
if [ -z "${ACTIVELOGIN}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  curl --fail --silent \
    --request POST "${API}/login" \
    --header "Content-Type: application/json" \
    --data "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" \
    --output "${PC_API_LOGIN_FILE}"
fi

if [ $? -ne 0 ]; then
  error_and_exit "API Login Failed"
fi

# Check the output instead of checking the response code.

if [ ! -s "${PC_API_LOGIN_FILE}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  error_and_exit "API Login Returned No Response Data"
fi

TOKEN=$(jq -r '.token' < "${PC_API_LOGIN_FILE}")
if [ -z "${TOKEN}" ]; then
  rm -f "${PC_API_LOGIN_FILE}"
  error_and_exit "Token Missing From 'API Login' Response"
fi

debug "Token: ${TOKEN}"

#### Policies

curl -s --request GET \
  --url "${API}/policy?policy.enabled=true" \
  --header 'Accept: */*' \
  --header "x-redlock-auth: ${TOKEN}" \
  | jq > ${ORGANIZATION}-policies.txt

#### Alerts (Last Month)

if [ -z "${ORGANIZATION_ACCOUNT}" ]; then
  curl -s --request POST \
    --url "${API}/alert" \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json; charset=UTF-8' \
    --header "x-redlock-auth: ${TOKEN}" \
    --data "{\"timeRange\":{\"value\":{\"unit\":\"month\",\"amount\":1},\"type\":\"relative\"}}" \
    | jq > ${ORGANIZATION}-alerts.txt
else
  curl -s --request POST \
    --url "${API}/alert" \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json; charset=UTF-8' \
    --header "x-redlock-auth: ${TOKEN}" \
    --data "{\"timeRange\":{\"value\":{\"unit\":\"month\",\"amount\":1},\"type\":\"relative\"},\"filters\":[{\"name\":\"cloud.accountId\",\"value\":\"${ORGANIZATION_ACCOUNT}\",\"operator\":\"=\"}]}" \
    | jq > ${ORGANIZATION}-alerts.txt
fi

echo