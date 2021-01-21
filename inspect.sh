#!/bin/bash

DEBUG=false

##########################################################################################
# PREREQUISITES
##########################################################################################

if ! type "jq" > /dev/null; then
  error_and_exit "jq not installed or not in execution path, jq is required for script execution."
fi

##########################################################################################
# CONFIGURATION
##########################################################################################

# Prisma Cloud API URL
API=""

# Prisma Cloud Login Credentials Access Key
ACCESS_KEY=""

# Prisma Cloud Login Credentials Secret Key
SECRET_KEY=""

# Customer Name
CUSTOMER_NAME=""

# Optionally limit the Alert API query to one Cloud Account
CUSTOMER_ACCOUNT=""

# Used for the (relative) time range for the Alert API query.
# https://api.docs.prismacloud.io/reference#time-range-model

TIME_RANGE_AMOUNT=1
TIME_RANGE_UNIT="month"

##########################################################################################
# UTILITY FUNCTIONS
##########################################################################################

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

prisma_usage() {
  echo ""
  echo "USAGE:"
  echo ""
  echo "  ${0} <OPTIONS>"
  echo ""
  echo "OPTIONS:"
  echo ""
  echo "  --url, -u                Prisma Cloud API URL"
  echo "  --access_key, -a         API Access Key"
  echo "  --secret_key, -s         API Secret Key"
  echo "  --customer, -c           Customer Name, used for output file names"
  echo "  --cloud_account, -ca     (Optional) Cloud Account ID to limit the Alert query"
  echo "  --time_range_amount, -ta (Optional) Time Range Amount [1, 2, 3] to limit the Alert query. Default: ${TIME_RANGE_AMOUNT}"
  echo "  --time_range_unit, -tu   (Optional) Time Range Unit ['day', 'week', 'month', 'year'] to limit the Alert query. Default: '${TIME_RANGE_UNIT}'"
  echo ""
}

##########################################################################################
# PARAMETERS
##########################################################################################

while (( "${#}" )); do
  case "${1}" in
    -u|--url)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        API=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -a|--access_key)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        ACCESS_KEY=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -s|--secret_key)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        SECRET_KEY=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -c|--customer)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        CUSTOMER_NAME=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -ca|--cloud_account)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        CUSTOMER_ACCOUNT=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -ta|--time_range_amount)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        if ! is_numeric "${2}"; then
          prisma_usage
          error_and_exit "Argument for ${1} is not a number"
        fi
        TIME_RANGE_AMOUNT=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -tu|--time_range_unit)
      if [ -n "${2}" ] && [ "${2:0:1}" != "-" ]; then
        TIME_RANGE_UNIT=$2
        shift 2
      else
        prisma_usage
        error_and_exit "Argument for ${1} not specified"
      fi
      ;;
    -h|--help)
      prisma_usage
      exit
      ;;
    -*)
      # Unsupported flags.
      prisma_usage
      error_and_exit "Unsupported flag ${1}"
      ;;
  esac
done

if [ -z "${API}" ]; then
  error_and_exit "Prisma Cloud API URL not specified"
fi

if [ -z "${ACCESS_KEY}" ]; then
  error_and_exit "API Access Key not specified"
fi

if [ -z "${SECRET_KEY}" ]; then
  error_and_exit "API Secret Key not specified"
fi

if [ -z "${CUSTOMER_NAME}" ]; then
  error_and_exit "Customer Name not specified"
fi

# Logon Data
PC_API_LOGIN_FILE=/tmp/prisma-api-login.json

##########################################################################################
# MAIN
##########################################################################################

# Use the active login, or login.
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
    --data "{\"username\":\"${ACCESS_KEY}\",\"password\":\"${SECRET_KEY}\"}" \
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

# Policies

curl -s --request GET \
  --url "${API}/policy?policy.enabled=true" \
  --header 'Accept: */*' \
  --header "x-redlock-auth: ${TOKEN}" \
  | jq > ${CUSTOMER_NAME}-policies.txt

# Alerts

if [ -z "${CUSTOMER_ACCOUNT}" ]; then
  curl -s --request POST \
    --url "${API}/alert" \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json; charset=UTF-8' \
    --header "x-redlock-auth: ${TOKEN}" \
    --data "{\"timeRange\":{\"value\":{\"unit\":\"${TIME_RANGE_UNIT}\",\"amount\":${TIME_RANGE_AMOUNT}},\"type\":\"relative\"}}" \
    | jq > "${CUSTOMER_NAME}-alerts.txt"
else
  curl -s --request POST \
    --url "${API}/alert" \
    --header 'Accept: */*' \
    --header 'Content-Type: application/json; charset=UTF-8' \
    --header "x-redlock-auth: ${TOKEN}" \
    --data "{\"timeRange\":{\"value\":{\"unit\":\"${TIME_RANGE_UNIT}\",\"amount\":${TIME_RANGE_AMOUNT}},\"type\":\"relative\"},\"filters\":[{\"name\":\"cloud.accountId\",\"value\":\"${CUSTOMER_ACCOUNT}\",\"operator\":\"=\"}]}" \
    | jq > "${CUSTOMER_NAME}-alerts.txt"
fi

echo