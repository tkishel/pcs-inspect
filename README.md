# Prisma Cloud Inspect

## Description

The `inspect.sh` script queries the Prisma Cloud API for all enabled Policies,  
and for all Alerts within a Relative Time Range of one (last) month,
and outputs them to `${ORGANIZATION}-policies.txt` and `${ORGANIZATION}-alerts.txt` files.

The `inspect.py` script parses the policies and alerts files created by the `inspect.sh` script, 
calculating various results. It's output utilizes tabs, allowing for import into a spreadsheet.

## Usage

* Download the `inspect.sh` and `inspect.py` scripts.
* Edit the `inspect.sh` script to configure the organization (customer) and logon variables.
* Execute the `inspect.sh -o ` script.
* Execute the `inspect.py -o <organization>` script.
* Profit!

## Example

```
vi inspect.sh
chmod +x inspect.sh
./inspect.sh
./inspect.py -o example
./inspect.py -o example > example.tab
```

Example output [here](example.tab)

## To Do:

* Allow the `inspect.sh` script to accept the same `--organization` parameter as the `inspect.py` script, as well as parameters for Prisma Cloud API URL, Access Key, and Secret Key, and an optional Cloud Account.
* Allow the `inspect.py` script to output directly to Google Sheets and/or Google Slides, or a to a file format directly importable into one or both of them.
* Allow for a Time Range parameter for both scripts.